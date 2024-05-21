#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$MerakiAPIKey = "<MERAKI API KEY>"
$ITGlue_Base_URI = "https://sts.itglue.com"
$FlexAssetName = "Licensing"

$ConfigurationTypes = @{ # This maps Meraki product types to ITG configuration types (by ITG type ID)
	"wireless" = 1
	"switch" = 2
	"firewall" = 3
	"appliance" = 4
}
$ConfigurationStatusID = 10 # The ITG Active status ID
$MerakiManufacturerID = 20 # The ITG manufacturer ID for Meraki
$Orgs_PreventConfigCreation = @("") # The meraki name or ID of any organizations you don't want to automatically add ITG configs for
#####################################################################

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

#Grabbing ITGlue Module and installing.
If (Get-Module -ListAvailable -Name "ITGlueAPI") { 
    Import-module ITGlueAPI 
} Else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
  
#Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy

# Get the flexible asset type id
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$ITGOrgs = Get-ITGlueOrganizations -page_size 1000
if (!$ITGOrgs -or !$ITGOrgs.data -or !$FilterID -or ($ITGOrgs.data | Measure-Object).Count -lt 1 -or !$ITGOrgs.data[0].attributes -or !$ITGOrgs.data[0].attributes.name) {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}
 
# Install/Import PSMeraki module
If (Get-Module -ListAvailable -Name "PSMeraki") {Import-module PSMeraki} Else { Install-ModuleFromGitHub -GitHubRepo chrisjantzen/PSMeraki -Branch build; import-module PSMeraki}

Set-MrkRestApiKey -key $MerakiAPIKey

# Get a list of ITG & Meraki organizations
$ITGOrgs = $ITGOrgs.data | Where-Object { $_.attributes.'organization-type-name' -like 'Customer' -and $_.attributes.'organization-status-name' -like 'Active' }
$MerakiOrgs = Get-MrkOrganization

# Levenshtein distance function for comparing similarity between two strings
function Measure-StringDistance {
    <#
        .SYNOPSIS
            Compute the distance between two strings using the Levenshtein distance formula.
        
        .DESCRIPTION
            Compute the distance between two strings using the Levenshtein distance formula.

        .PARAMETER Source
            The source string.

        .PARAMETER Compare
            The comparison string.

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Micheal"

            2

            There are two characters that are different, "a" and "e".

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Michal"

            1

            There is one character that is different, "e".

        .NOTES
            Author:
            Michael West
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([int])]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$Source = "",
        [string]$Compare = ""
    )
    $n = $Source.Length;
    $m = $Compare.Length;
    $d = New-Object 'int[,]' $($n+1),$($m+1)
        
    if ($n -eq 0){
      return $m
	}
    if ($m -eq 0){
	    return $n
	}

	for ([int]$i = 0; $i -le $n; $i++){
        $d[$i, 0] = $i
    }
    for ([int]$j = 0; $j -le $m; $j++){
        $d[0, $j] = $j
    }

	for ([int]$i = 1; $i -le $n; $i++){
	    for ([int]$j = 1; $j -le $m; $j++){
            if ($Compare[$($j - 1)] -eq $Source[$($i - 1)]){
                $cost = 0
            }
            else{
                $cost = 1
            }
		    $d[$i, $j] = [Math]::Min([Math]::Min($($d[$($i-1), $j] + 1), $($d[$i, $($j-1)] + 1)),$($d[$($i-1), $($j-1)]+$cost))
	    }
	}
	    
    return $d[$n, $m]
}

# Loads a WPF form and returns the loaded form
function loadForm($Path) {
	$inputXML = Get-Content $Path -Raw
	$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
	[xml]$XAML = $inputXML
	$reader = (New-Object System.Xml.XmlNodeReader $XAML) 
	try {
		$Form = [Windows.Markup.XamlReader]::Load( $reader )
	} catch {
		Write-Warning $_.Exception
		throw
	}

	# this finds all of the possible variables in the form (btn, listbox, textbox) and maps them to powershell variables with "var_" appended to the objects name. e.g. var_btnSave
	$XAML.SelectNodes("//*[@Name]") | ForEach-Object {
		#"trying item $($_.Name)"
		try {
			Set-Variable -Name "var_$($_.Name)" -Value $Form.FindName($_.Name) -Scope 1 -ErrorAction Stop
		} catch {
			throw
		}
	}

	return $Form
}

# Archives an ITG meraki license
function archive_itg($FlexAssetID) {
	$OriginalAsset = Get-ITGlueFlexibleAssets -id $FlexAssetID

	if ($OriginalAsset -and $OriginalAsset.data -and ($OriginalAsset.data | Measure-Object).Count -eq 1) {
		$OriginalAsset = $OriginalAsset.data[0]
	} else {
		Write-Warning "Could not find FlexAssetID $($FlexAssetID) in ITG. Skipping archival..."
		return $false
	}

	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
			'organization-id' = $OriginalAsset.attributes.'organization-id'
			'flexible-asset-type-id' = $OriginalAsset.attributes.'flexible-asset-type-id'
			'archived' = $true
			traits = $OriginalAsset.attributes.traits
		}
	}
	
	if ($FlexAssetBody.attributes.traits."assigned-device-s") {
		$FlexAssetBody.attributes.traits."assigned-device-s" = @($($FlexAssetBody.attributes.traits."assigned-device-s".values.id | Sort-Object -Unique))
	}

	try {
		Set-ITGlueFlexibleAssets -id $FlexAssetID -data $FlexAssetBody
		return $true
	} catch {
		Write-Error "Could not archive Meraki License '$FlexAssetID' for the reason: " + $_.Exception.Message
		return $false
	}
}

# Match the ITG / Meraki organizations by name
$OrgMatches = @()
$MatchNotFound = @()
$DontMatch = @()

# Import and use existing matches if they exist
$AllMatches = @()
if (Test-Path -Path "meraki_matches.json" -PathType Leaf) {
	$AllMatches = Get-Content -Raw -Path "meraki_matches.json" | ConvertFrom-Json
}

# Start matching
$ChangesMadeToMatches = $false
foreach ($MerakiOrg in $MerakiOrgs) {
	$Match = $null
	
	# Check existing matches first
	if ($MerakiOrg.id -in $AllMatches.merakiId) {
		$Match = $AllMatches | Where-Object { $_.merakiId -eq $MerakiOrg.id }
		if ($Match.itgId) {
			# match found
			$OrgMatches += [pscustomobject]@{
				merakiId = $Match.merakiId
				merakiName = $Match.merakiName
				itgId = $Match.itgId
				itgName = $Match.itgName
			}
		} else {
			# not matched (manually)
			$DontMatch += @{
				merakiId = $Match.merakiId
				merakiName = $Match.merakiName
			}
		}

		continue
	}

	# No existing match, lets handle the matching
	$Matches = $ITGOrgs | Where-Object { $_.attributes.name -like "*$($MerakiOrg.name)*" -or $MerakiOrg.name -like "*$($_.attributes.name)*" }
	if (($Matches | Measure-Object).Count -gt 1) {
		# narrow down to 1
		$Match = $Matches | Where-Object { $_.attributes.name -like $MerakiOrg.name -or $MerakiOrg.name -like $($_.attributes.name) }
		if (($Match | Measure-Object).Count -ne 1) {
			$BestDistance = 999;
			foreach ($TestMatch in $Matches) {
				$Distance = Measure-StringDistance -Source $MerakiOrg.name -Compare $TestMatch.attributes.name
				if ($Distance -lt $BestDistance) {
					$Match = $TestMatch
					$BestDistance = $Distance
				}
			}
		}
	} elseif (($Matches | Measure-Object).Count -eq 1) {
		$Match = $Matches[0]
	}
	
	if ($Match) {
		# match found
		$OrgMatches += [pscustomobject]@{
			merakiId = $MerakiOrg.id
			merakiName = $MerakiOrg.name
			itgId = $Match.id
			itgName = $Match.attributes.name
		}
	} else {
		# no match found
		$MatchNotFound += @{
			merakiId = $MerakiOrg.id
			merakiName = $MerakiOrg.name
		}
	}
	$ChangesMadeToMatches = $true
}

# Use a form to allow manual matching of any orgs we couldn't auto match
if (($MatchNotFound | Measure-Object).Count -gt 0) {

	foreach ($MissingMatch in $MatchNotFound) {
		$Match = $null

		$Form = loadForm -Path(".\Forms\OrgMatching\OrgMatching\MainWindow.xaml")

		function cmbItems($Items, $Filter = "") {
			$FilteredItems = $Items | Where-Object { $_ -like "*$Filter*" } | Sort-Object
			$var_cmbMatch.Items.Clear()
			foreach ($Item in $FilteredItems) {
				$var_cmbMatch.Items.Add($Item) | Out-Null
			}
		}

		$var_lblOrgName.Content = $MissingMatch.merakiName
		$var_lblMatchingNotes.Content = "Meraki ID: $($MissingMatch.merakiId)"

		# update the listbox with the ITG orgs
		$Items = $ITGOrgs.attributes.name
		cmbItems -Items $Items

		$var_cmbMatch.Add_KeyUp({
			if ($_.Key -eq "Down" -or $_.Key -eq "Up") {
				$var_cmbMatch.IsDropDownOpen = $true
			} elseif ($_.Key -ne "Enter" -and $_.Key -ne "Tab" -and $_.Key -ne "Return") {
				$var_cmbMatch.IsDropDownOpen = $true
				cmbItems -Items $Items -Filter $var_cmbMatch.Text
			}
		})

		$var_cmbMatch.Add_SelectionChanged({
			$SelectedAsset = $var_cmbMatch.SelectedItem
			$script:Match = $ITGOrgs | Where-Object { $_.attributes.name -eq $SelectedAsset }
		})

		$var_btnNoMatch.Add_Click({
			Write-Host "Organization skipped! ($($MissingMatch.merakiName))"
			$script:DontMatch += $MissingMatch
			$Form.Close()
			continue;
		})

		$var_btnSave.Add_Click({
			$Form.Close()
		})

		$Form.ShowDialog() | out-null

		if ($Match) {
			$OrgMatches += [pscustomobject]@{
				merakiId = $MissingMatch.merakiId
				merakiName = $MissingMatch.merakiName
				itgId = $Match.id
				itgName = $Match.attributes.name
			}
		}

		$ChangesMadeToMatches = $true
	}
}

# Create update json matching document for quick matching in the future
if ($ChangesMadeToMatches) {
	$AllMatches = $OrgMatches
	$DontMatch | ForEach-Object { 
		$AllMatches += [PSCustomObject]@{
			merakiId = $_.merakiId
			merakiName = $_.merakiName
			itgId = $null
			itgName = $null
		}
	}

	$AllMatches | ConvertTo-Json | Out-File "meraki_matches.json"
}

if ($DontMatch) {
	Write-Output "Some meraki orgs have been manually set to no match with ITG!"
	Write-Output "If you need to match these, please edit the meraki_matches.json file manually."
}


# All matches made, now lets get the license info and devices from Meraki
$LicenseInfo = @()
foreach ($Org in $OrgMatches) {
	if (!$Org.itgId) {
		continue # skip orgs not mapped with ITG
	}

	$LicenseState = Get-MrkLicenseState -orgId $Org.merakiId
	if ($LicenseState -like "HTTP Error*") {
		Write-Warning "An error occurred connecting to Meraki org: $($Org.merakiName)."
		Write-Warning "Please ensure the API is enabled for this company."
		Write-Output $LicenseState
	} else {
		$Licenses = Get-MrkLicenses -orgId $Org.merakiId
		$Devices = Get-MrkDevicesStatus -orgId $Org.merakiId
		if ($Licenses -like "HTTP Error*") {
			$Licenses = @()
		}
		if ($Devices -like "HTTP Error*") {
			$Devices = @()
		}
		$LicenseInfo += [PSCustomObject]@{
			merakiId = $Org.merakiId
			status = $LicenseState.status
			expirationDate = $LicenseState.expirationDate
			licensedDeviceCounts = $LicenseState.licensedDeviceCounts
			licenses = $Licenses
			devices = $Devices
		}
	}
}

$OrgDevices = @()
$OrgExistingLicenses = @()
$ITGMerakiModels = $false
foreach ($OrgLicensing in $LicenseInfo) {
	$UpdatedLicenses = 0
	# Skip empty licenses
	if ([string]::IsNullOrEmpty($OrgLicensing.licensedDeviceCounts) -and !$OrgLicensing.licenses -and !$OrgLicensing.devices) {
		continue
	}

	# Get org info
	$Organization = $OrgMatches | Where-Object { $_.merakiId -eq $OrgLicensing.merakiId }

	# If we haven't already, get all the configurations for this company from ITG for device matching
	if (($OrgLicensing.devices | Measure-Object).Count -gt 0) {
		if (($OrgDevices | Where-Object { $_.itgId -eq $Organization.itgId } | Measure-Object).Count -eq 0) {
			Write-Output "Downloading all ITG configurations for: $($Organization.itgName)"
			$FullConfigurationsList = Get-ITGlueConfigurations -page_size "1000" -organization_id $Organization.itgId
			$i = 1
			while ($FullConfigurationsList.links.next) {
				$i++
				$Configurations_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $Organization.itgId
				$FullConfigurationsList.data += $Configurations_Next.data
				$FullConfigurationsList.links = $Configurations_Next.links
			}
			$FullConfigurationsList = $FullConfigurationsList.data
			
			$OrgDevices += @{
				itgId = $Organization.itgId
				devices = $FullConfigurationsList
			}
		}
	}

	# If we haven't already, get any existing Meraki licenses for this company from ITG
	if (($OrgExistingLicenses | Where-Object { $_.itgId -eq $Organization.itgId } | Measure-Object).Count -eq 0) {
		Write-Output "Downloading existing Meraki licenses for: $($Organization.itgName)"
		$ExistingLicenses = (Get-ITGlueFlexibleAssets -page_size 1000 -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $Organization.itgId).data
		$ExistingLicenses = $ExistingLicenses | Where-Object { $_.attributes.name -like "*Meraki*" }
		$OrgExistingLicenses += @{
			itgId = $Organization.itgId
			licenses = $ExistingLicenses
		}
	}

	if (($OrgLicensing.licenses | Measure-Object).Count -gt 0) {
		# Per-device licensing
		$ExistingLicenses = $OrgExistingLicenses | Where-Object { $_.itgId -eq $Organization.itgId }

		foreach ($License in $OrgLicensing.licenses) {
			$LicenseName = "Meraki Per-Device License (State: $($License.state))"

			$MerakiDevice = $false
			if ($License.deviceSerial) {
				$MerakiDevice = $OrgLicensing.devices | Where-Object { $_.serial -eq $License.deviceSerial }
			}
			$ExistingLicense = $ExistingLicenses.licenses | Where-Object { $_.attributes.traits.name -like "Meraki Per-Device License*" -and $_.attributes.traits.'additional-notes' -like "*License ID: $($License.id)*" }

			$AllDevices = $OrgDevices | Where-Object { $_.itgId -eq $Organization.itgId }
			$OrgDevice = $false
			if ($License.deviceSerial -or $MerakiDevice) {
				$OrgDevice = $AllDevices.devices | Where-Object { ($License.deviceSerial -and $_.attributes.'serial-number' -eq $License.deviceSerial) -or ($MerakiDevice -and $_.attributes.name -like $MerakiDevice.name) }
			}
			$DeviceName = if ($OrgDevice) { $OrgDevice[0].attributes.name } elseif ($MerakiDevice) { $MerakiDevice.name } else { "Unassigned" }

			$ClaimDate = $null;
			$RenewalDate = $null;
			if ($License.claimDate -and ([string]$License.claimDate -as [DateTime])) {
				$ClaimDate = ([DateTime]$License.claimDate).ToString("yyyy-MM-dd")
			}
			if ($License.expirationDate -and ([string]$License.expirationDate -as [DateTime])) {
				$RenewalDate = ([DateTime]$License.expirationDate).ToString("yyyy-MM-dd")
			}

			$AdditionalNotes = "================== <br>"
			$AdditionalNotes += "Do NOT edit <br>"
			$AdditionalNotes += "Meraki ID: $($OrgLicensing.merakiId) <br>"
			$AdditionalNotes += "License ID: $($License.id) <br>"
			$AdditionalNotes += "Order #: $($License.orderNumber) <br>"
			$AdditionalNotes += "Duration: $($License.durationInDays) days <br>"
			if ($DeviceName -eq "Unassigned" -and $License.state -ne "active") {
				$AdditionalNotes += "Unassigned License <br>"
			}
			$AdditionalNotes += "=================="

			$FlexAssetBody = 
			@{
				type = 'flexible-assets'
				attributes = @{
					'organization-id' = $Organization.itgId
					'flexible-asset-type-id' = $FilterID.id
					traits = @{
						"name" = $LicenseName
						"version" = $License.licenseType
						"target-type" = "Hardware"
						"licensing-method" = "License Key"
						"license-product-serial-key" = $License.licenseKey
						"seats" = $License.seatCount
						"purchase-date" = $ClaimDate
						"renewal-date" = $RenewalDate
						"additional-notes" = $AdditionalNotes
						"assigned-device-s" = if ($OrgDevice) { @($($OrgDevice.id | Sort-Object -Unique)) } else { @() }
					}
				}
			}

			if ($ExistingLicense) {
				# Update existing license
				if ($ExistingLicense.attributes.traits.name -ne $LicenseName -or
					$ExistingLicense.attributes.traits.version -ne $License.licenseType -or
					$ExistingLicense.attributes.traits.'license-product-serial-key' -ne $License.licenseKey -or
					$ExistingLicense.attributes.traits.seats -ne $License.seatCount -or
					$ExistingLicense.attributes.traits.'purchase-date' -ne $ClaimDate -or
					$ExistingLicense.attributes.traits.'renewal-date' -ne $RenewalDate -or
					($ExistingLicense.attributes.traits.'assigned-device-s'.values.id | Sort-Object | Out-String) -ne ($OrgDevice.id | Sort-Object | Out-String) -or
					$ExistingLicense.attributes.traits.'additional-notes' -notlike "*$($AdditionalNotes)*") {
						# changes found, update
						if ($ExistingLicense.attributes.traits.'additional-notes') {
							$AdditionalNotes = $ExistingLicense.attributes.traits.'additional-notes' -replace "==================.+==================", $AdditionalNotes
							$AdditionalNotes = $AdditionalNotes.Trim()
							$FlexAssetBody.attributes.traits.'additional-notes' = $AdditionalNotes
						}
	
						if($ExistingLicense.attributes.traits.'other-keys-codes') {
							$FlexAssetBody.attributes.traits.'other-keys-codes' = $ExistingLicense.attributes.traits.'other-keys-codes'
						}
						if($ExistingLicense.attributes.traits.'ticket-number-for-original-purchase') {
							$FlexAssetBody.attributes.traits.'ticket-number-for-original-purchase' = $ExistingLicense.attributes.traits.'ticket-number-for-original-purchase'
						}

						# Filter out empty values
						($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
							$FlexAssetBody.attributes.traits.Remove($_.Name) 
						}
	
						Write-Host "Updating Per-Device License for: $($Organization.itgName) - $($DeviceName)"
						Set-ITGlueFlexibleAssets -id $ExistingLicense.id  -data $FlexAssetBody
					} else {
						Write-Host "Update not required for Per-Device License for: $($Organization.itgName) - $($DeviceName)"
					}
			} else {
				# New license asset
				Write-Host "Creating new per-device license asset for: $($Organization.itgName) - $($DeviceName)"
				New-ITGlueFlexibleAssets -data $FlexAssetBody
			}
			$UpdatedLicenses++
		}
	} else {
		# Co-term licensing
		$ExistingLicenses = $OrgExistingLicenses | Where-Object { $_.itgId -eq $Organization.itgId }
		$ExistingLicense = $ExistingLicenses.licenses | Where-Object { $_.attributes.name -like "Meraki Co-Term Licensing*" }

		$AllDevices = $OrgDevices | Where-Object { $_.itgId -eq $Organization.itgId }
		$AssignedDevices = $AllDevices.devices | Where-Object { $_.attributes.name -in $OrgLicensing.devices.name }

		if ($Organization.merakiName -notin $Orgs_PreventConfigCreation -and $Organization.merakiId -notin $Orgs_PreventConfigCreation) {
			$MissingDevices = $OrgLicensing.devices.name | Where-Object {!($AssignedDevices.attributes.name -contains $_)}

			if ($MissingDevices -and !$ITGMerakiModels) {
				$ITGMerakiModels = (Get-ITGlueModels -manufacturer_id $MerakiManufacturerID -page_size 1000).data
			}

			foreach ($MissingDeviceName in $MissingDevices) {
				$DeviceDetails = $OrgLicensing.devices | Where-Object { $_.name -eq $MissingDeviceName }
				$ConfigType = $false

				if (!$DeviceDetails.name) {
					continue
				}

				if ($DeviceDetails.productType -notin $ConfigurationTypes.keys) {
					continue
				} else {
					if ($DeviceDetails.productType -eq "appliance" -and ($DeviceDetails.name -like "*FW*" -or $DeviceDetails.name -like "*Firewall*")) {
						$DeviceDetails.productType = "firewall"
					}
					$ConfigType = $ConfigurationTypes[$DeviceDetails.productType]
					if (!$ConfigType) { continue }
				}

				$Model = $ITGMerakiModels | Where-Object { $_.attributes.name -like $DeviceDetails.model }
				if (!$Model) {
					$NewModelData = @{
						type = "models"
						attributes = @{
							name = $DeviceDetails.model
							"manufacturer-id" = $MerakiManufacturerID
						}
					}
					$Model = New-ITGlueModels -manufacturer_id $MerakiManufacturerID -data $NewModelData

					if ($Model -and $Model.data) {
						$Model = $Model.data[0]
						$ITGMerakiModels += $Model
					} else {
						continue
					}

				}

				$NewConfigData = 
				@{
					type = 'configurations'
					attributes = @{
						'name' = $DeviceDetails.name
						'serial-number' = $DeviceDetails.serial
						'mac-address' = $DeviceDetails.mac
						'primary-ip' = if ($DeviceDetails.lanIp) { $DeviceDetails.lanIp } elseif ($DeviceDetails.wan1Ip) { $DeviceDetails.wan1Ip } else { "" }
						'default-gateway' = if ($DeviceDetails.gateway) { $DeviceDetails.gateway } elseif ($DeviceDetails.wan1Gateway) { $DeviceDetails.wan1Gateway } else { "" }

						'configuration-type-id' = $ConfigType
						'configuration-status-id' = $ConfigurationStatusID
						'manufacturer-id' = $MerakiManufacturerID
						'model-id' = $Model.id
					}
				}

				$NewConfig = New-ITGlueConfigurations -organization_id $Organization.itgId -data $NewConfigData
				if ($NewConfig -and $NewConfig.data) {
					$NewConfig = $NewConfig.data[0]
					($OrgDevices | Where-Object { $_.itgId -eq $Organization.itgID }).devices += $NewConfig
					$AssignedDevices += $NewConfig
					Write-Host "Added new ITG config: $($NewConfig.attributes.name)"
				}
			}
		}


		$RenewalDate = [datetime]::ParseExact($OrgLicensing.expirationDate.Replace(" UTC", ""), 'MMM d, yyyy', $null).ToString("yyyy-MM-dd")
		$DeviceCounts = @()
		foreach ($LicenseCount in $OrgLicensing.licensedDeviceCounts.PSObject.Properties) {
			$DeviceCounts += [PSCustomObject]@{
				DeviceType = $LicenseCount.Name
				Count = $LicenseCount.Value
			}
		}

		$AdditionalNotes = "Meraki ID: $($OrgLicensing.merakiId) <br /><br />"
		$AdditionalNotes += "<h3>Licensed Device Counts</h3>"
		$AdditionalNotes += $DeviceCounts | ConvertTo-Html -Fragment | Out-String

		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
				'organization-id' = $Organization.itgId
				'flexible-asset-type-id' = $FilterID.id
				traits = @{
					"name" = "Meraki Co-Term Licensing (Status: $($OrgLicensing.status))"
					"target-type" = "Hardware"
					"licensing-method" = "License Key"
					"renewal-date" = $RenewalDate
					"additional-notes" = $AdditionalNotes
					"assigned-device-s" = @($($AssignedDevices.id | Sort-Object -Unique))
				}
			}
		}

		if ($ExistingLicense) {
			# Update existing license
			if ($ExistingLicense.attributes.traits.name -ne "Meraki Co-Term Licensing (Status: $($OrgLicensing.status))" -or
				$ExistingLicense.attributes.traits.'renewal-date' -ne $RenewalDate -or
				($ExistingLicense.attributes.traits.'assigned-device-s'.values.id | Sort-Object | Out-String) -ne ($AssignedDevices.id | Sort-Object | Out-String) -or
				($DeviceCounts | ForEach-Object { $ExistingLicense.attributes.traits.'additional-notes' -notlike "*$($_.DeviceType)</td><td>$($_.Count)*" })) {
					# changes found, update
					if ($ExistingLicense.attributes.traits.'additional-notes') {
						$AdditionalNotes = $ExistingLicense.attributes.traits.'additional-notes' -replace "<h3>Licensed Device Counts<\/h3>\s?<table>(.|\s)+?<\/table>", ""
						$AdditionalNotes = $AdditionalNotes.Trim()
						$AdditionalNotes = "$AdditionalNotes `n<h3>Licensed Device Counts</h3>`n$($DeviceCounts | ConvertTo-Html -Fragment | Out-String)"
						$FlexAssetBody.attributes.traits.'additional-notes' = $AdditionalNotes
					}

					if ($ExistingLicense.attributes.traits.seats) {
						$FlexAssetBody.attributes.traits.seats = $ExistingLicense.attributes.traits.seats
					}
					if ($ExistingLicense.attributes.traits.'license-product-serial-key') {
						$FlexAssetBody.attributes.traits.'license-product-serial-key' = $ExistingLicense.attributes.traits.'license-product-serial-key'
					}
					if($ExistingLicense.attributes.traits.'other-keys-codes') {
						$FlexAssetBody.attributes.traits.'other-keys-codes' = $ExistingLicense.attributes.traits.'other-keys-codes'
					}
					if($ExistingLicense.attributes.traits.'purchase-date') {
						$FlexAssetBody.attributes.traits.'purchase-date' = $ExistingLicense.attributes.traits.'purchase-date'
					}
					if($ExistingLicense.attributes.traits.'ticket-number-for-original-purchase') {
						$FlexAssetBody.attributes.traits.'ticket-number-for-original-purchase' = $ExistingLicense.attributes.traits.'ticket-number-for-original-purchase'
					}

					Write-Host "Updating Co-Term License for: $($Organization.itgName)"
					Set-ITGlueFlexibleAssets -id $ExistingLicense.id  -data $FlexAssetBody
				} else {
					Write-Host "Update not required for Co-Term License for: $($Organization.itgName)"
				}
		} else {
			# New license asset
			Write-Host "Creating new co-term license asset for: $($Organization.itgName)"
			New-ITGlueFlexibleAssets -data $FlexAssetBody
		}
		$UpdatedLicenses++
	}

	# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
	if ($LastUpdatedUpdater_APIURL -and $Organization.itgId -and $UpdatedLicenses -gt 0) {
		$Headers = @{
			"x-api-key" = $APIKEy
		}
		$Body = @{
			"apiurl" = $APIEndpoint
			"itgOrgID" = $Organization.itgId
			"HostDevice" = $env:computername
			"meraki-licensing" = (Get-Date).ToString("yyyy-MM-dd")
		}

		$Params = @{
			Method = "Post"
			Uri = $LastUpdatedUpdater_APIURL
			Headers = $Headers
			Body = ($Body | ConvertTo-Json)
			ContentType = "application/json"
		}			
		Invoke-RestMethod @Params 
	}
}

# Go through all existing ITG Meraki licensing assets and archive any that no longer exist in Meraki
foreach ($ExistingLicense in $OrgExistingLicenses.licenses) {
	$Match = $ExistingLicense.attributes.traits.'additional-notes' -match "Meraki ID: (\d+)"
	$MerakiID = $false
	if ($Match -and $Matches[1]) {
		$MerakiID = $Matches[1]
	}

	$Match = $ExistingLicense.attributes.traits.'additional-notes' -match "License ID: (\d+)"
	$LicenseID = $false
	if ($Match -and $Matches[1]) {
		$LicenseID = $Matches[1]
	}

	if (!$LicenseID -and $MerakiID) {
		# Co-term licensing
		if ($LicenseInfo.merakiId -contains $MerakiID) {
			# current license, skip
			continue
		} else {
			# license is no longer in the portal, archive
			$Archived = archive_itg -FlexAssetID $ExistingLicense.id
			if ($Archived) {
				Write-Host "Archived: $($ExistingLicense.attributes.name) (ID: $($ExistingLicense.id)) @ $($ExistingLicense.attributes.'organization-name')"
			} else {
				Write-Error "Failed to archive: $($ExistingLicense.attributes.name) (ID: $($ExistingLicense.id)) @ $($ExistingLicense.attributes.'organization-name')"
			}
		}
	} elseif ($LicenseID) {
		# Per-device licensing
		if (($LicenseInfo | Where-Object { $_.merakiID -eq $MerakiID }).licenses.id -contains $LicenseID) {
			# current license, skip
			continue
		} else {
			# license is no longer in the portal, archive
			$Archived = archive_itg -FlexAssetID $ExistingLicense.id
			if ($Archived) {
				Write-Host "Archived: $($ExistingLicense.attributes.name) (ID: $($ExistingLicense.id)) @ $($ExistingLicense.attributes.'organization-name')"
			} else {
				Write-Error "Failed to archive: $($ExistingLicense.attributes.name) (ID: $($ExistingLicense.id)) @ $($ExistingLicense.attributes.'organization-name')"
			}
		}
	} else {
		# No license info, skip
		continue
	}
}
