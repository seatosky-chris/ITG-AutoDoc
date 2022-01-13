#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$MerakiAPIKey = "<MERAKI API KEY>"
$ITGlue_Base_URI = "https://sts.itglue.com"
$FlexAssetName = "Licensing"
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
 
# Install/Import PSMeraki module
If (Get-Module -ListAvailable -Name "PSMeraki") {Import-module PSMeraki} Else { Install-ModuleFromGitHub -GitHubRepo chrisjantzen/PSMeraki -Branch build; import-module PSMeraki}

Set-MrkRestApiKey -key $MerakiAPIKey

# Get a list of ITG & Meraki organizations
$ITGOrgs = 	Get-ITGlueOrganizations -page_size 1000
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
		Write-Output $Licenses
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
foreach ($OrgLicensing in $LicenseInfo) {
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
			$FullConfigurationsList = (Get-ITGlueConfigurations -page_size 1000 -organization_id $Organization.itgId).data
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

			$MerakiDevice = $OrgLicensing.devices | Where-Object { $_.serial -eq $License.deviceSerial }
			$ExistingLicense = $ExistingLicenses.licenses | Where-Object { $_.attributes.traits.name -like "Meraki Per-Device License*" -and $_.attributes.traits.'additional-notes' -like "*License ID: $($License.id)*" }

			$AllDevices = $OrgDevices | Where-Object { $_.itgId -eq $Organization.itgId }
			$OrgDevice = $AllDevices.devices | Where-Object { $_.attributes.'serial-number' -eq $License.deviceSerial -or $_.attributes.name -like $MerakiDevice.name }

			$ClaimDate = ([DateTime]$License.claimDate).ToString("yyyy-MM-dd")
			$RenewalDate = ([DateTime]$License.expirationDate).ToString("yyyy-MM-dd")

			$AdditionalNotes = "================== <br>"
			$AdditionalNotes += "Do NOT edit <br>"
			$AdditionalNotes += "Meraki ID: $($OrgLicensing.merakiId) <br>"
			$AdditionalNotes += "License ID: $($License.id) <br>"
			$AdditionalNotes += "Order #: $($License.orderNumber) <br>"
			$AdditionalNotes += "Duration: $($License.durationInDays) days <br>"
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
						"assigned-device-s" = @($($OrgDevice.id | Sort-Object -Unique))
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
	
						Write-Host "Updating Per-Device License for: $($Organization.itgName) - $($OrgDevice[0].attributes.name)"
						Set-ITGlueFlexibleAssets -id $ExistingLicense.id  -data $FlexAssetBody
					} else {
						Write-Host "Update not required for Per-Device License for: $($Organization.itgName) - $($OrgDevice[0].attributes.name)"
					}
			} else {
				# New license asset
				Write-Host "Creating new per-device license asset for: $($Organization.itgName) - $($OrgDevice[0].attributes.name)"
				New-ITGlueFlexibleAssets -data $FlexAssetBody
			}
		}
	} else {
		# Co-term licensing
		$ExistingLicenses = $OrgExistingLicenses | Where-Object { $_.itgId -eq $Organization.itgId }
		$ExistingLicense = $ExistingLicenses.licenses | Where-Object { $_.attributes.name -like "Meraki Co-Term Licensing*" }

		$AllDevices = $OrgDevices | Where-Object { $_.itgId -eq $Organization.itgId }
		$AssignedDevices = $AllDevices.devices | Where-Object { $_.attributes.name -in $OrgLicensing.devices.name }

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
						$AdditionalNotes = $ExistingLicense.attributes.traits.'additional-notes' -replace "<h3>Licensed Device Counts<\/h3>\s?<table>.+<\/table>", ""
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
	}
}