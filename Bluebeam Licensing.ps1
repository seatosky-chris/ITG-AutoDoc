#####################################################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$ITGlue_Web_URI = "https://sts.itglue.com"
$FlexAssetName = "Licensing"
$ForceUpdate = $false # Forces every bluebeam license to be updated even if the primary fields won't change (good for a first run)
$PrimaryEmail = "" # The primary email bluebeam is generally licensed under
$OtherEmails = @() # Any other emails bluebeam might be licensed under
$ApplicationID = @() # The ID for the Bluebeam application to tag
$OverviewDocument = $false # Create a custom overview asset for a license overview and paste the ID here, or false to not update this
$Description = "Updates the Bluebeam licenses in ITG. Note, it will not create new licenses, it grabs the product key / serial's from the licenses already in ITG and updates the info for each."
$ImageURLs = @{
    'Free Seats' = "https://www.seatosky.com/wp-content/uploads/2022/09/seat.png"
    'Seats To Fix' = "https://www.seatosky.com/wp-content/uploads/2022/09/fix.png"
}
$SquareImages = @('Free Seats', 'Seats To Fix')
####################################################################

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

# Allows IE use without going through the first time run (IE is required for Invoke-WebRequest parsing)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2

# Powershell does not like the bluebeam.com SSL cert, this ignores the warnings
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@

}
$AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

# Grabbing ITGlue Module and installing.
If (Get-Module -ListAvailable -Name "ITGlueAPI") { 
    Import-module ITGlueAPI 
} else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}

# Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy
Write-Host "Configured the ITGlue API"

# Get the flexible asset type id
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$OrganizationInfo = Get-ITGlueOrganizations -id $orgID
if (!$OrganizationInfo -or !$OrganizationInfo.data -or !$FilterID -or ($OrganizationInfo.data | Measure-Object).Count -lt 1 -or !$OrganizationInfo.data[0].attributes -or !$OrganizationInfo.data[0].attributes."short-name") {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}

# Get all of the Bluebeam license in ITG
Write-Host "Downloading licenses"
$ExistingLicenses = Get-ITGlueFlexibleAssets -page_size 1000 -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $orgID
if (!$ExistingLicenses -or $ExistingLicenses.Error) {
    Write-Error "An error occurred trying to get the existing licenses from ITG. Exiting..."
	Write-Error $ExistingLicenses.Error
	exit 1
}
$ExistingLicenses = ($ExistingLicenses).data | Where-Object { $_.attributes.name -like "*Revu*" -or $_.attributes.name -like "*Bluebeam*" }
$LicenseCount = ($ExistingLicenses | Measure-Object).Count

# Get full configurations list from ITG (it's faster than searching for computers on a per api call basis)
Write-Host "Downloading all ITG configurations"
$FullConfigurationsList = Get-ITGlueConfigurations -page_size "1000" -organization_id $OrgID
$i = 1
while ($FullConfigurationsList.links.next) {
	$i++
	$Configurations_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $OrgID
	$FullConfigurationsList.data += $Configurations_Next.data
	$FullConfigurationsList.links = $Configurations_Next.links
}
$FullConfigurationsList = $FullConfigurationsList.data

# Get the locations (for the license overview)
$Locations = (Get-ITGlueLocations -org_id $OrgID).data

# Get the nonce in the global script to create the web session, then create a function to reset the nonce using the existing web session
$WebResponse = Invoke-WebRequest "https://www.reglookup.bluebeam.com/reglookup" -SessionVariable 'WebSession'
$Nonce = ($WebResponse.InputFields |Where-Object {$_.name -eq "form-nonce"}).value

function GetFormNonce($WebSession) {
# Get the form nonce (we need this to submit the form)
	$WebResponse = Invoke-WebRequest "https://www.reglookup.bluebeam.com/reglookup" -WebSession $WebSession
	$Nonce = ($WebResponse.InputFields | Where-Object {$_.name -eq "form-nonce"}).value
	$Nonce
	return
}

function New-BootstrapSinglePanel {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('active', 'success', 'info', 'warning', 'danger', 'blank')]
        [string]$PanelShading,
        
        [Parameter(Mandatory)]
        [string]$PanelTitle,

        [Parameter(Mandatory)]
        [string]$PanelContent,

        [switch]$ContentAsBadge,

        [string]$PanelAdditionalDetail,

        [Parameter(Mandatory)]
        [int]$PanelSize = 3
    )
    
    if ($PanelShading -ne 'Blank') {
        $PanelStart = "<div class=`"col-sm-$PanelSize`"><div class=`"panel panel-$PanelShading`">"
    }
    else {
        $PanelStart = "<div class=`"col-sm-$PanelSize`"><div class=`"panel`">"
    }

    $PanelTitle = "<div class=`"panel-heading`"><h3 class=`"panel-title text-center`">$PanelTitle</h3></div>"


    if ($PSBoundParameters.ContainsKey('ContentAsBadge')) {
        $PanelContent = "<div class=`"panel-body text-center`"><h4><span class=`"label label-$PanelShading`">$PanelContent</span></h4>$PanelAdditionalDetail</div>"
    }
    else {
        $PanelContent = "<div class=`"panel-body text-center`"><h4>$PanelContent</h4>$PanelAdditionalDetail</div>"
    }
    $PanelEnd = "</div></div>"
    $FinalPanelHTML = "{0}{1}{2}{3}" -f $PanelStart, $PanelTitle, $PanelContent, $PanelEnd
    return $FinalPanelHTML
    
}
    
function New-AtAGlancecard {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [boolean]$Enabled,

        [Parameter(Mandatory)]
        [string]$PanelContent,

        [Parameter(Mandatory)]
        [string]$ImageURL,

        [Parameter(Mandatory = $false)]
        [string]$PanelAdditionalDetail = "",

        [Parameter(Mandatory = $false)]
        [bool]$PanelShadingOverride = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet('active', 'success', 'info', 'warning', 'danger', 'blank', '')]
        [string]$PanelShading,

        [Parameter(Mandatory = $false)]
        [int]$PanelSize = 3,

        [Parameter(Mandatory = $false)]
        [boolean]$SquareIcon = $false
    )

    $Style = ""
    if ($SquareIcon) {
        $Style = "style=`"height: 5vw; margin-left: auto; margin-right: auto;`""
    }

    if ($enabled) {
        New-BootstrapSinglePanel -PanelShading (IIf $PanelShadingOverride $PanelShading "success") -PanelTitle "<img class=`"img-responsive`" $Style src=`"$ImageURL`">" -PanelContent $PanelContent -PanelAdditionalDetail $PanelAdditionalDetail -ContentAsBadge -PanelSize $PanelSize
    } else {
        New-BootstrapSinglePanel -PanelShading (IIf $PanelShadingOverride $PanelShading "danger") -PanelTitle "<img class=`"img-responsive`" $Style src=`"$ImageURL`">" -PanelContent $PanelContent -PanelAdditionalDetail $PanelAdditionalDetail -ContentAsBadge -PanelSize $PanelSize
    }
}

Function IIf($If, $Then, $Else) {
    If ($If -IsNot "Boolean") {$_ = $If}
    If ($If) {If ($Then -is "ScriptBlock") {&$Then} Else {$Then}}
    Else {If ($Else -is "ScriptBlock") {&$Else} Else {$Else}}
}

# Now we loop through all exiting bluebeam licenses and get the updated info for them
$i = 0
$LicenseOverview = @()
$UpdatedLicenses = 0
$TotalFreeSeats = 0
$TotalSeatsToFix = 0
foreach ($ExistingLicense in $ExistingLicenses) {
	$i++
	[int]$PercentComplete = $i / $LicenseCount * 100
	Write-Progress -Activity "Updating Licenses" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Getting info from Bluebeam for license '$($ExistingLicense.attributes.name))' ID: $($ExistingLicense.id))")

	# Get product / serial keys
	$ProductSerialKey = $ExistingLicense.attributes.traits.'license-product-serial-key'
	$OtherKeyCodes = $ExistingLicense.attributes.traits.'other-keys-codes'

	$ProductKey = [regex]::match($ProductSerialKey, '([A-Z0-9]{5}-[A-Z0-9]{7})').Groups[1].Value
	if (!$ProductKey) {
		$ProductKey = [regex]::match($OtherKeyCodes, '([A-Z0-9]{5}-[A-Z0-9]{7})').Groups[1].Value
	}

	$SerialKey = [regex]::match($OtherKeyCodes, 'Serial (?:#|Number):\s+([0-9]{7})').Groups[1].Value
	if (!$SerialKey) {
		$SerialKey = [regex]::match($ProductSerialKey, 'Serial (?:#|Number):\s+([0-9]{7})').Groups[1].Value
	}
	if (!$SerialKey) {
		$SerialKey = [regex]::match($OtherKeyCodes, '([0-9]{7})').Groups[1].Value
	}
	if (!$SerialKey) {
		$SerialKey = [regex]::match($ProductSerialKey, '([0-9]{7})').Groups[1].Value
	}

	# Get email (and alternatives if it does not work)
	$Email = $PrimaryEmail
	[System.Collections.ArrayList]$AlternateEmails = @()

	$EmailsInNotes = (Select-String -InputObject $ExistingLicense.attributes.traits.'additional-notes' -Pattern '\w+@\w+\.\w+' -AllMatches).Matches.Value
	if (($EmailsInNotes | Measure-Object).Count -eq 1 -and $PrimaryEmail -notin $EmailsInNotes) {
		$Email = $EmailsInNotes
		$AlternateEmails.Add($PrimaryEmail) | Out-Null
	} elseif (($EmailsInNotes | Measure-Object).Count -gt 0) {
		$EmailsInNotes | ForEach-Object { $AlternateEmails.Add($_) | Out-Null }
	}

	if ($Email -in $AlternateEmails) {
		$AlternateEmails.Remove($Email)
	}

	$OtherEmails | ForEach-Object { if ($_ -notin $AlternateEmails -and $_ -ne $Email) { $AlternateEmails.Add($_) | Out-Null }  }

	# Send a post request to https://www.reglookup.bluebeam.com/reglookup
	$FormBody = @{
		"__form-name__" = 'reglookupForm'
		"data[serialNumber]" = $SerialKey
		"data[productKey]" = $ProductKey
		"data[email]" = $Email
		"form-nonce" = $Nonce
	}

	$SuccessfullQuery = $false
	$attempt = 5
	while ($attempt -gt 0 -and -not $SuccessfullQuery) {
		try {
			$Response = Invoke-WebRequest 'https://www.reglookup.bluebeam.com/reglookup' -WebSession $WebSession -Body $FormBody -Method 'POST'
			if ($Response.Content -like "*Oops there was a problem, please check your input and submit the form again.*" -or $Response.Content -like "*License Key Lookup*" -or $Response.Content -like "*Validation failed:*" -or $Response.Content -like "*License information not found. Please check your information*") {
				$attempt--
				# Form input was wrong, either the wrong email or a bad nonce
				# Verify the nonce
				$NewNonce = GetFormNonce -WebSession $WebSession 
				if ($NewNonce -ne $Nonce) {
					# It was the nonce, try again
					$Nonce = $NewNonce
					$FormBody."form-nonce" = $Nonce
					continue
				}

				# It was not the nonce, try another email
				if (($AlternateEmails | Measure-Object).Count -gt 0) {
					$Email = $AlternateEmails[0]
					$AlternateEmails.RemoveAt(0)
					$FormBody."data[email]" = $Email
				} else {
					# No more emails to try, something is wrong with this license
					Write-Error "Could not get license details for $($ExistingLicense.attributes.name): $($ExistingLicense.attributes.'resource-url')"
					$attempt = 0
					break
				}
			} elseif ($Response.Content -like "*<h1>License Information</h1>*" -and $Response.Content -like "*var table = `$('#computers_id').DataTable*") {
				# We successfully got the data
				$SuccessfullQuery = $true
			} else {
				# Unknown issue
				$attempt -= 2
				if ($attempt -le 0) {
					Write-Error "Could not get license details for $($ExistingLicense.attributes.name): $($ExistingLicense.attributes.'resource-url')"
				}
			}
		} catch {
			$attempt -= 3
			if ($attempt -le 0) {
				Write-Warning "An exception was caught: $($_.Exception.Message)"
				Write-Error "Could not get license details for $($ExistingLicense.attributes.name): $($ExistingLicense.attributes.'resource-url')"
				break
			}
			start-sleep (get-random -Minimum 1 -Maximum 10)
		}
	}

	if (!$SuccessfullQuery) {
		# If we could not get any info on this license, move on to the next. we should have already wrote a warning
		continue
	}

	# Get the js containing the computers table
	$ComputersJS = ($Response.AllElements |Where-Object {$_.TagName -eq "script" -and $_.innerHTML -like "*var table = `$('#computers_id').DataTable*"}).innerHTML
	$Json = "{" + [regex]::match($ComputersJS, '\({[\s\S]+("data":\[[\s\S]+?}\]),[\s\S]+}\);').Groups[1].Value + "}" | ConvertFrom-Json

	# Parse the json to get the computer list
	$Computers = @()
	$ComputersError = $false
	if ($Json -and $Json.data -and ($Json.data | Measure-Object).Count -gt 0) {
		if ($Json.data) {
			foreach ($Computer in $Json.data) {
				if ($Computer.installed -ne 'True') {
					continue
				}
				$Computers += [PSCustomObject]@{
					hostname = $Computer.name
					authCode = $Computer.key
					version = $Computer.version
					authorizedOn = $Computer.authorizedOn
					modifiedOn = $Computer.modifiedOn
				}
			}
		}
	} elseif (!$ComputersJS -or $ComputersJS -notlike '*"data":`[`]*') {
		# Could not find a computer list
		Write-Warning "Could not find a computer list for $($ExistingLicense.attributes.name): $($ExistingLicense.attributes.'resource-url')"	
		$ComputersError = $true
	}

	# Get the license information details
	$AllTables = $Response.ParsedHtml.getElementsByTagName("TABLE")
	$LicenseInfoTable = $AllTables |Where-Object { $_.innerHTML -like '*Product Name:*' -and $_.innerHTML -like '*Serial Number:*' -and $_.innerHTML -like '*Product Key:*' -and $_.innerHTML -like '*Users Allowed:*' }

	$LicenseInfo = @{}
	if ($LicenseInfoTable -and $LicenseInfoTable.rows -and ($LicenseInfoTable.rows | Measure-Object).Count -gt 0) {
		foreach ($row in $LicenseInfoTable.rows) {
			$cells = @($row.Cells)

			$Key = ("" + $cells[0].InnerText).Trim().Trim(":")
			$Value = ("" + $cells[1].InnerText).Trim()

			if ($Key -eq "Expiration") {
				$Expiration = [regex]::match($cells[1].InnerHTML, 'var licenseExpiration = "(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"').Groups[1].Value
				if ($Expiration) {
					$Value = Get-Date -Date $Expiration
				} else {
					$Value = $Expiration
				}
			}

			$LicenseInfo[$Key] = $Value
		}
		$LicenseInfo.'Version' = ($LicenseInfo.'Product Name' -replace "Bluebeam", "" -replace "Revu", "").Trim()
	} else {
		# Could not find the license info
		Write-Warning "Could not find the license info for $($ExistingLicense.attributes.name): $($ExistingLicense.attributes.'resource-url')"
	}

	# Create the overview hashtable
	$Overview = [PSCustomObject]@{
		'License' = "<a href='$($ITGlue_Web_URI)/$($orgID)/assets/records/$($ExistingLicense.id)'>Revu $($LicenseInfo.Version)</a>"
		'Purchased By' = ""
		'Renewal Date' = ""
		'Seats Available' = $LicenseInfo."Users Allowed"
		'Seats Used' = $LicenseInfo.'Users Installed'
		'Seats To Fix' = ""
		'Free Seats' = ""
	}

	$FreeSeats = ([int]$LicenseInfo."Users Allowed" - [int]$LicenseInfo.'Users Installed')
	if ($FreeSeats -gt 0) {
		$TotalFreeSeats += $FreeSeats
		$FreeSeats = "<span style='background-color:#ffd700;'>$FreeSeats</span>"
	}
	$Overview."Free Seats" = $FreeSeats

	if ($ExistingLicense.attributes.traits."purchased-by-location") {
		$PurchaseLocation = $Locations | Where-Object { $_.id -in $ExistingLicense.attributes.traits."purchased-by-location".values.id }
		$Overview."Purchased By" = $PurchaseLocation.attributes.name -join ", "
	}

	$Now = Get-Date
	if ($LicenseInfo.Expiration -lt $Now) {
		# in the past
		$RenewalDate = "<span style='color:#ff0000;'>{0}</span>"
	} elseif ($LicenseInfo.Expiration -lt $Now.AddDays(30)) {
		# expires in the next 30 days
		$RenewalDate = "<span style='color:#FFBB33;'>{0}</span>"
	} else {
		# expiry beyond 30 days
		$RenewalDate = "<span>{0}</span>"
	}

	if ($LicenseInfo.Maintenance -and $LicenseInfo.Maintenance -eq "None") {
		$Overview."Renewal Date" = "None"
	} else {
		$Overview."Renewal Date" = $RenewalDate -f $LicenseInfo.Expiration.ToString("MMM d, yyyy")
	}

	# Update the ITG asset
	if (!$ComputersError -and $LicenseInfo -and $LicenseInfo.Count -gt 0) {
		# We were able to get the computer list and/or the license info so it seems we got all the info correctly. Lets update ITG
		Write-Progress -Activity "Updating Licenses" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating license '$($ExistingLicense.attributes.name))' ID: $($ExistingLicense.id))")	
		$ExistingTraits = $ExistingLicense.attributes.traits

		# Recreate the additional notes, trying to keep any notes that were added manually
		$AdditionalNotes = $ExistingTraits."additional-notes"
		if ($AdditionalNotes -like "*Seats Used:*") {
			$AdditionalNotes = $AdditionalNotes -replace "(<div>)?Seats Used: \d+(<\/div>)?", "<div>Seats Used: $($LicenseInfo.'Users Installed')</div>"
		} else {
			$AdditionalNotes = "$AdditionalNotes `n<div>Seats Used: $($LicenseInfo.'Users Installed')</div>"
		}
		if ($AdditionalNotes -like "*Maintenance Type:*") {
			$AdditionalNotes = $AdditionalNotes -replace "(<div>)?Maintenance Type: [\w| ]+(<\/div>)?", "<div>Maintenance Type: $($LicenseInfo.'Maintenance')</div>"
		} else {
			$AdditionalNotes = "$AdditionalNotes `n<div>Maintenance Type: $($LicenseInfo.'Maintenance')</div>"
		}

		# Get the configurations to tag for assigned devices
		$AssignedDevices = @()
		foreach ($Computer in $Computers) {
			$Hostname = $Computer.hostname
			$Computer | Add-Member -MemberType NoteProperty -Name ITGConfig -Value $null
			$Configurations = $FullConfigurationsList | Where-Object { $_.attributes.hostname -eq $Hostname }
			if (!$Configurations) {
				$Configurations = $FullConfigurationsList | Where-Object { $_.attributes.name -eq $Hostname }
			}
			if (!$Configurations) {
				$Configurations = $FullConfigurationsList | Where-Object { $_.attributes.hostname -like "*$Hostname*" }
			}
			if (!$Configurations) {
				$Configurations = $FullConfigurationsList | Where-Object { $_.attributes.name -like "*$Hostname*" }
			}
			if (($Configurations | Measure-Object).Count -gt 2) {
				Write-Warning "Found too many devices in ITG for the hostname $Hostname. Set the hostname or name field to exactly '$Hostname' on the correct asset for proper matching. Hostname skipped."
				$Configurations = @()
			} else {
				$AssignedDevices += $Configurations
				$Computer.ITGConfig = $Configurations.id
			}
		}

		# Add a table of added devices to the notes (so that we can get the extra details), mark any archived devices in red
		$AdditionalNotes = $AdditionalNotes -replace "<h3>Devices<\/h3>\s?<table>.+<th>hostname<\/th><th>authCode<\/th>.+<\/table>", ""
		$AdditionalNotes = $AdditionalNotes.Trim()
		$AdditionalNotes = "$AdditionalNotes `n<h3>Devices</h3>`n$($Computers | Select-Object -Property hostname, authCode, version, authorizedOn, modifiedOn | ConvertTo-HTML -Fragment)"
		$SeatsToFix = 0
		foreach ($Device in $AssignedDevices) {
			if ($Device.attributes.archived -eq 'True') {
				$Computer = $Computers | Where-Object { $Device.id -in $_.ITGConfig }
				foreach ($C in $Computer) {
					$SeatsToFix++
					$AdditionalNotes = $AdditionalNotes -replace "<td>$($C.hostname)</td>", "<td style='background-color:#FF8080' title='Device is archived and likely no longer exists.'>$($C.hostname)</td>"
				}
			}
		}

		if ($SeatsToFix -gt 0) {
			$TotalSeatsToFix += $SeatsToFix
			$Overview."Seats To Fix" = $SeatsToFix
		}

		if ($LicenseInfo.Maintenance -and $LicenseInfo.Maintenance -eq "None") {
			$RenewalDate = ""
		} else {
			$RenewalDate = $LicenseInfo.Expiration.ToString("yyyy-MM-dd")
		}

		Remove-Variable FlexAssetBody -ErrorAction SilentlyContinue
		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
					traits = @{
						"name" = "Bluebeam Revu"
						"version" = $LicenseInfo.Version
						"target-type" = "Software"
						"application" = @($ApplicationID)

						"seats" = $LicenseInfo."Users Allowed"
						"licensing-method" = "License Key"
						"license-product-serial-key" = $ProductKey
						"other-keys-codes" = "Serial #: $SerialKey"
						
						"renewal-date" = $RenewalDate
						"additional-notes" = $AdditionalNotes
						"assigned-device-s" = $($AssignedDevices.id | Sort-Object -Unique)
					}
			}
		}

		if ($ExistingTraits."user-login-s".values) {
			$FlexAssetBody.attributes.traits."user-login-s" = @($ExistingTraits."user-login-s".values.id)
		}
		if ($ExistingTraits."purchased-by-location".values) {
			$FlexAssetBody.attributes.traits."purchased-by-location" = @($ExistingTraits."purchased-by-location".values.id)
		}
		if ($ExistingTraits."purchase-date") {
			$FlexAssetBody.attributes.traits."purchase-date" = $ExistingTraits."purchase-date"
		}
		if ($ExistingTraits."ticket-number-for-original-purchase") {
			$FlexAssetBody.attributes.traits."ticket-number-for-original-purchase" = $ExistingTraits."ticket-number-for-original-purchase"
		}

		# Filter out empty values
		($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$FlexAssetBody.attributes.traits.Remove($_.Name) 
		}

		# Lets only actually update it in ITG if values are going to change
		if ($ForceUpdate -or $ExistingTraits.version -ne $LicenseInfo.Version -or [int]$ExistingTraits.seats -ne [int]$LicenseInfo."Users Allowed" -or ($ExistingTraits."renewal-date" -and $ExistingTraits."renewal-date" -ne $LicenseInfo.Expiration.ToString("yyyy-MM-dd")) -or 
			$(($ExistingTraits."assigned-device-s".values.id | Sort-Object -Descending -Unique) -join ",") -ne $(($AssignedDevices.id | Sort-Object -Descending -Unique) -join ",")) 
		{
			Write-Host "Updating License - $($ExistingTraits."name") $($ExistingTraits."version")  (ID: $($ExistingLicense.id))"
			Set-ITGlueFlexibleAssets -id $ExistingLicense.id  -data $FlexAssetBody
		} else {
			Write-Host "Updating not required for License - $($ExistingTraits."name") $($ExistingTraits."version")  (ID: $($ExistingLicense.id))"
		}
		$UpdatedLicenses++
	} else {
		# We couldn't find the computer or license info, lets not update this
		Write-Error "Did not update license. Could not find the computer list or license info for $($ExistingLicense.attributes.name): $($ExistingLicense.attributes.'resource-url')"
	}

	$LicenseOverview += $Overview
}
Write-Progress -Activity "Updating Licenses" -Status "Ready" -Completed


# We have now update all of the licenses, lets also update an overview document that shows all the licenses
if ($OverviewDocument -and $LicenseOverview) {
	$TableHeader = "<table class=`"table table-bordered table-hover`">"
	$Whitespace = "<br/>"
	$TableStyling = "<th>", "<th class='bg-info'>"

	$OverviewRaw = $LicenseOverview | ConvertTo-Html -Fragment | Select-Object -Skip 1
	$Overview = $TableHeader + ($OverviewRaw -replace $TableStyling) + $Whitespace
	$Overview = $Overview -replace "Seats To Fix", "Seats To Fix <span style='color:#ff0000;'>*</span>"
	$Overview = $Overview + "<div><br></div>
		<div><span style='color:#ff0000;'><strong>*</strong></span> These are computers that have been archived yet are still licensed for Bluebeam. We should verify the bad device (marked in red on the license asset) was decommissioned, and if so, contact Bluebeam to remove it from the license.</div>"
		$ATaGlanceHTML = New-AtAGlancecard -Enabled $true -PanelShadingOverride $true -PanelShading (IIf ($TotalFreeSeats -gt 0) "success" "danger") -PanelContent ("Free Seats: " + ($TotalFreeSeats | Out-String)) -ImageURL $ImageURLs['Free Seats'] -SquareIcon (IIf ('Free Seats' -in $SquareImages) $true $false) -PanelSize 4
		$ATaGlanceHTML += New-AtAGlancecard -Enabled $true -PanelShadingOverride $true -PanelShading (IIf ($TotalSeatsToFix -eq 0) "success" "warning") -PanelContent ("Seats to Fix: " + ($TotalSeatsToFix | Out-String)) -ImageURL $ImageURLs['Seats To Fix'] -SquareIcon (IIf ('Seats To Fix' -in $SquareImages) $true $false) -PanelSize 4
	
	Remove-Variable FlexAssetBody -ErrorAction SilentlyContinue
	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
				traits = @{
					"name" = "Bluebeam License Overview"
					"at-a-glance" = ($ATaGlanceHTML | Out-String)
					"overview" = [System.Web.HttpUtility]::HtmlDecode($Overview)
				}
		}
	}
	Set-ITGlueFlexibleAssets -id $OverviewDocument -data $FlexAssetBody

	$RelatedItemsBody = @()
	foreach ($AppID in $ApplicationID) {
		$RelatedItemsBody +=
		@{
			type = 'related_items'
			attributes = @{
				'destination_id' = $AppID
				'destination_type' = "Flexible Asset"
			}
		}
	}
	foreach ($ExistingLicense in $ExistingLicenses) {
		$RelatedItemsBody +=
		@{
			type = 'related_items'
			attributes = @{
				'destination_id' = $ExistingLicense.id
				'destination_type' = "Flexible Asset"
			}
		}
	}
	New-ITGlueRelatedItems -resource_type 'flexible_assets' -resource_id $OverviewDocument -data $RelatedItemsBody
}

# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $orgID -and $UpdatedLicenses -gt 0) {
	$Headers = @{
		"x-api-key" = $APIKEy
	}
	$Body = @{
		"apiurl" = $APIEndpoint
		"itgOrgID" = $orgID
		"HostDevice" = $env:computername
		"bluebeam-licensing" = (Get-Date).ToString("yyyy-MM-dd")
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