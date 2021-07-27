#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$orgID = "<ITG ORG ID>"
$ITGlue_Base_URI = "https://sts.itglue.com"
$LicensingFlexAssetName = "Licensing"
$OverviewFlexAssetName = "Custom Overview"
$LicenseNames = @("Autodesk *", "AutoCAD") # Enter the names of the type(s) of licenses you want to include in the overview. This matches with the Name field in the license asset. Accepts wildcards. E.g. @("Acrobat *")
$OverviewDocumentName = "Autodesk/AutoCAD Licensing Overview" # This name should be unique (within the organization)
$Description = "Creates a license overview table for a specific application."
####################################################################

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

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

# Get the licensing flexible asset type id
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $LicensingFlexAssetName).data

# Get all of the licenses in ITG matching $LicenseNames
Write-Host "Downloading licenses"
$ExistingLicenses = (Get-ITGlueFlexibleAssets -page_size 1000 -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $orgID).data
$ExistingLicenses = $ExistingLicenses | Where-Object {$License = $_; (($LicenseNames | Where-Object { $License.attributes.traits.name -like $_  }) | Measure-Object).Count -gt 0 }
$LicenseCount = ($ExistingLicenses | Measure-Object).Count

# Get the locations (for the license overview)
$Locations = (Get-ITGlueLocations -org_id $OrgID).data

# Get full configurations list from ITG (it's faster than searching for computers on a per api call basis)
Write-Host "Downloading all ITG configurations"
$FullConfigurationsList = (Get-ITGlueConfigurations -page_size 1000 -organization_id $OrgID).data

# Get full contacts list from ITG (it's faster than searching for users on a per api call basis)
Write-Host "Downloading all ITG contacts"
$FullContactsList = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data

# Now we loop through all existing licenses and build the overview
$i = 0
$LicenseOverview = @()
foreach ($ExistingLicense in $ExistingLicenses) {
	$i++
	[int]$PercentComplete = $i / $LicenseCount * 100
	Write-Progress -Activity "Building Overview" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Collecting details from license '$($ExistingLicense.attributes.name))' ID: $($ExistingLicense.id))")

	# Gather data
	$TotalSeats = $ExistingLicense.attributes.traits.seats -as [int]
	$AssignedDevices = $ExistingLicense.attributes.traits."assigned-device-s"
	$AssignedUsers = $ExistingLicense.attributes.traits."assigned-user-s"

	if ($TotalSeats -le 0) {
		continue
	}
	
	if (($AssignedUsers.values | Measure-Object).Count -gt ($AssignedDevices.values | Measure-Object).Count) {
		$AssignedBy = "User"
		$Assigned = $FullContactsList | Where-Object { $_.id -in $AssignedUsers.values.id };
	} else {
		$AssignedBy = "Computer"
		$Assigned = $FullConfigurationsList | Where-Object { $_.id -in $AssignedDevices.values.id };
	}
	$TotalUsed = ($Assigned | Measure-Object).Count
	$FreeSeats = $TotalSeats - $TotalUsed
	
	# Create the overview hashtable
	$Overview = [PSCustomObject]@{
		'Sort' = $ExistingLicense.attributes.name
		'License' = "<a href='$($ITGlue_Base_URI)/$($orgID)/assets/records/$($ExistingLicense.id)'>$($ExistingLicense.attributes.traits.name) $($ExistingLicense.attributes.traits.version)</a>"
		'Renewal Date' = ""
		'Seats Available' = $TotalSeats
		'Seats Used' = $TotalUsed
		'Seats To Fix' = ""
		'To Fix' = ""
		'Purchased By' = ""
		'Free Seats' = ""
	}

	$ToFixCount = 0
	$ToFixNames = @()

	foreach ($UserOrDevice in $Assigned) {
		if ($UserOrDevice.attributes.archived -eq 'True') {
			$ToFixCount++
			$ToFixNames += $UserOrDevice.attributes.name
		}
	}

	if ($FreeSeats -gt 0) {
		$FreeSeats = "<span style='background-color:#ffd700;'>$FreeSeats</span>"
	}
	$Overview."Free Seats" = $FreeSeats

	if ($ToFixCount -gt 0) {
		$Overview."Seats To Fix" = $ToFixCount
		$Overview."To Fix" = [System.Net.WebUtility]::HtmlEncode(($ToFixNames -join ", "))
	}

	if ($ExistingLicense.attributes.traits."purchased-by-location") {
		$PurchaseLocation = $Locations | Where-Object { $_.id -in $ExistingLicense.attributes.traits."purchased-by-location".values.id }
		$Overview."Purchased By" = $PurchaseLocation.attributes.name -join ", "
	}

	if ($ExistingLicense.attributes.traits."renewal-date") {
		$RenewalDate = [datetime]::ParseExact($ExistingLicense.attributes.traits."renewal-date", 'yyyy-mm-dd', $null)
		$Now = Get-Date

		if ($RenewalDate -lt $Now) {
			# in the past
			$RenewalStr = "<span style='color:#ff0000;'>{0}</span>"
		} elseif ($RenewalDate -lt $Now.AddDays(30)) {
			# expires in the next 30 days
			$RenewalStr = "<span style='color:#FFBB33;'>{0}</span>"
		} else {
			# expiry beyond 30 days
			$RenewalStr = "<span>{0}</span>"
		}
	
		$Overview."Renewal Date" = $RenewalStr -f $RenewalDate.ToString("MMM d, yyyy")
	}

	$LicenseOverview += $Overview
}

$LicenseOverview = $LicenseOverview | Sort-Object -Property Sort
$LicenseOverview = $LicenseOverview | Select-Object -Property * -ExcludeProperty Sort

if (($LicenseOverview."Seats To Fix" | Where-Object { $_ } | Measure-Object).Count -eq 0) {
	$LicenseOverview = $LicenseOverview | Select-Object -Property * -ExcludeProperty "Seats To Fix", "To Fix"
}

if (($LicenseOverview."Renewal Date" | Where-Object { $_ } | Measure-Object).Count -eq 0) {
	$LicenseOverview = $LicenseOverview | Select-Object -Property * -ExcludeProperty "Renewal Date"
}

if (($LicenseOverview."Purchased By" | Where-Object { $_ } | Measure-Object).Count -eq 0) {
	$LicenseOverview = $LicenseOverview | Select-Object -Property * -ExcludeProperty "Purchased By"
}


# Now lets update the overview document
if ($OverviewDocumentName -and $LicenseOverview) {
	# Get the overview documents ID if it exists
	$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $OverviewFlexAssetName).data
	$ExistingOverview = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $orgID -filter_name $OverviewDocumentName).data

	$ApplicationIDs = $ExistingLicenses.attributes.traits.application.values.id | Select-Object -Unique

	$Overview = $LicenseOverview | ConvertTo-Html -Fragment
	$Overview = $Overview -replace "Seats To Fix", "Seats To Fix <span style='color:#ff0000;'>*</span>"
	$Overview = $Overview + "<div><br></div>
		<div><span style='color:#ff0000;'><strong>*</strong></span> These are computers that have been archived yet are still licensed for this application. We should verify the bad device (marked in red on the license asset) was decommissioned, and if so, unassign the license.</div>"
	
	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
				traits = @{
					"name" = $OverviewDocumentName
					"overview" = [System.Web.HttpUtility]::HtmlDecode($Overview)
				}
		}
	}

	if ($ExistingOverview) {
		$ExistingOverviewID = $ExistingOverview[0].id
		Write-Host "Updating existing overview asset"
		Set-ITGlueFlexibleAssets -id $ExistingOverviewID -data $FlexAssetBody
	} else {
		$FlexAssetBody.attributes.'organization-id' = $orgID
		$FlexAssetBody.attributes.'flexible-asset-type-id' = $FilterID.id
		Write-Host "Creating new overview asset"
		$NewFlexAsset = New-ITGlueFlexibleAssets -data $FlexAssetBody
		$ExistingOverviewID = $NewFlexAsset.data.id
	}

	$RelatedItemsBody = @()
	foreach ($AppID in $ApplicationIDs) {
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
	New-ITGlueRelatedItems -resource_type 'flexible_assets' -resource_id $ExistingOverviewID -data $RelatedItemsBody
}