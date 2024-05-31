#####################################################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$ITGlue_Web_URI = "https://sts.itglue.com"
$LicensingFlexAssetName = "Licensing"
$OverviewFlexAssetName = "Custom Overview"
$LicenseNames = @("<Software Filters>") # Enter the names of the type(s) of licenses you want to include in the overview. This matches with the Name field in the license asset. Accepts wildcards. E.g. @("Acrobat *", "Adobe *")
$OverviewDocumentName = "<Software Name> Licensing Overview" # This name should be unique (within the organization)
$Description = "Creates a license overview table for a specific application."
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

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$OrganizationInfo = Get-ITGlueOrganizations -id $orgID
if (!$OrganizationInfo -or !$OrganizationInfo.data -or !$FilterID -or ($OrganizationInfo.data | Measure-Object).Count -lt 1 -or !$OrganizationInfo.data[0].attributes -or !$OrganizationInfo.data[0].attributes."short-name") {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}

# Get all of the licenses in ITG matching $LicenseNames
Write-Host "Downloading licenses"
$ExistingLicenses = Get-ITGlueFlexibleAssets -page_size 1000 -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $orgID
if (!$ExistingLicenses -or $ExistingLicenses.Error) {
    Write-Error "An error occurred trying to get the existing licenses from ITG. Exiting..."
	Write-Error $ExistingLicenses.Error
	exit 1
}
$ExistingLicenses = ($ExistingLicenses).data | Where-Object {$License = $_; (($LicenseNames | Where-Object { $License.attributes.traits.name -like $_  }) | Measure-Object).Count -gt 0 }
$LicenseCount = ($ExistingLicenses | Measure-Object).Count

# Get the locations (for the license overview)
$Locations = (Get-ITGlueLocations -org_id $OrgID).data

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

# Get full contacts list from ITG (it's faster than searching for users on a per api call basis)
Write-Host "Downloading all ITG contacts"
$FullContactList = @()
$i = 1
while ($i -le 10 -and ($FullContactList | Measure-Object).Count -eq (($i-1) * 500)) {
	$FullContactList += (Get-ITGlueContacts -page_size 500 -page_number $i -organization_id $OrgID).data
	Write-Host "- Got contact set $i"
	$TotalContacts = ($FullContactList | Measure-Object).Count
	Write-Host "- Total: $TotalContacts"
	$i++
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

# Now we loop through all existing licenses and build the overview
$i = 0
$LicenseOverview = @()
$TotalFreeSeats = 0
$TotalSeatsToFix = 0
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
		'License' = "<a href='$($ITGlue_Web_URI)/$($orgID)/assets/records/$($ExistingLicense.id)'>$($ExistingLicense.attributes.traits.name) $($ExistingLicense.attributes.traits.version)</a>"
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
		$TotalFreeSeats += $FreeSeats
		$FreeSeats = "<span style='background-color:#ffd700;'>$FreeSeats</span>"
	}
	$Overview."Free Seats" = $FreeSeats

	if ($ToFixCount -gt 0) {
		$Overview."Seats To Fix" = $ToFixCount
		$TotalSeatsToFix += $ToFixCount
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
	$TableHeader = "<table class=`"table table-bordered table-hover`">"
	$Whitespace = "<br/>"
	$TableStyling = "<th>", "<th class='bg-info'>"

	# Get the overview documents ID if it exists
	$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $OverviewFlexAssetName).data
	$ExistingOverview = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $FilterID.id -filter_organization_id $orgID -filter_name $OverviewDocumentName
	if (!$ExistingOverview -or $ExistingOverview.Error) {
		Write-Error "An error occurred trying to get the existing overview from ITG. Exiting..."
		Write-Error $ExistingOverview.Error
		exit 1
	}
	$ExistingOverview = ($ExistingOverview).data

	$ApplicationIDs = $ExistingLicenses.attributes.traits.application.values.id | Select-Object -Unique

	$OverviewRaw = $LicenseOverview | ConvertTo-Html -Fragment | Select-Object -Skip 1
	$Overview = $TableHeader + ($OverviewRaw -replace $TableStyling) + $Whitespace
	$Overview = $Overview -replace "Seats To Fix", "Seats To Fix <span style='color:#ff0000;'>*</span>"
	$Overview = $Overview + "<div><br></div>
		<div><span style='color:#ff0000;'><strong>*</strong></span> These are computers that have been archived yet are still licensed for this application. We should verify the bad device (marked in red on the license asset) was decommissioned, and if so, unassign the license.</div>"
	$ATaGlanceHTML = New-AtAGlancecard -Enabled $true -PanelShadingOverride $true -PanelShading (IIf ($TotalFreeSeats -gt 0) "success" "danger") -PanelContent ("Free Seats: " + ($TotalFreeSeats | Out-String)) -ImageURL $ImageURLs['Free Seats'] -SquareIcon (IIf ('Free Seats' -in $SquareImages) $true $false) -PanelSize 4
	$ATaGlanceHTML += New-AtAGlancecard -Enabled $true -PanelShadingOverride $true -PanelShading (IIf ($TotalSeatsToFix -eq 0) "success" "warning") -PanelContent ("Seats to Fix: " + ($TotalSeatsToFix | Out-String)) -ImageURL $ImageURLs['Seats To Fix'] -SquareIcon (IIf ('Seats To Fix' -in $SquareImages) $true $false) -PanelSize 4
	
	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
				traits = @{
					"name" = $OverviewDocumentName
					"at-a-glance" = ($ATaGlanceHTML | Out-String)
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

	# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
	if ($LastUpdatedUpdater_APIURL -and $orgID) {
		$Headers = @{
			"x-api-key" = $APIKEy
		}
		$Body = @{
			"apiurl" = $APIEndpoint
			"itgOrgID" = $orgID
			"HostDevice" = $env:computername
			"licensing-overview" = (Get-Date).ToString("yyyy-MM-dd")
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