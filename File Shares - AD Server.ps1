#####################################################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$UpdateOnly = $false # If set to $true, the script will only update existing assets. If $false, it will add new file shares (that have members) and add them to ITG with as much info as possible.
$FlexAssetName = "File Shares / Storage"
$ADGroupsAssetName = "AD Security Groups"
$Description = "Updates/creates all file shares in ITG with their associated permissions. It will tag AD security groups where possible."
$PermissionsBackupFileJSON = "\PermissionsBackup_XXXX.json"
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

# Get the flexible asset type id
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
$ADGroupsFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $ADGroupsAssetName).data

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$OrganizationInfo = Get-ITGlueOrganizations -id $orgID
if (!$OrganizationInfo -or !$OrganizationInfo.data -or !$FilterID -or ($OrganizationInfo.data | Measure-Object).Count -lt 1 -or !$OrganizationInfo.data[0].attributes -or !$OrganizationInfo.data[0].attributes."short-name") {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}

# Get existing shares
Write-Host "Downloading existing shares"
$ExistingShares = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID -page_size 1000
if (!$ExistingShares -or $ExistingShares.Error) {
    Write-Error "An error occurred trying to get the existing file shares from ITG. Exiting..."
	Write-Error $ExistingShares.Error
	exit 1
}
$ExistingShares = $ExistingShares.data
$TotalShares = ($ExistingShares | Measure-Object).Count
Write-Host "Downloaded $TotalShares shares"

# Filter down to Windows file shares
$ExistingShares = $ExistingShares | Where-Object { $_.attributes.traits."share-type" -eq "Windows File Share" }

if (!$ExistingShares -and $UpdateOnly) {
	# We are doing an update only but no shares exist in ITG
	Read-Host "The script is running in Update-Only mode but there were no existing shares found in ITG. Check the variables and try again. Press any key to exit..."
	exit
}

# Get all security groups (so that we can determine if a permission is a security group or a user)
$AllGroupSIDs = (Get-ADGroup -Filter 'GroupCategory -eq "Security"' | Select-Object SID).SID

# Get security groups assets on ITG
Write-Host "Downloading existing security groups"
# For companies with many groups trying to get them all at once sometimes times out
# By looping through 200 at a time we prevent a timeout from happening.
$ExistingGroups = @()
$i = 1
while ($i -le 10 -and ($ExistingGroups | Measure-Object).Count -eq (($i-1) * 200)) {
	$ExistingGroups += (Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $ADGroupsFilterID.id -filter_organization_id $orgID).data
	Write-Host "- Got group set $i"
	$TotalGroups = ($ExistingGroups | Measure-Object).Count
	Write-Host "- Total: $TotalGroups"
	$i++
}

# Get DFS Namespaces
If (Get-Module -ListAvailable -Name "DFSN") {
	$DFSNs = Get-DfsnRoot -erroraction 'silentlycontinue' | Where-Object { $_.State -eq "Online" }
	$DFSNs | Add-Member -MemberType NoteProperty -Name TargetPaths -Value $null
	$DFSns | ForEach-Object {
		$_.TargetPaths = @((Get-DfsnRootTarget -Path $_.Path | Where-Object { $_.State -eq "Online" } | Select-Object TargetPath).TargetPath)
	}
} else {
	$DFSNs = $false
}

# Get all drive mapping GPOs
If (Get-Module -ListAvailable -Name "GroupPolicy") {
	$GPOs = Get-GPO -All | Where-Object { $GPOID = $_.Id; $GPODom = $_.DomainName; $GPODisp = $_.DisplayName; Test-Path "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml" }
	$GPOs | Add-Member -MemberType NoteProperty -Name DriveMappings -Value @()
	$GPOs | ForEach-Object {
		$GPOID = $_.Id; $GPODom = $_.DomainName; $GPODisp = $_.DisplayName;
		[xml]$DriveXML = Get-Content "\\$($GPODom)\SYSVOL\$($GPODom)\Policies\{$($GPOID)}\User\Preferences\Drives\Drives.xml"
		foreach ($drivemap in $DriveXML.Drives.Drive) {
			$_.DriveMappings += New-Object PSObject -Property @{
				GPOName = $GPODisp
				DriveLetter = $drivemap.Properties.Letter + ":"
				DrivePath = $drivemap.Properties.Path
				DriveAction = $drivemap.Properties.action.Replace("U","Update").Replace("C","Create").Replace("D","Delete").Replace("R","Replace")
				DriveLabel = $drivemap.Properties.label
				DrivePersistent = $drivemap.Properties.persistent.Replace("0","False").Replace("1","True")
				DriveFilterGroup = $drivemap.Filters.FilterGroup.Name
			}
		}
	}
} else {
	$GPOs = $false
}

# Loop through each share in ITG and update where applicable
$i = 0
$UpdatedShares = 0
foreach ($ExistingShare in $ExistingShares) {
	$i++
	[int]$PercentComplete = $i / $TotalShares * 100
	
	$SharePaths = $ExistingShare.attributes.traits.'share-path' -split ", "
	$Permissions = $false
	$Base64CSV = $false

	foreach ($Path in $SharePaths) {
		if (Test-Path -Path ($Path + $PermissionsBackupFileJSON)) {
			$Permissions = Get-Content -Raw -Path ($Path + $PermissionsBackupFileJSON)
		} elseif (Test-Path -Path ($Path + "$" + $PermissionsBackupFileJSON)) {
			$Permissions = Get-Content -Raw -Path ($Path + "$" + $PermissionsBackupFileJSON)
		}

		if ($Permissions) {
			break;
		}
	}

	if ($Permissions) {
		$Permissions = $Permissions | ConvertFrom-Json
		$PermCSV = (
				$Permissions | 
				Select-Object AccountType, Name, FullName, InheritanceEnabled, InheritedFrom, 
					AccessControlType, AccessRights, @{Name="Account"; E={$_.Account.AccountName}}, InheritanceFlags, IsInherited, PropagationFlags | 
				ConvertTo-Csv -NoTypeInformation -Delimiter ","
			) -join [Environment]::NewLine
		$Bytes = [System.Text.Encoding]::UTF8.GetBytes($PermCSV)
		$Base64CSV =[Convert]::ToBase64String($Bytes)
	} else {
		continue;
	}

	$FullAccess = $Permissions | Where-Object { $_.'AccessRights' -eq "FullControl" -and $_.'AccessControlType' -ne "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType
    $Modify = $Permissions | Where-Object { $_.'AccessRights' -Match "Modify" -and $_.'AccessControlType' -ne "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType
    $ReadOnly = $Permissions | Where-Object { $_.'AccessRights' -Match "Read" -and $_.'AccessControlType' -ne "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType
    $Deny =   $Permissions | Where-Object { $_.'AccessControlType' -eq "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType


	# See if this share is in a DFS namespace, we'll use this info to get mapped drive info
	$Namespace = $false
	if ($DFSNs) {
		foreach ($SharePath in $SharePaths) {
			$Namespace = $DFSNs | Where-Object { $_.TargetPaths -contains $SharePath -or $_.TargetPaths -contains ($SharePath + "$") }
			if ($Namespace) {
				break;
			}
		}
	}

	# See if there is a GPO that maps this drive using the share path or a namespace path
	$GPODriveMap = $false
	if ($Namespace.Path) {
		if ($GPOs) {
			foreach ($SharePath in $SharePaths) {
				$GPO = $GPOs | Where-Object { $_.DriveMappings.DrivePath -like $SharePath -or $_.DriveMappings.DrivePath -like ($SharePath + "$") -or $_.DriveMappings.DrivePath -like $Namespace.Path }
				$GPODriveMap = $GPO.DriveMappings | Where-Object { $_.DrivePath -like $SharePath -or $_.DrivePath -like ($SharePath + "$") -or $_.DrivePath -like $Namespace.Path }
				if ($GPODriveMap) {
					break;
				}
			}		
		}
	} else {
		if ($GPOs) {
			foreach ($SharePath in $SharePaths) {
				$GPO = $GPOs | Where-Object { $_.DriveMappings.DrivePath -like $SharePath -or $_.DriveMappings.DrivePath -like ($SharePath + "$") }
				$GPODriveMap = $GPO.DriveMappings | Where-Object { $_.DrivePath -like $SharePath -or $_.DrivePath -like ($SharePath + "$") }
				if ($GPODriveMap) {
					break;
				}
			}
		}
	}
	
	$MappedDriveLetter = $false
	$RelatedGPO = $false
	if ($GPODriveMap) {
		$MappedDriveLetter = $($GPODriveMap.DriveLetter | Sort-Object -Unique) -join ", "
		$RelatedGPO = $($GPODriveMap.GPOName | Sort-Object -Unique) -join ", "

		foreach ($SharePath in $SharePaths) {
			if ($SharePaths -notlike "*$($GPODriveMap.DrivePath)*") {
				$SharePaths += $($GPODriveMap.DrivePath | Sort-Object -Unique) -join ", "
			}
		}
	}

	# Now lets run through each permission set and find the associated AD Groups in ITG for tagging
	$FullAccessAccounts = ($FullAccess.Account | Sort-Object | Get-Unique -AsString) | Where-Object { $_.SID -in $AllGroupSIDs }
	$ModifyAccounts = ($Modify.Account | Sort-Object | Get-Unique -AsString) | Where-Object { $_.SID -in $AllGroupSIDs }
	$ReadOnlyAccounts = ($ReadOnly.Account | Sort-Object | Get-Unique -AsString) | Where-Object { $_.SID -in $AllGroupSIDs }
	$DenyAccounts = ($Deny.Account | Sort-Object | Get-Unique -AsString) | Where-Object { $_.SID -in $AllGroupSIDs }

	$FullAccessAccounts | Add-Member -MemberType NoteProperty -Name Name -Value $null
	$ModifyAccounts | Add-Member -MemberType NoteProperty -Name Name -Value $null
	$ReadOnlyAccounts | Add-Member -MemberType NoteProperty -Name Name -Value $null
	$DenyAccounts | Add-Member -MemberType NoteProperty -Name Name -Value $null

	$FullAccessAccounts | ForEach-Object { $_.Name = (Get-ADGroup $_.SID | Select-Object Name).Name	}
	$ModifyAccounts | ForEach-Object { $_.Name = (Get-ADGroup $_.SID | Select-Object Name).Name	}
	$ReadOnlyAccounts | ForEach-Object { $_.Name = (Get-ADGroup $_.SID | Select-Object Name).Name }
	$DenyAccounts | ForEach-Object { $_.Name = (Get-ADGroup $_.SID | Select-Object Name).Name }
	
	$FullAccessGroups = $ExistingGroups | Where-Object { $_.attributes.traits."group-name" -in $FullAccessAccounts.Name }
	$ModifyGroups = $ExistingGroups | Where-Object { $_.attributes.traits."group-name" -in $ModifyAccounts.Name }
	$ReadOnlyGroups = $ExistingGroups | Where-Object { $_.attributes.traits."group-name" -in $ReadOnlyAccounts.Name }
	$DenyGroups = $ExistingGroups | Where-Object { $_.attributes.traits."group-name" -in $DenyAccounts.Name }

	# Update existing asset
	Write-Progress -Activity "Updating Shares" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating share '$($ExistingShare.attributes.traits."share-name")' - Updating asset)")

	if (!$MappedDriveLetter) {
		$MappedDriveLetter = $ExistingShare.attributes.traits."mapped-drive-letter"
	}
	if (!$RelatedGPO) {
		$RelatedGPO = $ExistingShare.attributes.traits."related-gpo"
	}
	$SharePath = ($SharePaths | Sort-Object | Get-Unique) -join ", "
	if (!$GPODriveMap -and $ExistingShare.attributes.traits."share-path" -and $ExistingShare.attributes.traits."share-path" -like "*$($SharePath), *" ) {
		$SharePath = $ExistingShare.attributes.traits."share-path"
	}

	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
			'organization-id' = $orgID
			'flexible-asset-type-id' = $FilterID.id
			traits = @{
				"share-name" = $ExistingShare.attributes.traits."share-name"
				"share-type" = $ExistingShare.attributes.traits."share-type"
				"share-description" = $ExistingShare.attributes.traits."share-description"
				"mapped-drive-letter" = $MappedDriveLetter
				"share-path" = $SharePath
				"related-gpo" = $RelatedGPO
				"servers" = @($ExistingShare.attributes.traits.servers.values.id)
				"disk-path-on-server" = $ExistingShare.attributes.traits."disk-path-on-server"
				"approver-for-access-to-folder" = @($ExistingShare.attributes.traits."approver-for-access-to-folder".values.id)
				"specific-setup-instructions" = $ExistingShare.attributes.traits."specific-setup-instructions"
				"ad-groups-full-access" = @($($FullAccessGroups.id | Sort-Object -Unique))
				"ad-groups-modify" = @($($ModifyGroups.id | Sort-Object -Unique))
				"ad-groups-read-only" = @($($ReadOnlyGroups.id | Sort-Object -Unique))
				"ad-groups-deny" = @($($DenyGroups.id | Sort-Object -Unique))
				"full-access-permissions" = $ExistingShare.attributes.traits."full-access-permissions"
				"read-permissions" = $ExistingShare.attributes.traits."read-permissions"
				"modify-permissions" = $ExistingShare.attributes.traits."modify-permissions"
				"deny-permissions" = $ExistingShare.attributes.traits."deny-permissions"
				"permissions-csv" = $false
			}
		}
	}

	if ($Base64CSV) {
		$FlexAssetBody.attributes.traits."permissions-csv" = @{
			"content" = $Base64CSV
			"file_name" = "Permissions.csv"
		}
	}
	# Filter out empty values
	($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$FlexAssetBody.attributes.traits.Remove($_.Name) 
	}

	Write-Host "Updating Flexible Asset - $($ExistingShare.attributes.traits."share-name")"
	Set-ITGlueFlexibleAssets -id $ExistingShare.id -data $FlexAssetBody

	$UpdatedShares++
}
Write-Progress -Activity "Updating Shares" -Status "Ready" -Completed

# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $orgID -and $UpdatedShares -gt 0) {
	$Headers = @{
		"x-api-key" = $APIKEy
	}
	$Body = @{
		"apiurl" = $APIEndpoint
		"itgOrgID" = $orgID
		"HostDevice" = $env:computername
		"file-shares-ad-server" = (Get-Date).ToString("yyyy-MM-dd")
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