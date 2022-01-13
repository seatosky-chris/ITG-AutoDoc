#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$orgID = "<ITG ORG ID>"
$UpdateOnly = $false # If set to $true, the script will only update existing assets. If $false, it will add new file shares (that have members) and add them to ITG with as much info as possible.
$FlexAssetName = "File Shares / Storage"
$ADGroupsAssetName = "AD Security Groups"
$Description = "Updates/creates all file shares in ITG with their associated permissions. It will tag AD security groups where possible."
# Ignore by name
$IgnoreShares = @(
	""
)
# Ignore by path
$IgnoreSharePaths = @(
	"C:\Windows\system32*", "*\DFSRoots\*"
) 
$RecursiveDepth = 3 # How deep in the file structure to look for permissions
$IgnoreLocalGroups = $true # If true, it will ignore permissions of local groups/accounts and only look up domain groups & accounts
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
# Grabbing NTFS Security Module and installing.
If (Get-Module -ListAvailable -Name "NTFSSecurity") {
	Import-Module "NTFSSecurity"
} Else { 
	Install-Module "NTFSSecurity" -Force 
	Import-Module "NTFSSecurity"
}

# Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy
Write-Host "Configured the ITGlue API"

# Get the flexible asset type id
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
$ADGroupsFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $ADGroupsAssetName).data

# Get existing shares
Write-Host "Downloading existing shares"
$ExistingShares = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID).data
$TotalShares = ($ExistingShares | Measure-Object).Count
Write-Host "Downloaded $TotalShares shares"

if (!$ExistingShares -and $UpdateOnly) {
	# We are doing an update only but no shares exist in ITG
	Read-Host "The script is running in Update-Only mode but there were no existing shares found in ITG. Check the variables and try again. Press any key to exit..."
	exit
}

# Get all File Shares
$AllSmbShares = Get-SmbShare | Where-Object {
	$Share = $_;
	$_.ShareType -eq "FileSystemDirectory" -and
	@('Remote Admin','Default share','Remote IPC','Logon server share ','Logon server share', 'Printer Drivers') -notcontains $_.Description -and 
	$IgnoreShares -notcontains $_.Name -and 
	($IgnoreSharePaths | ForEach-Object {$Share.Path -like $_}) -notcontains $true
}
$TotalShares = ($AllSmbShares | Measure-Object).Count

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

# Get this servers configuration ID for tagging
$ServerAsset = (Get-ITGlueConfigurations -page_size "1000" -filter_name $ENV:COMPUTERNAME -organization_id $orgID).data

# Loop through each share and get permissions then update ITG
$i = 0
foreach ($SMBShare in $AllSmbShares) {
	$i++
	[int]$PercentComplete = $i / $TotalShares * 100
	$Permissions = Get-Item $SMBShare.path | Get-NTFSAccess
    $Permissions += Get-ChildItem -Depth $RecursiveDepth -Recurse $SMBShare.path | Get-NTFSAccess
	# Filter out inherited permissions and deleted groups
	$Permissions = $Permissions | Where-Object { $_.IsInherited -eq $false -and $_.Account.AccountName }
	# Filter out local groups
	if ($IgnoreLocalGroups) {
		$Permissions = $Permissions | Where-Object { $_.Account -notlike "NT AUTHORITY\*" -and $_.Account -notlike "BUILTIN\*" -and $_.Account -notlike "CREATOR OWNER" -and $_.Account -notlike "*\seatosky" }
	}

    $FullAccess = $Permissions | Where-Object { $_.'AccessRights' -eq "FullControl" -and $_.'AccessControlType' -ne "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType
    $Modify = $Permissions | Where-Object { $_.'AccessRights' -Match "Modify" -and $_.'AccessControlType' -ne "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType
    $ReadOnly = $Permissions | Where-Object { $_.'AccessRights' -Match "Read" -and $_.'AccessControlType' -ne "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType
    $Deny =   $Permissions | Where-Object { $_.'AccessControlType' -eq "Deny" } | Select-Object FullName, Account, AccessRights, AccessControlType

	# Make csv's of the permissions
	$FullAccessCsv = if ($FullAccess) { $FullAccess | ConvertTo-Html -Fragment | Out-String } else { "" }
    $ModifyCsv = if ($Modify) { $Modify | ConvertTo-Html -Fragment | Out-String } else { "" }
    $ReadOnlyCsv = if ($ReadOnly) { $ReadOnly | ConvertTo-Html -Fragment | Out-String } else { "" }
    $DenyCsv = if ($Deny) { $Deny | ConvertTo-Html -Fragment | Out-String } else { "" }

	if($FullAccessCsv.Length /1kb -gt 64) { $FullAccessCsv = "The table is too long to display. Please see included CSV file."}
	if($ModifyCsv.Length /1kb -gt 64) { $ModifyCsv = "The table is too long to display. Please see included CSV file."}
	if($ReadOnlyCsv.Length /1kb -gt 64) { $ReadOnlyCsv = "The table is too long to display. Please see included CSV file."}
	if($DenyCsv.Length /1kb -gt 64) { $DenyCsv = "The table is too long to display. Please see included CSV file."}

	$PermCSV = ($Permissions | ConvertTo-Csv -NoTypeInformation -Delimiter ",") -join [Environment]::NewLine
	$Bytes = [System.Text.Encoding]::UTF8.GetBytes($PermCSV)
	$Base64CSV =[Convert]::ToBase64String($Bytes)

	# Gather our data for ITG
	$ShareName = $SMBShare.Name.trimend("$")
	$ShareType = "Windows File Share"
	$ShareDescription = $SMBShare.Description
	$MappedDriveLetter = ""
	$RelatedGPO = ""
	$SharePath = "\\$($env:computername)\$ShareName"
	$Servers = @($ServerAsset.ID)
	$DiskPath = $SMBShare.Path

	# See if this share is in a DFS namespace, we'll use this info to get mapped drive info
	if ($DFSNs) {
		$Namespace = $DFSNs | Where-Object { $_.TargetPaths -contains $SharePath -or $_.TargetPaths -contains ($SharePath + "$") }
	} else {
		$Namespace = $false
	}

	# See if there is a GPO that maps this drive using the share path or a namespace path
	if ($Namespace.Path) {
		if ($GPOs) {
			$GPO = $GPOs | Where-Object { $_.DriveMappings.DrivePath -like $SharePath -or $_.DriveMappings.DrivePath -like ($SharePath + "$") -or $_.DriveMappings.DrivePath -like $Namespace.Path }
			$GPODriveMap = $GPO.DriveMappings | Where-Object { $_.DrivePath -like $SharePath -or $_.DrivePath -like ($SharePath + "$") -or $_.DrivePath -like $Namespace.Path }
		} else {
			$GPODriveMap = $false
		}
	} else {
		if ($GPOs) {
			$GPO = $GPOs | Where-Object { $_.DriveMappings.DrivePath -like $SharePath -or $_.DriveMappings.DrivePath -like ($SharePath + "$") }
			$GPODriveMap = $GPO.DriveMappings | Where-Object { $_.DrivePath -like $SharePath -or $_.DrivePath -like ($SharePath + "$") }
		} else {
			$GPODriveMap = $false
		}
	}
	
	if ($GPODriveMap) {
		$MappedDriveLetter = $($GPODriveMap.DriveLetter | Sort-Object -Unique) -join ", "
		$RelatedGPO = $($GPODriveMap.GPOName | Sort-Object -Unique) -join ", "
		if ($GPODriveMap.DrivePath -ne $SharePath -and $SharePath -notlike "*$($GPODriveMap.DrivePath)*") {
			$SharePath += ", " + $($GPODriveMap.DrivePath | Sort-Object -Unique) -join ", "
		}
	}

	# Now lets run through each permission set and find the associated AD Groups in ITG for tagging
	$FullAccessAccounts = ($FullAccess | Select-Object Account -Unique).Account | Where-Object { $_.SID -in $AllGroupSIDs }
	$ModifyAccounts = ($Modify | Select-Object Account -Unique).Account | Where-Object { $_.SID -in $AllGroupSIDs }
	$ReadOnlyAccounts = ($ReadOnly | Select-Object Account -Unique).Account | Where-Object { $_.SID -in $AllGroupSIDs }
	$DenyAccounts = ($Deny | Select-Object Account -Unique).Account | Where-Object { $_.SID -in $AllGroupSIDs }

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

	# Get existing asset to update (if one exists)
	$ExistingShare = $ExistingShares | Where-Object { $_.attributes.traits."disk-path-on-server" -eq $DiskPath -and $_.attributes.traits.servers.values.id -contains $Servers[0] -and $_.attributes.traits."share-type" -eq "Windows File Share" } | Select-Object -First 1
	# If the Asset does not exist, create a new asset, if it does exist we'll combine the old and the new
	if (!$ExistingShare) {
		Write-Progress -Activity "Updating Shares" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating share '$($ShareName)' - Creating new asset)")
		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
				'organization-id' = $orgID
				'flexible-asset-type-id' = $FilterID.id
				traits = @{
					"share-name" = $ShareName
					"share-type" = $ShareType
					"share-description" = $ShareDescription
					"mapped-drive-letter" = $MappedDriveLetter
					"share-path" = $SharePath
					"related-gpo" = $RelatedGPO
					"servers" = $Servers
					"disk-path-on-server" = $DiskPath
					"ad-groups-full-access" = $($FullAccessGroups.id | Sort-Object -Unique)
					"ad-groups-modify" = $($ModifyGroups.id | Sort-Object -Unique)
					"ad-groups-read-only" = $($ReadOnlyGroups.id | Sort-Object -Unique)
					"ad-groups-deny" = $($DenyGroups.id | Sort-Object -Unique)
					"full-access-permissions" = $FullAccessCsv
					"read-permissions" = $ReadOnlyCsv
					"modify-permissions" = $ModifyCsv
					"deny-permissions" = $DenyCsv
					"permissions-csv" = @{
                        "content" = $Base64CSV
                        "file_name" = "Permissions.csv"
                    }
				}
			}
		}
		# Filter out empty values
		($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$FlexAssetBody.attributes.traits.Remove($_.Name) 
		}
		if (!$Base64CSV) {
			$FlexAssetBody.attributes.traits.Remove("permissions-csv") 
		}

		Write-Host "Creating new flexible asset - $($ShareName)"
		New-ITGlueFlexibleAssets -data $FlexAssetBody

	} else {
		# Update existing asset
		Write-Progress -Activity "Updating Shares" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating share '$($ShareName)' - Updating asset)")

		if (!$MappedDriveLetter) {
			$MappedDriveLetter = $ExistingShare.attributes.traits."mapped-drive-letter"
		}
		if (!$RelatedGPO) {
			$RelatedGPO = $ExistingShare.attributes.traits."related-gpo"
		}
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
					"share-type" = $ShareType
					"share-description" = $ExistingShare.attributes.traits."share-description"
					"mapped-drive-letter" = $MappedDriveLetter
					"share-path" = $SharePath
					"related-gpo" = $RelatedGPO
					"servers" = $ExistingShare.attributes.traits.servers.values.id
					"disk-path-on-server" = $DiskPath
					"approver-for-access-to-folder" = $ExistingShare.attributes.traits."approver-for-access-to-folder"
					"specific-setup-instructions" = $ExistingShare.attributes.traits."specific-setup-instructions"
					"ad-groups-full-access" = $($FullAccessGroups.id | Sort-Object -Unique)
					"ad-groups-modify" = $($ModifyGroups.id | Sort-Object -Unique)
					"ad-groups-read-only" = $($ReadOnlyGroups.id | Sort-Object -Unique)
					"ad-groups-deny" = $($DenyGroups.id | Sort-Object -Unique)
					"full-access-permissions" = $FullAccessCsv
					"read-permissions" = $ReadOnlyCsv
					"modify-permissions" = $ModifyCsv
					"deny-permissions" = $DenyCsv
					"permissions-csv" = @{
                        "content" = $Base64CSV
                        "file_name" = "Permissions.csv"
                    }
				}
			}
		}
		# Filter out empty values
		($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$FlexAssetBody.attributes.traits.Remove($_.Name) 
		}
		if (!$Base64CSV) {
			$FlexAssetBody.attributes.traits.Remove("permissions-csv") 
		}

		Write-Host "Updating Flexible Asset - $($ExistingShare.attributes.traits."share-name")"
		Set-ITGlueFlexibleAssets -id $ExistingShare.id -data $FlexAssetBody
	}
}
Write-Progress -Activity "Updating Shares" -Status "Ready" -Completed