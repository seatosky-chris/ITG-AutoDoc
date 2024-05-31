#####################################################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$UpdateOnly = $false # If set to $true, the script will only update existing assets. If $false, it will add new file shares (that have members) and add them to ITG with as much info as possible.
$FlexAssetName = "File Shares / Storage"
$Description = "Updates/creates all file shares in ITG with their associated permissions. It will tag AD security groups where possible."
# Ignore by name
$IgnoreShares = @(
	""
)
# Ignore by path
$IgnoreSharePaths = @(
	"C:\Windows\system32*", "*\DFSRoots\*"
)
# Full access accounts for permissions file (generally the account(s) that will run this autodoc) (if you don't include the domain, it will be auto appended to the username, for local accounts append .\)
$FullAccessAccounts_PermsFile = @(
	"seatosky", "sts-autodoc"
)
$RecursiveDepth = 3 # How deep in the file structure to look for permissions
$IgnoreLocalGroups = $true # If true, it will ignore permissions of local groups/accounts and only look up domain groups & accounts
$PermissionsFileUUID = "XXXX"
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

# ConvertTo-Json filter that turns enums into strings (for permissions json)
# https://stackoverflow.com/a/54024450
Filter ConvertTo-EnumsAsStrings ([int] $Depth = 2, [int] $CurrDepth = 0) {
	if ($_ -is [enum]) { # enum value -> convert to symbolic name as string
		$_.ToString() 
	} elseif ($null -eq $_ -or $_.GetType().IsPrimitive -or $_ -is [string] -or $_ -is [decimal] -or $_ -is [datetime] -or $_ -is [datetimeoffset]) {
		$_
	} elseif ($_ -is [Collections.IEnumerable] -and $_ -isnot [Collections.IDictionary]) { # enumerable (other than a dictionary)
		, ($_ | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth+1))
	} else { # non-primitive type or dictionary (hashtable) -> recurse on properties / entries
		if ($CurrDepth -gt $Depth) { # depth exceeded -> return .ToString() representation
			Write-Warning "Recursion depth $Depth exceeded - reverting to .ToString() representations."
			"$_"
		} else {
			$oht = [ordered] @{}
			foreach ($prop in $(if ($_ -is [Collections.IDictionary]) { $_.GetEnumerator() } else { $_.psobject.properties })) {
		  		if ($prop.Value -is [Collections.IEnumerable] -and $prop.Value -isnot [Collections.IDictionary] -and $prop.Value -isnot [string]) {
					$oht[$prop.Name] = @($prop.Value | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth+1))
		  		} else {      
					$oht[$prop.Name] = $prop.Value | ConvertTo-EnumsAsStrings -Depth $Depth -CurrDepth ($CurrDepth+1)
		  		}
			}
			$oht
	  	}
	}
}

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

# Get this servers configuration ID for tagging
$ServerAsset = (Get-ITGlueConfigurations -page_size "1000" -filter_name $ENV:COMPUTERNAME -organization_id $orgID).data

# Loop through each share and get permissions then update ITG
$i = 0
$UpdatedShares = 0
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

	# Also save a permissions json file to the file share for the AD Server portion to use for updating
	$PermsJson = ($Permissions | ConvertTo-EnumsAsStrings -Depth 10 | ConvertTo-Json -Depth 10)
	$PermissionsBackupFileLoc = $DiskPath + "/PermissionsBackup_$PermissionsFileUUID.json"

	Remove-Item $PermissionsBackupFileLoc -Force -ErrorAction Ignore # Remove first as sometimes due to a permissions error we can't overwrite the file

	$PermsJson | Out-File -FilePath ($DiskPath + "/PermissionsBackup_$PermissionsFileUUID.json")

	# Set permissions on the file to ensure no access right issues when accessing it later
	if ($FullAccessAccounts_PermsFile -and $FullAccessAccounts_PermsFile.Count -gt 0) {
		$CurUser = [Security.Principal.WindowsIdentity]::GetCurrent()
		$Domain = $CurUser.Name.Split("\")[0]
		if (!$Domain) {
			$Domain = $env:USERDNSDOMAIN -replace ".local", ""
		}
		$PermFileACL = Get-Acl $PermissionsBackupFileLoc

		# Set owner
		$UserAccount = $FullAccessAccounts_PermsFile[0]
		$NewUsername = $UserAccount
		if ($UserAccount -notlike "*\*" -and $UserAccount -notlike "*/*" -and $Domain) {
			$NewUsername = $Domain + "\" + $UserAccount
		}
		$NewUser = [System.Security.Principal.NTAccount] $NewUsername
		$PermFileACL.SetOwner($NewUser)

		# Setup file permissions
		$PermFileACL.SetAccessRuleProtection($true,$false)
		
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins", "FullControl", "Allow")
		$PermFileACL.SetAccessRule($AccessRule)
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
		$PermFileACL.SetAccessRule($AccessRule)

		$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users","Read","Allow")
		$PermFileACL.RemoveAccessRule($AccessRule)
		$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","Read","Allow")
		$PermFileACL.RemoveAccessRule($AccessRule)

		foreach ($UserAccount in $FullAccessAccounts_PermsFile) {
			$NewUsername = $UserAccount
			if ($UserAccount -notlike "*\*" -and $UserAccount -notlike "*/*" -and $Domain) {
				$NewUsername = $Domain + "\" + $UserAccount
			}
			$NewUser = [System.Security.Principal.NTAccount] $NewUsername
			
			$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($NewUsername, "FullControl", "Allow")
			$PermFileACL.SetAccessRule($AccessRule)
		}

		Set-Acl -aclobject $PermFileACL -path $PermissionsBackupFileLoc
	}
	(get-item $PermissionsBackupFileLoc).Attributes += 'Hidden'
	
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
					"servers" = @($Servers)
					"disk-path-on-server" = $DiskPath
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
					"mapped-drive-letter" = $ExistingShare.attributes.traits."mapped-drive-letter"
					"share-path" = $SharePath
					"related-gpo" = $ExistingShare.attributes.traits."related-gpo"
					"servers" = @($ExistingShare.attributes.traits.servers.values.id)
					"disk-path-on-server" = $DiskPath
					"approver-for-access-to-folder" = @($ExistingShare.attributes.traits."approver-for-access-to-folder".values.id)
					"specific-setup-instructions" = $ExistingShare.attributes.traits."specific-setup-instructions"
					"ad-groups-full-access" = @($ExistingShare.attributes.traits."ad-groups-full-access".values.id)
					"ad-groups-modify" = @($ExistingShare.attributes.traits."ad-groups-modify".values.id)
					"ad-groups-read-only" = @($ExistingShare.attributes.traits."ad-groups-read-only".values.id)
					"ad-groups-deny" = @($ExistingShare.attributes.traits."ad-groups-deny".values.id)
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
		"file-shares-file-server" = (Get-Date).ToString("yyyy-MM-dd")
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