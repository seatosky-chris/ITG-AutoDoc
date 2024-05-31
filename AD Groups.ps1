#####################################################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$UpdateOnly = $false # If set to $true, the script will only update existing assets. If $false, it will add new groups (that have members) and add them to ITG with as much info as possible.
$FlexAssetName = "AD Security Groups"
$AD_FlexAssetName = "Active Directory"
$Description = "Updates/creates all security groups in ITG with their members and parents. When creating new one's it will do its best to categorize them properly."
$EmployeeContactTypes = @( 
	"Approver", "Champion", "Contractor", "Decision Maker", "Employee", "Employee - On Leave",
	"Employee - Email Only", "Employee - Part Time", "Employee - Temporary", "Employee - Multi User",
	"Influencer", "Internal IT", "Management", "Owner", "Shared Account", "Terminated"
)
$IgnoreGroups = @(
	"Domain Users", "Domain Computers"
)
$DictionaryFolder = "C:\seatosky\AutoDoc\DictionaryAlphabetJSON"
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
$ApplicationsAssetID = (Get-ITGlueFlexibleAssetTypes -filter_name "Applications").data
$AD_FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $AD_FlexAssetName).data

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$OrganizationInfo = Get-ITGlueOrganizations -id $OrgID
if (!$OrganizationInfo -or !$OrganizationInfo.data -or !$FilterID -or ($OrganizationInfo.data | Measure-Object).Count -lt 1 -or !$OrganizationInfo.data[0].attributes -or !$OrganizationInfo.data[0].attributes."short-name") {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}

# If a matched user list csv (from the user audit) exists, get that and use it later for matching ITG contacts to AD usernames
$OrganizationInfo = $OrganizationInfo.data
$OrgShortName = $OrganizationInfo[0].attributes."short-name"
if (Test-Path -Path "C:\seatosky\UserAudit\$($OrgShortName)_Matched_User_List.csv" -PathType Leaf) {
	$MatchedUserList = Import-CSV "C:\seatosky\UserAudit\$($OrgShortName)_Matched_User_List.csv"
} elseif (Test-Path -Path "C:\seatosky\$($OrgShortName)_Matched_User_List.csv" -PathType Leaf) {
	$MatchedUserList = Import-CSV "C:\seatosky\$($OrgShortName)_Matched_User_List.csv"
} else {
	$MatchedUserList = @()
}

# Get existing groups
Write-Host "Downloading existing groups"
# For companies with many groups trying to get them all at once sometimes times out, and then it goes and creates duplicates of every single group
# By looping through 200 at a time we prevent a timeout from happening.
$ExistingGroups = @()
$i = 1
while ($i -le 10 -and ($ExistingGroups | Measure-Object).Count -eq (($i-1) * 200)) {
	$ExistingGroups_Partial = Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID
	if (!$ExistingGroups_Partial -or $ExistingGroups_Partial.Error) {
		# We got an error querying groups, wait and try again
		Start-Sleep -Seconds 2
		$ExistingGroups_Partial = Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID

		if (!$ExistingGroups_Partial -or $ExistingGroups_Partial.Error) {
			Write-Error "An error occurred trying to get the existing AD groups from ITG. Exiting..."
			Write-Error $ExistingGroups_Partial.Error
			exit 1
		}
	}
	$ExistingGroups += ($ExistingGroups_Partial).data

	Write-Host "- Got group set $i"
	$TotalGroups = ($ExistingGroups | Measure-Object).Count
	Write-Host "- Total: $TotalGroups"
	$i++
}

if (!$ExistingGroups -and $UpdateOnly) {
	# We are doing an update only but no groups exist in ITG
	Read-Host "The script is running in Update-Only mode but there were no existing groups found in ITG. Check the variables and try again. Press any key to exit..."
	exit
}

$ExistingGroupIdentifiers = $ExistingGroups.attributes.traits | Select-Object "group-name", guid

# Get full contact list from ITG (it's faster than searching for members on a per contact basis)
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

# Get dictionary for application checks
$Dictionary = @{}
If (test-path $DictionaryFolder) {
	[char[]]"abcdefghijklmnopqrstuvwxyz" | ForEach-Object {
		$Alpha = $_
		
		$AlphaPath = "$DictionaryFolder\$Alpha.json"
		if (Test-Path $AlphaPath) {
			$Dictionary.add([string]$Alpha, (Get-Content $AlphaPath | Out-String | ConvertFrom-Json))
		}
	}
}
$Dictionary = @($Dictionary.Values.Word)

# Get application names from ITG, for finding application-related groups
Write-Host "Downloading applications list"
$Applications = (Get-ITGlueFlexibleAssets -page_size 1000 -filter_flexible_asset_type_id $ApplicationsAssetID.id -filter_organization_id $orgID).data
$Applications = $Applications.attributes.traits.name
$ApplicationWords = $Applications | ForEach-Object { $_.split(" _-") } | Where-Object { $_ -notin $Dictionary -and $_.substring(0,$_.length-1) -notin $Dictionary -and $_.substring(0,$_.length-2) -notin $Dictionary }

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

# Get AD site details
$ForestInformation = $(Get-ADForest)
$ADSiteName = $ForestInformation.Name
$ADFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $AD_FilterID.id -filter_organization_id $OrgID).data | Where-Object { $_.attributes.traits.'ad-full-name' -eq $ADSiteName }
if (($ADFlexAsset | Measure-Object).Count -gt 1) {
	$ADFlexAsset = $ADFlexAsset | Sort-Object -Property {$_.attributes.'updated-at'} -Descending | Select-Object -First 1
}
$ADSiteText = $ADSiteName
if ($ADFlexAsset) {
	$ADSiteText += " (ITG ID: $($ADFlexAsset.id))"
}

# Collect Data
Write-Host "Updating Groups"
$AllGroups = Get-ADGroup -Filter 'GroupCategory -eq "Security"' -Properties Description, info | Sort-Object -Property Name -Unique
$GroupCount = ($AllGroups | Measure-Object).Count
$UpdatedGroups = 0
$i = 0
foreach ($Group in $AllGroups) {
	$i++
	[int]$PercentComplete = $i / $GroupCount * 100
	Write-Progress -Activity "Updating Groups" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.name)')")

	if ($Group.Name -in $IgnoreGroups) {
		Write-Host "Group $($Group.name) was ignored." -ForegroundColor Yellow
		continue;
	}

	if ($UpdateOnly) {
		if ($Group.ObjectGUID -notin $ExistingGroupIdentifiers.guid -and $($Group.Name) -notin $ExistingGroupIdentifiers."group-name") {
			continue;
		}
	}

	$MemberUsers = @()
	$MemberComputers = @()
	$MemberGroups = @()
	$Members = Get-ADGroupMember $Group
	$MembersTable = $members | Sort-Object -Property objectClass, Name | Select-Object Name, objectClass, distinguishedName | ConvertTo-Html -Fragment | Out-String

	if (!$UpdateOnly -and ($Members | Measure-Object).Count -eq 0) {
		continue;
	}
	
	Write-Progress -Activity "Updating Groups" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.name)' - Building members list)")
	foreach ($Member in $Members) {
		$MemberType = $Member.objectClass

		if ($MemberType -eq "computer") {
			$MemberComputers += $FullConfigurationsList | Where-Object { $_.attributes.name -like $Member.name }

		} elseif ($MemberType -eq "group") {
			$MemberGroups += $ExistingGroups | Where-Object { $_.attributes.traits.guid -eq $Member.objectGUID -or $_.attributes.traits."group-name" -like $Member.name }

		} elseif ($MemberType -eq "user") {
			$ADUser = Get-ADUser $member -Properties EmailAddress
			$Email = $ADUser.UserPrincipalName
			$Email2 = $ADUser.EmailAddress
			$FirstName = $ADUser.GivenName
			$LastName = $ADUser.Surname
			$Username = $ADUser.SamAccountName

			$Match = @()
			$MatchedUser = $MatchedUserList | Where-Object { $_."AD Username" -like $Username -and $_.ID }

			if ($MatchedUser) {
				$Match += $FullContactList | Where-Object { $_.id -eq $MatchedUser.ID }
			}

			# Search the contacts from ITG if necessary
			while (!$Match) {
				# Primary email search
				if ($Email) {
					$Match += $FullContactList | Where-Object { $Email -in ($_.attributes."contact-emails" | Where-Object { $_.primary -eq "True" }).value }
				}
				if ($Match) { break }
				if ($Email2) {
					$Match += $FullContactList | Where-Object { $Email2 -in ($_.attributes."contact-emails" | Where-Object { $_.primary -eq "True" }).value }
				}
				if ($Match) { break }
				# Username search
				$Match += $FullContactList | Where-Object { $_.attributes.notes -like "*Username: $Username*" }
				if ($Match) { break }
				# Primary email search by notes
				if ($Email) {
					$Match += $FullContactList | Where-Object { $_.attributes.notes -like "*Primary O365 Email: $Email*" }
				}
				if ($Email2) {
					$Match += $FullContactList | Where-Object { $_.attributes.notes -like "*Primary O365 Email: $Email2*" }
				}
				if ($Match) { break }
				# First and last name
				if ($FirstName -and $LastName) {
					$Match += $FullContactList | Where-Object { $_.attributes."first-name" -like $FirstName -and $_.attributes."last-name" -like $LastName }
				}
				if ($Match) { break }
				# Other emails & first/last name if more than 1 is found
				if ($Email) {
					$Match += $FullContactList | Where-Object { $Email -in $_.attributes."contact-emails".value -and ($_.attributes."first-name" -like "*$FirstName*" -or $_.attributes."last-name" -like "*$LastName*") }
				}
				if ($Email2) {
					$Match += $FullContactList | Where-Object { $Email2 -in $_.attributes."contact-emails".value -and ($_.attributes."first-name" -like "*$FirstName*" -or $_.attributes."last-name" -like "*$LastName*") }
				}
				if ($Match) { break }
				# Partial name search
				if ($FirstName -and $LastName) {
					$Match += $FullContactList | Where-Object { $_.attributes."first-name" -like "*$FirstName*" -and $_.attributes."last-name" -like "*$LastName*" }
				}
				break
			}

			# If more than 1 match, narrow down to 1
			$Match = $Match | Sort-Object id -Unique
			if ($Match -and ($Match | Measure-Object).Count -gt 1) {
				$MostLikelyMatches = $Match | Where-Object { $_.first_name -like $FirstName -and $_.last_name -like $LastName }
				if ($MostLikelyMatches) {
					$Match = $MostLikelyMatches
				}
				if (($Match | Measure-Object).Count -gt 1) {
					if ($ADUser -and $ADUser.DistinguishedName -like "*OU=ServiceAccounts,*") {
						$MatchesWithType = $Match | Where-Object { $_.attributes."contact-type-id" -and $_.attributes."contact-type-name" -in @("Service Account", "Internal / Shared Mailbox") }
					} else {
						$MatchesWithType = $Match | Where-Object { $_.attributes."contact-type-id" -and $_.attributes."contact-type-name" -in $EmployeeContactTypes }
					}
					if ($MatchesWithType) {
						$Match = $MatchesWithType
					}
				}
				if (($Match | Measure-Object).Count -gt 1) {
					$Match = $Match | Select-Object -First 1
				}
			}

			if ($Match) {
				$MemberUsers += $Match
			}
		}
	}

	# Now get a list of parent groups
	$ParentGroups = @()
	$MemberOf =  Get-ADPrincipalGroupMembership $Group
	$ParentGroupsTable = $MemberOf | Select-Object Name, objectClass, distinguishedName | ConvertTo-Html -Fragment | Out-String

	Write-Progress -Activity "Updating Groups" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.name) - Building parent groups list')")
	foreach ($MemberGroup in $MemberOf) {
		if ($MemberGroup.objectClass -eq "group") {
			$ParentGroups += $ExistingGroups | Where-Object { $_.attributes.traits.guid -eq $MemberGroup.objectGUID -or $_.attributes.traits."group-name" -like $MemberGroup.name }
		}
	}

	# Get existing asset to update (if one exists)
	$ExistingGroup = $ExistingGroups | Where-Object { $_.attributes.traits.guid -eq $Group.ObjectGUID -or $_.attributes.traits.'group-name' -eq $($Group.Name) } | Select-Object -First 1
	# If the Asset does not exist, create a new asset, if it does exist we'll combine the old and the new
	if (!$ExistingGroup) {
		Write-Progress -Activity "Updating Groups" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.name)' - Creating new asset)")
		# Try to determine what type of group this is (how to categorize it)
		# Options: Applications, Built-In, Computer Access, Email / Calendar, File Share / Drive Mappings, Permissions, Printers, Remote Access, Security Tools, Servers, Service Groups, Team / Division, Other
		$ServiceGroups = @("ADAudit*", "ADSync*", "Allowed RODC*", "Denied RODC*", "DHCP*", "Dns*", "IIS_*", "Schema *", "WinRM*")

		$GroupType = "Other"
		if ($Group.DistinguishedName -like "*CN=Builtin,*") {
			$GroupType = "Built-In"
		} elseif ($Group.Name -like "*Share-*" -or $Group.Name -like "*Share_*" -or $Group.Name -like "TRV-*" -or $Group.Name -like "*Drive Map*" -or $Group.Name -like "*Drive-Map*" -or $Group.Name -like "*DriveMap*" -or 
			$Group.Name -like "*HomeDrive*" -or $Group.Name -like "Drives-*" -or $Group.Name -like "*UserFolder*" -or $Group.Name -like "*User Folder*" -or 
			$Group.Name -like "*Folder Redirection*" -or $Group.Name -like "*FolderRedirection*") 
		{
			$GroupType = "File Share / Drive Mappings"
		} elseif ($Group.Name -like "*Printer*" -or $Group.Name -like "*Scanner*") {
			$GroupType = "Printers"
		# APPS
		} elseif ($Group.Name -like "Computers-Deploy*" -or $Group.Name -like "SQLServer*" -or 
			($Applications | Where-Object { $Group.Name -like "*$_*" -or ($Group.Name -replace " ", "_") -like "*$_*" -or ($Group.Name -replace " ", "-") -like "*$_*" -or ($Group.Name -replace " ", "") -like "*$_*" } | Measure-Object).Count -gt 0 -or
			($Applications | Where-Object { $Group.Description -like "*$_*" -or ($Group.Description -replace " ", "_") -like "*$_*" -or ($Group.Description -replace " ", "-") -like "*$_*" -or ($Group.Description -replace " ", "") -like "*$_*" } | Measure-Object).Count -gt 0
		) {
			$GroupType = "Applications"
		} elseif ($Group.Name -like "*VPN*" -or $Group.Name -like "*Remote Desktop*" -or $Group.Name -like "*Remote Management*" -or $Group.Name -clike "*RDS*" -or $Group.Name -clike "*RDP*") {
			$GroupType = "Remote Access"
		} elseif ($Group.Name -like "*Calendar*" -or $Group.Name -like "*Email*" -or $Group.Name -like "*Exchange*" -or $Group.Name -like "Office365Users*" -or $Group.Name -like "O365Users*" -or $Group.Name -like "Mailbox") {
			$GroupType = "Email / Calendar"
		} elseif (($ServiceGroups | Where-Object { $Group.Name -like $_ } | Measure-Object).Count -gt 0) {
			$GroupType = "Service Groups"
		} elseif ($Group.Name -like "*Division*" -or ($Group.Name -like "*Team*" -and $Group.Name -notlike "*Teams*") -or $Group.Name -like "*Building*") {
			$GroupType = "Team / Division"
		} elseif ($Group.Name -like "*Servers*" -or $Group.Name -like "*Domain Controllers*" -or $Group.Name -like "*Publishers") {
			$GroupType = "Servers"
		} elseif ($Group.Name -like "*Sophos*" -or $Group.Name -like "*OpenDNS*" -or $Group.Name -like "*Webroot*" -or $Group.Name -like "SMSMSE *" -or $Group.Name -like "*BitLocker*") {
			$GroupType = "Security Tools"
		} elseif ($Group.Name -like "*Computer*") {
			$GroupType = "Computer Access"
		} elseif ($Group.Name -like "Domain *" -or $Group.Name -like "*Admin*" -or $Group.Name -like "*Owner*") {
			$GroupType = "Permissions"
		} elseif (($ApplicationWords | Where-Object { $Group.Name -like "*$_*" -or ($Group.Name -replace " ", "_") -like "*$_*" -or ($Group.Name -replace " ", "-") -like "*$_*" -or ($Group.Name -replace " ", "") -like "*$_*" } | Measure-Object).Count -gt 0) {
			$GroupType = "Applications"
		}

		$IsTraverse = $false
		if ($GroupType -eq "File Share / Drive Mappings" -and $Group.name -like "TRV*") {
			$IsTraverse = $true
		}

		$FolderAccessType = ""
		if ($GroupType -eq "File Share / Drive Mappings") {
			if ($Group.Name -like "*-Full") {
				$FolderAccessType = "Full Control"
			} elseif ($Group.Name -like "*-RW*" -or $Group.Name -like "*_RW*") {
				$FolderAccessType = "Read-Write"
			} elseif ($Group.Name -like "*-RO*" -or $Group.Name -like "*_RO*") {
				$FolderAccessType = "Read-Only"
			} elseif ($Group.Name -like "*-Deny" -or $Group.Name -like "*_Deny") {
				$FolderAccessType = "Deny Full Control"
			}
		}

		$Description = $($Group.description)
		$GroupDetails = $($Group.info)

		if ($Description.length -gt 255) {
			if ($GroupDetails) {
				$GroupDetails = "$($Description) <br /><br />$($GroupDetails)"
			} else {
				$GroupDetails = $Description
			}
			$Description = ($Description -split "\. ")[0] + "."
			if ($Description.length -gt 255) {
				$Description = $Description.Substring(0, 255)
			}
		}

		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
				'organization-id' = $orgID
				'flexible-asset-type-id' = $FilterID.id
				traits = @{
					"group-name" = $($Group.name)
					"group-type" = $GroupType
					"group-description" = $Description
					"folder-traverse" = $IsTraverse
					"folder-access-type" = $FolderAccessType
					"guid" = $($group.objectguid.guid)
					"ad-site" = $ADSiteText
					"group-details" = $GroupDetails
					"member-groups" = $($MemberGroups.id | Sort-Object -Unique)
					"member-users" = $($MemberUsers.id | Sort-Object -Unique)
					"member-configurations" = $($MemberComputers.id | Sort-Object -Unique)
					"members-table" = $MembersTable
					"parent-groups" = $($ParentGroups.id | Sort-Object -Unique)
					"parent-groups-table" = $ParentGroupsTable
				}
			}
		}
		# Filter out empty values
		($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$FlexAssetBody.attributes.traits.Remove($_.Name) 
		}

		Write-Host "Creating new flexible asset - $($Group.name)"
		$Response = New-ITGlueFlexibleAssets -data $FlexAssetBody
		if ($Response.Error -and $Response.Error -like "422 - *") {
			Write-Host "Error uploading flexible asset, too large. Trying again - $($Group.name)" -ForegroundColor Yellow
			$FlexAssetBody.attributes.traits.Remove("member-users") 
			$FlexAssetBody.attributes.traits."members-table" = "Too large to upload."
			New-ITGlueFlexibleAssets -data $FlexAssetBody
		} elseif ($Response.Error) {
			Write-Host "Error uploading flexible asset - $($Group.name)" -ForegroundColor Red
			continue
		}
		$UpdatedGroups++
	} else {
		Write-Progress -Activity "Updating Groups" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.name) - Updating asset')")
		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
					traits = @{
						"group-name" = $ExistingGroup.attributes.traits."group-name"
						"group-type" = $ExistingGroup.attributes.traits."group-type"
						"group-description" = $ExistingGroup.attributes.traits."group-description"
						"folder-traverse" = $ExistingGroup.attributes.traits."folder-traverse"
						"folder-access-type" = $ExistingGroup.attributes.traits."folder-access-type"
						"who-to-add" = $ExistingGroup.attributes.traits."who-to-add"
						"approver-for-access" = @($ExistingGroup.attributes.traits."approver-for-access".values.id)
						"guid" = $($group.objectguid.guid)
						"ad-site" = $ADSiteText
						"group-details" = $ExistingGroup.attributes.traits."group-details"
						"member-groups" = $($MemberGroups.id | Sort-Object -Unique)
						"member-users" = $($MemberUsers.id | Sort-Object -Unique)
						"member-configurations" = $($MemberComputers.id | Sort-Object -Unique)
						"members-table" = $MembersTable
						"parent-groups" = $($ParentGroups.id | Sort-Object -Unique)
						"parent-groups-table" = $ParentGroupsTable
					}
			}
		}
		# Filter out empty values
		($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$FlexAssetBody.attributes.traits.Remove($_.Name) 
		}

		Write-Host "Updating Flexible Asset - $($ExistingGroup.attributes.traits."group-name")"
		$Response = Set-ITGlueFlexibleAssets -id $ExistingGroup.id  -data $FlexAssetBody
		if ($Response.Error -and $Response.Error -like "422 - *") {
			Write-Host "Error uploading flexible asset, too large. Trying again - $($Group.name)" -ForegroundColor Yellow
			$FlexAssetBody.attributes.traits.Remove("member-users") 
			$FlexAssetBody.attributes.traits.Remove("member-configurations") 
			$FlexAssetBody.attributes.traits."members-table" = "Too large to upload."
			Set-ITGlueFlexibleAssets -id $ExistingGroup.id  -data $FlexAssetBody
		} elseif ($Response.Error) {
			Write-Host "Error updating flexible asset - $($Group.name)" -ForegroundColor Red
			continue
		}
		$UpdatedGroups++
	}
} 
Write-Progress -Activity "Updating Groups" -Status "Ready" -Completed

# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $orgID -and $UpdatedGroups -gt 0) {
	$Headers = @{
		"x-api-key" = $APIKEy
	}
	$Body = @{
		"apiurl" = $APIEndpoint
		"itgOrgID" = $orgID
		"HostDevice" = $env:computername
		"ad-groups" = (Get-Date).ToString("yyyy-MM-dd")
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