################# IT-Glue Information ######################################
$ITGApiKey = "<ITG API KEY>"
$ITGApiEndpoint = "<ITG API URL>"
$OrgID = "<ITG Org ID>"
$UpdateOnly = $false # If set to $true, the script will only update existing assets. If $false, it will add new groups and add them to ITG with as much info as possible.
$FlexAssetName = "Email Groups"
$ADGroupsFlexAssetName = "AD Security Groups"
$Description = "Auto documentation of all O365 distribution lists and shared mailboxes."
################# /IT-Glue Information #####################################

#################### O365 Unattended Login using Certs #####################
$O365LoginUser = ""
$O365UnattendedLogin = @{
	AppID = ""
	TenantID = ""
	Organization = ""
	CertificateThumbprint = ""
  }
#################### /O365 Unattended Login using Certs ####################

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

#Grabbing ITGlue Module and installing.
If (Get-Module -ListAvailable -Name "ITGlueAPI") { 
    Import-module ITGlueAPI 
} else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
  
#Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $ITGApiEndpoint
Add-ITGlueAPIKey $ITGApiKey

# Connect to Office 365 and Azure
Write-Host "Connecting to Office 365..."
If (Get-Module -ListAvailable -Name "AzureAD") {
	Import-Module AzureAD
} else {
	Install-Module -Name AzureAD
}
if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
	Connect-AzureAD -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -ApplicationId $O365UnattendedLogin.AppID -TenantId $O365UnattendedLogin.TenantId
} else {
	Connect-AzureAD -AccountID $O365LoginUser
}

If (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {
	Import-Module ExchangeOnlineManagement
} else {
	Install-Module PowerShellGet -Force
	Install-Module -Name ExchangeOnlineManagement
}
if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
	Connect-ExchangeOnline -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -AppID $O365UnattendedLogin.AppID -Organization $O365UnattendedLogin.Organization -ShowProgress $true -ShowBanner:$false
} else {
	Connect-ExchangeOnline -UserPrincipalName $O365LoginUser -ShowProgress $true -ShowBanner:$false
}

# Get the flexible asset type ids
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
$ADGroupsFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $ADGroupsFlexAssetName).data

# If a matched user list csv (from the user audit) exists, get that and user it later for matching ITG contacts to AD usernames
$OrganizationInfo = (Get-ITGlueOrganizations -id $OrgID).data
$OrgShortName = $OrganizationInfo[0].attributes."short-name"
$MatchedUserList = Import-CSV "C:\seatosky\$($OrgShortName)_Matched_User_List.csv"

# Get existing groups
Write-Host "Downloading existing email groups"
# For companies with many groups trying to get them all at once sometimes times out, and then it goes and creates duplicates of every single group
# By looping through 200 at a time we prevent a timeout from happening.
$ExistingGroups = @()
$i = 1
while ($i -le 10 -and ($ExistingGroups | Measure-Object).Count -eq (($i-1) * 200)) {
	$ExistingGroups += (Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $OrgID).data
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

$ExistingGroupIdentifiers = @($ExistingGroups.attributes.traits | Select-Object "group-name", "email-address", ObjectID)

# Get full contact list from ITG
Write-Host "Downloading all ITG contacts"
$FullContactList = (Get-ITGlueContacts -page_size 1000 -organization_id $OrgID).data

# Get AD groups
Write-Host "Downloading all AD groups"
$AllADGroups = @()
$i = 1
while ($i -le 10 -and ($AllADGroups | Measure-Object).Count -eq (($i-1) * 200)) {
	$AllADGroups += (Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $ADGroupsFilterID.id -filter_organization_id $orgID).data
	Write-Host "- Got group set $i"
	$TotalADGroups = ($AllADGroups | Measure-Object).Count
	Write-Host "- Total: $TotalADGroups"
	$i++
}

# Get disabled accounts, unlicensed accounts, and guests to add extra data to tables
$DisabledAccounts = Get-AzureADUser -Filter "AccountEnabled eq false" | Select-Object -ExpandProperty UserPrincipalName
$UnlicensedUsers = Get-AzureADUser | Where-Object {
	$licensed = $false
	for ($i = 0; $i -le ($_.AssignedLicenses | Measure-Object).Count ; $i++) { 
		if ([string]::IsNullOrEmpty($_.AssignedLicenses[$i].SkuId) -ne $true) { 
			$licensed = $true 
		} 
	} 
	if ($licensed -eq $false) { 
		return $true
	} else {
		return $false
	}
} | Select-Object DisplayName, UserPrincipalName, @{N="FirstName"; E={$_."GivenName"}}, @{N="LastName"; E={$_."Surname"}}, @{N="Title"; E={$_."JobTitle"}}
$GuestUsers = Get-AzureADUser -Filter "UserType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, @{N="FirstName"; E={$_."GivenName"}}, @{N="LastName"; E={$_."Surname"}}, @{N="Title"; E={$_."JobTitle"}}

# Get all groups
$Microsoft365Groups = Get-AzureADMSGroup -Filter "groupTypes/any(c:c eq 'Unified')" -All $true
$DistributionLists = Get-DistributionGroup -ResultSize Unlimited -RecipientTypeDetails MailUniversalDistributionGroup
$MailSecurityGroups = Get-AzureADGroup -Filter "SecurityEnabled eq true and MailEnabled eq true"
$SecurityGroups = Get-AzureADGroup -Filter "SecurityEnabled eq true and MailEnabled eq false" | Where-Object { !$_.DirSyncEnabled }
$SharedMailboxes = Get-Mailbox -Filter {RecipientTypeDetails -eq "SharedMailbox"} -ResultSize Unlimited

# Get group members and add to above lists
foreach ($Group in $Microsoft365Groups) {
	$Group | Add-Member -MemberType NoteProperty -Name Members -Value @()
	$GroupMembers = Get-AzureADGroupMember -ObjectId $Group.Id -All $true
	foreach ($User in $GroupMembers) {
		$Group.Members += New-Object PSObject -property $([ordered]@{ 
			UserName = $User.DisplayName
			UserPrincipalName  = $User.UserPrincipalName
			AccountEnabled  = $User.AccountEnabled
			JobTitle  = $User.JobTitle
			IsGuestUser  = if ($User.UserType -eq 'Guest') { $true } else { $false }
			IsLicensed  = if ($User.AssignedLicenses.Count -ne 0) { $true } else { $false }
		})
	}

	$Group | Add-Member -MemberType NoteProperty -Name Owners -Value @()
	$GroupOwners = Get-AzureADGroupOwner -ObjectId $Group.Id -All $true
	foreach ($User in $GroupOwners) {
		$Group.Owners += New-Object PSObject -property $([ordered]@{ 
			UserName = $User.DisplayName
			UserPrincipalName  = $User.UserPrincipalName
			AccountEnabled  = $User.AccountEnabled
			JobTitle  = $User.JobTitle
			IsGuestUser  = if ($User.UserType -eq 'Guest') { $true } else { $false }
			IsLicensed  = if ($User.AssignedLicenses.Count -ne 0) { $true } else { $false }
		})
	}
}

foreach ($DL in $DistributionLists) {
	$DL | Add-Member -MemberType NoteProperty -Name Members -Value @()
	$GroupMembers = Get-DistributionGroupMember -Identity $DL.Guid.Guid -ResultSize Unlimited
	foreach ($User in $GroupMembers) {
		$DL.Members += New-Object PSObject -property $([ordered]@{ 
			UserName = $User.DisplayName
			UserPrincipalName  = $User.PrimarySmtpAddress
			AccountEnabled  = if ($User.PrimarySmtpAddress -in $DisabledAccounts.UserPrincipalName) { $true } else { $false }
			JobTitle  = $User.Title
			IsGuestUser  = if ($User.PrimarySmtpAddress -in $GuestUsers.UserPrincipalName) { $true } else { $false }
			IsLicensed  = if ($User.PrimarySmtpAddress -in $UnlicensedUsers.UserPrincipalName) { $true } else { $false }
		})
	}

	$DL | Add-Member -MemberType NoteProperty -Name Owners -Value @()
	foreach ($User in $DL.ManagedBy) {
		$UserDetails = Get-Recipient $User
		$DL.Owners += New-Object PSObject -property $([ordered]@{ 
			UserName = $UserDetails.DisplayName
			UserPrincipalName  = $UserDetails.PrimarySmtpAddress
			AccountEnabled  = if ($UserDetails.PrimarySmtpAddress -notin $DisabledAccounts.UserPrincipalName) { $true } else { $false }
			JobTitle  = $UserDetails.Title
			IsGuestUser  = if ($UserDetails.PrimarySmtpAddress -in $GuestUsers.UserPrincipalName) { $true } else { $false }
			IsLicensed  = if ($UserDetails.PrimarySmtpAddress -notin $UnlicensedUsers.UserPrincipalName) { $true } else { $false }
		})
	}
}

$MailSecurityGroups_Owners = Get-DistributionGroup -RecipientTypeDetails MailUniversalSecurityGroup | Select-Object DisplayName,PrimarySmtpAddress,ManagedBy
foreach ($Group in $MailSecurityGroups) {
	$Group | Add-Member -MemberType NoteProperty -Name Members -Value @()
	$GroupMembers = Get-AzureADGroupMember -ObjectId $Group.ObjectId -All $true
	foreach ($User in $GroupMembers) {
		$Group.Members += New-Object PSObject -property $([ordered]@{ 
			UserName = $User.DisplayName
			UserPrincipalName  = $User.UserPrincipalName
			AccountEnabled  = $User.AccountEnabled
			JobTitle  = $User.JobTitle
			IsGuestUser  = if ($User.UserType -eq 'Guest') { $true } else { $false }
			IsLicensed  = if ($User.AssignedLicenses.Count -ne 0) { $true } else { $false }
		})
	}

	$Group | Add-Member -MemberType NoteProperty -Name Owners -Value @()
	$Owners = $MailSecurityGroups_Owners | Where-Object { $_.PrimarySmtpAddress -eq $Group.Mail }
	foreach ($User in $Owners.ManagedBy) {
		$UserDetails = Get-Recipient $User
		$Group.Owners += New-Object PSObject -property $([ordered]@{ 
			UserName = $UserDetails.DisplayName
			UserPrincipalName  = $UserDetails.PrimarySmtpAddress
			AccountEnabled  = if ($UserDetails.PrimarySmtpAddress -notin $DisabledAccounts.UserPrincipalName) { $true } else { $false }
			JobTitle  = $UserDetails.Title
			IsGuestUser  = if ($UserDetails.PrimarySmtpAddress -in $GuestUsers.UserPrincipalName) { $true } else { $false }
			IsLicensed  = if ($UserDetails.PrimarySmtpAddress -notin $UnlicensedUsers.UserPrincipalName) { $true } else { $false }
		})
	}
}

foreach ($Group in $SecurityGroups) {
	$Group | Add-Member -MemberType NoteProperty -Name Members -Value @()
	$GroupMembers = Get-AzureADGroupMember -ObjectId $Group.ObjectId -All $true
	foreach ($User in $GroupMembers) {
		$Group.Members += New-Object PSObject -property $([ordered]@{ 
			UserName = $User.DisplayName
			UserPrincipalName  = $User.UserPrincipalName
			AccountEnabled  = $User.AccountEnabled
			JobTitle  = $User.JobTitle
			IsGuestUser  = if ($User.UserType -eq 'Guest') { $true } else { $false }
			IsLicensed  = if ($User.AssignedLicenses.Count -ne 0) { $true } else { $false }
		})
	}

	$Group | Add-Member -MemberType NoteProperty -Name Owners -Value @()
	$GroupOwners = Get-AzureADGroupOwner -ObjectId $Group.ObjectId -All $true
	foreach ($User in $GroupOwners) {
		$Group.Owners += New-Object PSObject -property $([ordered]@{ 
			UserName = $User.DisplayName
			UserPrincipalName  = $User.UserPrincipalName
			AccountEnabled  = $User.AccountEnabled
			JobTitle  = $User.JobTitle
			IsGuestUser  = if ($User.UserType -eq 'Guest') { $true } else { $false }
			IsLicensed  = if ($User.AssignedLicenses.Count -ne 0) { $true } else { $false }
		})
	}
}

$SharedMailboxPermissions = $SharedMailboxes | Get-MailboxPermission | Where-Object {($_.user -like '*@*')}
$SharedMailboxSendAs = $SharedMailboxes | Get-RecipientPermission | Where-Object {($_.Trustee -like '*@*')}
foreach ($Mailbox in $SharedMailboxes) {
	$Mailbox | Add-Member -MemberType NoteProperty -Name Members -Value @()
	$MemberPermissions = $SharedMailboxPermissions | Where-Object { $_.Identity -eq $Mailbox.Name }
	foreach ($Permission in $MemberPermissions) {
		$UserDetails = Get-Recipient $Permission.User
		$Member = New-Object PSObject -property $([ordered]@{ 
			UserName = $UserDetails.DisplayName
			UserPrincipalName  = $UserDetails.PrimarySmtpAddress
			AccountEnabled  = if ($UserDetails.PrimarySmtpAddress -notin $DisabledAccounts.UserPrincipalName) { $true } else { $false }
			JobTitle  = $UserDetails.Title
			IsGuestUser  = if ($UserDetails.PrimarySmtpAddress -in $GuestUsers.UserPrincipalName) { $true } else { $false }
			IsLicensed  = if ($UserDetails.PrimarySmtpAddress -notin $UnlicensedUsers.UserPrincipalName) { $true } else { $false }
			AccessRights  =  [System.Collections.ArrayList]@()
		})
		$Permission.AccessRights | ForEach-Object { $Member.AccessRights.Add($_) }
		$Mailbox.Members += $Member
	}

	$MemberSendAsPermissions = $SharedMailboxSendAs | Where-Object { $_.Identity -eq $Mailbox.Name }
	foreach ($Permission in $MemberSendAsPermissions) {
		if ($Permission.Trustee -in $Mailbox.Members.UserPrincipalName) {
			$Member = $Mailbox.Members | Where-Object { $_.UserPrincipalName -eq $Permission.Trustee }
			foreach ($AccessRight in $Permission.AccessRights) {
				$Member.AccessRights.Add($AccessRight)
			}
		} else {
			$UserDetails = Get-Recipient $Permission.Trustee
			$Member = New-Object PSObject -property $([ordered]@{ 
				UserName = $UserDetails.DisplayName
				UserPrincipalName  = $UserDetails.PrimarySmtpAddress
				AccountEnabled  = if ($UserDetails.PrimarySmtpAddress -notin $DisabledAccounts.UserPrincipalName) { $true } else { $false }
				JobTitle  = $UserDetails.Title
				IsGuestUser  = if ($UserDetails.PrimarySmtpAddress -in $GuestUsers.UserPrincipalName) { $true } else { $false }
				IsLicensed  = if ($UserDetails.PrimarySmtpAddress -notin $UnlicensedUsers.UserPrincipalName) { $true } else { $false }
				AccessRights  =  [System.Collections.ArrayList]@()
			})
			$Permission.AccessRights | ForEach-Object { $Member.AccessRights.Add($_) }
			$Mailbox.Members += $Member
		}
	}

	foreach ($User in $Mailbox.GrantSendOnBehalfTo) {
		if ($User -in $Mailbox.Members.UserName) {
			$Member = $Mailbox.Members | Where-Object { $_.UserPrincipalName -eq $Permission.Trustee }
			$Member.AccessRights.Add("SendOnBehalf")
		} else {
			$UserDetails = Get-Recipient $User
			$Member = New-Object PSObject -property $([ordered]@{ 
				UserName = $UserDetails.DisplayName
				UserPrincipalName  = $UserDetails.PrimarySmtpAddress
				AccountEnabled  = if ($UserDetails.PrimarySmtpAddress -notin $DisabledAccounts.UserPrincipalName) { $true } else { $false }
				JobTitle  = $UserDetails.Title
				IsGuestUser  = if ($UserDetails.PrimarySmtpAddress -in $GuestUsers.UserPrincipalName) { $true } else { $false }
				IsLicensed  = if ($UserDetails.PrimarySmtpAddress -notin $UnlicensedUsers.UserPrincipalName) { $true } else { $false }
				AccessRights  =  [System.Collections.ArrayList]@()
			})
			$Member.AccessRights.Add("SendOnBehalf")
			$Mailbox.Members += $Member
		}
	}
}


# Now loop through all the groups and create/update assets in ITG
Write-Host "Updating Email Groups"
$GroupCount = ($Microsoft365Groups | Measure-Object).Count + 
	($DistributionLists | Measure-Object).Count + 
	($MailSecurityGroups | Measure-Object).Count + 
	($SecurityGroups | Measure-Object).Count +
	($SharedMailboxes | Measure-Object).Count

# First setup a function so that we can loop through this same code for each group type
function UpdateGroupAsset {
	param (
		[Parameter(Mandatory)]
		[PSObject]$Group,
		[Parameter(Mandatory)]
		[ValidateSet('Microsoft 365 Group', 'Distribution List', 'Mail-enabled Security', 'Security', 'Shared Mailbox')]
		[string]$GroupType
	)

	$GroupName = $Group.DisplayName
	if ($GroupType -eq 'Microsoft 365 Group') {
		$GroupID = $Group.Id
		$EmailAddress = $Group.Mail
		$Description = $Group.Description
	} elseif ($GroupType -eq 'Distribution List') {
		$GroupID = $Group.ExchangeObjectId.Guid
		$EmailAddress = $Group.PrimarySmtpAddress
		$Description = $Group.Description
	} elseif ($GroupType -eq 'Mail-enabled Security') {
		$GroupID = $Group.ObjectId
		$EmailAddress = $Group.Mail
		$Description = $Group.Description
	} elseif ($GroupType -eq 'Security') {
		$GroupID = $Group.ObjectId
		$EmailAddress = $Group.Mail
		$Description = $Group.Description
	} elseif ($GroupType -eq 'Shared Mailbox') {
		$GroupID = $Group.ExchangeObjectId.Guid
		$EmailAddress = $Group.PrimarySmtpAddress
		$Description = ""
	}

	if ($UpdateOnly) {
		if ($GroupID -notin $ExistingGroupIdentifiers.ObjectID -and $GroupName -notin $ExistingGroupIdentifiers."group-name" -and (!$EmailAddress -or $EmailAddress -notin $ExistingGroupIdentifiers."email-address")) {
			continue;
		}
	}

	$MemberUsers = @()
	$OwnerUsers = @()
	$MembersTable = $Group.Members | Sort-Object -Property UserName | ConvertTo-Html -Fragment | Out-String
	$OwnersTable = $Group.Owners | Sort-Object -Property UserName | ConvertTo-Html -Fragment | Out-String

	foreach ($Member in $Group.Members) {
		$Match = @()
		$MatchedUser = $MatchedUserList | Where-Object { ($_."O365 Email" -like $Member.UserPrincipalName -or $_."O365 Name" -like $Member.UserName) -and $_.ID }

		if ($MatchedUser) {
			$Match += $FullContactList | Where-Object { $_.id -eq $MatchedUser.ID }
		} else {
			$Match += $FullContactList | Where-Object { $_.attributes.name -like $Member.UserName -or $_.attributes."contact-emails".value -contains $Member.UserPrincipalName }
		}

		# If more than 1 match, narrow down to 1
		$Match = $Match | Sort-Object id -Unique
		if ($Match -and ($Match | Measure-Object).Count -gt 1) {
			$MostLikelyMatches = $Match | Where-Object { $_.attributes.name -like $Member.UserName -and $_.attributes."contact-emails".value -contains $Member.UserPrincipalName }
			if ($MostLikelyMatches) {
				$Match = $MostLikelyMatches
			}
			if (($Match | Measure-Object).Count -gt 1) {
				$MostLikelyMatches = $Match | Where-Object { $_.attributes."contact-emails".value -contains $Member.UserPrincipalName }
				if ($MostLikelyMatches) {
					$Match = $MostLikelyMatches
				}
			}
			$MostLikelyMatches = $Match | Where-Object { $_.attributes.name -like $Member.UserName }
			if ($MostLikelyMatches) {
				$Match = $MostLikelyMatches
			}
			if (($Match | Measure-Object).Count -gt 1) {
				$Match = $Match | Select-Object -First 1
			}
		}

		if ($Match) {
			$MemberUsers += $Match
		}
	}

	foreach ($Owner in $Group.Owners) {
		$Match = @()
		$MatchedUser = $MatchedUserList | Where-Object { ($_."O365 Email" -like $Owner.UserPrincipalName -or $_."O365 Name" -like $Owner.UserName) -and $_.ID }

		if ($MatchedUser) {
			$Match += $FullContactList | Where-Object { $_.id -eq $MatchedUser.ID }
		} else {
			$Match += $FullContactList | Where-Object { $_.attributes.name -like $Owner.UserName -or $_.attributes."contact-emails".value -contains $Owner.UserPrincipalName }
		}

		# If more than 1 match, narrow down to 1
		$Match = $Match | Sort-Object id -Unique
		if ($Match -and ($Match | Measure-Object).Count -gt 1) {
			$MostLikelyMatches = $Match | Where-Object { $_.attributes.name -like $Owner.UserName -and $_.attributes."contact-emails".value -contains $Owner.UserPrincipalName }
			if ($MostLikelyMatches) {
				$Match = $MostLikelyMatches
			}
			if (($Match | Measure-Object).Count -gt 1) {
				$MostLikelyMatches = $Match | Where-Object { $_.attributes."contact-emails".value -contains $Owner.UserPrincipalName }
				if ($MostLikelyMatches) {
					$Match = $MostLikelyMatches
				}
			}
			$MostLikelyMatches = $Match | Where-Object { $_.attributes.name -like $Owner.UserName }
			if ($MostLikelyMatches) {
				$Match = $MostLikelyMatches
			}
			if (($Match | Measure-Object).Count -gt 1) {
				$Match = $Match | Select-Object -First 1
			}
		}

		if ($Match) {
			$OwnerUsers += $Match
		}
	}

	$ADGroups = @()
	if (($GroupType -eq 'Microsoft 365 Group' -and $Group.OnPremisesSyncEnabled) -or
		($GroupType -eq 'Distribution List' -and $Group.IsDirSynced) -or
		($GroupType -eq 'Mail-enabled Security' -and $Group.DirSyncEnabled)) 
	{
		$ADGroups = @($AllADGroups | Where-Object { $_.attributes.traits."group-name" -like $GroupName } | Select-Object id)
	}

	$ConfigurationDetails = ""
	if ($GroupType -eq 'Microsoft 365 Group') {
		$ConfigurationDetails = "Visibility: " + $Group.Visibility
	} elseif ($GroupType -eq 'Distribution List') {
		$ConfigurationDetails = "Allow external senders: " + !$Group.RequireSenderAuthenticationEnabled
	} elseif ($GroupType -eq 'Shared Mailbox') {
		if ($Group.DeliverToMailboxAndForward) {
			$ConfigurationDetails += "Email forwarding enabled.`n"
			$ConfigurationDetails += "Forwarding to: " + $Group.ForwardingAddress
			$ConfigurationDetails += "`n"
		}
		if ($Group.MessageCopyForSentAsEnabled) {
			$ConfigurationDetails += '✓ Copy items sent as this mailbox.' + "`n"
		}
		if ($Group.MessageCopyForSendOnBehalfEnabled) {
			$ConfigurationDetails += '✓ Copy items sent on behalf of this mailbox.' + "`n"
		}
	}

	# Get existing asset to update (if one exists)
	$ExistingGroup = $ExistingGroups | Where-Object { $_.attributes.traits.ObjectID -eq $GroupID -or ($_.attributes.traits.'group-name' -eq $GroupName -and $_.attributes.traits.'email-address' -eq $EmailAddress -and $_.attributes.traits.'o365-group-type' -eq $GroupType) } | Select-Object -First 1

	# If the Asset does not exist, create a new asset, if it does exist we'll combine the old and the new
	if (!$ExistingGroup) {

		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
				'organization-id' = $OrgID
				'flexible-asset-type-id' = $FilterID.id
				traits = @{
					"group-name" = $GroupName
					"email-address" = $EmailAddress
					"o365-group-type" = $GroupType
					"group-description" = $Description
					"ad-access-group" = $ADGroups
					"objectid" = $GroupID
					"configuration-details" = $ConfigurationDetails
					"owners" = $($OwnerUsers.id | Sort-Object -Unique)
					"member-mailboxes" = $($MemberUsers.id | Sort-Object -Unique)
					"owners-table" = $OwnersTable
					"members-table" = $MembersTable
				}
			}
		}
		# Filter out empty values
		($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$FlexAssetBody.attributes.traits.Remove($_.Name) 
		}

		Write-Host "Creating new flexible asset - $GroupName"
		$Response = New-ITGlueFlexibleAssets -data $FlexAssetBody
		if ($Response.Error -and $Response.Error -like "422 - *") {
			Write-Host "Error uploading flexible asset, too large. Trying again - $GroupName" -ForegroundColor Yellow
			$FlexAssetBody.attributes.traits.Remove("member-mailboxes") 
			$FlexAssetBody.attributes.traits."members-table" = "Too large to upload."
			New-ITGlueFlexibleAssets -data $FlexAssetBody
		} elseif ($Response.Error) {
			Write-Host "Error uploading flexible asset - $GroupName" -ForegroundColor Red
		}
	} else {
		$FlexAssetBody = 
		@{
			type = 'flexible-assets'
			attributes = @{
					traits = @{
						"group-name" = $GroupName
						"email-address" = $EmailAddress
						"o365-group-type" = $ExistingGroup.attributes.traits."o365-group-type"
						"user-additions" = $ExistingGroup.attributes.traits."user-additions"
						"group-description" = $ExistingGroup.attributes.traits."group-description"

						"ad-access-group" = $ExistingGroup.attributes.traits."ad-access-group"
						"objectid" = $GroupID
						"configuration-details" = $ExistingGroup.attributes.traits."configuration-details"
						"group-details" = $ExistingGroup.attributes.traits."group-details"

						"who-to-add" = $ExistingGroup.attributes.traits."who-to-add"
						"approver-for-access" = @($ExistingGroup.attributes.traits."approver-for-access".values.id)
						"owners" = $($OwnerUsers.id | Sort-Object -Unique)
						"member-mailboxes" = $($MemberUsers.id | Sort-Object -Unique)
						"owners-table" = $OwnersTable
						"members-table" = $MembersTable
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
			Write-Host "Error uploading flexible asset, too large. Trying again - $GroupName" -ForegroundColor Yellow
			$FlexAssetBody.attributes.traits.Remove("member-mailboxes") 
			$FlexAssetBody.attributes.traits."members-table" = "Too large to upload."
			Set-ITGlueFlexibleAssets -id $ExistingGroup.id  -data $FlexAssetBody
		} elseif ($Response.Error) {
			Write-Host "Error updating flexible asset - $GroupName" -ForegroundColor Red
		}

		# If this is a shared mailbox, connect any associated contact
		if ($GroupType -eq 'Shared Mailbox') {
			$SanitizedName = $GroupName -replace "- Disabled", ""
			$RelatedContacts = $FullContactList | Where-Object { $_.attributes.name -like $GroupName -or $_.attributes.name -like $SanitizedName.Trim() }
			$RelatedContact = $RelatedContacts | Select-Object -First 1
			
			if ($RelatedContact) {
				$RelatedItemsBody =
				@{
					type = 'related_items'
					attributes = @{
						'destination_id' = $RelatedContact.id
						'destination_type' = "Contact"
					}
				}
				New-ITGlueRelatedItems -resource_type 'flexible_assets' -resource_id $ExistingGroup.id -data $RelatedItemsBody
			}
		}
	}
}

# Now loop through each group type and run the updates
$i = 0

foreach ($Group in $Microsoft365Groups) {
	$i++

	[int]$PercentComplete = $i / $GroupCount * 100
	Write-Progress -Activity "Updating Email Groups (Microsoft 365 Groups)" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.DisplayName))')")

	UpdateGroupAsset -Group $Group -GroupType "Microsoft 365 Group"
}

foreach ($Group in $DistributionLists) {
	$i++

	[int]$PercentComplete = $i / $GroupCount * 100
	Write-Progress -Activity "Updating Email Groups (Distribution Lists)" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.DisplayName))')")

	UpdateGroupAsset -Group $Group -GroupType "Distribution List"
}

foreach ($Group in $MailSecurityGroups) {
	$i++

	[int]$PercentComplete = $i / $GroupCount * 100
	Write-Progress -Activity "Updating Email Groups (Mail-enabled Security Groups)" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.DisplayName))')")

	UpdateGroupAsset -Group $Group -GroupType "Mail-enabled Security"
}

foreach ($Group in $SecurityGroups) {
	$i++

	[int]$PercentComplete = $i / $GroupCount * 100
	Write-Progress -Activity "Updating Email Groups (Security Groups)" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.DisplayName))')")

	UpdateGroupAsset -Group $Group -GroupType "Security"
}

foreach ($Group in $SharedMailboxes) {
	$i++

	[int]$PercentComplete = $i / $GroupCount * 100
	Write-Progress -Activity "Updating Email Groups (Shared Mailboxes)" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating group '$($Group.DisplayName))')")

	UpdateGroupAsset -Group $Group -GroupType "Shared Mailbox"
}

Write-Progress -Activity "Updating Groups" -Status "Ready" -Completed