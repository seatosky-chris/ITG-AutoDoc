###
# File: \Email - Office365.ps1
# Project: AutoDoc
# Created Date: Friday, September 29th 2023, 4:58:10 pm
# Author: Chris Jantzen
# -----
# Last Modified: Tue May 21 2024
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
###

################# IT-Glue Information ######################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$FlexAssetName = "Email"
$LicenseFlexAssetName = "Licensing"
$BackupFlexAssetName = "Backup"
$ADGroupsFlexAssetName = "AD Security Groups"
$CustomOverviewFlexAssetName = "Custom Overview"
$UpdateO365Report = $true # Turns on/off the O365 overview export (the user audit also can create this)
$UserAudit_CustomPath = $false # Optional string, the custom path to the User Audit folder (for if it's not at the same path as this file or up one folder)
$Description = "Auto documentation of all O365 email configuration."

$ManagementLogin_PasswordCategories = @("Cloud Management / Licensing Portal", "Microsoft 365", "Office 365", "Microsoft 365 - Global Admin") # Possible categorires from management login passwords
$ADConnectGroupNames = @("Office365", "Office365Users", "Office365Sync", "Office365 Users", "Office365 Sync", "Office_365", "Office 365", "ADSync", "AD Sync", "AzureAD-Sync", "AzureAD Sync") # Possible names for the AD connect groups (searches ITG for anything matching these names)
$AntiSpamOptions = @("Sophos", "Barracuda") # Checks the MX record to see if this anti spam is setup
################# /IT-Glue Information #####################################

#################### O365 Unattended Login using Certs #####################
$O365LoginUser = "<O365 Login User>"
$O365UnattendedLogin = @{
	AppID = "<O365 Login AppID>"
	TenantID = "<O365 Login TenantID>"
	Organization = "<O365 Login Org>"
	CertificateThumbprint = "<O365 Login Cert Thumprint>"
}
#################### /O365 Unattended Login using Certs ####################

if ($UserAudit_CustomPath -and [System.IO.File]::Exists("$UserAudit_CustomPath\O365Licenses.ps1")) {
	. "$UserAudit_CustomPath\O365Licenses.ps1"
} elseif ([System.IO.File]::Exists("$PSScriptRoot\O365Licenses.ps1")) {
	. "$PSScriptRoot\O365Licenses.ps1"
} elseif ([System.IO.File]::Exists("$PSScriptRoot\..\O365Licenses.ps1")) {
	. "$PSScriptRoot\..\O365Licenses.ps1"
} elseif ([System.IO.File]::Exists("$PSScriptRoot\..\UserAudit\O365Licenses.ps1")) {
	. "$PSScriptRoot\..\UserAudit\O365Licenses.ps1"
} elseif ($UpdateO365Report) {
	Write-Warning "The O365Licenses.ps1 file could not load. Either set this up alongside the user audit, or copy the O365Licenses.ps1 file to the AutoDoc folder."
}

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

$Version = (Get-Module -ListAvailable -Name "ImportExcel").Version
if ($Version.Major -lt 7 -or $Version.Minor -lt 8 -or $Version.Build -lt 4) {
	Remove-Module ImportExcel
	Uninstall-Module ImportExcel
	Install-Module -Name ImportExcel
	Import-Module ImportExcel -Force
}

If (Get-Module -ListAvailable -Name "ImportExcel") {Import-module ImportExcel} Else { install-module ImportExcel -Force; import-module ImportExcel}
  
# Setting IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy

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

$GraphModules = (Get-Module -ListAvailable).Name | Where-Object { $_ -like "Microsoft.Graph*" }
If ("Microsoft.Graph" -in $GraphModules -or ("Microsoft.Graph.Users" -in $GraphModules -and "Microsoft.Graph.Identity.SignIns" -in $GraphModules -and "Microsoft.Graph.Identity.DirectoryManagement" -in $GraphModules)) {
	Import-Module Microsoft.Graph.Users
	Import-Module Microsoft.Graph.Identity.SignIns
	Import-Module Microsoft.Graph.Identity.DirectoryManagement
} else {
	Install-Module -Name Microsoft.Graph.Authentication
	Install-Module -Name Microsoft.Graph.Users
	Install-Module Microsoft.Graph.Identity.SignIns
	Install-Module Microsoft.Graph.Identity.DirectoryManagement
}
if ($O365UnattendedLogin -and $O365UnattendedLogin.AppId) {
	Connect-MgGraph -CertificateThumbprint $O365UnattendedLogin.CertificateThumbprint -ClientID $O365UnattendedLogin.AppID -TenantId $O365UnattendedLogin.TenantId -NoWelcome
} else {
	Connect-MgGraph
}

# Get the flexible asset type ids
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
$LicenseFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $LicenseFlexAssetName).data
$BackupFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $BackupFlexAssetName).data
$ADGroupsFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $ADGroupsFlexAssetName).data
$CustomOverview_FlexAssetID = (Get-ITGlueFlexibleAssetTypes -filter_name $CustomOverviewFlexAssetName).data[0].id

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$OrganizationInfo = Get-ITGlueOrganizations -id $orgID
if (!$OrganizationInfo -or !$OrganizationInfo.data -or !$FilterID -or ($OrganizationInfo.data | Measure-Object).Count -lt 1 -or !$OrganizationInfo.data[0].attributes -or !$OrganizationInfo.data[0].attributes."short-name") {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}

# Get Tenant details and domains (for matching the email asset and/or updating the domains in the asset)
$TenantDetails = Get-AzureADTenantDetail
$Domains = $TenantDetails.VerifiedDomains.Name | Sort-Object -Unique
$DefaultDomain = ($TenantDetails.VerifiedDomains | Where-Object { $_._Default }).Name

# Get users and mailboxes
$AllUsers = Get-AzureADUser -All $true
$AllUserMailboxes = Get-Mailbox -RecipientTypeDetails UserMailbox -ResultSize unlimited

# Get the existing asset if one exists
$ExistingFlexAssets = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $filterID.id -filter_organization_id $OrgID).data | Where-Object { $_.attributes.traits.'type' -eq "Office 365" }

# Do a quick check to see if this O365 has been decommed, if so, exit
$ExistingFlexAsset = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'azure-tenant-id' -eq $O365UnattendedLogin.TenantID }
if (!$ExistingFlexAsset -and $ExistingFlexAssets) {
	$ExistingFlexAsset = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'default-domain' -eq $DefaultDomain }
}

if (($ExistingFlexAsset | Where-Object { $_.attributes.traits.'status' -ne "Decommissioned" } | Measure-Object).Count -eq 0 -and ($ExistingFlexAsset | Where-Object { $_.attributes.traits.'status' -eq "Decommissioned" } | Measure-Object).Count -gt 0) {
	Write-Warning "This O365 tenant shows as being decommissioned. Exiting..."
	exit
}

$ExistingFlexAssets = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'status' -ne "Decommissioned" }

$ExistingFlexAsset = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'azure-tenant-id' -eq $O365UnattendedLogin.TenantID }
if (!$ExistingFlexAsset -and $ExistingFlexAssets) {
	$ExistingFlexAsset = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'default-domain' -eq $DefaultDomain }
}

# If no match was found, try matching based on domains (for older email assets without tenant id or default domain)
if (!$ExistingFlexAsset -and $ExistingFlexAssets) {
	$ExistingFlexAssets_Filtered = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'domain-s'.values.name -in $Domains }

	if (($ExistingFlexAssets_Filtered | Measure-Object).Count -eq 1) {
		$ExistingFlexAsset = $ExistingFlexAssets_Filtered
	} else {
		if (($ExistingFlexAssets_Filtered | Measure-Object).Count -gt 1) {
			$ExistingFlexAssets = $ExistingFlexAssets_Filtered
		}

		$BestMatchCount = 0
		$MatchCount = 0
		foreach ($ExistingFlexAsset_Old in $ExistingFlexAssets) {
			if (!$ExistingFlexAsset_Old.attributes.traits.'domain-s' -or !$ExistingFlexAsset_Old.attributes.traits.'domain-s'.values) {
				continue
			}
			foreach ($Domain in $Domains) {
				$MatchingDomains = $ExistingFlexAsset_Old.attributes.traits.'domain-s'.values.name | Where-Object { $_ -like $Domain }
				$SimilarDomains = $ExistingFlexAsset_Old.attributes.traits.'domain-s'.values.name | Where-Object { $_ -like "*$Domain" -and $_ -notin $MatchingDomains }
				$MatchCount += ($MatchingDomains | Measure-Object).Count
				$MatchCount += (($SimilarDomains | Measure-Object).Count / 2)
			}

			if ($MatchCount -gt 0 -and $MatchCount -gt $BestMatchCount) {
				$BestMatchCount = $MatchCount
				$ExistingFlexAsset = $ExistingFlexAsset_Old
			} elseif ($MatchCount -gt 0 -and $MatchCount -eq $BestMatchCount -and ($ExistingFlexAsset_Old.attributes.traits.'default-domain' -like $DefaultDomain -or ($ExistingFlexAsset_Old | Where-Object { $_.attributes.traits.'domain-s'.values.name -like $DefaultDomain }))) {
				$BestMatchCount = $MatchCount
				$ExistingFlexAsset = $ExistingFlexAsset_Old
			}
			$MatchCount = 0
		}
	}
}

# Narrow down matches if more than 1 existing was found
if (($ExistingFlexAsset | Measure-Object).Count -gt 1) {
	$ExistingFlexAssets_Filtered = $ExistingFlexAsset | Where-Object { $FlexAsset = $_; $FlexAsset.attributes.traits.'default-domain' -like $DefaultDomain -or (($FlexAsset | Where-Object { $_.attributes.traits.'domain-s'.values.name -like $DefaultDomain }) | Measure-Object).Count -gt 0}
	if (($ExistingFlexAssets_Filtered | Measure-Object).Count -gt 0) {
		$ExistingFlexAsset = $ExistingFlexAssets_Filtered
	}
}
if (($ExistingFlexAsset | Measure-Object).Count -gt 1) {
	$ExistingFlexAsset = $ExistingFlexAssets | Sort-Object -Property {$_.attributes.'updated-at'} -Descending | Select-Object -First 1
}

# Get all passwords for filtering
$ITGPasswords = Get-ITGluePasswords -page_size 1000 -organization_id $orgID
$i = 1
while ($ITGPasswords.links.next) {
	$i++
	$Passwords_Next = Get-ITGluePasswords -page_size 1000 -page_number $i -organization_id $orgID
	$ITGPasswords.data += $Passwords_Next.data
	$ITGPasswords.links = $Passwords_Next.links
}
if ($ITGPasswords -and $ITGPasswords.data) {
	$ITGPasswords = $ITGPasswords.data
}

# Try to find the management login password
$ManagementLogin = @()
if (!$ExistingFlexAsset -or !$ExistingFlexAsset.attributes.traits.'management-login') {
	$Possible_ManagementPasswords = $ITGPasswords | Where-Object { $_.attributes.name -like "*Global Admin*" -and ($_.attributes.name -like "*O365*" -or $_.attributes.name -like "*M365*" -or $_.attributes.name -like "*Office 365*" -or $_.attributes.name -like "*AAD *" -or $_.attributes.name -like "*Azure*") }

	if (!$Possible_ManagementPasswords) {
		$Possible_ManagementPasswords = $ITGPasswords | Where-Object { $_.attributes.name -like "*Global Admin*" -and ($_.attributes.'password-category-name' -in $ManagementLogin_PasswordCategories -or $_.attributes.username -like "*.onmicrosoft.com") }
	}
	if (!$Possible_ManagementPasswords) {
		$Possible_ManagementPasswords = $ITGPasswords | Where-Object { $_.attributes.name -like "*Admin*" -and ($_.attributes.'password-category-name' -in $ManagementLogin_PasswordCategories -or $_.attributes.username -like "*.onmicrosoft.com") }
	}
	if (!$Possible_ManagementPasswords) {
		$Possible_ManagementPasswords = $ITGPasswords | Where-Object { $_.attributes.name -like "*Global Admin*" -and !$_.attributes.'password-category-id' }
	}

	if (($Possible_ManagementPasswords | Measure-Object).Count -gt 4) {
		$Possible_ManagementPasswords_Filtered = $Possible_ManagementPasswords | Where-Object { $_.attributes.'password-category-name' -in $ManagementLogin_PasswordCategories }
		if (($Possible_ManagementPasswords_Filtered | Measure-Object).Count -gt 0) {
			$Possible_ManagementPasswords = $Possible_ManagementPasswords_Filtered
		}
	}
	if (($Possible_ManagementPasswords | Measure-Object).Count -gt 1) {
		$Possible_ManagementPasswords = $Possible_ManagementPasswords | Where-Object { $_.attributes.name -notlike "*Old*" }
	}

	if (($Possible_ManagementPasswords | Measure-Object).Count -gt 0) {
		$ManagementLogin = @($Possible_ManagementPasswords.id)
	}
} else {
	$ManagementLogin = @($ExistingFlexAsset.attributes.traits.'management-login'.values.id)
}

# Get AD sync info
$AzureADConnect = if ($TenantDetails.DirSyncEnabled) { "Yes" } else { "No" }
if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-ad-connect' -and $ExistingFlexAsset.attributes.traits.'azure-ad-connect' -like "Yes*") {
	$AzureADConnect = $ExistingFlexAsset.attributes.traits.'azure-ad-connect'
}

$AzureADConnectADGroups = @()
if (!$ExistingFlexAsset) {
	$ExistingADGroups = @()
	$i = 1
	while ($i -le 10 -and ($ExistingADGroups | Measure-Object).Count -eq (($i-1) * 200)) {
		$ExistingADGroups += (Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $ADGroupsFilterID.id -filter_organization_id $orgID).data
		$i++
	}

	if ($ExistingADGroups) {
		$RelatedGroups = $ExistingADGroups | Where-Object { $_.attributes.traits.'group-name' -in $ADConnectGroupNames }
		if ($RelatedGroups) {
			$AzureADConnectADGroups = @($RelatedGroups.id)
		}
	}
} elseif ($ExistingFlexAsset.attributes.traits.'azure-ad-connect-scope-ad-groups') {
	$AzureADConnectADGroups = @($ExistingFlexAsset.attributes.traits.'azure-ad-connect-scope-ad-groups'.values.id)
}

$AzureADConnect_Accounts = @()
$AzureADConnect_Server = @()
if ($AzureADConnect -like "Yes*") {
	if (Get-Command ActiveDirectory\Get-ADUser -erroraction silentlycontinue) {
		$AzureADConnect_Accounts = Get-ADUser -LDAPFilter "(description=*configured to synchronize to tenant*)" -Properties Description
	}	
	if (!$AzureADConnect_Accounts) {
		$AzureADConnect_Accounts = Get-AzureADDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Synchronization Accounts" } | Get-AzureADDirectoryRoleMember
	}
	if ($AzureADConnect_Accounts) {
		if ($AzureADConnect_Accounts.Description) {
			$AzureADConnect_Server += $AzureADConnect_Accounts | Foreach-Object { $_.description.SubString(142, $_.description.IndexOf(" ", 142) - 142)}
		} elseif ($AzureADConnect_Accounts.UserPrincipalName -contains "_") {
			$AzureADConnect_Server += $AzureADConnect_Accounts | ForEach-Object { $_.UserPrincipalName.split("_")[1] }
		}

		if (($AzureADConnect_Server | Measure-Object).Count -gt 1) {
			$AzureADConnect_Server = $AzureADConnect_Server | Sort-Object -Unique
		}
	}
}

$ITG_AzureADConnect_Accounts = @()
$PossibleUsernames = @()
foreach ($AzureADConnect_Account in @($AzureADConnect_Accounts)) {
	if ($AzureADConnect_Account.SamAccountName) {
		$ITG_AzureADConnect_Accounts += $ITGPasswords | Where-Object { $_.attributes.name -like "*$($AzureADConnect_Account.Name)*" -or $_.attributes.name -like "*$($AzureADConnect_Account.SamAccountName)*" -or $_.attributes.username -like "*$($AzureADConnect_Account.Name)*" -or $_.attributes.username -like "*$($AzureADConnect_Account.SamAccountName)*" }
		if ($AzureADConnect_Account.Name -match "MSOL_([\w|\d]+)" -and $Matches[1]) {
			$AccountIdentifier = $Matches[1]
			$ITG_AzureADConnect_Accounts += $ITGPasswords | Where-Object { $_.attributes.username -like "*Sync_*_$($AccountIdentifier)@*" -or $_.attributes.username -like "*AAD_*_$($AccountIdentifier)@*" }
		}
		
		$PossibleUsernames += $AzureADConnect_Account.Name
		$PossibleUsernames += $AzureADConnect_Account.SamAccountName
		$PossibleUsernames += "Sync_*_$($AccountIdentifier)@*"
		$PossibleUsernames += "AAD_*_$($AccountIdentifier)@*"
	} elseif ($AzureADConnect_Account.UserPrincipalName) {
		$ITG_AzureADConnect_Accounts += $ITGPasswords | Where-Object { $_.attributes.name -like "*$($AzureADConnect_Account.UserPrincipalName)*" -or $_.attributes.name -like "*$($AzureADConnect_Account.UserPrincipalName.split("@")[0])*" -or $_.attributes.username -like "*$($AzureADConnect_Account.UserPrincipalName)*" -or $_.attributes.username -like "*$($AzureADConnect_Account.UserPrincipalName.split("@")[0])*" }
		if ($AzureADConnect_Account.UserPrincipalName -match "(Sync|AAD)_[\w\s-]+_([\w|\d]+)@.+" -and $Matches[2]) {
			$AccountIdentifier = $Matches[2]
			$ITG_AzureADConnect_Accounts += $ITGPasswords | Where-Object { $_.attributes.username -like "*MSOL_$($AccountIdentifier)*" }
		}
		$PossibleUsernames += $AzureADConnect_Account.UserPrincipalName
		$PossibleUsernames += $AzureADConnect_Account.UserPrincipalName.split("@")[0]
		$PossibleUsernames += "MSOL_$($AccountIdentifier)"
	}
}

if (($ITG_AzureADConnect_Accounts | Measure-Object).Count -gt 2) {
	$PossibleUsernames = $PossibleUsernames | Sort-Object -Unique
	$ITG_AzureADConnect_Accounts_Filtered = $ITG_AzureADConnect_Accounts | Where-Object { $Account = $_; $Account.attributes.username -and ($PossibleUsernames | Foreach-Object { if ($Account.attributes.username.Trim() -like $_) { return $true; } }) }

	if (($ITG_AzureADConnect_Accounts_Filtered | Measure-Object).Count -gt 0) {
		$ITG_AzureADConnect_Accounts = $ITG_AzureADConnect_Accounts_Filtered
	}
}
$ITG_AzureADConnect_Accounts = $ITG_AzureADConnect_Accounts | Sort-Object -Property id -Unique


if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-ad-connect-directory-sync-account' -and $ITG_AzureADConnect_Accounts) {
	$Connected = $ExistingFlexAsset.attributes.traits.'azure-ad-connect-directory-sync-account'.values.id | Where-Object { $_ -in $ITG_AzureADConnect_Accounts.id }
	if (!$Connected) {
		$ExistingFlexAsset.attributes.traits.'azure-ad-connect-directory-sync-account'.values.id | Foreach-Object { 
			if ($_ -notin $ITG_AzureADConnect_Accounts.id) {
				$ITG_AzureADConnect_Accounts += [PSCustomObject]@{
					id = $_
				}
			}
		}
	}
}

if (!$ITG_AzureADConnect_Accounts -and $ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-ad-connect-directory-sync-account') {
	$ITG_AzureADConnect_Accounts = @($ExistingFlexAsset.attributes.traits.'azure-ad-connect-directory-sync-account'.values)
}

if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-ad-connect-server' -and $AzureADConnect_Server) {
	$Connected = $ExistingFlexAsset.attributes.traits.'azure-ad-connect-server'.values.name | Where-Object { $_ -in $AzureADConnect_Server }
	if (!$Connected) {
		$ExistingFlexAsset.attributes.traits.'azure-ad-connect-server'.values.name | Foreach-Object { 
			if ($_ -notin $AzureADConnect_Server) {
				$AzureADConnect_Server += $_
			}
		}
	}
}

$ITG_AzureADConnect_Server = @()
if ($AzureADConnect_Server) {
	foreach ($Server in $AzureADConnect_Server) {
		$ExistingServerInfo = $false 
		if ($ExistingFlexAsset) {
			$ExistingServerInfo = $ExistingFlexAsset.attributes.traits.'azure-ad-connect-server'.values | Where-Object { $_.name -like $Server }
		}

		if ($ExistingServerInfo) {
			$ITG_AzureADConnect_Server += $ExistingServerInfo
		} else {
			$ITG_AzureADConnect_Server += (Get-ITGlueConfigurations -page_size "1000" -filter_name $Server -organization_id $orgID).data
		}
	}
} elseif ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-ad-connect-server') {
	$ITG_AzureADConnect_Server = @($ExistingFlexAsset.attributes.traits.'azure-ad-connect-server'.values.id)
}

# Get ITG domains
$ITGDomains = (Get-ITGlueDomains -page_size 1000 -organization_id $orgId).data
$ITG_O365Domains = $ITGDomains | Where-Object { $_.attributes.name -in $Domains }

# Get connectors to look for custom inbound/outbound setups
$MXRecords = $Domains | Where-Object { $_ -notlike "*.onmicrosoft.com" } | Resolve-DnsName -Type MX -ErrorAction Ignore | Where-Object { $_.QueryType -eq "MX" } | Select-Object NameExchange -ExpandProperty NameExchange | Sort-Object -Unique
$InboundConnectors = Get-InboundConnector

$OutboundSmtpHost = $MXRecords -join ", "
if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'outbound-smtp-host' -and $ExistingFlexAsset.attributes.traits.'outbound-smtp-host' -notlike "*, *" -and $OutboundSmtpHost -like "*$($ExistingFlexAsset.attributes.traits.'outbound-smtp-host'.Trim())*") {
	$OutboundSmtpHost = $ExistingFlexAsset.attributes.traits.'outbound-smtp-host'.Trim()
}
if ($OutboundSmtpHost.length -gt 254) {
	$MXRecords_Filtered = @()
	foreach ($MXRecord in $MXRecords) {
		$DomainMatches = $Domains | Where-Object { $CleanedDomain = $_ -replace "\.\w\w\w?", ""; $MXRecord -like "*$($CleanedDomain)*" }
		$AntiSpamMatches = $AntiSpamOptions | Where-Object { $MXRecord -like "*$($_)*" }
		if (($DomainMatches | Measure-Object).Count -gt 0 -or ($AntiSpamMatches | Measure-Object).Count -gt 0)	{
			$MXRecords_Filtered += $MXRecord
		}
	}
	$OutboundSmtpHost = $MXRecords_Filtered -join ", "
}
if ($OutboundSmtpHost.length -gt 254 -and $DefaultDomain -notlike "*.onmicrosoft.com") {
	$MXRecords_Filtered = $DefaultDomain | Resolve-DnsName -Type MX -ErrorAction Ignore | Where-Object { $_.QueryType -eq "MX" } | Select-Object NameExchange -ExpandProperty NameExchange | Sort-Object -Unique
	$OutboundSmtpHost = $MXRecords_Filtered -join ", "
}
$OutboundSmtpHost = $OutboundSmtpHost.substring(0, [System.Math]::Min(254, $OutboundSmtpHost.Length))

if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'inbound-delivery') {
	$InboundDelivery = $ExistingFlexAsset.attributes.traits.'inbound-delivery'
} else {
	$InboundDelivery = "Office 365"
	if ($InboundConnectors) {
		$InboundConnectors_Sophos = $InboundConnectors | Where-Object { 
			$_.Name -like "Sophos Email Inbound Connector" -or $_.Name -like "Sophos Email*" -or 
			$_.Name -like "Sophos Inbound*" -or $_.Name -like "Sophos Connector*" -or $_.Name -like "Sophos Relay*"
		}
		if (($InboundConnectors_Sophos | Measure-Object).Count -gt 0) {
			$InboundDelivery = "Sophos"
		}
	}
}

# Find spam filter
$AntiSpam = "Microsoft Office 365 (Standard)"
foreach ($Option in $AntiSpamOptions) {
	if ($MXRecords -like "*$Option*") {
		$AntiSpam = $Option;
		break;
	}
}

if ($AntiSpam -like "Microsoft Office 365*") {
	# Determine if Microsoft AntiSpam is using ATP
	try {
		$AttachmentPolicies = Get-SafeAttachmentPolicy
		if ($AttachmentPolicies) {
			$AttachmentPolicies = $AttachmentPolicies | Where-Object { $_.Enable -eq $true }
		}
	} catch {
		$AttachmentPolicies = $false
	}
	try {
		$ATPBuiltInPolicy = Get-ATPBuiltInProtectionRule
		if ($ATPBuiltInPolicy) {
			$ATPBuiltInPolicy = $ATPBuiltInPolicy | Where-Object { $_.State -eq "Enabled" }
		}
	} catch {
		$ATPBuiltInPolicy = $false
	}
	try {
		$ATPProtectionPolicies = Get-ATPProtectionPolicyRule
		if ($ATPProtectionPolicies) {
			$ATPProtectionPolicies = $ATPProtectionPolicies | Where-Object { $_.State -eq "Enabled" }
		}
	} catch {
		$ATPProtectionPolicies = $false
	}

	if (($AttachmentPolicies -and ($AttachmentPolicies | Measure-Object).Count -gt 0) -or ($ATPBuiltInPolicy -and ($ATPBuiltInPolicy | Measure-Object).Count -gt 0) -or ($ATPProtectionPolicies -and ($ATPProtectionPolicies | Measure-Object).Count -gt 0)) {
		$AntiSpam = "Microsoft Office 365 w Advanced Threat Protection"
	}
}

if ($AntiSpam -like "Microsoft Office 365 (Standard)" -and $ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'anti-spam-technology' -and $ExistingFlexAsset.attributes.traits.'anti-spam-technology' -notlike "None") {
	$AntiSpam = $ExistingFlexAsset.attributes.traits.'anti-spam-technology'
}

# Determine default email format
$FormatCounts = @{
	"john.doe" 	= 0
	"john_doe" 	= 0
	"john"		= 0
	"doe"		= 0
	"jdoe"		= 0
	"doej" 		= 0
	"johnd" 	= 0
	"jd" 		= 0
}

$FormatRanks = @{
	"john.doe" 	= 10
	"john_doe" 	= 10
	"john"		= 3
	"doe"		= 3
	"jdoe"		= 8
	"doej" 		= 8
	"johnd" 	= 5
	"jd" 		= 3
}

foreach ($User in $AllUsers) {
	if (!$User.GivenName -or !$User.Surname -or !$User.Mail -or $User.UserPrincipalName -notin $AllUserMailboxes.UserPrincipalName) {
		continue
	}

	$FirstName = $User.GivenName
	$LastName = $User.Surname
	$FirstInitial = $FirstName.SubString(0,1)
	$LastInitial = $LastName.SubString(0,1)

	if ($User.Mail -like "$($FirstInitial)$($LastInitial)@*") {
		$FormatCounts."jd"++
	} elseif ($User.Mail -like "*$FirstName*" -or $User.Mail -like "*$LastName*") {
		if ($User.Mail -like "$FirstName.$LastName@*") {
			$FormatCounts."john.doe"++
		} elseif ($User.Mail -like "$($FirstName)_$($LastName)@*") {
			$FormatCounts."john_doe"++
		} elseif ($User.Mail -like "$FirstName@*") {
			$FormatCounts."john"++
		} elseif ($User.Mail -like "$LastName@*") {
			$FormatCounts."doe"++
		} elseif ($User.Mail -like "$($FirstInitial)$($LastName)@*") {
			$FormatCounts."jdoe"++
		} elseif ($User.Mail -like "$($LastName)$($FirstInitial)@*") {
			$FormatCounts."doej"++
		} elseif ($User.Mail -like "$($FirstName)$($LastInitial)@*") {
			$FormatCounts."johnd"++
		}
	}
}

$EmailFormat = $FormatCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1 -Property Name -ExpandProperty Name

if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'email-address-format' -and $ExistingFlexAsset.attributes.traits.'email-address-format' -notlike "Other" -and $ExistingFlexAsset.attributes.traits.'email-address-format' -notlike "$EmailFormat@*") {
	$ExistingEmailFormat = (($ExistingFlexAsset.attributes.traits.'email-address-format'.Split('@'))[0]).Trim()
	$NewRank = $FormatRanks["$EmailFormat"]
	$ExistingRank = $FormatRanks["$ExistingEmailFormat"]
	if ($ExistingRank -ge $NewRank) {
		$EmailFormat = $ExistingEmailFormat
	}
}

$EmailFormat = "$EmailFormat@domain.com"

# Determine if auto-signatures are setup
$Signature = "Outlook - User Managed"

if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'signature' -and $ExistingFlexAsset.attributes.traits.'signature' -like "Exclaimer Software") {
	$Signature = "Exclaimer Software"
} else {
	$TransportRules = Get-TransportRule -ResultSize Unlimited -State Enabled
	if ($TransportRules) {
		if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'signature' -and $ExistingFlexAsset.attributes.traits.'signature' -like "Outlook - User Managed") {
			$SignatureRules = $TransportRules | Where-Object { $_.Name -like "*Signature*" -and $_.ApplyHtmlDisclaimerText -and $_.ApplyHtmlDisclaimerLocation -like "Append" }
			if (($SignatureRules | Measure-Object).Count -gt 0) {
				$Signature = "Office 365 Rule"
			}
		} else {
			$SignatureRules = $TransportRules | Where-Object { $_.Name -like "*Signature*" -or ($_.ApplyHtmlDisclaimerText -and $_.ApplyHtmlDisclaimerLocation -like "Append") }
			if (($SignatureRules | Measure-Object).Count -gt 0) {
				$Signature = "Office 365 Rule"
			}
		}
	}
}

# Determine if MFA is enabled
$MFAEnabled = "No"
if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'mfa-enabled' -and $ExistingFlexAsset.attributes.traits.'mfa-enabled' -like "Setup In Progress") {
	$MFAEnabled = "Setup In Progress"
}

$MGUsers = Get-MgUser -Filter 'accountEnabled eq true' -Property Id,DisplayName,UserType,GivenName,Surname,Mail,UserPrincipalName,AssignedLicenses -All
$MFAUsers = 0
$TotalUsers = 0
foreach ($User in $MGUsers) {
	if (!$User.GivenName -or !$User.Surname -or !$User.Mail -or $User.UserType -ne "Member" -or $User.AssignedLicenses.Count -lt 1 -or $User.UserPrincipalName -notin $AllUserMailboxes.UserPrincipalName) {
		continue
	}
	$TotalUsers++
	$MFAData = Get-MgUserAuthenticationMethod -UserId $User.UserPrincipalName -ErrorAction SilentlyContinue

	if ($MFAData) {
		$MFAOptions = $MFAData | Where-Object { $_.AdditionalProperties["@odata.type"] -notlike "*passwordAuthenticationMethod" -and $_.AdditionalProperties["@odata.type"] -notlike "*temporaryAccessPassAuthenticationMethod" }

		if (($MFAOptions | Measure-Object).Count -gt 0) {
			# MFA is setup
			$MFAUsers++
		}
	}
}
if (($MFAUsers / $TotalUsers -gt 0.95)) {
	$MFAEnabled = "Yes - All Users"
} elseif (($MFAUsers / $TotalUsers) -gt 0.75) {
	$MFAEnabled = "Yes - Some Users"
} elseif ($MFAEnabled -notlike "Setup In Progress" -and $MFAUsers -gt 0) {
	$MFAEnabled = "Yes - Some Users"
}

# Get conditional access policies
$GeoFiltering = "No"

if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-conditional-access-geo-filtering' -and $ExistingFlexAsset.attributes.traits.'azure-conditional-access-geo-filtering' -like "Custom Policies") {
	$GeoFiltering = "Custom Policies"
} else {
	$AccessPolicies = Get-MgIdentityConditionalAccessPolicy
	if ($AccessPolicies) {
		$AccessPolicies = $AccessPolicies | Where-Object { $_.State -eq "enabled" }
	}
	if ($AccessPolicies) {
		if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'azure-conditional-access-geo-filtering' -and $ExistingFlexAsset.attributes.traits.'azure-conditional-access-geo-filtering' -like "No") {
			$GeoFilterPolicies = $AccessPolicies | Where-Object { ($_.DisplayName -like "*Country*" -or $_.DisplayName -like "*Countries*" -or $_.DisplayName -like "*Travel*") -and $_.Conditions.Locations -and $_.Conditions.Locations.IncludeLocations -and $_.Conditions.Locations.IncludeLocations.Count -gt 0 -and $_.GrantControls.BuiltInControls -contains "Block" }
			if (($GeoFilterPolicies | Measure-Object).Count -gt 0) {
				$GeoFiltering = "Yes"
			}
		} else {
			$GeoFilterPolicies = $AccessPolicies | Where-Object { ($_.DisplayName -like "*Country*" -or $_.DisplayName -like "*Countries*" -or $_.DisplayName -like "*Travel*") -or ($_.Conditions.Locations -and $_.Conditions.Locations.IncludeLocations -and $_.Conditions.Locations.IncludeLocations.Count -gt 0 -and $_.GrantControls.BuiltInControls -contains "Block") }
			if (($GeoFilterPolicies | Measure-Object).Count -gt 0) {
				$GeoFiltering = "Yes"
			}
		}
	}
}

# See if there is a Datto SaaS backup solution documented for this
$BackupSolution = @()
$ITGBackups = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $BackupFilterID.id -filter_organization_id $OrgID -page_size 1000).data
$SaasBackups = $ITGBackups | Where-Object { $_.attributes.name -like "*Datto*" -or $_.attributes.name -like "*SaaS*" }

if ($SaasBackups -and ($SaasBackups | Measure-Object).Count -gt 0) {
	$O365Backups = $SaasBackups | Where-Object {
		$_.attributes.traits.'backup-solution-name' -like "*O365*" -or $_.attributes.traits.'backup-solution-name' -like "*Office 365*" -or $_.attributes.traits.'backup-solution-name' -like "*Exchange*" -or
		$_.attributes.traits.'backup-description' -like "*O365*" -or $_.attributes.traits.'backup-description' -like "*Office 365*" -or $_.attributes.traits.'backup-description' -like "*Exchange*" -or
		$_.attributes.traits.'protected-services' -like "*O365*" -or $_.attributes.traits.'protected-services' -like "*Office 365*" -or $_.attributes.traits.'protected-services' -like "*Exchange*"
	}

	if ($O365Backups -and ($O365Backups | Measure-Object).Count -gt 0) {
		$BackupSolution = @($O365Backups.id)
	}
}

if ($ExistingFlexAsset -and $ExistingFlexAsset.attributes.traits.'backup-solution-name') {
	$BackupSolution += $ExistingFlexAsset.attributes.traits.'backup-solution-name'.values.id
	$BackupSolution = $BackupSolution | Sort-Object -Unique
}

# Get subscribed licenses and create/update the license asset
$LicenseAsset = $false
$LinkLicenseAsset = $false
if ($LicenseFlexAssetName -and $LicenseFilterID -and $LicenseFilterID.id) {
	$AllLicenses = Get-MgSubscribedSku
	$LicenseTranslationTable = Invoke-RestMethod -Method Get -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv

	$LicensesCleaned = foreach ($License in $AllLicenses) {
		if (($License.prepaidUnits.enabled - $License.prepaidUnits.suspended) -eq 0) {
			continue
		}
		
		$PrettyName = ($LicenseTranslationTable |  Where-Object {$_.GUID -eq $License.skuId } | Sort-Object Product_Display_Name -Unique).Product_Display_Name
		[PSCustomObject]@{
			'License Name'      = if ($PrettyName) { $PrettyName } else { $License.SkuPartNumber }
			'Active Licenses'   = $License.prepaidUnits.enabled - $License.prepaidUnits.suspended
			'Consumed Licenses' = $License.consumedunits
			'Unused Licenses'   = $License.prepaidUnits.enabled - $License.prepaidUnits.suspended - $License.consumedunits
		} 
	}

	$ITGLicenses = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $LicenseFilterID.id -filter_organization_id $OrgID -page_size 1000).data
	$ITGLicenses = $ITGLicenses | Where-Object { $_.attributes.name -like "Office 365 - User Licenses*" }
	if ($ITGLicenses -and ($ITGLicenses | Measure-Object).Count -gt 1) {
		$ITGLicenses = $ITGLicenses | Where-Object { $_.attributes.traits.'additional-notes' -like "*$($O365UnattendedLogin.TenantID)*" }
	}

	if ($ITGLicenses -and ($ITGLicenses | Measure-Object).Count -gt 0) {
		# Update licenses
		if (($ITGLicenses | Measure-Object).Count -gt 1) {
			$ITGLicenses = $ITGLicenses | Sort-Object -Property {$_.attributes.'updated-at'} -Descending | Select-Object -First 1
		}

		Write-Host "Updating Licensing Flexible Asset"

		$UpdatedLicenseFlexAssetBody = @{
			type       = 'flexible-assets'
			attributes = @{
				traits = @{
					'name'						= "Office 365 - User Licenses - $($TenantDetails.DisplayName)"
					'target-type'				= "Software"
					application					= if ($ITGLicenses.attributes.traits.application) { @($ITGLicenses.attributes.traits.application.values.id) } else { @() }

					'licensing-method'			= "User Login"
					'license-product-serial-key' = if ($ITGLicenses.attributes.traits.'license-product-serial-key') { $ITGLicenses.attributes.traits.'license-product-serial-key' } else { $false }
					'other-keys-codes'			= ($LicensesCleaned | Sort-Object -Property 'License Name' | select-object 'License Name', 'Active Licenses', 'Consumed Licenses', 'Unused Licenses' | ConvertTo-Html -Fragment  | Out-String)

					'purchased-by-location'		= if ($ITGLicenses.attributes.traits.'purchased-by-location') { @($ITGLicenses.attributes.traits.'purchased-by-location'.values.id) } else { @() }
					'purchase-date'				= if ($ITGLicenses.attributes.traits.'purchase-date') { $ITGLicenses.attributes.traits.'purchase-date' } else { $false }
					'renewal-date'				= if ($ITGLicenses.attributes.traits.'renewal-date') { $ITGLicenses.attributes.traits.'renewal-date' } else { $false }
					'microsoft-agreement'		= if ($ITGLicenses.attributes.traits.'microsoft-agreement') { @($ITGLicenses.attributes.traits.'microsoft-agreement'.values.id) } else { @() }
					'ticket-number-for-original-purchase' = if ($ITGLicenses.attributes.traits.'ticket-number-for-original-purchase') { $ITGLicenses.attributes.traits.'ticket-number-for-original-purchase' } else { $false }

					'additional-notes'			= if ($ITGLicenses.attributes.traits.'additional-notes' -like "*$($O365UnattendedLogin.TenantID)*") { $ITGLicenses.attributes.traits.'additional-notes' } else {"This license info is auto-updated by the Email AutoDoc. `n<br>Tenant ID: $($O365UnattendedLogin.TenantID)"}

					'assigned-device-s'		= if ($ITGLicenses.attributes.traits.'assigned-device-s') { @($ITGLicenses.attributes.traits.'assigned-device-s'.values.id) } else { @() }
					'assigned-user-s'		= if ($ITGLicenses.attributes.traits.'assigned-user-s') { @($ITGLicenses.attributes.traits.'assigned-user-s'.values.id) } else { @() }
				}
			}
		}
		# Filter out empty values
		($UpdatedLicenseFlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
			$UpdatedLicenseFlexAssetBody.attributes.traits.Remove($_.Name) 
		}

		$LicenseAsset = Set-ITGlueFlexibleAssets -id $ITGLicenses.id  -data $UpdatedLicenseFlexAssetBody

	} else {
		# Create new license asset
		$LicenseFlexAssetBody = @{
			type       = 'flexible-assets'
			attributes = @{
				'organization-id' 			= $orgID
				'flexible-asset-type-id' 	= $LicenseFilterID.id
				traits = @{
					'name'						= "Office 365 - User Licenses - $($TenantDetails.DisplayName)"
					'target-type'				= "Software"

					'licensing-method'			= "User Login"
					'other-keys-codes'			= ($LicensesCleaned | Sort-Object -Property 'License Name' | select-object 'License Name', 'Active Licenses', 'Consumed Licenses', 'Unused Licenses' | ConvertTo-Html -Fragment  | Out-String)

					'additional-notes'			= "This license info is auto-updated by the Email AutoDoc. `n<br>Tenant ID: $($O365UnattendedLogin.TenantID)"
				}
			}
		}
		Write-Host "Creating new Licensing flexible asset"
		$LicenseAsset = New-ITGlueFlexibleAssets -data $LicenseFlexAssetBody
		$LinkLicenseAsset = $true
	}
}

# If the Asset does not exist, create a new asset, if it does exist we'll combine the old and the new
if (!$ExistingFlexAsset) {
	$FlexAssetBody = @{
		type       = 'flexible-assets'
		attributes = @{
			'organization-id' = $orgID
			'flexible-asset-type-id' = $FilterID.id
			traits = @{
				type						= "Office 365"
				'status'					= "Active"
				'hosting-location'			= "Cloud"
				'webmail-url'				= "https://outlook.office365.com"

				'management-url'			= "https://admin.microsoft.com"
				'management-login'			= $ManagementLogin

				'azure-ad-connect'			= $AzureADConnect
				'azure-ad-connect-server'	= if ($ITG_AzureADConnect_Server) { @($ITG_AzureADConnect_Server.id) } else { @() }
				'azure-ad-connect-scope-ad-groups' = $AzureADConnectADGroups
				'azure-ad-connect-directory-sync-account' 	= if ($ITG_AzureADConnect_Accounts) { @($ITG_AzureADConnect_Accounts.id) } else { @() }

				'domain-s'					= if ($ITG_O365Domains) { @($ITG_O365Domains.id) } else { @() }
				'default-domain'			= $DefaultDomain
				'azure-tenant-id'			= $O365UnattendedLogin.TenantID
				'inbound-delivery'			= $InboundDelivery
				'outbound-smtp-host'		= $OutboundSmtpHost
				'email-address-format'		= $EmailFormat
				'signature'					= $Signature

				'mfa-enabled'				= $MFAEnabled
				'azure-conditional-access-geo-filtering'	= $GeoFiltering

				'anti-spam-technology'		= $AntiSpam
				
				'backup-solution'			= $BackupSolution
			}
		}
	}

	# Filter out empty values
	($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$FlexAssetBody.attributes.traits.Remove($_.Name) 
	}

    Write-Host "Creating new Email flexible asset"
    $ExistingFlexAsset = New-ITGlueFlexibleAssets -data $FlexAssetBody
	if ($ExistingFlexAsset -and $ExistingFlexAsset.data) {
		$ExistingFlexAsset = $ExistingFlexAsset.data
	}
}
else {
    Write-Host "Updating Flexible Asset"

	$UpdatedFlexAssetBody = @{
		type       = 'flexible-assets'
		attributes = @{
			traits = @{
                type						= "Office 365"
				'status'					= if ($ExistingFlexAsset.attributes.traits.status -like "Deployment In-Progress") { "Deployment In-Progress" } else { "Active" }
				'hosting-location'			= "Cloud"
				'webmail-url'				= if ($ExistingFlexAsset.attributes.traits.'webmail-url' -like "*outlook.office365.com*") { $ExistingFlexAsset.attributes.traits.'webmail-url' } else { "https://outlook.office365.com" }

				'management-url'			= if ($ExistingFlexAsset.attributes.traits.'management-url' -like "*admin.microsoft.com*") { $ExistingFlexAsset.attributes.traits.'management-url' } else { "https://admin.microsoft.com" }
				'management-login'			= $ManagementLogin
				'distribution-list-manager-approver' = if ($ExistingFlexAsset.attributes.traits.'distribution-list-manager-approver') { @($ExistingFlexAsset.attributes.traits.'distribution-list-manager-approver'.values.id) } else { @() }

				'azure-ad-connect'			= $AzureADConnect
				'azure-ad-connect-server'	= if ($ITG_AzureADConnect_Server) { @($ITG_AzureADConnect_Server.id) } else { @() }
				'azure-ad-connect-scope' 	= if ($ExistingFlexAsset.attributes.traits.'azure-ad-connect-scope') { $ExistingFlexAsset.attributes.traits.'azure-ad-connect-scope' } else { $false }
				'azure-ad-connect-scope-ad-groups' = $AzureADConnectADGroups
				'azure-ad-connect-directory-sync-account' 	= if ($ITG_AzureADConnect_Accounts) { @($ITG_AzureADConnect_Accounts.id) } else { @() }

				'domain-s'					= if ($ITG_O365Domains) { @($ITG_O365Domains.id) } else { @() }
				'default-domain'			= $DefaultDomain
				'email-servers'				= if ($ExistingFlexAsset.attributes.traits.'email-servers') { @($ExistingFlexAsset.attributes.traits.'email-servers'.values.id) } else { @() }
				'azure-tenant-id'			= $O365UnattendedLogin.TenantID
				'inbound-delivery'			= $InboundDelivery
				'inbound-pop-imap-host' 	= if ($ExistingFlexAsset.attributes.traits.'inbound-pop-imap-host') { $ExistingFlexAsset.attributes.traits.'inbound-pop-imap-host' } else { $false }
				'outbound-smtp-host'		= $OutboundSmtpHost
				'email-address-format'		= $EmailFormat
				'signature'					= $Signature

				'mfa-enabled'				= $MFAEnabled
				'azure-conditional-access-geo-filtering'	= $GeoFiltering
				'azure-conditional-access-policy-details' 	= if ($ExistingFlexAsset.attributes.traits.'azure-conditional-access-policy-details') { $ExistingFlexAsset.attributes.traits.'azure-conditional-access-policy-details' | Out-String } else { "" }

				'anti-spam-technology'		= $AntiSpam
				'anti-spam-details' 		= if ($ExistingFlexAsset.attributes.traits.'anti-spam-details') { $ExistingFlexAsset.attributes.traits.'anti-spam-details' } else { $false }
				'anti-spam-management-login' = if ($ExistingFlexAsset.attributes.traits.'anti-spam-management-login') { @($ExistingFlexAsset.attributes.traits.'anti-spam-management-login'.values.id) } else { @() }

				'pst-export-location' 		= if ($ExistingFlexAsset.attributes.traits.'pst-export-location') { $ExistingFlexAsset.attributes.traits.'pst-export-location' } else { $false }
				'export-location-file-store' = if ($ExistingFlexAsset.attributes.traits.'export-location-file-store') { @($ExistingFlexAsset.attributes.traits.'export-location-file-store'.values.id) } else { @() }
				'backup-solution'			= $BackupSolution

				'creating-accounts' 		= if ($ExistingFlexAsset.attributes.traits.'creating-accounts') { @($ExistingFlexAsset.attributes.traits.'creating-accounts'.values.id) } else { @() }
				'disabling-removing-accounts' = if ($ExistingFlexAsset.attributes.traits.'disabling-removing-accounts') { @($ExistingFlexAsset.attributes.traits.'disabling-removing-accounts'.values.id) } else { @() }
				'creating-shared-mailboxes' = if ($ExistingFlexAsset.attributes.traits.'creating-shared-mailboxes') { @($ExistingFlexAsset.attributes.traits.'creating-shared-mailboxes'.values.id) } else { @() }
				'creating-distribution-lists' = if ($ExistingFlexAsset.attributes.traits.'creating-distribution-lists') { @($ExistingFlexAsset.attributes.traits.'creating-distribution-lists'.values.id) } else { @() }
				'computer-email-client-setup' = if ($ExistingFlexAsset.attributes.traits.'computer-email-client-setup') { @($ExistingFlexAsset.attributes.traits.'computer-email-client-setup'.values.id) } else { @() }
				'mobile-phone-setup' 		= if ($ExistingFlexAsset.attributes.traits.'mobile-phone-setup') { @($ExistingFlexAsset.attributes.traits.'mobile-phone-setup'.values.id) } else { @() }
				'spam-filter-management' 	= if ($ExistingFlexAsset.attributes.traits.'spam-filter-management') { @($ExistingFlexAsset.attributes.traits.'spam-filter-management'.values.id) } else { @() }
				'outbound-smtp-setup' 		= if ($ExistingFlexAsset.attributes.traits.'outbound-smtp-setup') { @($ExistingFlexAsset.attributes.traits.'outbound-smtp-setup'.values.id) } else { @() }

				'additional-details'		= if ($ExistingFlexAsset.attributes.traits.'additional-details') { $ExistingFlexAsset.attributes.traits.'additional-details' | Out-String } else { "" }
			}
		}
	}

	# Filter out empty values
	($UpdatedFlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$UpdatedFlexAssetBody.attributes.traits.Remove($_.Name) 
	}

    Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id  -data $UpdatedFlexAssetBody
}

# Tag the licensing asset as a related item
if ($LinkLicenseAsset -and $LicenseAsset -and $LicenseAsset.data.id -and $ExistingFlexAsset -and $ExistingFlexAsset.id) {
	$RelatedItemsBody =
	@{
		type = 'related_items'
		attributes = @{
			'destination_id' = $LicenseAsset.data.id
			'destination_type' = "Flexible Asset"
		}
	}
	New-ITGlueRelatedItems -resource_type 'flexible_assets' -resource_id $ExistingFlexAsset.id -data $RelatedItemsBody
}

# Record an office 365 overview
$UserO365ReportUpdated = $false
if ($UpdateO365Report -and $O365LicenseTypes) {
	Write-Host "Exporting Office 365 license report..."
	if (!$LicenseTranslationTable) {
		$LicenseTranslationTable = Invoke-RestMethod -Method Get -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv
	}

	$LicenseList = @()
	$AllUsers | ForEach-Object {
		$LicenseSkus = $_.AssignedLicenses | Select-Object SkuId
		$Licenses = @()
		$LicenseSkus | ForEach-Object {
			$sku = $_.SkuId
			$PrettyName = ($LicenseTranslationTable |  Where-Object {$_.GUID -eq $sku } | Sort-Object Product_Display_Name -Unique).Product_Display_Name
			$Licenses += $PrettyName
		}

		$UserInfo = [pscustomobject]@{
			Name = $_.DisplayName
			Email = $_.UserPrincipalName
			PrimaryLicense = ""
			AssignedLicenses = $Licenses
		}

		foreach ($PrimaryLicenseType in $O365LicenseTypes_Primary.GetEnumerator()) {
			if ($PrimaryLicenseType.Value -in $Licenses) {
				$UserInfo.PrimaryLicense = $PrimaryLicenseType.Value
				break
			}
		}

		$LicenseList += $UserInfo
	}

	# Create a custom overview document (or update it)
	$LicenseList_FlexAssetBody =
	@{
		type       = 'flexible-assets'
		attributes = @{
			traits = @{
				'name' = "Office 365 License Overview - $($TenantDetails.DisplayName)"
				'overview' = ""
			}
		}
	}

	$LicenseListHTML = ($LicenseList | Where-Object { $_.PrimaryLicense } | Select-Object -Property Name, Email, PrimaryLicense -First 600 | convertto-html -Fragment | Out-String)
	if (($LicenseList | Where-Object { $_.PrimaryLicense } | Measure-Object).Count -gt 600) {
		$LicenseList_FlexAssetBody.attributes.traits.overview = "<p>This list has been truncated due to its size. Please see the attached excel document for the full list.</p>"
	} else {
		$LicenseList_FlexAssetBody.attributes.traits.overview = "<p>This list only includes primary licenses. Please see the attached excel document for the full list.</p>"
	}
	$LicenseList_FlexAssetBody.attributes.traits.overview += $LicenseListHTML

	$ExistingLicenseOverview = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $CustomOverview_FlexAssetID -filter_organization_id $orgID -include attachments
	if (($ExistingLicenseOverview.data | Where-Object { $_.attributes.traits.name -eq "Office 365 License Overview - $($TenantDetails.DisplayName)" } | Measure-Object).Count -gt 0) {
		$ExistingLicenseOverview.data = $ExistingLicenseOverview.data | Where-Object { $_.attributes.traits.name -eq "Office 365 License Overview - $($TenantDetails.DisplayName)" }  | Select-Object -First 1
	} elseif (($ExistingLicenseOverview.data | Where-Object { $_.attributes.traits.name -eq "Office 365 License Overview" } | Measure-Object).Count -gt 0) {
		$ExistingLicenseOverview.data = $ExistingLicenseOverview.data | Where-Object { $_.attributes.traits.name -eq "Office 365 License Overview" }  | Select-Object -First 1
	} else {
		$ExistingLicenseOverview.data = $ExistingLicenseOverview.data | Where-Object { $_.attributes.traits.name -eq "Office 365 License Overview*" }  | Select-Object -First 1
	}
	if ($ExistingLicenseOverview.data -and $ExistingLicenseOverview.data.id) {
		$ExistingLicenseOverview = Get-ITGlueFlexibleAssets -id $ExistingLicenseOverview.data.id -include attachments
	}

	if (!$ExistingLicenseOverview.data) {
		$LicenseList_FlexAssetBody.attributes.add('organization-id', $orgID)
		$LicenseList_FlexAssetBody.attributes.add('flexible-asset-type-id', $CustomOverview_FlexAssetID)
		$ExistingLicenseOverview = New-ITGlueFlexibleAssets -data $LicenseList_FlexAssetBody
		Write-Host "Created a new O365 License Overview."

		# relate to the Email page
		if ($ExistingFlexAsset) {
			$RelatedItems = @{
				type = 'related_items'
				attributes = @{
					destination_id = $ExistingFlexAsset.id
					destination_type = "Flexible Asset"
				}
			}
			New-ITGlueRelatedItems -resource_type flexible_assets -resource_id $ExistingLicenseOverview.data.id -data $RelatedItems | Out-Null
		}

		# and customer billing page too if it exists
		$BillingFilterID = (Get-ITGlueFlexibleAssetTypes -filter_name "Customer Billing").data
		$BillingOverview = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $BillingFilterID.id -filter_organization_id $orgID
		$BillingOverview.data = $BillingOverview.data | Where-Object { $_.attributes.name -eq "Customer Billing" }  | Select-Object -First 1
		if ($BillingOverview) {
			$RelatedItems = @{
				type = 'related_items'
				attributes = @{
					destination_id = $BillingOverview.data.id
					destination_type = "Flexible Asset"
				}
			}
			New-ITGlueRelatedItems -resource_type flexible_assets -resource_id $ExistingLicenseOverview.data.id -data $RelatedItems | Out-Null
		}
	} else {
		Set-ITGlueFlexibleAssets -id $ExistingLicenseOverview.data.id -data $LicenseList_FlexAssetBody | Out-Null
		Write-Host "Updated the O365 License Overview."
	}

	# Create the O365 overview excel document
	$OrganizationInfo = $OrganizationInfo.data
	$OrgShortName = $OrganizationInfo[0].attributes."short-name"
	$MonthName = (Get-Culture).DateTimeFormat.GetMonthName([int](Get-Date -Format MM))
	$Year = Get-Date -Format yyyy
	$FileName = "$($OrgShortName)--O365_License_Overview--$($MonthName)_$Year.xlsx"
	if ($UserAudit_CustomPath -and ([System.IO.File]::Exists("$UserAudit_CustomPath\O365LicenseOverview") -or [System.IO.File]::Exists("$UserAudit_CustomPath\User Audit.ps1"))) {
		New-Item -ItemType Directory -Force -Path ("$UserAudit_CustomPath\O365LicenseOverview") | Out-Null
		$Path = "$UserAudit_CustomPath\O365LicenseOverview\$FileName"
	} elseif ([System.IO.File]::Exists(($PSScriptRoot + "\..\UserAudit\O365LicenseOverview")) -or [System.IO.File]::Exists(($PSScriptRoot + "\..\UserAudit\User Audit.ps1"))) {
		New-Item -ItemType Directory -Force -Path ($PSScriptRoot + "\..\UserAudit\O365LicenseOverview") | Out-Null
		$Path = $PSScriptRoot + "\..\UserAudit\O365LicenseOverview\$FileName"
	} elseif ([System.IO.File]::Exists(($PSScriptRoot + "\..\O365LicenseOverview")) -or [System.IO.File]::Exists(($PSScriptRoot + "\..\User Audit.ps1"))) {
		New-Item -ItemType Directory -Force -Path ($PSScriptRoot + "\..\O365LicenseOverview") | Out-Null
		$Path = $PSScriptRoot + "\..\O365LicenseOverview\$FileName"
	} else {
		New-Item -ItemType Directory -Force -Path ($PSScriptRoot + "\O365LicenseOverview") | Out-Null
		$Path = $PSScriptRoot + "\O365LicenseOverview\$FileName"
	}
	Remove-Item $Path -ErrorAction SilentlyContinue

	$LicenseList | Where-Object { $_.AssignedLicenses } | Select-Object -Property Name, Email, PrimaryLicense, @{Name="AssignedLicenses"; E={$_.AssignedLicenses -join ", "}} | Export-Excel $Path -AutoFilter -AutoSize -AutoNameRange -TableStyle "Medium2"
	$ReportEncoded = [System.Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))

	# Attach the excel doc to the custom overview (delete first if necessary)
	if ($ExistingLicenseOverview -and $ExistingLicenseOverview.data.id -and $ExistingLicenseOverview.included) {
		$Attachments = $ExistingLicenseOverview.included | Where-Object {$_.type -eq 'attachments'}
		if ($Attachments -and ($Attachments | Measure-Object).Count -gt 0 -and $Attachments.attributes) {
			$MonthsAttachment = $Attachments.attributes | Where-Object { $_.name -like $FileName + '*' -or $_."attachment-file-name" -like $FileName + '*' }
			if ($MonthsAttachment) {
				$data = @()
				foreach ($Attachment in @($MonthsAttachment)) {
					$data += @{ 
						'type' = 'attachments'
						'attributes' = @{
							'id' = $Attachment.id
						}
					}
				}
				Remove-ITGlueAttachments -resource_type 'flexible_assets' -resource_id $ExistingLicenseOverview.data.id -data $data | Out-Null
			}
		}
	}

	if ($ExistingLicenseOverview -and $ExistingLicenseOverview.data.id) {
		$data = @{ 
			'type' = 'attachments'
			'attributes' = @{
				'attachment' = @{
					'content' = $ReportEncoded
					'file_name'	= $FileName
				}
			}
		}
		New-ITGlueAttachments -resource_type 'flexible_assets' -resource_id $ExistingLicenseOverview.data.id -data $data | Out-Null
		Write-Host "O365 license overview xls uploaded and attached." -ForegroundColor Green
		$UserO365ReportUpdated = $true
	}
}

# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $orgID) {
    $Headers = @{
        "x-api-key" = $APIKEy
    }
    $Body = @{
        "apiurl" = $APIEndpoint
        "itgOrgID" = $orgID
        "HostDevice" = $env:computername
        "email" = (Get-Date).ToString("yyyy-MM-dd")
    }
	if ($UserO365ReportUpdated) {
		$Body.Add("o365-license-report", (Get-Date).ToString("yyyy-MM-dd"))
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
