#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$orgID = "<ITG Org ID>"
$FlexAssetName = "Active Directory"
$Description = "A network one-page document that shows the current configuration for Active Directory."
#####################################################################

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

#Grabbing ITGlue Module and installing.
If (Get-Module -ListAvailable -Name "ITGlueAPI") { 
    Import-module ITGlueAPI 
}
Else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
  
#Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy
  
function Get-WinADForestInformation {
    $Data = @{ }
    $ForestInformation = $(Get-ADForest)
    $Data.Forest = $ForestInformation
    $Data.RootDSE = $(Get-ADRootDSE -Properties *)
    $Data.ForestName = $ForestInformation.Name
    $Data.ForestNameDN = $Data.RootDSE.defaultNamingContext
    $Data.Domains = $ForestInformation.Domains
    $Data.ForestInformation = @{
        'Name'                    = $ForestInformation.Name
        'Root Domain'             = $ForestInformation.RootDomain
        'Forest Functional Level' = $ForestInformation.ForestMode
        'Domains Count'           = ($ForestInformation.Domains).Count
        'Sites Count'             = ($ForestInformation.Sites).Count
        'Domains'                 = ($ForestInformation.Domains) -join ", "
        'Sites'                   = ($ForestInformation.Sites) -join ", "
    }
      
    $Data.UPNSuffixes = Invoke-Command -ScriptBlock {
        $UPNSuffixList  =  [PSCustomObject] @{ 
                "Primary UPN" = $ForestInformation.RootDomain
                "UPN Suffixes"   = $ForestInformation.UPNSuffixes -join ","
            }  
        return $UPNSuffixList
    }
      
    $Data.GlobalCatalogs = $ForestInformation.GlobalCatalogs
    $Data.SPNSuffixes = $ForestInformation.SPNSuffixes
      
    $Data.Sites = Invoke-Command -ScriptBlock {
      $Sites = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites            
        $SiteData = foreach ($Site in $Sites) {          
          [PSCustomObject] @{ 
                "Site Name" = $site.Name
                "Subnets"   = ($site.Subnets) -join ", "
                "Servers" = ($Site.Servers) -join ", "
            }  
        }
        Return $SiteData
    }
      
        
    $Data.FSMO = Invoke-Command -ScriptBlock {
        [PSCustomObject] @{ 
            "Domain" = $ForestInformation.RootDomain
            "Role"   = 'Domain Naming Master'
            "Holder" = $ForestInformation.DomainNamingMaster
        }
 
        [PSCustomObject] @{ 
            "Domain" = $ForestInformation.RootDomain
            "Role"   = 'Schema Master'
            "Holder" = $ForestInformation.SchemaMaster
        }
          
        foreach ($Domain in $ForestInformation.Domains) {
            $DomainFSMO = Get-ADDomain $Domain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
 
            [PSCustomObject] @{ 
                "Domain" = $Domain
                "Role"   = 'PDC Emulator'
                "Holder" = $DomainFSMO.PDCEmulator
            } 
 
             
            [PSCustomObject] @{ 
                "Domain" = $Domain
                "Role"   = 'Infrastructure Master'
                "Holder" = $DomainFSMO.InfrastructureMaster
            } 
 
            [PSCustomObject] @{ 
                "Domain" = $Domain
                "Role"   = 'RID Master'
                "Holder" = $DomainFSMO.RIDMaster
            } 
 
        }
          
        Return $FSMO
    }
      
    $Data.OptionalFeatures = Invoke-Command -ScriptBlock {
        $OptionalFeatures = $(Get-ADOptionalFeature -Filter * )
        $Optional = @{
            'Recycle Bin Enabled'                          = ''
            'Privileged Access Management Feature Enabled' = ''
        }
        ### Fix Optional Features
        foreach ($Feature in $OptionalFeatures) {
            if ($Feature.Name -eq 'Recycle Bin Feature') {
                if ("$($Feature.EnabledScopes)" -eq '') {
                    $Optional.'Recycle Bin Enabled' = $False
                }
                else {
                    $Optional.'Recycle Bin Enabled' = $True
                }
            }
            if ($Feature.Name -eq 'Privileged Access Management Feature') {
                if ("$($Feature.EnabledScopes)" -eq '') {
                    $Optional.'Privileged Access Management Feature Enabled' = $False
                }
                else {
                    $Optional.'Privileged Access Management Feature Enabled' = $True
                }
            }
        }
        return $Optional
        ### Fix optional features
    }
    return $Data
}
  
$TableHeader = "<table class=`"table table-bordered table-hover`" style=`"width:80%`">"
$Whitespace = "<br/>"
$TableStyling = "<th>", "<th style=`"background-color:#4CAF50`">"
  
$RawAD = Get-WinADForestInformation
  
$ForestRawInfo = new-object PSCustomObject -property $RawAD.ForestInformation | convertto-html -Fragment | Select-Object -Skip 1
$ForestNice = $TableHeader + ($ForestRawInfo -replace $TableStyling) + $Whitespace
  
$SiteRawInfo = $RawAD.Sites | Select-Object 'Site Name', Servers, Subnets | ConvertTo-Html -Fragment | Select-Object -Skip 1
$SiteNice = $TableHeader + ($SiteRawInfo -replace $TableStyling) + $Whitespace
  
$OptionalRawFeatures = new-object PSCustomObject -property $RawAD.OptionalFeatures | convertto-html -Fragment | Select-Object -Skip 1
$OptionalNice = $TableHeader + ($OptionalRawFeatures -replace $TableStyling) + $Whitespace
  
$UPNRawFeatures = $RawAD.UPNSuffixes |  convertto-html -Fragment -as list| Select-Object -Skip 1
$UPNNice = $TableHeader + ($UPNRawFeatures -replace $TableStyling) + $Whitespace
  
$DCRawFeatures = $RawAD.GlobalCatalogs | ForEach-Object { Add-Member -InputObject $_ -Type NoteProperty -Name "Domain Controller" -Value $_; $_ } | convertto-html -Fragment | Select-Object -Skip 1
$DCNice = $TableHeader + ($DCRawFeatures -replace $TableStyling) + $Whitespace
  
$FSMORawFeatures = $RawAD.FSMO | convertto-html -Fragment | Select-Object -Skip 1
$FSMONice = $TableHeader + ($FSMORawFeatures -replace $TableStyling) + $Whitespace
  
$ForestFunctionalLevel = $RawAD.RootDSE.forestFunctionality
$DomainFunctionalLevel = $RawAD.RootDSE.domainFunctionality
$domaincontrollerMaxLevel = $RawAD.RootDSE.domainControllerFunctionality
  
$passwordpolicyraw = Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled, PasswordHistoryCount, LockoutDuration, LockoutThreshold, MaxPasswordAge, MinPasswordAge | convertto-html -Fragment -As List | Select-Object -skip 1
$passwordpolicyheader = "<tr><th><b>Policy</b></th><th><b>Setting</b></th></tr>"
$passwordpolicyNice = $TableHeader + ($passwordpolicyheader -replace $TableStyling) + ($passwordpolicyraw -replace $TableStyling) + $Whitespace

$adminaccounts = @()
$adminaccounts += Get-ADGroupMember "Domain Admins" | Select-Object SamAccountName, Name
$adminaccounts += Get-ADGroupMember "Administrators" | Where-Object { $_.SamAccountName -ne "Domain Admins" } | Select-Object SamAccountName, Name
$adminsraw = $adminaccounts | Sort-Object Name -Unique | convertto-html -Fragment | Select-Object -Skip 1
$adminsnice = $TableHeader + ($adminsraw -replace $TableStyling) + $Whitespace
  
$EnabledUsers = (Get-AdUser -filter * | Where-Object { $_.enabled -eq $true }).count
$DisabledUSers = (Get-AdUser -filter * | Where-Object { $_.enabled -eq $false }).count
$AdminUsers = (Get-ADGroupMember -Identity "Domain Admins").count
$Users = @"
There are <b> $EnabledUsers </b> users Enabled<br>
There are <b> $DisabledUSers </b> users Disabled<br>
There are <b> $AdminUsers </b> Domain Administrator users<br>
"@

$DomainShortName = (Get-WmiObject -Query "SELECT DomainName FROM Win32_NTDomain WHERE DomainName LIKE '%' AND DNSForestName = `'$((gwmi win32_computersystem).domain)`'").DomainName
$DomainLevelFull = [regex]::match($RawAD.RootDSE.forestFunctionality, '(\d{4}.*)(Forest)').Groups[1].Value
$DomainLevelSplit = [regex]::match($DomainLevelFull, '(\d{4})(.*)')
$DomainLevel = $DomainLevelSplit.Groups[1].Value
if ($DomainLevelSplit.Groups[2].Value) {
	$DomainLevel += " "
	$DomainLevel += $DomainLevelSplit.Groups[2].Value
}

$DomainControllers = $RawAD.GlobalCatalogs | Foreach-Object { $_ -replace ".$($RawAD.ForestName)$", "" }
$DCAssets = @()
foreach ($DC in $DomainControllers) {
    $DCAssets += (Get-ITGlueConfigurations -page_size "1000" -filter_name $DC -organization_id $OrgID).data
}
  
# Get the flexible assets ID
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
  
# Upload data to IT-Glue. We try to match the Server name to current computer name.
$ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID).data | Where-Object { $_.attributes.traits.'ad-full-name' -eq $RawAD.ForestName }
  
# If the Asset does not exist, create a new asset, if it does exist we'll combine the old and the new
if (!$ExistingFlexAsset) {
	$FlexAssetBody = @{
		type       = 'flexible-assets'
		attributes = @{
			'organization-id' = $orgID
			'flexible-asset-type-id' = $FilterID.id
			traits = @{
				'ad-full-name'              = $RawAD.ForestName
				'ad-short-name'				= $DomainShortName
                'ad-level'					= $DomainLevel
                'ad-servers'                = $DCAssets.ID
				'forest-summary'            = $ForestNice
				'site-summary'              = $SiteNice
				'domain-controllers'        = $DCNice
				'fsmo-roles'                = $FSMONice
				'optional-features'         = $OptionalNice
				'upn-suffixes'              = $UPNNice
				'default-password-policies' = $passwordpolicyNice
				'domain-admins'             = $adminsnice
				'user-count'                = $Users
			}
		}
	}
    Write-Host "Creating new flexible asset"
    New-ITGlueFlexibleAssets -data $FlexAssetBody
}
else {
    Write-Host "Updating Flexible Asset"

	$UpdatedFlexAssetBody = @{
		type       = 'flexible-assets'
		attributes = @{
			traits = @{
				'ad-full-name'              = $RawAD.ForestName
				'ad-short-name'				= $DomainShortName
                'ad-level'					= $DomainLevel
                'ad-servers'                = $DCAssets.ID
				'forest-summary'            = $ForestNice
				'site-summary'              = $SiteNice
				'domain-controllers'        = $DCNice
				'fsmo-roles'                = $FSMONice
				'optional-features'         = $OptionalNice
				'upn-suffixes'              = $UPNNice
				'default-password-policies' = $passwordpolicyNice
				'domain-admins'             = $adminsnice
				'user-count'                = $Users
			}
		}
	}

	foreach ($trait in $ExistingFlexAsset.attributes.traits.PSObject.Properties) {
		$traitName = $trait.Name
		$traitValue = $trait.Value
		# If any existing fields have tagged assets, we need to extract the id's and replace the values with those
		if ($traitValue -is [System.Object] -and $traitValue.PSobject.Properties.Name -contains "type") {
			$traitValue = $traitValue.values.id
		}

		# If the updated body doesn't already have this field filled with new data, add the existing data
		if (!$UpdatedFlexAssetBody.attributes.traits.ContainsKey($traitName) -or !$UpdatedFlexAssetBody.attributes.traits.$traitName) {
			$UpdatedFlexAssetBody.attributes.traits.$traitName = $traitValue
		}
	}

    Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id  -data $UpdatedFlexAssetBody
} 