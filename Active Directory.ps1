#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$orgID = "<ITG Org ID>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$FlexAssetName = "Active Directory"
$Description = "A network one-page document that shows the current configuration for Active Directory."
$ImageURLs = @{
    'AD Level' = @{
        'default' = "https://www.seatosky.com/wp-content/uploads/2022/09/active-directory.png"
        '2000' = "https://www.seatosky.com/wp-content/uploads/2022/09/windows_2000_server.png"
        '2003' = "https://www.seatosky.com/wp-content/uploads/2022/09/windows-server-2003.png"
        '2008' = "https://www.seatosky.com/wp-content/uploads/2022/09/server-2008.png"
        '2008 R2' = "https://www.seatosky.com/wp-content/uploads/2022/09/windows-server-2008-r2.png"
        '2012' = "https://www.seatosky.com/wp-content/uploads/2022/09/windows-server-2012.png"
        '2012 R2' = "https://www.seatosky.com/wp-content/uploads/2022/09/Windows-2012-R2.png"
        '2016' = "https://www.seatosky.com/wp-content/uploads/2022/09/windows-server-2016.png"
    }
    'DNS Server' = "https://www.seatosky.com/wp-content/uploads/2022/09/dns.png"
    'DHCP Server' = "https://www.seatosky.com/wp-content/uploads/2022/09/dhcp.png"
    'Password Complexity Requirements' = "https://www.seatosky.com/wp-content/uploads/2022/09/password.png"
    'Dell Server' = "https://www.seatosky.com/wp-content/uploads/2022/08/Dell-logo2.png"
	'Site Details' = "https://www.seatosky.com/wp-content/uploads/2022/08/DetailsIcon.png"
}
$SquareImages = @('DNS Server', 'Password Complexity Requirements', 'Site Details')
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
} Else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
  
#Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy

Function IIf($If, $Then, $Else) {
    If ($If -IsNot "Boolean") {$_ = $If}
    If ($If) {If ($Then -is "ScriptBlock") {&$Then} Else {$Then}}
    Else {If ($Else -is "ScriptBlock") {&$Else} Else {$Else}}
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
$TableStyling = "<th>", "<th class='bg-info'>"
  
$RawAD = Get-WinADForestInformation
$ServerDetails = (Get-CimInstance -Class Win32_ComputerSystem);
  
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
  
$passwordpolicyraw = Get-ADDefaultDomainPasswordPolicy | Select-Object ComplexityEnabled, MinPasswordLength, PasswordHistoryCount, LockoutDuration, LockoutThreshold, MaxPasswordAge, MinPasswordAge 
$passwordpolicyhtml = $passwordpolicyraw | convertto-html -Fragment -As List | Select-Object -skip 1
$passwordpolicyheader = "<tr><th><b>Policy</b></th><th><b>Setting</b></th></tr>"
$passwordpolicyNice = $TableHeader + ($passwordpolicyheader -replace $TableStyling) + ($passwordpolicyhtml -replace $TableStyling) + $Whitespace

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

# Get all configurations for filtering
$Configurations = Get-ITGlueConfigurations -page_size "1000" -organization_id $OrgID
$i = 1
while ($Configurations.links.next) {
	$i++
	$Configurations_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $i -organization_id $OrgID
	$Configurations.data += $Configurations_Next.data
	$Configurations.links = $Configurations_Next.links
}
$Configurations = $Configurations.data

$DomainControllers = $RawAD.GlobalCatalogs | Foreach-Object { $_ -replace ".$($RawAD.ForestName)$", "" }
$DCAssets = @()
foreach ($DC in $DomainControllers) {
    $DCAssets += $Configurations | Where-Object { $_.attributes.Name -like $DC }
}

$PrimaryDomainControllers = Get-ADDomainController -Discover -Domain $RawAD.ForestName -Service "PrimaryDC"
$PrimaryDCAssets = @()
foreach ($DC in $PrimaryDomainControllers) {
    if ($DC.Name -in $DCAssets.attributes.name) {
        $PrimaryDCAssets +=  $DCAssets | Where-Object { $_.attributes.name -eq $DC.Name } | Select-Object -First 1
    } else {
        $PrimaryDCAssets += $Configurations | Where-Object { $_.attributes.Name -like $DC.Name }
    }
}

$AllDHCPServers = Get-DhcpServerInDC
$DHCPServers = @()
foreach ($Server in $AllDHCPServers) {
    $Lookup = $false
    try {
        $Lookup = [System.Net.Dns]::GetHostbyAddress($Server.IPAddress.IPAddressToString)
    } catch {}
    if ($Lookup) {
        $Hostname = ($Lookup.Hostname -replace $RawAD.ForestName, "").Trim(".")
        $DHCPAsset = $Configurations | Where-Object { $_.attributes.Name -like $Hostname }
        if (!$DHCPAsset) {
            $Hostname = ($Lookup.Hostname.Split("."))[0]
            $DHCPAsset = $Configurations | Where-Object { $_.attributes.Name -like $Hostname -or $_.attributes.'primary-ip' -like $Server.IPAddress.ToString() }
        }
        if ($DHCPAsset) {
            $DHCPServers += $DHCPAsset
        }
    }
}

$AllDNSServers = Resolve-DnsName -Name $RawAD.ForestName
$DNSServers = @()
foreach ($Server in $AllDNSServers) {
    $Lookup = $false
    try {
        $Lookup = [System.Net.Dns]::GetHostbyAddress($Server.IPAddress)
    } catch {}
    if ($Lookup) {
        $Hostname = ($Lookup.Hostname -replace $RawAD.ForestName, "").Trim(".")
        $DNSAsset = $Configurations | Where-Object { $_.attributes.Name -like $Hostname }
        if (!$DNSAsset) {
            $Hostname = ($Lookup.Hostname.Split("."))[0]
            $DNSAsset = $Configurations | Where-Object { $_.attributes.Name -like $Hostname -or $_.attributes.'primary-ip' -like $Server.IPAddress.ToString() }
        }
        if ($DNSAsset) {
            $DNSServers += $DNSAsset
        }
    }
}


# At a Glance Summary
$AtAGlanceHash = [ordered]@{
    'AD Level'          = $true
    'Site Details'       = $true
    'Dell Server'       = if ($ServerDetails.Manufacturer -like '*Dell*') { $true } else { $false }
    'DNS Server'        = if (($DNSServers | Measure-Object).Count -gt 0) { $true } else { $false }
    'DHCP Server'       = if (($DHCPServers | Measure-Object).Count -gt 0) { $true } else { $false }
    'Password Complexity Requirements' = if ($passwordpolicyraw -and $passwordpolicyraw.ComplexityEnabled) { $true } else { $false }
}

$i = 0
$ATaGlanceHTML = foreach ($Hash in $AtAGlanceHash.GetEnumerator()) {
    if ($i -eq 0) {
        "<div class='row'>"
    }
    $AdditionalDetails = ""
    $DomainLevelImage = $false
    if ($Hash.name -eq 'AD Level' -and $Hash.value) {
        $AdditionalDetails = "<strong>$DomainLevel</strong><br>"
        $AdditionalDetails += "<span style=`"text-decoration: underline;`">$($RawAD.ForestName)</span><br>";
        if ($PrimaryDCAssets) {
            foreach ($Asset in $PrimaryDCAssets) {
                $AdditionalDetails += "<a href=`"$($Asset.attributes.'resource-url')`">$($Asset.attributes.name)</a>, ";
            }
            $AdditionalDetails = $AdditionalDetails.Substring(0, $AdditionalDetails.Length-2)
        }
        
        if ($ImageURLs[$hash.name][$DomainLevel]) {
            $DomainLevelImage = $ImageURLs[$hash.name][$DomainLevel]
        } else {
            $DomainLevelImage = $ImageURLs[$hash.name]['default']
        }
    } elseif ($Hash.name -eq 'Site Details' -and $Hash.value) {
        $AdditionalDetails = "Sites count: $($RawAD.ForestInformation.'Sites Count')";
        $AdditionalDetails += "<br />Enabled Users: $EnabledUsers <br>Domain Admins: $AdminUsers";
    } elseif ($Hash.name -eq 'Dell Server') {
        if ($hash.value) {
            $AdditionalDetails = $ServerDetails.Model
        } else {
            $AdditionalDetails = $ServerDetails.Manufacturer + " " + $ServerDetails.Model
        }
    }
    
    New-AtAGlancecard -Enabled $hash.value -PanelContent $hash.name -ImageURL (IIf $DomainLevelImage $DomainLevelImage $ImageURLs[$hash.name]) -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ($Hash.name -in $SquareImages) $true $false) -PanelShadingOverride (IIf ($Hash.name -eq "Site Details") $true $false) -PanelShading (IIf ($Hash.name -eq "Site Details") 'info') -PanelSize 4
    $i++
    if ($i % 3 -eq 0) {
        "</div><div class='row'>"
    }
}

$PhysicalConfig = if ($AtAGlanceHash.'Dell server' -eq $true) {

    $Preferences = omconfig preferences cdvformat delimiter=pipe
    [xml]$ControllerList = (omreport storage controller -fmt xml)
    $DiskLayoutRaw = foreach ($Controller in $ControllerList.oma.controllers.DCStorageObject.GlobalNo.'#text') {
        omreport storage pdisk controller=$Controller -fmt cdv
    }

    "<h4>Disks</h4>"
    ($DiskLayoutRaw |  select-string -SimpleMatch "ID|Status|" -context 0, ($DiskLayoutRaw).Length | convertfrom-csv -Delimiter "|" | Select-Object Name, Status, Capacity, State, "Bus Protocol", "Product ID", "Serial No.", "Part Number", Media | Where-Object { $_.Name -and $_.Name -ne "Name" } | convertto-html -Fragment)
    $DiskNumbers = (0..1000)
    $RAIDLayoutRaw = omreport storage vdisk -fmt cdv

    "<br /><h4>RAID</h4>"
    ($RAIDLayoutRaw |  select-string -SimpleMatch "ID|Status|" -context 0, ($RAIDLayoutRaw).Length | convertfrom-csv -Delimiter "|" | Select-Object '> ID', Name, Status, State, Layout, "Device Name", "Read Policy", "Write Policy", Media | Where-Object { $_.'> ID' -and $_.'> ID' -in $DiskNumbers -and $_.Name -ne "Name"} |  convertto-html -Fragment)

} else {
    "Could not retrieve physical host settings - This server is not a Dell Physical machine"
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
                'at-a-glance'               = ($ATaGlanceHTML | Out-String)
				'ad-full-name'              = $RawAD.ForestName
				'ad-short-name'				= $DomainShortName
                'ad-level'					= $DomainLevel
                'ad-servers'                = @($DCAssets.ID)
                'primary-domain-controller' = @($PrimaryDCAssets.ID)
                'dns-servers'               = @($DNSServers.ID | Sort-Object -Unique)
                'dhcp-servers'              = @($DHCPServers.ID | Sort-Object -Unique)
				'forest-summary'            = $ForestNice
				'site-summary'              = $SiteNice
				'domain-controllers'        = $DCNice
				'fsmo-roles'                = $FSMONice
				'optional-features'         = $OptionalNice
				'upn-suffixes'              = $UPNNice
				'default-password-policies' = $passwordpolicyNice
				'domain-admins'             = $adminsnice
                'physical-host-configuration' = ($PhysicalConfig | Out-String)
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
                'at-a-glance'               = ($ATaGlanceHTML | Out-String)
				'ad-full-name'              = $RawAD.ForestName
				'ad-short-name'				= $DomainShortName
                'ad-level'					= $DomainLevel
                'ad-servers'                = @($DCAssets.ID)
                'primary-domain-controller' = @($PrimaryDCAssets.ID)
                'dns-servers'               = @($DNSServers.ID | Sort-Object -Unique)
                'dhcp-servers'              = @($DHCPServers.ID | Sort-Object -Unique)
				'forest-summary'            = $ForestNice
				'site-summary'              = $SiteNice
				'domain-controllers'        = $DCNice
				'fsmo-roles'                = $FSMONice
				'optional-features'         = $OptionalNice
				'upn-suffixes'              = $UPNNice
				'default-password-policies' = $passwordpolicyNice
				'domain-admins'             = $adminsnice
                'physical-host-configuration' = ($PhysicalConfig | Out-String)
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

# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $orgID) {
    $Headers = @{
        "x-api-key" = $APIKEy
    }
    $Body = @{
        "apiurl" = $APIEndpoint
        "itgOrgID" = $orgID
        "HostDevice" = $env:computername
        "active-directory" = (Get-Date).ToString("yyyy-MM-dd")
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