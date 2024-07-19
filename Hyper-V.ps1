#Requires -RunAsAdministrator
########################## IT-Glue ############################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$FlexAssetName = "Hyper-V Host"
$Cluster_FlexAssetName = "Virtualization"
$Description = "A network one-page document that displays the current Hyper-V Settings and virtual machines"
# some layout options, change if you want colours to be different or do not like the whitespace.
$TableHeader = "<table class=`"table table-bordered table-hover`" style=`"width:80%`">"
$Whitespace = "<br/>"
$TableStyling = "<th>", "<th class=`"bg-info`">"
$ImageURLs = @{
    'Hyper-V Server' = "https://www.seatosky.com/wp-content/uploads/2022/08/Hyper-V-server.png"
    'Hyper-V Replicas' = "https://www.seatosky.com/wp-content/uploads/2022/08/hyper-v-replication.png"
    'Hyper-V Cluster' = "https://www.seatosky.com/wp-content/uploads/2022/08/Hyper-V-Cluster.png"
    'Dell Server' = "https://www.seatosky.com/wp-content/uploads/2022/08/Dell-logo2.png"
	'Info' = "https://www.seatosky.com/wp-content/uploads/2022/08/DetailsIcon.png"
}
$SquareImages = @('Info')
########################## IT-Glue ############################

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

$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
$Cluster_FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $Cluster_FlexAssetName).data

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$OrganizationInfo = Get-ITGlueOrganizations -id $orgID
if (!$OrganizationInfo -or !$OrganizationInfo.data -or !$FilterID -or !$Cluster_FilterID -or ($OrganizationInfo.data | Measure-Object).Count -lt 1 -or !$OrganizationInfo.data[0].attributes -or !$OrganizationInfo.data[0].attributes."short-name") {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
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
 
write-host "Start documentation process." -foregroundColor green
 
$VMs = get-vm | select-object VMName, State, Generation, Path, Automatic*, @{n = "Minimum(gb)"; e = { $_.memoryminimum / 1gb } }, @{n = "Maximum(gb)"; e = { $_.memorymaximum / 1gb } }, @{n = "Startup(gb)"; e = { $_.memorystartup / 1gb } }, @{n = "Currently Assigned(gb)"; e = { $_.memoryassigned / 1gb } }, ProcessorCount, @{n = "Uptime (@ last checkin)"; e = { $_.Uptime } }, Status 
$VMTotalCount = ($VMs | Measure-Object).Count
$VMRunningCount = ($VMs | Where-Object { $_.State -eq "Running" } | Measure-Object).Count
$VMBadCount = ($VMs | Where-Object { $_.Status -ne "Operating normally" } | Measure-Object).Count
$VirtualMachines = $VMs | ConvertTo-Html -Fragment | Out-String
$VirtualMachines = "Last updated: $(Get-Date) <br />" + $TableHeader + ($VirtualMachines -replace $TableStyling) + $Whitespace
$NetworkSwitches = Get-VMSwitch | select-object name, switchtype, NetAdapterInterfaceDescription, AllowManagementOS | convertto-html -Fragment -PreContent "<h4>Network Switches</h4>" | Out-String
$VMNetworkSettings = Get-VMNetworkAdapter * | Select-Object Name, IsManagementOs, VMName, SwitchName, MacAddress, @{Name = 'IP'; Expression = { $_.IPaddresses -join "," } } | ConvertTo-Html -Fragment -PreContent "<br><h4>VM Network Settings</h4>" | Out-String
$NetworkSettings = $TableHeader + ($NetworkSwitches -replace $TableStyling) + ($VMNetworkSettings -replace $TableStyling) + $Whitespace
$ReplicationSettings = get-vmreplication | Select-Object VMName, State, Mode, FrequencySec, PrimaryServer, ReplicaServer, ReplicaPort, AuthType
if ($ReplicationSettings) { 
	$ReplicationSettings = $ReplicationSettings | convertto-html -Fragment | Out-String
	$ReplicationSettings = $TableHeader + ($ReplicationSettings -replace $TableStyling) + $Whitespace
} else {
	$ReplicationSettings = "Replication not setup on any VM's. <div><br></div>"
}
$HostSettings = get-vmhost | Select-Object  Computername, LogicalProcessorCount, iovSupport, EnableEnhancedSessionMode, MacAddressMinimum, *max*, NumaspanningEnabled, VirtualHardDiskPath, VirtualMachinePath, UseAnyNetworkForMigration, VirtualMachineMigrationEnabled | convertto-html -Fragment -as List | Out-String
$ServerDetails = (Get-CimInstance -Class Win32_ComputerSystem);
$IsCluster = $null -ne (Get-CimInstance -Class MSCluster_ResourceGroup -Namespace root\mscluster -ErrorAction SilentlyContinue);
if ($IsCluster) {
    $ClusterName = Get-Cluster;
    $ClusterDetails = Get-ClusterNode;
}
$HyperVFeatureDetails = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V

$AtAGlanceHash = [ordered]@{
    'Hyper-V Server'   = if (($HyperVFeatureDetails).state -eq 'enabled') { $true } else { $False }
    'Hyper-V Replicas' = if ($ReplicationSettings -notlike "Replication not setup*") { $true } else { $False }
    'Hyper-V Cluster'  = if ($IsCluster) { $true } else { $false }
    'Dell Server'      = if ($ServerDetails.Manufacturer -like '*Dell*') { $true } else { $false }
}

$ATaGlanceHTML = foreach ($Hash in $AtAGlanceHash.GetEnumerator()) {
    $AdditionalDetails = ""
    if ($Hash.name -eq 'Hyper-V Server' -and $Hash.value) {
        $AdditionalDetails = "VMs Total: $VMTotalCount, Running: $VMRunningCount";
        if ($VMBadCount -gt 0) {
            $AdditionalDetails += "<br /><strong><span style=`"color: red;`">BAD Status VMs: <span style=`"text-decoration: underline;`">$VMBadCount</span></span></strong>";
        }
    } elseif ($Hash.name -eq "Hyper-V Cluster" -and $Hash.value) {
        if ($ClusterName) {
            $AdditionalDetails = "<span style=`"text-decoration: underline;`">$($ClusterName.Name)</span><br />";
        }
        foreach ($Node in $ClusterDetails) {
            if ($Node.Name -like $ENV:computername) {
                $AdditionalDetails += "<strong>$($Node.Name)</strong>, ";
            } elseif ($Node.State -eq "Down") {
                $AdditionalDetails += "<span style=`"color: red;`">$($Node.Name) (Down)</span>, ";
            } else {
                $AdditionalDetails += $Node.Name + ", "
            }
        }
        $AdditionalDetails = $AdditionalDetails.TrimEnd(", ");
    } elseif ($Hash.name -eq 'Dell Server') {
        if ($hash.value) {
            $AdditionalDetails = $ServerDetails.Model
        } else {
            $AdditionalDetails = $ServerDetails.Manufacturer + " " + $ServerDetails.Model
        }
    }
    
    New-AtAGlancecard -Enabled $hash.value -PanelContent $hash.name -ImageURL $ImageURLs[$hash.name] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ($Hash.name -in $SquareImages) $true $false)  
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

# Find the associated configuration to tag
$DeviceAsset = $Configurations | Where-Object { $_.attributes.name -like $ENV:COMPUTERNAME }
 
$FlexAssetBody =
@{
    type       = 'flexible-assets'
    attributes = @{
        traits = @{
			'host-name'            	= $env:COMPUTERNAME
            'at-a-glance'           = ($ATaGlanceHTML | out-string)
			'host-device'			= $DeviceAsset.ID
            'virtual-machines'     	= $VirtualMachines
            'network-settings'     	= $NetworkSettings
            'replication-settings' 	= $ReplicationSettings
            'host-settings'        	= $HostSettings
            'physical-host-configuration' = ($PhysicalConfig | Out-String)
        }
    }
}
 
write-host "Documenting to IT-Glue"  -ForegroundColor Green
$ExistingFlexAssets = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($filterID.ID) -filter_organization_id $OrgID
if (!$ExistingFlexAssets -or $ExistingFlexAssets.Error) {
    Write-Error "An error occurred trying to get the existing flex assets from ITG. Exiting..."
    Write-Error $ExistingFlexAssets.Error
	exit 1
}
$ExistingFlexAsset = ($ExistingFlexAssets).data | Where-Object { $_.attributes.traits.'host-name' -eq $ENV:computername }

#If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just upload.
if (!$ExistingFlexAsset) {
    $FlexAssetBody.attributes.add('organization-id', $OrgID)
    $FlexAssetBody.attributes.add('flexible-asset-type-id', $($filterID.ID))
    write-host "  Creating Hyper-v into IT-Glue organisation $OrgID" -ForegroundColor Green
    New-ITGlueFlexibleAssets -data $FlexAssetBody
} else {
    write-host "  Editing Hyper-v into IT-Glue organisation $OrgID"  -ForegroundColor Green
    $ExistingFlexAsset = $ExistingFlexAsset[-1]
    Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
}

# Update / Create the "Scripts - Last Run" ITG page which shows when this AutoDoc (and other scripts) last ran
if ($LastUpdatedUpdater_APIURL -and $OrgID) {
    $Headers = @{
        "x-api-key" = $APIKEy
    }
    $Body = @{
        "apiurl" = $APIEndpoint
        "itgOrgID" = $orgID
        "HostDevice" = $env:computername
        "hyper-v" = (Get-Date).ToString("yyyy-MM-dd")
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


############
# Lets also update the primary virtualizations page if one exists that is related to this Host or Cluster
############
$ExistingClusterFlexAsset = Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($Cluster_FilterID.ID) -filter_organization_id $OrgID
if (!$ExistingClusterFlexAsset -or $ExistingClusterFlexAsset.Error) {
    Write-Error "An error occurred trying to get the existing virtualization flex asset from ITG. Exiting..."
    Write-Error $ExistingClusterFlexAsset.Error
	exit 1
}

if ($ClusterName) {
    $ExistingClusterFlexAsset = $ExistingClusterFlexAsset.data | Where-Object { $_.attributes.traits.'virtualization-friendly-name' -like "*$($ClusterName.Name)*" -or $_.attributes.traits.'virtualization-friendly-name' -like "*$($ENV:computername)*" }
} else {
    $ExistingClusterFlexAsset = $ExistingClusterFlexAsset.data | Where-Object { $_.attributes.traits.'virtualization-friendly-name' -like "*$($ENV:computername)*" }
}

foreach ($ExistingAsset in $ExistingClusterFlexAsset) {

    $VirtFlexAssetBody =
    @{
        type       = 'flexible-assets'
        attributes = @{
            traits = @{
                'virtualization-friendly-name'  = $ExistingAsset.attributes.traits.'virtualization-friendly-name'
                'office-location'               = @($ExistingAsset.attributes.traits.'office-location'.values.id)
				'at-a-glance'					= ""
                'virtualization-technology'     = "Hyper-V"
                'virtualization-hosts'			= @($ExistingAsset.attributes.traits.'virtualization-hosts'.values.id)
                'hyper-v-host-details'			= @($ExistingAsset.attributes.traits.'hyper-v-host-details'.values.id)
                'virtual-machine-configurations' = @($ExistingAsset.attributes.traits.'virtual-machine-configurations'.values.id)
                'management-login'				= @($ExistingAsset.attributes.traits.'management-login'.values.id)
                'notes'                         = ($ExistingAsset.attributes.traits.'notes' | Out-String)
            }
        }
    }

	if ($ClusterName -and $ExistingAsset.attributes.traits.'virtualization-friendly-name' -like "*$($ClusterName.Name)*") {
		$HostAssets = $Configurations | Where-Object { $_.attributes.name -in $ClusterDetails.Name }
		$VirtFlexAssetBody.attributes.traits.'virtualization-hosts' = @($HostAssets.ID);

		$HostDetails = $ExistingFlexAssets | Where-Object { $_.attributes.name -in $ClusterDetails.Name }
		$VirtFlexAssetBody.attributes.traits.'hyper-v-host-details' = @($HostDetails.ID);

		$ClusterVMs = Get-VM -ComputerName (Get-ClusterNode) -ErrorAction SilentlyContinue
		$VMNames = $ClusterVMs.VMName
		foreach ($Name in $VMNames) {
			if ($Name -like "*(*") {
				$ParsedName = $Name -replace ' ?(?<!^)\(.+\)', ''
				if ($ParsedName -ne $Name) {
					$VMNames += $ParsedName
				}
			}
		}
		$VMAssets = $Configurations | Where-Object { $_.attributes.name -in $VMNames }
		$VirtFlexAssetBody.attributes.traits.'virtual-machine-configurations' = @($VMAssets.ID);

		$ClusterVMTotalCount = ($ClusterVMs | Measure-Object).Count
		$ClusterVMRunningCount = ($ClusterVMs | Where-Object { $_.State -eq "Running" } | Measure-Object).Count
		$ClusterVMBadCount = ($ClusterVMs | Where-Object { $_.Status -ne "Operating normally" } | Measure-Object).Count
		$ClusterReplication = Get-VMReplication -ComputerName (Get-ClusterNode) -ErrorAction SilentlyContinue

		$ClusterAtAGlanceHash = [ordered]@{
			'Hyper-V Server'   = if (($HyperVFeatureDetails).state -eq 'enabled') { $true } else { $False }
			'Hyper-V Replicas' = if ($ClusterReplication) { $true } else { $False }
			'Hyper-V Cluster'  = if ($IsCluster) { $true } else { $false }
			'Host Details'	   = $true
		}
		
		$ClusterATaGlanceHTML = foreach ($Hash in $ClusterAtAGlanceHash.GetEnumerator()) {
			$AdditionalDetails = ""
			if ($Hash.name -eq 'Hyper-V Server' -and $Hash.value) {
				$AdditionalDetails = "VMs Total: $ClusterVMTotalCount, Running: $ClusterVMRunningCount";
				if ($ClusterVMBadCount -gt 0) {
					$AdditionalDetails += "<br /><strong><span style=`"color: red;`">BAD Status VMs: <span style=`"text-decoration: underline;`">$ClusterVMBadCount</span></span></strong>";
				}
			} elseif ($Hash.name -eq "Hyper-V Cluster" -and $Hash.value) {
				if ($ClusterName) {
					$AdditionalDetails = "<span style=`"text-decoration: underline;`">$($ClusterName.Name)</span><br />";
				}
				foreach ($Node in $ClusterDetails) {
					if ($Node.State -eq "Down") {
						$AdditionalDetails += "<span style=`"color: red;`">$($Node.Name) (Down)</span>, ";
					} else {
						$AdditionalDetails += $Node.Name + ", "
					}
				}
				$AdditionalDetails = $AdditionalDetails.TrimEnd(", ");
			} elseif ($Hash.name -eq "Host Details") {
				foreach ($Details in ($HostDetails | Sort-Object -Property @{e={$_.attributes.name}})) {
					$AdditionalDetails += "<a href=`"$($Details.attributes.'resource-url')`">$($Details.attributes.name)</a></br>";
				}
				$AdditionalDetails = $AdditionalDetails -replace ".{5}$";
			}
			
			if ($Hash.name -eq "Host Details") {
				New-AtAGlancecard -Enabled $hash.value -PanelContent $hash.name -ImageURL $ImageURLs.Info -PanelAdditionalDetail $AdditionalDetails -PanelShadingOverride $true -PanelShading "info" -SquareIcon (IIf ('Info' -in $SquareImages) $true $false) 
			} else {
				New-AtAGlancecard -Enabled $hash.value -PanelContent $hash.name -ImageURL $ImageURLs[$hash.name] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ($Hash.name -in $SquareImages) $true $false) 
			}
		}

		$VirtFlexAssetBody.attributes.traits.'at-a-glance' = ($ClusterATaGlanceHTML | Out-String);
		
	} else {
		$VirtFlexAssetBody.attributes.traits.'virtualization-hosts' = @($DeviceAsset.ID)
		$VirtFlexAssetBody.attributes.traits.'hyper-v-host-details' = @($ExistingFlexAsset.ID);

		$VMNames = $VMs.VMName
		foreach ($Name in $VMNames) {
			if ($Name -like "*(*") {
				$ParsedName = $Name -replace ' ?(?<!^)\(.+\)', ''
				if ($ParsedName -ne $Name) {
					$VMNames += $ParsedName
				}
			}
		}
		$VMAssets = $Configurations | Where-Object { $_.attributes.name -in $VMNames }
		$VirtFlexAssetBody.attributes.traits.'virtual-machine-configurations' = @($VMAssets.ID);

		$VirtAtAGlanceHash = [ordered]@{
			'Hyper-V Server'   = $AtAGlanceHash.'Hyper-V Server'
			'Hyper-V Replicas' = $AtAGlanceHash.'Hyper-V Replicas'
			'Hyper-V Cluster'  = $AtAGlanceHash.'Hyper-V Cluster'
			'Host Details'	   = $true
		}
		
		$VirtATaGlanceHTML = foreach ($Hash in $VirtAtAGlanceHash.GetEnumerator()) {
			$AdditionalDetails = ""
			if ($Hash.name -eq 'Hyper-V Server' -and $Hash.value) {
				$AdditionalDetails = "VMs Total: $VMTotalCount, Running: $VMRunningCount";
				if ($VMBadCount -gt 0) {
					$AdditionalDetails += "<br /><strong><span style=`"color: red;`">BAD Status VMs: <span style=`"text-decoration: underline;`">$VMBadCount</span></span></strong>";
				}
			} elseif ($Hash.name -eq "Hyper-V Cluster" -and $Hash.value) {
				foreach ($Node in $ClusterDetails) {
					if ($Node.Name -like $ENV:computername) {
						$AdditionalDetails += "<strong>$($Node.Name)</strong>, ";
					} elseif ($Node.State -eq "Down") {
						$AdditionalDetails += "<span style=`"color: red;`">$($Node.Name) (Down)</span>, ";
					} else {
						$AdditionalDetails += $Node.Name + ", "
					}
				}
				$AdditionalDetails = $AdditionalDetails.TrimEnd(", ");
			} elseif ($Hash.name -eq "Host Details") {
				$AdditionalDetails = "<a href=`"$($ExistingFlexAsset.attributes.'resource-url')`">$($ExistingFlexAsset.attributes.name)</a></br>";
			}
			
			if ($Hash.name -eq "Host Details") {
				New-AtAGlancecard -Enabled $hash.value -PanelContent $hash.name -ImageURL $ImageURLs.Info -PanelAdditionalDetail $AdditionalDetails -PanelShadingOverride $true -PanelShading "info" -SquareIcon (IIf ('Info' -in $SquareImages) $true $false) 
			} else {
				New-AtAGlancecard -Enabled $hash.value -PanelContent $hash.name -ImageURL $ImageURLs[$hash.name] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ($Hash.name -in $SquareImages) $true $false) 
			}
		}

		$VirtFlexAssetBody.attributes.traits.'at-a-glance' = ($VirtATaGlanceHTML | Out-String);
	}

    # Filter out empty values
	($VirtFlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$VirtFlexAssetBody.attributes.traits.Remove($_.Name) 
	}

	write-host "  Updating Virtualization page: $($ExistingAsset.attributes.traits.'virtualization-friendly-name')"  -ForegroundColor Green
    Set-ITGlueFlexibleAssets -id $ExistingAsset.id -data $VirtFlexAssetBody
}
