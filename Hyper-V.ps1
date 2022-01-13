#Requires -RunAsAdministrator
########################## IT-Glue ############################
$APIKEy = "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$FlexAssetName = "Hyper-V Host"
$OrgID = "<ITG Org ID>"
$Description = "A network one-page document that displays the current Hyper-V Settings and virtual machines"
# some layout options, change if you want colours to be different or do not like the whitespace.
$TableHeader = "<table class=`"table table-bordered table-hover`" style=`"width:80%`">"
$Whitespace = "<br/>"
$TableStyling = "<th>", "<th style=`"background-color:#4CAF50`">"
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
 
write-host "Start documentation process." -foregroundColor green
 
$VirtualMachines = get-vm | select-object VMName, State, Generation, Path, Automatic*, @{n = "Minimum(gb)"; e = { $_.memoryminimum / 1gb } }, @{n = "Maximum(gb)"; e = { $_.memorymaximum / 1gb } }, @{n = "Startup(gb)"; e = { $_.memorystartup / 1gb } }, @{n = "Currently Assigned(gb)"; e = { $_.memoryassigned / 1gb } }, ProcessorCount, @{n = "Uptime (@ last checkin)"; e = { $_.Uptime } }, Status | ConvertTo-Html -Fragment | Out-String
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
$HostSettings = get-vmhost | Select-Object  Computername, LogicalProcessorCount, iovSupport, EnableEnhancedSessionMode,MacAddressMinimum, *max*, NumaspanningEnabled, VirtualHardDiskPath, VirtualMachinePath, UseAnyNetworkForMigration, VirtualMachineMigrationEnabled | convertto-html -Fragment -as List | Out-String

# Find the associated configuration to tag
$DeviceAsset = (Get-ITGlueConfigurations -page_size "1000" -filter_name $ENV:COMPUTERNAME -organization_id $OrgID).data
 
$FlexAssetBody =
@{
    type       = 'flexible-assets'
    attributes = @{
        traits = @{
			'host-name'            	= $env:COMPUTERNAME
			'host-device'			= $DeviceAsset.ID
            'virtual-machines'     	= $VirtualMachines
            'network-settings'     	= $NetworkSettings
            'replication-settings' 	= $ReplicationSettings
            'host-settings'        	= $HostSettings
        }
    }
}
 
write-host "Documenting to IT-Glue"  -ForegroundColor Green
$ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($filterID.ID) -filter_organization_id $OrgID).data | Where-Object { $_.attributes.traits.'host-name' -eq $ENV:computername }

#If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just upload.
if (!$ExistingFlexAsset) {
    $FlexAssetBody.attributes.add('organization-id', $OrgID)
    $FlexAssetBody.attributes.add('flexible-asset-type-id', $($filterID.ID))
    write-host "  Creating Hyper-v into IT-Glue organisation $OrgID" -ForegroundColor Green
    New-ITGlueFlexibleAssets -data $FlexAssetBody
}
else {
    write-host "  Editing Hyper-v into IT-Glue organisation $OrgID"  -ForegroundColor Green
    $ExistingFlexAsset = $ExistingFlexAsset[-1]
    Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
}