#####################################################################
$APIKEy =  "<ITG API KEY>"
$orgID = "<ITG Org ID>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$FlexAssetName = "Security"
$Description = "Updates the Security Summary flexible asset. It will fill out what is possible automatically."

$AntiVirusOptions = @('Sophos', 'Avast', 'BitDefender', 'Cylance', 'ESET', 'F-Secure', 'Kaspersky', 'McAfee', 'Norton', 'Panda', 'Trend Micro', 'Webroot', 'Microsoft') # The selection options for the Anti-Virus field
$AllowAVUpdates = $true # If true, this will update the Anti-Virus field based on the currently active AV on this device

$FirewallAssetName = "Firewall" # If you use a flexible asset for Firewalls, add it here. If set to $false it will look at configurations with the "Firewall" type.
$FirewallManufacturers = @('Sophos', 'Sonicwall', 'Meraki', 'Cisco', 'Palo Alto', 'Watchguard') # A list of firewall manufacturers in order of preference. It will loop through them in order and if any firewalls in the company use that manufacturer, it will set this as the main type of firewall.
$AllowFirewallUpdates = $true # If true, this will search ITG for firewall info and try to get the current firewall technology.
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
} else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
  
#Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKEy

Function Get-AVStatus {

	<#
	.Synopsis
	Get anti-virus product information.
	.Description
	This command uses WMI via the Get-CimInstance command to query the state of installed anti-virus products. The default behavior is to only display enabled products, unless you use -All. You can query by computername or existing CIMSessions.
	.Example
	PS C:\> Get-AVStatus chi-win10
	
	Displayname  : ESET NOD32 Antivirus 9.0.386.0
	ProductState : 266256
	Enabled      : True
	UpToDate     : True
	Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
	Timestamp    : Thu, 21 Jul 2016 15:20:18 GMT
	Computername : CHI-WIN10
	
	.Example
	PS C:\>  import-csv s:\computers.csv | Get-AVStatus -All | Group Displayname | Select Name,Count | Sort Count,Name
	
	Name                           Count
	----                           -----
	ESET NOD32 Antivirus 9.0.386.0    12
	ESET Endpoint Security 5.0         6
	Windows Defender                   4
	360 Total Security                 1
	
	Import a CSV file which includes a Computername heading. The imported objects are piped to this command. The results are sent to Group-Object.
	
	.Example
	PS C:\> $cs | Get-AVStatus | where {-Not $_.UptoDate}
	
	Displayname  : ESET NOD32 Antivirus 9.0.386.0
	ProductState : 266256
	Enabled      : True
	UpToDate     : False
	Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
	Timestamp    : Wed, 20 Jul 2016 11:10:13 GMT
	Computername : CHI-WIN11
	
	Displayname  : ESET NOD32 Antivirus 9.0.386.0
	ProductState : 266256
	Enabled      : True
	UpToDate     : False
	Path         : C:\Program Files\ESET\ESET NOD32 Antivirus\ecmd.exe
	Timestamp    : Thu, 07 Jul 2016 15:15:26 GMT
	Computername : CHI-WIN81
	
	You can also pipe CIMSession objects. In this example, the output are enabled products that are not up to date.
	.Notes
	version: 1.1
	
	Learn more about PowerShell:
	http://jdhitsolutions.com/blog/essential-powershell-resources/
	
	.Inputs
	[string[]]
	[Microsoft.Management.Infrastructure.CimSession[]]
	
	.Outputs
	[pscustomboject]
	
	.Link
	Get-CimInstance
	#>
	
	[cmdletbinding(DefaultParameterSetName = "computer")]

	Param(
		#The name of a computer to query.
		[Parameter(
			Position = 0,
			ValueFromPipeline,
			ValueFromPipelineByPropertyName,
			ParameterSetName = "computer"
			)]
		[ValidateNotNullorEmpty()]
		[string[]]$Computername = $env:COMPUTERNAME,

		#An existing CIMsession.
		[Parameter(ValueFromPipeline, ParameterSetName = "session")]
		[Microsoft.Management.Infrastructure.CimSession[]]$CimSession,

		#The default is enabled products only.
		[switch]$All
	)

	Begin {
		Write-Verbose "[BEGIN  ] Starting: $($MyInvocation.Mycommand)"

		Function ConvertTo-Hex {
			Param([int]$Number)
			'0x{0:x}' -f $Number
		}

		#initialize an hashtable of paramters to splat to Get-CimInstance
		$cimParams = @{
			Namespace   = "root/SecurityCenter2"
			ClassName   = "Antivirusproduct"
			ErrorAction = "Stop"
		}

		If ($All) {
			Write-Verbose "[BEGIN  ] Getting all AV products"
		}

		$results = @()
	} #begin

	Process {

		#initialize an empty array to hold results
		$AV = @()

		Write-Verbose "[PROCESS] Using parameter set: $($pscmdlet.ParameterSetName)"
		Write-Verbose "[PROCESS] PSBoundparameters: "
		Write-Verbose ($PSBoundParameters | Out-String)

		if ($pscmdlet.ParameterSetName -eq 'computer') {
			foreach ($computer in $Computername) {

				Write-Verbose "[PROCESS] Querying $($computer.ToUpper())"
				$cimParams.ComputerName = $computer
				Try {
					$AV += Get-CimInstance @CimParams
				}
				Catch {
					Write-Warning "[$($computer.ToUpper())] $($_.Exception.Message)"
					$cimParams.ComputerName = $null
				}

			} #foreach computer
		}
		else {
			foreach ($session in $CimSession) {

				Write-Verbose "[PROCESS] Using session $($session.computername.toUpper())"
				$cimParams.CimSession = $session
				Try {
					$AV += Get-CimInstance @CimParams
				}
				Catch {
					Write-Warning "[$($session.computername.ToUpper())] $($_.Exception.Message)"
					$cimParams.cimsession = $null
				}

			} #foreach computer
		}

		foreach ($item in $AV) {
			Write-Verbose "[PROCESS] Found $($item.Displayname)"
			$hx = ConvertTo-Hex $item.ProductState
			$mid = $hx.Substring(3, 2)
			if ($mid -match "00|01") {
				$Enabled = $False
			}
			else {
				$Enabled = $True
			}
			$end = $hx.Substring(5)
			if ($end -eq "00") {
				$UpToDate = $True
			}
			else {
				$UpToDate = $False
			}

			$results += $item | Select-Object Displayname, ProductState,
			@{Name = "Enabled"; Expression = { $Enabled } },
			@{Name = "UpToDate"; Expression = { $UptoDate } },
			@{Name = "Path"; Expression = { $_.pathToSignedProductExe } },
			Timestamp,
			@{Name = "Computername"; Expression = { $_.PSComputername.toUpper() } }

		} #foreach

	} #process

	End {
		If ($All) {
			$results
		}
		else {
			#filter for enabled only
			($results).Where( { $_.enabled })
		}

		Write-Verbose "[END    ] Ending: $($MyInvocation.Mycommand)"
	} #end
} #end function

Function Test-CommandExists {
	Param ($command)

	$oldPreference = $ErrorActionPreference

	$ErrorActionPreference = 'stop'

	try {if(Get-Command $command){RETURN $true}}

	Catch {RETURN $false}

Finally {$ErrorActionPreference=$oldPreference}

} #end function test-CommandExists

function TimespanDisplay($Timespan) {
	$CheckOrder = @("TotalDays", "TotalHours", "TotalMinutes", "TotalSeconds")
	foreach ($Property in $CheckOrder) {
		if ($Timespan.$Property -ge 1) {
			$Label = $Property.Replace("Total", "")
			if ([Math]::Round($Timespan.$Property) -eq 1) {
				$Label = $Label.TrimEnd('s')
			}
			return [Math]::Round($Timespan.$Property).ToString() + " " + $Label
			break
		}
	}
}

# Get the flexible assets ID
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
  
# Get the current Security asset, if one exists.
$ExistingFlexAssets = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID).data
if (($ExistingFlexAssets | Measure-Object).Count -gt 1) {
	$ExistingFlexAssets = $ExistingFlexAssets | Where-Object { !$_.attributes.archived }
}
$ExistingFlexAsset = $false
if ($ExistingFlexAssets) {
	$ExistingFlexAsset = $ExistingFlexAssets | Sort-Object -Property 'updated-at' -Descending | Select-Object -First 1
}

# Get AV program
$AntiVirus = $false
if ($AllowAVUpdates) {
	$cs = New-CimSession
	$AVDetails = $cs | Get-AVStatus

	if (($AVDetails | Measure-Object).Count -gt 1 -and $AVDetails.Enabled -contains $true) {
		$AVDetails = $AVDetails | Where-Object { $_.Enabled }
	}
	if (($AVDetails | Measure-Object).Count -gt 1 -and $AVDetails.Displayname -like "Windows Defender") {
		$AVDetails = $AVDetails | Where-Object { $_.Displayname -notlike "Windows Defender" }
	}
	if (($AVDetails | Measure-Object).Count -gt 1) {
		$AVDetails = $AVDetails | Sort-Object -Property Timestamp -Descending | Select-Object -First 1
	}

	if (($AVDetails | Measure-Object).Count -gt 0) {
		foreach ($AVOption in $AntiVirusOptions) {
			if ($AVDetails.Displayname -like "*$AVOption*") {
				$AntiVirus = $AVOption
				break;
			}
		}
		if (!$AntiVirus) {
			$AntiVirus = "Other"
		}
	} elseif ($ExistingFlexAsset) {
		$AntiVirus = $ExistingFlexAsset.attributes.traits.'anti-virus'
		Write-Warning "Unable to get Anti-Virus information."
	}
} elseif ($ExistingFlexAsset) {
	$AntiVirus = $ExistingFlexAsset.attributes.traits.'anti-virus'
}

# Get the Firewall Platform
$Firewall = $false
$FirewallDevices = @()
if ($AllowFirewallUpdates) {
	if ($FirewallAssetName) {
		$FirewallAssetID = (Get-ITGlueFlexibleAssetTypes -filter_name $FirewallAssetName).data
	}

	$FirewallModels = @()
	if (!$FirewallAssetName -or !$FirewallAssetID) {
		$ConfigurationTypes = (Get-ITGlueConfigurationTypes -filter_name "Firewall").data
		$FirewallConfigurations = (Get-ITGlueConfigurations -filter_configuration_type_id $ConfigurationTypes[0].id -organization_id $orgID).data
		$FirewallModels = $FirewallConfigurations | ForEach-Object { "$($_.attributes.'manufacturer-name') $($_.attributes.'model-name')" }
	} else {
		$FirewallAssets = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $FirewallAssetID.id -filter_organization_id $orgID).data
		$FirewallModels = $FirewallAssets.attributes.traits.model
	}
	$FirewallModels = $FirewallModels | Where-Object { $_ -and $_.Trim() -notlike "" }

	foreach ($FirewallManufacturer in $FirewallManufacturers) {
		if ($FirewallModels -like "$FirewallManufacturer*") {
			$Firewall = $FirewallManufacturer
			break;
		}
	}

	if ($FirewallAssets) {
		$FirewallDevices = @($FirewallAssets.id)
	} elseif ($FirewallConfigurations) {
		$FirewallDevices = @($FirewallConfigurations.id)
	}
} elseif ($ExistingFlexAsset) {
	$Firewall = $ExistingFlexAsset.attributes.traits.'firewall-platform'
	if ($ExistingFlexAsset.attributes.traits.'firewall-devices') {
		$FirewallDevices = @($ExistingFlexAsset.attributes.traits.'firewall-devices'.values.id)
	}
}

# Get the password complexity standards
$MinLength = ""
$MinMaxPasswordAge = ""
$LockoutThresholdDuration = ""
$ComplexityEnabled = ""
$OtherPasswordRestrictions = ""
if ($ExistingFlexAsset) {
	$MinLength = $ExistingFlexAsset.attributes.traits.'minimum-length'
	$MinMaxPasswordAge = $ExistingFlexAsset.attributes.traits.'min-max-password-age'
	$LockoutThresholdDuration = $ExistingFlexAsset.attributes.traits.'lockout-threshold-duration'
	$ComplexityEnabled = $ExistingFlexAsset.attributes.traits.'complexity-enabled'
	$OtherPasswordRestrictions = $ExistingFlexAsset.attributes.traits.'other-restrictions'
}
if (Test-CommandExists Get-ADDefaultDomainPasswordPolicy) {
	$PasswordPolicy = Get-ADDefaultDomainPasswordPolicy

	if ($PasswordPolicy) {
		$MinLength = $PasswordPolicy.MinPasswordLength
		$MinMaxPasswordAge = "Min: $(TimespanDisplay $PasswordPolicy.MinPasswordAge) / Max: $(TimespanDisplay $PasswordPolicy.MaxPasswordAge)"
		$LockoutThresholdDuration = "Threshold: $($PasswordPolicy.LockoutThreshold) / Duration: $(TimespanDisplay $PasswordPolicy.LockoutDuration)"
		$ComplexityEnabled = $PasswordPolicy.ComplexityEnabled
		if (!$OtherPasswordRestrictions) {
			$OtherPasswordRestrictions = "Length of password history maintained: $($PasswordPolicy.PasswordHistoryCount)"
		}
	}
}

if (!$ExistingFlexAsset) {
	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
			'organization-id' = $OrgID
			'flexible-asset-type-id' = $FilterID.id
			traits = @{
				"client-compliance-requirements" = ""
				"anti-virus" = $AntiVirus

				"firewall-platform" = $Firewall
				"firewall-devices" = $FirewallDevices
				"inbound-rules" = ""
				"outbound-rules" = ""
				"site-to-site-vpn" = ""

				"minimum-length" = $MinLength
				"min-max-password-age" = $MinMaxPasswordAge
				"lockout-threshold-duration" = $LockoutThresholdDuration
				"complexity-enabled" = $ComplexityEnabled
				"other-restrictions" = $OtherPasswordRestrictions
			}
		}
	}

	# Filter out empty values
	($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$FlexAssetBody.attributes.traits.Remove($_.Name) 
	}

	Write-Host "Creating new flexible asset"
    New-ITGlueFlexibleAssets -data $FlexAssetBody
} else {
	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
			traits = @{
				"client-compliance-requirements" = $ExistingFlexAsset.attributes.traits.'client-compliance-requirements'
				"anti-virus" = $AntiVirus

				"firewall-platform" = $Firewall
				"firewall-devices" = $FirewallDevices
				"inbound-rules" = $ExistingFlexAsset.attributes.traits.'inbound-rules'
				"outbound-rules" = $ExistingFlexAsset.attributes.traits.'outbound-rules'
				"site-to-site-vpn" = $ExistingFlexAsset.attributes.traits.'site-to-site-vpn'

				"minimum-length" = $MinLength
				"min-max-password-age" = $MinMaxPasswordAge
				"lockout-threshold-duration" = $LockoutThresholdDuration
				"complexity-enabled" = $ComplexityEnabled
				"other-restrictions" = $OtherPasswordRestrictions
			}
		}
	}

	# Filter out empty values
	($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$FlexAssetBody.attributes.traits.Remove($_.Name) 
	}

	Write-Host "Updating Flexible Asset"
	Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id  -data $FlexAssetBody
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
        "security" = (Get-Date).ToString("yyyy-MM-dd")
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