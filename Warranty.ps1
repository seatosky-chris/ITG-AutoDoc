$DattoAPI = @{
	Key = ""
	Secret = ""
	URL = "https://xxx-api.centrastage.net"
}

$DellAPI = @{
	ID = ""
	Secret = ""
}

$AutotaskAPI = @{
	Url = "https://webservicesX.autotask.net/atservicesrest"
	Username = ""
	Key = ''
	IntegrationCode = ""
}

$IgnoreSerials = @("System Serial Number", "SNMP No-Such-Object", "Default string", "To be filled by O.E.M.")

If (Get-Module -ListAvailable -Name "PSWarranty") { 
    Import-module PSWarranty 
} Else { 
    Install-Module PSWarranty -Force
    Import-Module PSWarranty
}

Set-WarrantyAPIKeys -DellClientID $DellAPI.ID -DellClientSecret $DellAPI.Secret

# Customer version of Get-WarrantyAutotask (in the PSWarranty module) that is faster than the original
function Get-WarrantyAutotaskCustom {
	[CmdletBinding()]
    Param(
        [Pscredential]$AutotaskCredentials,
        [String]$AutotaskAPIKey,
		[String]$AutotaskBaseURI,
        [Switch]$SyncWithSource,
        [Switch]$Missingonly,
        [Switch]$OverwriteWarranty
    )

	If (Get-Module -ListAvailable -Name "AutoTaskAPI") { Import-module "AutotaskAPI" } Else { install-module "AutotaskAPI" -Force }
    Import-Module AutotaskAPI
    Add-AutotaskAPIAuth -ApiIntegrationcode $AutotaskAPIKey -credentials $AutotaskCredentials
	Add-AutotaskBaseURI -BaseURI $AutotaskBaseURI

	# Verify the Autotask API key works
	$AutotaskConnected = $true
	try { 
		Get-AutotaskAPIResource -Resource Companies -ID 0 -ErrorAction Stop 
	} catch { 
		$CleanError = ($_ -split "/n")[0]
		if ($_ -like "*(401) Unauthorized*") {
			$CleanError = "API Key Unauthorized. ($($CleanError))"
		}
		Write-Host $CleanError -ForegroundColor Red
		$AutotaskConnected = $false
	}

	if (!$AutotaskConnected) {
		return
	}

	$Filters = @(
		@{
			op = "eq"
			field = "isActive"
			value = "True"
		},
		@{
			op = "exist"
			field = "serialNumber"
		},
		@{
			op = "notIn"
			field = "serialNumber"
			value = $IgnoreSerials
		}
	)
	if ($Missingonly) {
		$Filters += @{
			op = "notExist"
			field = "warrantyExpirationDate"
		}
	}
	$DeviceFilter = @{
		filter = @(
			@{
				op = "and"
				items = $Filters
			}
		)
	} | ConvertTo-Json -Depth 10 -Compress

	If ($ResumeLast) {
        write-host "Found previous run results. Starting from last object." -foregroundColor green
        $AllDevices = get-content 'Devices.json' | convertfrom-json
    } else {
		write-host "Logging into Autotask. Grabbing all client information." -ForegroundColor "Green"
        $AllClients = Get-AutotaskAPIResource -resource Companies -SimpleSearch 'isactive eq true'
        write-host "Client information found. Grabbing all devices" -ForegroundColor "Green"
		$AllDevices = Get-AutotaskAPIResource -Resource ConfigurationItems -SearchQuery $DeviceFilter
        write-host "Collecting information. This can take a long time." -ForegroundColor "Green"
	}

	$i = 0
    $warrantyObject = foreach ($Device in $AllDevices) {
        $i++
        Write-Progress -Activity "Grabbing Warranty information" -status "Processing $($device.serialnumber). Device $i of $($Alldevices.Count)" -percentComplete ($i / $Alldevices.Count * 100)
        $Client = ($AllClients | Where-Object { $_.id -eq $device.companyID }).CompanyName

		if ($i % 10 -eq 0) { 
			# to speed this up, just update every 10 device, if we redo a few it's not a big deal
        	$RemainingList = set-content 'Devices.json' -force -value ($AllDevices | select-object -skip $alldevices.indexof($device) | convertto-json -depth 5)
		}

		if (!$Client) { continue }

        $WarState = Get-Warrantyinfo -DeviceSerial $device.serialnumber -client $Client

        if ($SyncWithSource -eq $true) {
			$UpdatedConfig = [PSCustomObject]@{
				id = $Device.id
				userDefinedFields = @()
			}

            switch ($OverwriteWarranty) {
                $true {
                    if ($null -ne $warstate.EndDate) {
						$UpdatedConfig | Add-Member -NotePropertyName warrantyExpirationDate -NotePropertyValue $null
						$UpdatedConfig.warrantyExpirationDate = $warstate.EndDate;
						if ([string]$WarState.'Shipped Date' -as [DateTime]) {
							$UpdatedConfig.userDefinedFields +=
								[PSCustomObject]@{
									"name" = "Shipped Date"
									"value" = (Get-Date $WarState.'Shipped Date' -Format 's')
								};
						}
						if ([string]$WarState.StartDate -as [DateTime]) {
							$UpdatedConfig.userDefinedFields +=
								[PSCustomObject]@{
									"name" = "Warranty Start Date"
									"value" = (Get-Date $WarState.StartDate -Format 's')
								};
						}
						if ($WarState."Warranty Product name") {
							$UpdatedConfig.userDefinedFields +=
								[PSCustomObject]@{
									"name" = "Warranty Product Name"
									"value" = ($WarState."Warranty Product name"[0..209] -join ""  -replace "`n",", " -replace "`r",", ")
								};
						}

						Set-AutotaskAPIResource -Resource ConfigurationItems -Body $UpdatedConfig | Out-Null
                        "$((get-date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) Autotask: $Client / $($device.SerialNumber) with AT ID $($device.id) warranty has been overwritten to $($warstate.EndDate)" | out-file $script:LogPath -Append -Force
                    }
                     
                }
                $false { 
                    if ($null -ne $warstate.EndDate) { 
						$Update = $false
						if ($null -eq $device.WarrantyExpirationDate) {
							$UpdatedConfig | Add-Member -NotePropertyName warrantyExpirationDate -NotePropertyValue $null
							$UpdatedConfig.warrantyExpirationDate = $warstate.EndDate; 
							$Update = $true
						}
						$CurAT_ShippedDate = ($device.userDefinedFields | Where-Object { $_.name -eq "Shipped Date" }).value
						$CurAT_WarrantyStart = ($device.userDefinedFields | Where-Object { $_.name -eq "Warranty Start Date" }).value
						$CurAT_WarrantyName = ($ATDevice.userDefinedFields | Where-Object { $_.name -eq "Warranty Product Name" }).value

						if ([string]$WarState.'Shipped Date' -as [DateTime] -and $null -eq $CurAT_ShippedDate) {
							$UpdatedConfig.userDefinedFields +=
								[PSCustomObject]@{
									"name" = "Shipped Date"
									"value" = (Get-Date $WarState.'Shipped Date' -Format 's')
								};
						}
						if ([string]$WarState.StartDate -as [DateTime] -and $null -eq $CurAT_WarrantyStart) {
							$UpdatedConfig.userDefinedFields +=
								[PSCustomObject]@{
									"name" = "Warranty Start Date"
									"value" = (Get-Date $WarState.StartDate -Format 's')
								};
							$Update = $true
						}
						if ($WarState."Warranty Product name" -and $null -eq $CurAT_WarrantyName) {
							$UpdatedConfig.userDefinedFields +=
								[PSCustomObject]@{
									"name" = "Warranty Product Name"
									"value" = ($WarState."Warranty Product name"[0..209] -join ""  -replace "`n",", " -replace "`r",", ")
								};
							$Update = $true
						}

						if ($Update) {
							Set-AutotaskAPIResource -Resource ConfigurationItems -Body $UpdatedConfig | Out-Null
                        	"$((get-date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')) Autotask: $Client / $($device.SerialNumber) with AT ID $($device.id) warranty has been set to $($warstate.EndDate)" | out-file $script:LogPath -Append -Force
						}
                    } 
                }
            }
        }
        $WarState
    }
	Write-Progress -Activity "Grabbing Warranty information" -status "Ready" -Completed
    Remove-item 'devices.json' -Force -ErrorAction SilentlyContinue
    return $warrantyObject
}

$script:HPNotified = $false
$script:ExcludeApple = $true
$script:LogPath = ".\WarrantyUpdateLog.txt"

$CurrentDate = (Get-Date)

$AutotaskPassword = ConvertTo-SecureString $AutotaskAPI.Key -AsPlainText -Force
$AutotaskCreds = New-Object System.Management.Automation.PSCredential -ArgumentList ($AutotaskAPI.Username, $AutotaskPassword)
Write-Host "Updating Autotask Warranties" -ForegroundColor Green

if ($CurrentDate.Day -le 7) {
	# On the first run of the month, do a full update overwriting existing warranty info
	$WarrantyUpdates = Get-WarrantyAutotaskCustom -AutotaskCredentials $AutotaskCreds -AutotaskAPIKey $AutotaskAPI.IntegrationCode -AutotaskBaseURI $AutotaskAPI.Url -SyncWithSource -OverwriteWarranty | Sort-Object -Property Client
} else {
	$WarrantyUpdates = Get-WarrantyAutotaskCustom -AutotaskCredentials $AutotaskCreds -AutotaskAPIKey $AutotaskAPI.IntegrationCode -AutotaskBaseURI $AutotaskAPI.Url -SyncWithSource -MissingOnly | Sort-Object -Property Client
}

Write-Host "Updating RMM Warranties" -ForegroundColor Green
if ($CurrentDate.Day -le 7) {
	Update-WarrantyInfo -DattoRMM -DattoAPIKey $DattoAPI.Key -DattoAPISecret $DattoAPI.Secret -DattoAPIURL $DattoAPI.URL -SyncWithSource -OverwriteWarranty -ExcludeApple -LogActions
} else {
	Update-WarrantyInfo -DattoRMM -DattoAPIKey $DattoAPI.Key -DattoAPISecret $DattoAPI.Secret -DattoAPIURL $DattoAPI.URL -SyncWithSource -MissingOnly -ExcludeApple -LogActions
}
