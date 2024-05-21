#####################################################################
$ITGAPIKey =  "<ITG API KEY>"
$ITGAPIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$DattoAPICreds = @{
	PublicKey = "<DATTO BDR API PUBLIC KEY>"
	SecretKey = "<DATTO BDR API SECRET KEY>"
	BaseURI = $false # If you have your own API gateway or proxy, you may put in your own custom uri
}
$FlexAssetName = "Backup"
$Description = "This will auto-backup all Datto BDR's into IT Glue including their settings and the servers each BDR backs up."

$DisplayLastXBackups = 5 # The amount of previous backups to show (Max: 10)
$ImageURLs = @{
    'Datto BDR' = "https://www.seatosky.com/wp-content/uploads/2022/09/datto_logo.png"
    'Active Service Plan' = "https://www.seatosky.com/wp-content/uploads/2022/09/service-plan.png"
    'Storage Used' = "https://www.seatosky.com/wp-content/uploads/2022/09/storage.png"
    'Alert' = "https://www.seatosky.com/wp-content/uploads/2022/09/warning.png"
	'BackupsCondition' = "https://www.seatosky.com/wp-content/uploads/2022/09/backup.png"
	'Info' = "https://www.seatosky.com/wp-content/uploads/2022/08/DetailsIcon.png"
}
$SquareImages = @('Info', 'Alert', 'Storage Used', 'Active Service Plan', 'BackupsCondition')
$DattoBadVerificationsIcon = "https://www.seatosky.com/wp-content/uploads/2022/09/datto-bad-verification-icon2.png"
#####################################################################

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -Assembly PresentationFramework

# Grabbing ITGlue Module and installing.
If (Get-Module -ListAvailable -Name "ITGlueAPI") { 
    Import-module ITGlueAPI 
} Else { 
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}
  
# Setting IT-Glue logon information
Add-ITGlueBaseURI -base_uri $ITGAPIEndpoint
Add-ITGlueAPIKey $ITGAPIKey

# Grabbing DattoAPI Backup module and installing
If (Get-Module -ListAvailable -Name "DattoAPI") { 
    Import-module DattoAPI 
} Else { 
    Install-Module DattoAPI -Force
    Import-Module DattoAPI
}

# Setting Datto BCDR API login information
if ($DattoAPICreds.BaseURI) {
	Add-DattoBaseURI -base_uri $DattoAPICreds.BaseURI
} else {
	Add-DattoBaseURI
}
Add-DattoAPIKey -Api_Key_Public $DattoAPICreds.PublicKey -Api_Key_Secret $DattoAPICreds.SecretKey

# Get the flexible asset type id
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data

# Verify we can connect to the ITG API (if we can't this can cause duplicates)
$ITGOrgs = Get-ITGlueOrganizations -page_size 1000
if (!$ITGOrgs -or !$ITGOrgs.data -or !$FilterID -or ($ITGOrgs.data | Measure-Object).Count -lt 1 -or !$ITGOrgs.data[0].attributes -or !$ITGOrgs.data[0].attributes.name) {
	Write-Error "Could not connect to the IT Glue API. Exiting..."
	exit 1
} else {
	Write-Host "Successfully connected to the ITG API."
}

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

function Convert-Size {
	[cmdletbinding()]            
	param(            
		[validateset("Bytes","B","KB","MB","GB","TB")]            
		[string]$From,            
		[validateset("Bytes","B","KB","MB","GB","TB","Auto")]            
		[string]$To,            
		[Parameter(Mandatory=$true)]   
		[double]$Value,            
		[int]$Precision = 4,
		[switch]$ToString = $false
	)            
	switch($From) {            
		"Bytes" {$value = $Value }
		"B" {$value = $Value }
		"KB" {$value = $Value * 1024 }            
		"MB" {$value = $Value * 1024 * 1024}            
		"GB" {$value = $Value * 1024 * 1024 * 1024}            
		"TB" {$value = $Value * 1024 * 1024 * 1024 * 1024}            
	}            
				
	switch ($To) {
		"Auto" {
			$ToString = $true;
			switch ($value) {
				{$value -gt 1TB} {$value = ($value / 1TB); $To = 'TB'; break}
				{$value -gt 1GB} {$value = ($value / 1GB); $To = 'GB'; break}
				{$value -gt 1MB} {$value = ($value / 1MB); $To = 'MB'; break}
				{$value -gt 1KB} {$value = ($value / 1KB); $To = 'KB'; break}
				default {$To = 'Bytes'}
			}
		}        
		"Bytes" {return $value}
		"B" {return $value}
		"KB" {$Value = $Value/1KB}            
		"MB" {$Value = $Value/1MB}            
		"GB" {$Value = $Value/1GB}            
		"TB" {$Value = $Value/1TB}            
				
	}            
				
	$value = [Math]::Round($value,$Precision,[MidPointRounding]::AwayFromZero)

	if ($ToString) {
		return $value.ToString() + " " + $To.ToString()
	} else {
		return $value
	}			
} 

Function Convert-FromUnixDate ($UnixDate) {
	[timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate))
}

Function Convert-FromUnixDateToHumanReadable ($UnixDate) {
	$Date = Convert-FromUnixDate $UnixDate
	if ($Date.Year -lt 1970) {
		return "None"
	} else {
		return $Date
	}
}

function CalculateBackupInterval($AllBackupTimes) {
	if (!$AllBackupTimes -or ($AllBackupTimes | Measure-Object).Count -lt 2) {
		return $false;
	}

	$AllBackupTimes = $AllBackupTimes | ForEach-Object { Get-Date $_ } | Sort-Object
	$Differences = @()
	for ($i = 0; $i -lt ($AllBackupTimes.Count - 1); $i++) {
		if (!$AllBackupTimes[$i+1]) {
			break
		}
		$StartDate = $AllBackupTimes[$i]
		$EndDate = $AllBackupTimes[$i+1]
		$Difference = New-TimeSpan -Start $StartDate -End $EndDate
		$Differences += $Difference
	}

	$Averages = @{}
	foreach ($Property in ($Differences[0] | Get-Member)) {
		if ($Property.Name -notlike "Total*") {
			continue
		}
		$Averages[$Property.Name] = ($Differences.($Property.Name) | Measure-Object -Average).Average
	}

	$CheckOrder = @("TotalDays", "TotalHours", "TotalMinutes", "TotalSeconds")
	foreach ($Property in $CheckOrder) {
		if ($Averages.$Property + 0.2 -ge 1) {
			$Label = $Property.Replace("Total", "")
			if ([Math]::Round($Averages.$Property) -eq 1) {
				$Label = $Label.TrimEnd('s')
			}
			return [Math]::Round($Averages.$Property).ToString() + " " + $Label
			break
		}
	}
}

function UptimeDisplay($Uptime) {
	$Timespan = New-TimeSpan -Seconds $Uptime

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

function LastXBackupsDisplay($LastXBackups) {
	$LastXBackups | ForEach-Object { $_.timestamp = (Get-Date $_.timestamp) }
	$LastXBackups = $LastXBackups | Sort-Object -Property timestamp

	$DisplayStr = "<div>"
	foreach ($Backup in $LastXBackups) {
		if ($Backup.backup.status -eq 'success' -and $Backup.localVerification.status -ne 'success') {
			$DisplayStr += "<div class='fa'><img src='$DattoBadVerificationsIcon' /></div> "
		} elseif ($Backup.backup.status -ne 'success') {
			$DisplayStr += "<div style='color: #f3523e' class='fa fa-close'></div> "
		} else {
			$DisplayStr += "<div style='color: #58c990' class='fa fa-circle'></div> "
		}
	}

	$DisplayStr += "</div><div>"

	$Backup = $LastXBackups[$LastXBackups.Count - 1]
	$FormattedDate = $(Get-Date -Date $Backup.timestamp -UFormat "%d-%b-%Y %I:%M %p")
	if ($Backup.advancedVerification.screenshotVerification -and !$Backup.advancedVerification.screenshotVerification.status) {
		$DisplayStr = $DisplayStr.Substring(5)
		$DisplayStr = "<div class='panel panel-danger' style='background-color: #f2dede;'>$DisplayStr"
		$DisplayStr += "<br /><div><span>Successful backup taken on $($FormattedDate). <strong><a href='$($Backup.advancedVerification.screenshotVerification.image)'>Screenshot Verification Failed</a></strong>.</span>"
	} elseif ($Backup.backup.status -eq 'success' -and $Backup.localVerification.status -ne 'success') {
		$DisplayStr += "<br /><span>Successful backup taken on $($FormattedDate). Local Verification Failed. Errors: $(($Backup.localVerification.errors | Foreach-Object {"$($_.errorType) - $($_.errorMessage), "}).TrimEnd(", "))</span>"
	} elseif ($Backup.backup.status -ne 'success') {
		$DisplayStr += "<br /><span>Failed backup at $($FormattedDate). Error: $($Backup.backup.errorMessage). Verification Error: $(($Backup.localVerification.errors | Foreach-Object {"$($_.errorType) - $($_.errorMessage), "}).TrimEnd(", ")) </span>"
	} else {
		$DisplayStr += "<br /><span>Successful backup taken on $($FormattedDate).</span>"
	}
	$DisplayStr += "</div>"	

	return $DisplayStr
}

# Levenshtein distance function for comparing similarity between two strings
function Measure-StringDistance {
    <#
        .SYNOPSIS
            Compute the distance between two strings using the Levenshtein distance formula.
        
        .DESCRIPTION
            Compute the distance between two strings using the Levenshtein distance formula.

        .PARAMETER Source
            The source string.

        .PARAMETER Compare
            The comparison string.

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Micheal"

            2

            There are two characters that are different, "a" and "e".

        .EXAMPLE
            PS C:\> Measure-StringDistance -Source "Michael" -Compare "Michal"

            1

            There is one character that is different, "e".

        .NOTES
            Author:
            Michael West
    #>

    [CmdletBinding(SupportsShouldProcess=$true)]
    [OutputType([int])]
    param (
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string]$Source = "",
        [string]$Compare = ""
    )
    $n = $Source.Length;
    $m = $Compare.Length;
    $d = New-Object 'int[,]' $($n+1),$($m+1)
        
    if ($n -eq 0){
      return $m
	}
    if ($m -eq 0){
	    return $n
	}

	for ([int]$i = 0; $i -le $n; $i++){
        $d[$i, 0] = $i
    }
    for ([int]$j = 0; $j -le $m; $j++){
        $d[0, $j] = $j
    }

	for ([int]$i = 1; $i -le $n; $i++){
	    for ([int]$j = 1; $j -le $m; $j++){
            if ($Compare[$($j - 1)] -eq $Source[$($i - 1)]){
                $cost = 0
            }
            else{
                $cost = 1
            }
		    $d[$i, $j] = [Math]::Min([Math]::Min($($d[$($i-1), $j] + 1), $($d[$i, $($j-1)] + 1)),$($d[$($i-1), $($j-1)]+$cost))
	    }
	}
	    
    return $d[$n, $m]
}

# Loads a WPF form and returns the loaded form
function loadForm($Path) {
	$inputXML = Get-Content $Path -Raw
	$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
	[xml]$XAML = $inputXML
	$reader = (New-Object System.Xml.XmlNodeReader $XAML) 
	try {
		$Form = [Windows.Markup.XamlReader]::Load( $reader )
	} catch {
		Write-Warning $_.Exception
		throw
	}

	# this finds all of the possible variables in the form (btn, listbox, textbox) and maps them to powershell variables with "var_" appended to the objects name. e.g. var_btnSave
	$XAML.SelectNodes("//*[@Name]") | ForEach-Object {
		#"trying item $($_.Name)"
		try {
			Set-Variable -Name "var_$($_.Name)" -Value $Form.FindName($_.Name) -Scope 1 -ErrorAction Stop
		} catch {
			throw
		}
	}

	return $Form
}

function Parse-JsonFileAsHash([string]$file) {
	$text = Get-Content -Raw -Path $file
	$parser = New-Object Web.Script.Serialization.JavaScriptSerializer
	$parser.MaxJsonLength = $text.length
	return $parser.Deserialize($text, @{}.GetType())
}

function Set-CachedScreenshotData($CompanyName, $ServerName, $ScreenshotData) {
	$CachedScreenshots = @{}
	if (Test-Path -Path "datto_backup_cached_screenshots.json" -PathType Leaf) {
		$CachedScreenshots = Parse-JsonFileAsHash "datto_backup_cached_screenshots.json"
		if (!$CachedScreenshots) {
			$CachedScreenshots = @{}
		}
	}

	$ScreenShotdata.Timestamp = [DateTime]::UtcNow
	if ($CompanyName -notin $CachedScreenshots.Keys) {
		$CachedScreenshots.$CompanyName = @{}	
	}
	$CachedScreenshots.$CompanyName.$ServerName = $ScreenshotData

	$CachedScreenshots | ConvertTo-Json | Out-File "datto_backup_cached_screenshots.json"
}

function Get-CachedScreenshotData($CompanyName, $ServerName) {
	if (Test-Path -Path "datto_backup_cached_screenshots.json" -PathType Leaf) {
		$CachedScreenshots = Parse-JsonFileAsHash "datto_backup_cached_screenshots.json"
	}

	if ($CachedScreenshots -and $CompanyName -in $CachedScreenshots.Keys -and $ServerName -in $CachedScreenshots.$CompanyName.Keys) {
		$CachedScreenshot = $CachedScreenshots.$CompanyName.$ServerName
		$CacheAge = NEW-TIMESPAN -Start (Get-Date $CachedScreenshot.Timestamp) -End (Get-Date)
		if ($CacheAge -gt 7) {
			return $false
		} else {
			return $CachedScreenshot
		}
	} else {
		return $false
	}
}

$TableHeader = "<table class=`"table table-bordered table-hover`" style=`"width:100%`">"
$Whitespace = "<br/>"
$TableStyling = "<th>", "<th class='bg-info'>"

# Get a list of ITG organizations, Datto orgs, and Datto BDR devices
$ITGOrgs = $ITGOrgs.data | Where-Object { $_.attributes.'organization-type-name' -like 'Customer' -and $_.attributes.'organization-status-name' -like 'Active' }

$BDRDevices = Get-DattoDevice
$DattoOrgs = $BDRDevices.items.clientCompanyName | Sort-Object -Unique

# Match the ITG / Datto organizations by name
$OrgMatches = @()
$MatchNotFound = @()
$DontMatch = @()

# Import and use existing matches if they exist
$AllMatches = @()
if (Test-Path -Path "datto_backup_matches.json" -PathType Leaf) {
	$AllMatches = Get-Content -Raw -Path "datto_backup_matches.json" | ConvertFrom-Json
}

# Start matching
$ChangesMadeToMatches = $false
foreach ($DattoOrg in $DattoOrgs) {
	$Match = $null
	
	# Check existing matches first
	if ($DattoOrg -in $AllMatches.dattoName) {
		$Match = $AllMatches | Where-Object { $_.dattoName -eq $DattoOrg }
		if ($Match.itgId) {
			# match found
			$OrgMatches += [pscustomobject]@{
				dattoName = $Match.dattoName
				itgId = $Match.itgId
				itgName = $Match.itgName
			}
		} else {
			# not matched (manually)
			$DontMatch += @{
				dattoName = $Match.dattoName
			}
		}

		continue
	}

	# No existing match, lets handle the matching
	$Matches = $ITGOrgs | Where-Object { $_.attributes.name -like "*$($DattoOrg)*" -or $DattoOrg -like "*$($_.attributes.name)*" }
	if (($Matches | Measure-Object).Count -gt 1) {
		# narrow down to 1
		$Match = $Matches | Where-Object { $_.attributes.name -like $DattoOrg -or $DattoOrg -like $($_.attributes.name) }
		if (($Match | Measure-Object).Count -ne 1) {
			$BestDistance = 999;
			foreach ($TestMatch in $Matches) {
				$Distance = Measure-StringDistance -Source $DattoOrg -Compare $TestMatch.attributes.name
				if ($Distance -lt $BestDistance) {
					$Match = $TestMatch
					$BestDistance = $Distance
				}
			}
		}
	} elseif (($Matches | Measure-Object).Count -eq 1) {
		$Match = $Matches[0]
	}
	
	if ($Match) {
		# match found
		$OrgMatches += [pscustomobject]@{
			dattoName = $DattoOrg
			itgId = $Match.id
			itgName = $Match.attributes.name
		}
	} else {
		# no match found
		$MatchNotFound += @{
			dattoName = $DattoOrg
		}
	}
	$ChangesMadeToMatches = $true
}

if (($MatchNotFound | Measure-Object).Count -gt 0) {

	foreach ($MissingMatch in $MatchNotFound) {
		$Match = $null

		$Form = loadForm -Path(".\Forms\OrgMatching\OrgMatching\MainWindow.xaml")

		function cmbItems($Items, $Filter = "") {
			$FilteredItems = $Items | Where-Object { $_ -like "*$Filter*" } | Sort-Object
			$var_cmbMatch.Items.Clear()
			foreach ($Item in $FilteredItems) {
				$var_cmbMatch.Items.Add($Item) | Out-Null
			}
		}

		$var_lblOrgName.Content = $MissingMatch.dattoName
		$var_lblMatchingNotes.Content = "BDR Devices: " + (($BDRDevices.items | Where-Object { $_.clientCompanyName -like $MissingMatch.dattoName }).name -join ", ")

		# update the listbox with the ITG orgs
		$Items = $ITGOrgs.attributes.name
		cmbItems -Items $Items

		$var_cmbMatch.Add_KeyUp({
			if ($_.Key -eq "Down" -or $_.Key -eq "Up") {
				$var_cmbMatch.IsDropDownOpen = $true
			} elseif ($_.Key -ne "Enter" -and $_.Key -ne "Tab" -and $_.Key -ne "Return") {
				$var_cmbMatch.IsDropDownOpen = $true
				cmbItems -Items $Items -Filter $var_cmbMatch.Text
			}
		})

		$var_cmbMatch.Add_SelectionChanged({
			$SelectedAsset = $var_cmbMatch.SelectedItem
			$script:Match = $ITGOrgs | Where-Object { $_.attributes.name -eq $SelectedAsset }
		})

		$var_btnNoMatch.Add_Click({
			Write-Host "Organization skipped! ($($MissingMatch.dattoName))"
			$script:DontMatch += $MissingMatch
			$Form.Close()
			continue;
		})

		$var_btnSave.Add_Click({
			$Form.Close()
		})

		$Form.ShowDialog() | out-null

		if ($Match) {
			$OrgMatches += [pscustomobject]@{
				dattoName = $MissingMatch.dattoName
				itgId = $Match.id
				itgName = $Match.attributes.name
			}
		}

		$ChangesMadeToMatches = $true
	}
}

# Create update json matching document for quick matching in the future
if ($ChangesMadeToMatches) {
	$AllMatches = $OrgMatches
	$DontMatch | ForEach-Object { 
		$AllMatches += [PSCustomObject]@{
			dattoName = $_.dattoName
			itgId = $null
			itgName = $null
		}
	}

	$AllMatches | ConvertTo-Json | Out-File "datto_backup_matches.json"
}

if ($DontMatch) {
	Write-Output "Some Datto orgs have been manually set to no match with ITG!"
	Write-Output "If you need to match these, please edit the datto_backup_matches.json file manually."
}

# Ignore any devices with orgs in $DontMatch as we won't be documenting them
$BDRDevices.items = $BDRDevices.items | Where-Object { $_.clientCompanyName -notin $DontMatch.dattoName }
$DattoOrgs = $BDRDevices.items.clientCompanyName | Sort-Object -Unique

# Get all configurations for filtering
$i = 0
$OrgConfigurations = @{}
foreach ($Org in $DattoOrgs) {
	$i++
	[int]$PercentComplete = $i / $DattoOrgs.Count * 100
	$OrgID = ($OrgMatches | Where-Object { $_.dattoName -eq $Org })[0].itgId
	Write-Progress -Activity "Downloading ITG Configurations" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Getting configurations for '$($Org)' ID: $($OrgID))")

	$Configurations = Get-ITGlueConfigurations -page_size "1000" -organization_id $OrgID
	$j = 1
	while ($Configurations.links.next) {
		$j++
		$Configurations_Next = Get-ITGlueConfigurations -page_size "1000" -page_number $j -organization_id $OrgID
		$Configurations.data += $Configurations_Next.data
		$Configurations.links = $Configurations_Next.links
	}
	$Configurations = $Configurations.data
	$OrgConfigurations[$OrgID] = $Configurations
}
Write-Progress -Activity "Downloading ITG Configurations" -Status "Ready" -Completed

# All org matches made, now we can continue


######################
## Now loop through each BDR device and update/add documentation
######################
$i = 0
foreach ($BDRDevice in $BDRDevices.items) {
	$i++
	Write-Host "Documenting $($BDRDevice.name)"
	if (!$BDRDevice.clientCompanyName -or $BDRDevice.hidden) {
		Write-Host "Skipping documenting $($BDRDevice.name)" -ForegroundColor Red
		continue
	}
	[int]$PercentComplete = $i / $BDRDevices.items.Count * 100
	Write-Progress -Activity "Updating ITG Backup pages" -PercentComplete $PercentComplete -Status ("Working - " + $PercentComplete + "%  (Updating page for '$($BDRDevice.name)' Customer: $($BDRDevice.clientCompanyName))")

	$OrgID = ($OrgMatches | Where-Object { $_.dattoName -eq $BDRDevice.clientCompanyName })[0].itgId

	$LocalStorageUsed = Convert-Size -From $BDRDevice.localStorageUsed.units -To 'Auto' -Value $BDRDevice.localStorageUsed.size -Precision 2 -ToString
	$LocalStorageAvailable = Convert-Size -From $BDRDevice.localStorageAvailable.units -To 'Auto' -Value $BDRDevice.localStorageAvailable.size -Precision 2 -ToString
	$LocalStorageUsedKB = Convert-Size -From $BDRDevice.localStorageUsed.units -To 'KB' -Value $BDRDevice.localStorageUsed.size -Precision 2
	$LocalStorageAvailableKB = Convert-Size -From $BDRDevice.localStorageAvailable.units -To 'KB' -Value $BDRDevice.localStorageAvailable.size -Precision 2
	$LocalStorageTotalKB = $LocalStorageUsedKB + $LocalStorageAvailableKB
	$LocalStorageTotal = Convert-Size -From 'KB' -To 'Auto' -Value $LocalStorageTotalKB -Precision 2 -ToString
	$LocalStorageUsedPercentage = [Math]::Round($LocalStorageUsedKB / $LocalStorageTotalKB * 100)
	$OffsiteStorageUsed = Convert-Size -From $BDRDevice.offsiteStorageUsed.units -To 'Auto' -Value $BDRDevice.offsiteStorageUsed.size -Precision 2 -ToString

	$BDRDeviceServers = Get-DattoAsset -serialNumber $BDRDevice.serialNumber
	$BDRDeviceServers.items | ForEach-Object { 
		if ($_.lastScreenshotUrl) {
			Set-CachedScreenshotData $BDRDevice.clientCompanyName $_.name @{
				lastScreenshotAttempt = $_.lastScreenshotAttempt
				lastScreenshotAttemptStatus = $_.lastScreenshotAttemptStatus
				lastScreenshotUrl = $_.lastScreenshotUrl
			}
		}
	}
	$BDRDeviceServers.items | ForEach-Object {
		if (!$_.lastScreenshotUrl) {
			$CachedScreenshot = Get-CachedScreenshotData $BDRDevice.clientCompanyName $_.name
			if ($CachedScreenshot) {
				$_.lastScreenshotAttempt = $CachedScreenshot.lastScreenshotAttempt
				$_.lastScreenshotAttemptStatus = $CachedScreenshot.lastScreenshotAttemptStatus
				$_.lastScreenshotUrl = $CachedScreenshot.lastScreenshotUrl
			}
		}
	}

	$LatestBackups = $BDRDeviceServers.items | Where-Object { !$_.isArchived -and !$_.isPaused } | Foreach-Object { $_.backups[0] }
	$FailedBackups = ($LatestBackups | Where-Object { $_.backup.status -ne 'success' } | Measure-Object).Count
	$BadVerificationBackups = ($LatestBackups | Where-Object { $_.backup.status -eq 'success' -and $_.localVerification.status -ne 'success' } | Measure-Object).Count
	$BadScreenshotBackups = ($LatestBackups | Where-Object { $_.advancedVerification.screenshotVerification -and !$_.advancedVerification.screenshotVerification.status } | Measure-Object).Count
	$BDRDeviceServersRaw = $BDRDeviceServers.items | Sort-Object isPaused, isArchived, Name | 
		Select-Object @{Name="Server Name"; E={$_.name}}, @{Name="Server IP"; E={$_.localIP}}, os, 
			@{Name="Protected Volumes"; E={$_.protectedVolumeNames -join ", "}}, @{Name="Unprotected Volumes"; E={$_.unprotectedVolumeNames -join ", "}}, 
			agentVersion, @{Name="Local Backups Paused"; E={$_.isPaused}}, isArchived, @{Name="Local Backup Interval"; E={CalculateBackupInterval $_.backups.timestamp}}, @{Name="Latest Offsite"; E={Convert-FromUnixDateToHumanReadable $_.latestOffsite}}, 
			@{Name="Latest Local Snapshot"; E={Convert-FromUnixDateToHumanReadable $_.lastSnapshot}}, 
			@{Name="Latest Screenshot Attempt (Success)"; E={("$(Convert-FromUnixDateToHumanReadable $_.lastScreenshotAttempt) $(IIf $_.lastScreenshotAttemptStatus " &#9989;" " &#10060;")")}},
			@{Name="Screenshot"; E={(IIf $_.lastScreenshotUrl "<a href='$($_.lastScreenshotUrl)'>View Screenshot</a>" "")}},
			@{
				Name="Last $($DisplayLastXBackups) Backups"; 
				E={ 
					if ($_.isArchived) {
						"<span style='color: #9aa9af; font-style: italic;'>— Archived agent —</span>"
					} elseif ($_.isPaused) {
						"<span style='color: #9aa9af; font-style: italic;'>— Paused agent —</span>"
					} else {
						LastXBackupsDisplay ($_.backups | Select-Object -First $DisplayLastXBackups)
					}
				}
			} |
		ConvertTo-HTML -Fragment | Select-Object -Skip 1
	$BDRDeviceServersHTML = $TableHeader + ($BDRDeviceServersRaw -replace $TableStyling) + $Whitespace
	$BDRDeviceServersHTML = [System.Web.HttpUtility]::HtmlDecode($BDRDeviceServersHTML)

	$BDRDeviceAlerts = Get-DattoAlert -serialNumber $BDRDevice.serialNumber
	$RecentAlerts = $BDRDeviceAlerts.items | Where-Object { (Get-Date $_.dateTriggered) -gt (Get-Date).AddDays(-14) }
	$RecentAlertsHTML = ""
	foreach ($Alert in $RecentAlerts) {
		$AdditionalDetails = "<span>Triggered on: $(Get-Date $Alert.dateTriggered -UFormat "%d-%b-%Y %I:%M %p")</span><br /><span>Threshold: $($Alert.threshold) $($Alert.unit)</span>"
		$RecentAlertsHTML += New-AtAGlancecard -Enabled $false -PanelContent $Alert.type -ImageURL $ImageURLs["Alert"] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ("Alert" -in $SquareImages) $true $false)
	}

	$ITGDevices = @()
	$ITGConfigurations = $OrgConfigurations[$OrgID]
	foreach ($Device in $BDRDeviceServers.items) {
		$MatchedDevice = $ITGConfigurations | Where-Object { $_.attributes.name -like $Device.name -or ($_.attributes.'primary-ip' -and $_.attributes.'primary-ip' -like $Device.localIp) }
		$ITGDevices += $MatchedDevice
	}

	$BDRITGDevice = $ITGConfigurations | Where-Object { $_.attributes.name -like $BDRDevice.name -or ($_.attributes.'primary-ip' -and $_.attributes.'primary-ip' -like $BDRDevice.internalIP) }

	$FrequencyConversion = @{ "Hour" = "Hourly"; "Day" = "Daily" }
	if (($BDRDeviceServers.items | Measure-Object).Count -gt 0) {
		$BackupFrequencies = $BDRDeviceServers.items | Foreach-Object { CalculateBackupInterval $_.backups.timestamp } | Where-Object { $_ }
		$BackupFrequenciesCleaned = $BackupFrequencies | ForEach-Object { $_.Split(" ")[1].TrimEnd("s") }
		$BackupFrequenciesGrouped = $BackupFrequenciesCleaned | Group-Object
		$BackupFrequency = ($BackupFrequenciesGrouped | Sort-Object -Property Count | Select-Object Name -First 1).Name
		$BackupFrequency = IIf ($BackupFrequency -in $FrequencyConversion.Keys) $FrequencyConversion[$BackupFrequency] "Hourly"
	} else {
		$BackupFrequency = $false
	}

	$BDRDevice.servicePlan -match '(Infinite|\d\d? (years?|months?))'
	$CloudRetention = $Matches[1]
	
	$AdditionalDetails = "<strong>$($BDRDevice.model)</strong><br /><span>Uptime: $(UptimeDisplay $BDRDevice.uptime) <br />Protecting: $(($BDRDeviceServers.items | Where-Object { !$_.isArchived -and !$_.isPaused } | Measure-Object).Count) devices</span>";
	$ATaGlanceHTML = New-AtAGlancecard -Enabled $true -PanelContent "Datto BDR" -ImageURL $ImageURLs["Datto BDR"] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ("Datto BDR" -in $SquareImages) $true $false)
	$AdditionalDetails = "<span>$($BDRDevice.servicePlan)</span><br /><span>Expires: $(Get-Date $BDRDevice.servicePeriod -UFormat "%d-%b-%Y %I:%M %p")</span>"
	$ATaGlanceHTML += New-AtAGlancecard -Enabled ((Get-Date $BDRDevice.servicePeriod) -gt (Get-Date)) -PanelContent "Active Service Plan" -ImageURL $ImageURLs["Active Service Plan"] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ("Active Service Plan" -in $SquareImages) $true $false)
	$AdditionalDetails = "<span>Available: $($LocalStorageAvailable)</span><br /><span>$($LocalStorageUsed) / $($LocalStorageTotal)</span><br /><span>Cloud Used: $($OffsiteStorageUsed)</span>"
	$PanelShading = if ($LocalStorageUsedPercentage -ge 95) {
		'danger'
	} elseif ($LocalStorageUsedPercentage -gt 75) {
		'warning'
	} else {
		'success'
	}
	$ATaGlanceHTML += New-AtAGlancecard -Enabled ($LocalStorageUsedPercentage -ge 98) -PanelShadingOverride $true -PanelShading $PanelShading -PanelContent "Storage Used" -ImageURL $ImageURLs["Storage Used"] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ("Storage Used" -in $SquareImages) $true $false)

	$AdditionalDetails = "Failed: $FailedBackups <br /> Bad Verification: $BadVerificationBackups"
	if ($FailedBackups -gt 0) {
		$PanelShading = 'danger'
		$PanelContent = 'Failed Backups'
	} elseif ($BadVerificationBackups -gt 0 -or $BadScreenshotBackups -gt 0) {
		$PanelShading = 'warning'
		$PanelContent = 'Unverified Backups'
		if ($BadScreenshotBackups -gt 0 -and $BadVerificationBackups -eq 0) {
			$PanelContent += ' (Screenshots)'
		}
	} else {
		$PanelShading = 'success'
		$PanelContent = 'All Backups OK'
		$AdditionalDetails = ""
	}
	$ATaGlanceHTML += New-AtAGlancecard -Enabled ($FailedBackups -gt 0) -PanelShadingOverride $true -PanelShading $PanelShading -PanelContent $PanelContent -ImageURL $ImageURLs["BackupsCondition"] -PanelAdditionalDetail $AdditionalDetails -SquareIcon (IIf ("BackupsCondition" -in $SquareImages) $true $false)

	$ATaGlanceHTML += "<div class=`"col-sm-12`"><div class=`"panel`"><div class=`"panel-body`">BDR Remote URL: <a href='$($BDRDevice.remoteWebUrl)'>$($BDRDevice.remoteWebUrl)</a></div></div></div>"

	$FlexAssetBody = 
	@{
		type = 'flexible-assets'
		attributes = @{
			'organization-id' = $OrgID
			'flexible-asset-type-id' = $FilterID.id
			traits = @{
				"backup-type" = "Datto - BCDR"
				"backup-solution-name" = $BDRDevice.name
				"at-a-glance" = ($ATaGlanceHTML | Out-String)
				"recent-alerts" = ($RecentAlertsHTML | Out-String)

				"backup-frequency" = $BackupFrequency
				"protected-servers" = @(($ITGDevices.id | Sort-Object -Unique))

				"bdr-device" = @($BDRITGDevice.id)
				"backup-location" = $BDRDevice.remoteWebUrl
				"serial" = $BDRDevice.serialNumber
				"bdr-ip" = $BDRDevice.internalIP

				"offsite-service" = "Datto"
				"offsite-provider" = "Datto"
				'offsite-retention-period' = $CloudRetention

				"protected-device-details" = ($BDRDeviceServersHTML | Out-String)
			}
		}
	}
	
	# Filter out empty values
	($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
		$FlexAssetBody.attributes.traits.Remove($_.Name) 
	}

	write-host "Documenting $($BDRDevice.name) to IT-Glue"  -ForegroundColor Green
	$ExistingFlexAssets = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $($FilterID.ID) -filter_organization_id $OrgID).data
	$ExistingFlexAsset = $ExistingFlexAssets | Where-Object { $_.attributes.traits.'backup-solution-name' -eq $BDRDevice.name -and $_.attributes.traits.'serial' -eq $BDRDevice.serialNumber  }

	#If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just upload.
	if (!$ExistingFlexAsset) {
		Write-Host "  Creating Backup Solution into IT-Glue organizsation $OrgID" -ForegroundColor Green
		New-ITGlueFlexibleAssets -data $FlexAssetBody
	} else {
		Write-Host "  Editing Backup Solution in IT-Glue organization $OrgID" -ForegroundColor Green
		$ExistingFlexAsset = $ExistingFlexAsset[-1]

		if ($ExistingFlexAsset.attributes.traits.'bdr-ip' -and $ExistingFlexAsset.attributes.traits.'bdr-ip' -like "*$($BDRDevice.internalIP)*") {
			# Keep the original ip if it at least contains the correct bdr IP so we can customize this field.
			# Some BDR's have more than 1 IP and we only get data on the first from the API
			$FlexAssetBody.attributes.traits.'bdr-ip' = $ExistingFlexAsset.attributes.traits.'bdr-ip'
		}

		foreach ($trait in $ExistingFlexAsset.attributes.traits.PSObject.Properties) {
			$traitName = $trait.Name
			$traitValue = $trait.Value
			# If any existing fields have tagged assets, we need to extract the id's and replace the values with those
			if ($traitValue -is [System.Object] -and $traitValue.PSobject.Properties.Name -contains "type") {
				$traitValue = $traitValue.values.id
			}
	
			# If the updated body doesn't already have this field filled with new data, add the existing data
			if (!$FlexAssetBody.attributes.traits.ContainsKey($traitName) -or !$FlexAssetBody.attributes.traits.$traitName) {
				$FlexAssetBody.attributes.traits.$traitName = $traitValue
			}
		}

		Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
	}
}
Write-Progress -Activity "Updating ITG Backup pages" -Status "Ready" -Completed