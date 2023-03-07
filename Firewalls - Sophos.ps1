###
# File: \Firewalls - Sophos.ps1
# Project: AutoDoc
# Created Date: Tuesday, February 14th 2023, 11:56:58 am
# Author: Chris Jantzen
# -----
# Last Modified: Tue Mar 07 2023
# Modified By: Chris Jantzen
# -----
# Copyright (c) 2023 Sea to Sky Network Solutions
# License: MIT License
# -----
# 
# HISTORY:
# Date      	By	Comments
# ----------	---	----------------------------------------------------------
# 2023-03-07	CJ	Modified to update external IPs
###

#####################################################################
$APIKEy =  "<ITG API KEY>"
$APIEndpoint = "<ITG API URL>"
$LastUpdatedUpdater_APIURL = "<LastUpdatedUpdater API URL>"
$Sophos_ClientID = "<SOPHOS API CLIENT ID>"
$Sophos_ClientSecret = "<SOPHOS API CLIENT SECRET>"
$ITGlue_Base_URI = "https://sts.itglue.com"
$FlexAssetName = "Firewall"
$FirewallConfigType = 33
$ConfigurationStatusID = 22
$SophosManufacturerID = 11
$LocationIPsLocation = "<PATH TO Device Audit LocationIPs Folder>" # These are exported by the device audit and will be used to match WAN info to external IPs

$IgnoreExternalIPs = @() # If the external IP is one of these, dont use it (for local office or VPN ips, or somewhere it might be setup)
$Orgs_PreventConfigCreation = @("") # The Sophos name or ID of any organizations you don't want to automatically add ITG configs for
#####################################################################
$IPRegex = "\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(-(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)?)?(\/[1-3][0-9])?\b"

# Ensure they are using the latest TLS version
$CurrentTLS = [System.Net.ServicePointManager]::SecurityProtocol
if ($CurrentTLS -notlike "*Tls12" -and $CurrentTLS -notlike "*Tls13") {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	Write-Host "This device is using an old version of TLS. Temporarily changed to use TLS v1.2."
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

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

# Get the flexible asset type ids
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data

# Sophos connection functions
$Global:SophosJWT = $false
function Sophos_Authenticator {
    try {
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Content-Type", "application/x-www-form-urlencoded")
        $body = "grant_type=client_credentials&client_id=$Sophos_ClientID&client_secret=$Sophos_ClientSecret&scope=token"
        $response = Invoke-RestMethod 'https://id.sophos.com/api/v2/oauth2/token' -Method 'POST' -Headers $headers -Body $body
		$response | Add-Member -NotePropertyName expiry -NotePropertyValue $null
		$response.expiry = (Get-Date).AddSeconds($response.expires_in - 60)
		$Global:SophosJWT = 'Bearer ' + $response.access_token
        '[+] Bearer Token Received'
    }
    catch {
        '[-] Problem in getting Bearer Token Using function = Sophos_Authenticator'
    }
}

$Global:SophosPartnerID = $false
function Get_Sophos_Partner_ID {
    try{
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add('Authorization', $Global:SophosJWT)
        $response = Invoke-RestMethod 'https://api.central.sophos.com/whoami/v1' -Method 'GET' -Headers $headers
        $Global:SophosPartnerID = $response.id
        '[+] Authorization Successfull'
    }
    catch {
        '[-] Authorization Failed using function = Get_Sophos_Partner_ID'      
    }

}

$Global:SophosTenants = $false
function Get_Sophos_Tenants {
	try {
		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add('Authorization', $Global:SophosJWT)
		$headers.Add('X-Partner-ID', $Global:SophosPartnerID)
		$response = Invoke-RestMethod 'https://api.central.sophos.com/partner/v1/tenants?pageTotal=true' -Method 'GET' -Headers $headers

		if ($response.pages -and $response.pages.total -gt 1) {
			$TotalPages = $response.pages.total
			for ($i = 2; $i -le $TotalPages; $i++) {
				$response.items += (Invoke-RestMethod "https://api.central.sophos.com/partner/v1/tenants?page=$i" -Method GET -Headers $headers).items
			}
		}
		$Global:SophosTenants = $response.items
		'[+] Got Tenant List'
	}
	catch {
		'[-] Could not get tenant list using function = Get_Sophos_Tenants'      
	}
}

function Get_Sophos_Firewalls($Tenant) {
	try {
		$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
		$headers.Add("X-Tenant-ID", $Tenant.id)
		$headers.Add("Accept", "application/json")
		$headers.Add("Authorization", $Global:SophosJWT)

		$response = Invoke-RestMethod "$($Tenant.apiHost)/firewall/v1/firewalls" -Method 'GET' -Headers $headers
		$response
	} 
	catch {
		Write-Warning "Could not get firewalls for tenant: $($Tenant.name)"
	}
}


# Connect to Sophos
Sophos_Authenticator
if ($Global:SophosJWT) {
    
    Get_Sophos_Partner_ID
    if ($Global:SophosPartnerID) {

		Get_Sophos_Tenants
		if (!$Global:SophosTenants) {
			Write-Error "Failed to Get Sophos Tenants. Exiting..."
			exit
		}
	} else {
		Write-Error "Failed to Get Sophos Partner ID. Exiting..."
		exit
	}
} else {
	Write-Error "Failed to Get Sophos JWT. Exiting..."
	exit
}

# Get a list of ITG organizations (we already got the Sophos tenants)
$ITGOrgs = 	Get-ITGlueOrganizations -page_size 1000
$ITGOrgs = $ITGOrgs.data | Where-Object { $_.attributes.'organization-type-name' -like 'Customer' -and $_.attributes.'organization-status-name' -like 'Active' }

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

# Match the ITG / Sophos organizations by name
$OrgMatches = @()
$MatchNotFound = @()
$DontMatch = @()

# Import and use existing matches if they exist
$AllMatches = @()
if (Test-Path -Path "sophos_matches.json" -PathType Leaf) {
	$AllMatches = Get-Content -Raw -Path "sophos_matches.json" | ConvertFrom-Json
}

# Start matching
$ChangesMadeToMatches = $false
foreach ($SophosTenant in $Global:SophosTenants) {
	$Match = $null
	
	# Check existing matches first
	if ($SophosTenant.id -in $AllMatches.sophosId) {
		$Match = $AllMatches | Where-Object { $_.sophosId -eq $SophosTenant.id }
		if ($Match.itgId) {
			# match found
			$OrgMatches += [pscustomobject]@{
				sophosId = $Match.sophosId
				sophosName = $Match.sophosName
				itgId = $Match.itgId
				itgName = $Match.itgName
			}
		} else {
			# not matched (manually)
			$DontMatch += @{
				sophosId = $Match.sophosId
				sophosName = $Match.sophosName
			}
		}

		continue
	}

	# No existing match, lets handle the matching
	$Matches = $ITGOrgs | Where-Object { 
		$_.attributes.name -like "*$($SophosTenant.name)*" -or $SophosTenant.name -like "*$($_.attributes.name)*" -or
		$_.attributes.name -like "*$($SophosTenant.showAs)*" -or $SophosTenant.showAs -like "*$($_.attributes.name)*"
	}
	if (($Matches | Measure-Object).Count -gt 1) {
		# narrow down to 1
		$Match = $Matches | Where-Object { $_.attributes.name -like $SophosTenant.name -or $SophosTenant.name -like $($_.attributes.name) }
		if (($Match | Measure-Object).Count -eq 0) {
			$Match = $Matches | Where-Object { $_.attributes.name -like $SophosTenant.showAs -or $SophosTenant.showAs -like $($_.attributes.name) }
		}
		if (($Match | Measure-Object).Count -ne 1) {
			$BestDistance = 999;
			foreach ($TestMatch in $Matches) {
				$Distance = Measure-StringDistance -Source $SophosTenant.name -Compare $TestMatch.attributes.name
				$Distance2 = Measure-StringDistance -Source $SophosTenant.showAs -Compare $TestMatch.attributes.namesophosName
				if ($Distance2 -lt $Distance) {
					$Distance = $Distance2
				}

				if ($Distance -lt $BestDistance) {
					$Match = $TestMatch
					$BestDistance = $Distance
				}
			}
		}
	} elseif (($Matches | Measure-Object).Count -eq 1) {
		$Match = $Matches[0]
	}

	$SophosFullName = $SophosTenant.name.Trim()
	if ($SophosTenant.showAs -and $SophosTenant.showAs.Trim() -ne $SophosTenant.name.Trim()) {
		$SophosFullName += " ($($SophosTenant.showAs.Trim()))"
	}
	
	if ($Match) {
		# match found
		$OrgMatches += [pscustomobject]@{
			sophosId = $SophosTenant.id
			sophosName = $SophosFullName
			itgId = $Match.id
			itgName = $Match.attributes.name
		}
	} else {
		# no match found
		$MatchNotFound += @{
			sophosId = $SophosTenant.id
			sophosName = $SophosFullName
		}
	}
	$ChangesMadeToMatches = $true
}

# Use a form to allow manual matching of any orgs we couldn't auto match
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

		$var_lblOrgName.Content = $MissingMatch.sophosName
		$var_lblMatchingNotes.Content = "Sophos ID: $($MissingMatch.sophosId)"

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
			Write-Host "Organization skipped! ($($MissingMatch.sophosName))"
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
				sophosId = $MissingMatch.sophosId
				sophosName = $MissingMatch.sophosName
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
			sophosId = $_.sophosId
			sophosName = $_.sophosName
			itgId = $null
			itgName = $null
		}
	}

	$AllMatches | ConvertTo-Json | Out-File "sophos_matches.json"
}

if ($DontMatch) {
	Write-Output "Some sophos orgs have been manually set to no match with ITG!"
	Write-Output "If you need to match these, please edit the sophos_matches.json file manually."
}

# Get Firewalls from ITG
$ITGFirewalls = (Get-ITGlueFlexibleAssets -page_size 1000 -filter_flexible_asset_type_id $FilterID.id).data

# Get Sophos models from ITG
$ITGSophosModels = (Get-ITGlueModels -manufacturer_id $SophosManufacturerID -page_size 1000).data

if (!$ITGFirewalls -or !$ITGSophosModels) {
	Write-Error "Could not get ITG Firewalls or ITG Sophos Models"
	exit
}

# Get the Firewalls flexible asset fields so we can ensure the model is an existing choice
$Firewall_FAFields = (Get-ITGlueFlexibleAssetFields -flexible_asset_type_id $FilterID.id).data
$FAModelFieldID = ($Firewall_FAFields | Where-Object { $_.attributes.name -like "Model" }).id
$FAModelOptions = ($Firewall_FAFields | Where-Object { $_.attributes.name -like "Model" }).attributes."default-value" -split "\n"

function Add-FAModelField($Model) {
	if ($Global:FAModelFieldID -and $Global:FAModelOptions) {
		$Global:FAModelOptions += $Model
		$NewModels = ($Global:FAModelOptions | Sort-Object) -join "`n"

		$Update = 
		@{
			type = 'flexible-asset-fields'
			attributes = @{
				'default-value' = $NewModels
			}
		}
		try {
			$UpdatedFA = Set-ITGlueFlexibleAssetFields -flexible_asset_type_id $Global:FilterID.id -id $Global:FAModelFieldID -data $Update
			if ($UpdatedFA -and $UpdatedFA.data -and ($UpdatedFA.data | Where-Object { $_.id -eq $Global:FAModelFieldID }).attributes.'default-value' -like "*$($Model)*") {
				return $true
			}
		} catch {
			Write-Warning "Could not update the Firewall FA Models field with the new model: $($Model)"
		}
		return $false
	}
}

# All matches made, now lets go through the Sophos tenants and see which have firewalls
foreach ($Match in $AllMatches) {
	$SophosTenant = $SophosTenants | Where-Object { $_.id -eq $Match.sophosId }
	$TenantsFirewalls = Get_Sophos_Firewalls -Tenant $SophosTenant

	if (!$TenantsFirewalls -or !$TenantsFirewalls.items -or ($TenantsFirewalls.items | Measure-Object).count -lt 1) {
		continue
	}

	$LocationIPs = $false
	if ($LocationIPsLocation -and (Test-Path $LocationIPsLocation)) {
		$ITGOrg = (Get-ITGlueOrganizations -filter_id $Match.itgId).data | Select-Object -First 1
		$Company_Acronym = $ITGOrg.attributes.'short-name'
		
		$LocationIPsPath = "$($LocationIPsLocation)\$($Company_Acronym)_location_ips.json"
		if (Test-Path -Path $LocationIPsPath -PathType Leaf) {
			$LocationIPs = Get-Content -Path $LocationIPsPath -Raw | ConvertFrom-Json
		}
	}

	$ITGPasswords = $false

	# This tenant has firewalls, lets handle the documentation of them
	foreach ($Firewall in $TenantsFirewalls.items) {
		$OrgFirewalls = $ITGFirewalls | Where-Object { $_.attributes.'organization-id' -eq $Match.itgId }
		$ITGFirewall = $OrgFirewalls | Where-Object { $_.attributes.traits.'serial-number' -and $_.attributes.traits.'serial-number'.Trim() -like $Firewall.serialNumber }
		if (!$ITGFirewall) {
			$ITGFirewall = $OrgFirewalls | Where-Object { $_.attributes.traits.name -and ($_.attributes.traits.name.Trim() -like $Firewall.hostname -or $_.attributes.traits.name.Trim() -like $Firewall.name) }
		}
		if (!$ITGFirewall) {
			$ITGFirewall = $OrgFirewalls | Where-Object { $_.attributes.traits.name -and ($_.attributes.traits.name.Trim() -like "$($Firewall.hostname) *" -or $_.attributes.traits.name.Trim() -like "$($Firewall.name) *") }
		}

		# Narrow down if more than 1
		if (($ITGFirewall | Measure-Object).Count -gt 1) {
			$ITGFirewall_Temp = $ITGFirewall | Where-Object { $_.attributes.traits.name -and ($_.attributes.traits.name.Trim() -like $Firewall.hostname -or $_.attributes.traits.name.Trim() -like $Firewall.name) }
			if (($ITGFirewall_Temp | Measure-Object).Count -gt 0) {
				$ITGFirewall = $ITGFirewall_Temp
			}
		}
		if (($ITGFirewall | Measure-Object).Count -gt 1) {
			$ITGFirewall_Temp = $ITGFirewall | Where-Object { $_.attributes.traits.name -and ($_.attributes.traits.name.Trim() -like "$($Firewall.hostname) *" -or $_.attributes.traits.name.Trim() -like "$($Firewall.name) *") }
			if (($ITGFirewall_Temp | Measure-Object).Count -gt 0) {
				$ITGFirewall = $ITGFirewall_Temp
			}
		}
		if (($ITGFirewall | Measure-Object).Count -gt 1) {
			$ITGFirewall = $ITGFirewall | Sort-Object -Property {$_.attributes.'updated-at'} -Descending | Select-Object -First 1
		}

		# If this is a cluster, only add the serial number of the auxiliary FW
		$AuxCluster = $false
		$PrimaryCluster = $false
		if ($Firewall.cluster) {
			$ClusterCount = ($TenantsFirewalls.items | Where-Object { $_.cluster.id -eq $Firewall.cluster.id } | Measure-Object).Count
			if ($Firewall.cluster.status -eq "auxiliary") {
				$AuxCluster = $true
				if (!$ITGFirewall) {
					# If this is an auxiliary firewall, dont create a new one, just update an existing
					continue
				}
			} else {
				$PrimaryCluster = $true
			}
		}

		if ($ITGFirewall) {
			## UPDATE
			# Found a firewall, lets update it
			$Name = $ITGFirewall.attributes.traits.name
			if (!$AuxCluster -and $Name -notlike "*$($Firewall.hostname)*" -and $Name -notlike "*$($Firewall.name)*") {
				if ($Firewall.hostname -notlike $Firewall.serialNumber) {
					$Name = $Firewall.hostname
				} else {
					$Name = $Firewall.name
				}
			}

			$FlexAssetBody = 
			@{
				type = 'flexible-assets'
				attributes = @{
					'organization-id' = $Match.itgId
					'flexible-asset-type-id' = $FilterID.id
					traits = @{
						"name" = $Name
						"location" = @()
						"configuration-item" = @()
						"model" = $ITGFirewall.attributes.traits.model
						"serial-number" = $ITGFirewall.attributes.traits."serial-number"
						"sts-asset-tag" = $ITGFirewall.attributes.traits."sts-asset-tag"
						"notes" = ""

						"external-ip" = $ITGFirewall.attributes.traits."external-ip"
						"internal-ip" = $ITGFirewall.attributes.traits."internal-ip"
						"dynamic-dns-hostname" = $ITGFirewall.attributes.traits."dynamic-dns-hostname"
						"cloud-managed" = "Sophos Cloud"
						"password" = @()
						"extra-details" = $ITGFirewall.attributes.traits."extra-details"

						"monthly-rental" = $ITGFirewall.attributes.traits."monthly-rental"
						"license-type" = $ITGFirewall.attributes.traits."license-type"
						"firewall-licenses" = @()
						"license-expiry" = $ITGFirewall.attributes.traits."license-expiry"

						"ssl-vpn-license-count" = $ITGFirewall.attributes.traits."ssl-vpn-license-count"
						"ssl-vpn-licenses" = @()
						"ssl-vpn-info" = @()
					}
				}
			}

			$Notes = $ITGFirewall.attributes.traits.notes
			if ($PrimaryCluster) {
				if ($Notes -notlike "*This is a Firewall Cluster*") {
					$Notes += "<div><span><strong>This is a Firewall Cluster of $($ClusterCount) devices</strong></span></div>"
				}
				# update the s/n if this is a primary cluster, in case it's set to the auxilary FW's s/n
				$FlexAssetBody.attributes.traits."serial-number" = $Firewall.serialNumber
			}
			if (!$AuxCluster) {
				if ($Firewall.status.suspended -and $Notes -notlike "*Suspended*") {
					$Notes += '<div><span style="color:#ff0000;"><strong>Suspended</strong></span></div>'
				} elseif (!$Firewall.status.suspended -and $Notes -like "*Suspended*") {
					$Notes = $Notes -replace "Suspended", ""
				}
			} else {
				if ($Notes -notlike "*Auxilary FW '$($Firewall.name)' S/N:*") {
					$Notes += "<div><span>Auxilary FW '$($Firewall.name)' S/N: $($Firewall.serialNumber)</span></div>"
				}
			}
			$FlexAssetBody.attributes.traits."notes" = $Notes

			# Add any firewall licenses
			if ($ITGFirewall.attributes.traits."firewall-licenses" -and $ITGFirewall.attributes.traits."firewall-licenses".values) {
				$FlexAssetBody.attributes.traits."firewall-licenses" = @($ITGFirewall.attributes.traits."firewall-licenses".values.id)
			}
			# Add any ssl vpn licenses or info items
			if ($ITGFirewall.attributes.traits."ssl-vpn-licenses" -and $ITGFirewall.attributes.traits."ssl-vpn-licenses".values) {
				$FlexAssetBody.attributes.traits."ssl-vpn-licenses" = @($ITGFirewall.attributes.traits."ssl-vpn-licenses".values.id)
			}
			if ($ITGFirewall.attributes.traits."ssl-vpn-info" -and $ITGFirewall.attributes.traits."ssl-vpn-info".values) {
				$FlexAssetBody.attributes.traits."ssl-vpn-info" = @($ITGFirewall.attributes.traits."ssl-vpn-info".values.id)
			}

			if (!$AuxCluster) {
				# See if we should update the external IP
				$GoodExternalIPs = $Firewall.externalIpv4Addresses | Where-Object { $_ -notin $IgnoreExternalIPs }
				if ($GoodExternalIPs) {
					$DoUpdateIPs = $false
					foreach ($IP in $GoodExternalIPs) {
						if ($ITGFirewall.attributes.traits.'external-ip' -notlike "*$($IP)*") {
							$DoUpdateIPs = $true
							break
						}
					}
					if ($DoUpdateIPs) {
						$NewFormattedIPs = @($GoodExternalIPs | ForEach-Object { "https://" + $_ + ":4444" })
						$FlexAssetBody.attributes.traits.'external-ip' = $NewFormattedIPs -join " / "
					}
				}

				# See if we can update the location
				if ($FlexAssetBody.attributes.traits.'external-ip' -and $LocationIPs) {
					$IPMatches = ([regex]$IPRegex).Matches($FlexAssetBody.attributes.traits.'external-ip')
					$ExternalIPs = @($IPMatches.Value)
					if ($ExternalIPs -and ($ExternalIPs | Measure-Object).Count -gt 0) {
						$PossibleLocations = @()
						foreach ($ExternalIP in $ExternalIPs) {
							$PossibleLocations += $LocationIPs | Where-Object { $_.ExternalIPs -contains $ExternalIP }
						}

						if ($PossibleLocations -and $ITGFirewall.attributes.traits.location -and $ITGFirewall.attributes.traits.location.values) {
							$Overlap = $false
							$ITGFirewall.attributes.traits.location.values | Foreach-Object { 
								if ($_.id -in $PossibleLocations.ITGLocation) {
									$Overlap = $true
								}
							}
							if ($Overlap) {
								$FlexAssetBody.attributes.traits.location = @($ITGFirewall.attributes.traits.location.values.id)
							}
						} elseif (($PossibleLocations | Measure-Object).Count -gt 1) {
							# More than 1 possible location, narrow down
							$ITGFirewall.attributes.traits.'internal-ip' -match $IPRegex
							$InternalIP = $Matches[0]
							if ($InternalIP -in $PossibleLocations.InternalIPs) {
								$PossibleLocations = $PossibleLocations | Where-Object { $_.InternalIPs -contains $InternalIP }
							}
							$FlexAssetBody.attributes.traits.location = @($PossibleLocations.ITGLocation)
						} elseif ($PossibleLocations) {
							$FlexAssetBody.attributes.traits.location = @($PossibleLocations.ITGLocation)
						}
					}
				}
				if (!$FlexAssetBody.attributes.traits.location -and $ITGFirewall.attributes.traits.location -and $ITGFirewall.attributes.traits.location.values) {
					$FlexAssetBody.attributes.traits.location = @($ITGFirewall.attributes.traits.location.values.id)
				}

				# See if we can find any related configuration (if not set)
				if (!$ITGFirewall.attributes.traits."configuration-item" -or !$ITGFirewall.attributes.traits."configuration-item".values) {
					$RelatedConfigurations = Get-ITGlueConfigurations -organization_id $Match.itgId -filter_serial_number $Firewall.serialNumber
					if (!$RelatedConfigurations -or !$RelatedConfigurations.data) {
						$RelatedConfigurations = Get-ITGlueConfigurations -organization_id $Match.itgId -filter_name $Firewall.hostname
					}
					$RelatedConfigurations = $RelatedConfigurations.data

					# Narrow down if more than 1
					if (($RelatedConfigurations | Measure-Object).Count -gt 1) {
						$RelatedConfigurations_Temp = $RelatedConfigurations | Where-Object { 
							($_.attributes.name -like $Firewall.hostname -or $_.attributes.hostname -like $Firewall.hostname -or
							$_.attributes.name -like $Firewall.name -or $_.attributes.hostname -like $Firewall.name) -and
							$_.attributes.'serial-number' -like $Firewall.serialNumber
						}
						if (($RelatedConfigurations_Temp | Measure-Object).Count -gt 0) {
							$RelatedConfigurations = $RelatedConfigurations_Temp
						}
					}
					if (($RelatedConfigurations | Measure-Object).Count -gt 1) {
						$RelatedConfigurations_Temp = $RelatedConfigurations | Where-Object { 
							$_.attributes.name -like $Firewall.hostname -or $_.attributes.hostname -like $Firewall.hostname -or
							$_.attributes.name -like $Firewall.name -or $_.attributes.hostname -like $Firewall.name
						}
						if (($RelatedConfigurations_Temp | Measure-Object).Count -gt 0) {
							$RelatedConfigurations = $RelatedConfigurations_Temp
						}
					}
					if (($RelatedConfigurations | Measure-Object).Count -gt 1) {
						$RelatedConfigurations_Temp = $RelatedConfigurations | Where-Object { $_.attributes.'serial-number' -like $Firewall.serialNumber }
						if (($RelatedConfigurations_Temp | Measure-Object).Count -gt 0) {
							$RelatedConfigurations = $RelatedConfigurations_Temp
						}
					}

					$FlexAssetBody.attributes.traits."configuration-item" = @($RelatedConfigurations.id)
				} else {
					$FlexAssetBody.attributes.traits."configuration-item" = @($ITGFirewall.attributes.traits."configuration-item".values.id)
				}

				# See if we can find any related passwords (if not set)
				if (!$ITGFirewall.attributes.traits."password" -or !$ITGFirewall.attributes.traits."password".values) {
					# Get all passwords for filtering if we haven't already
					if (!$ITGPasswords) {
						$ITGPasswords = Get-ITGluePasswords -page_size 1000 -organization_id $Match.itgId
						$i = 1
						while ($ITGPasswords.links.next) {
							$i++
							$Passwords_Next = Get-ITGluePasswords -page_size 1000 -page_number $i -organization_id $Match.itgId
							$ITGPasswords.data += $Passwords_Next.data
							$ITGPasswords.links = $Passwords_Next.links
						}
						if ($ITGPasswords -and $ITGPasswords.data) {
							$ITGPasswords = $ITGPasswords.data
						}
					}

					$RelatedPasswords = $ITGPasswords | Where-Object { $_.attributes.name -like "*$($Firewall.hostname)*" -or $_.attributes.name -like "*$($Firewall.name)*" }
					if ($FlexAssetBody.attributes.traits."external-ip" -and !$RelatedPasswords) {
						$RelatedPasswords = $ITGPasswords | Where-Object { $_.attributes.url -like "$($FlexAssetBody.attributes.traits."external-ip".Trim())" }

						if (!$RelatedPasswords) {
							$IPMatches = ([regex]$IPRegex).Matches($FlexAssetBody.attributes.traits.'external-ip')
							$ExternalIPs = @($IPMatches.Value)
							if ($ExternalIPs) {
								$RelatedPasswords = @()
								foreach ($ExternalIP in $ExternalIPs) {
									$RelatedPasswords += $ITGPasswords | Where-Object { $_.attributes.url -like "*$($ExternalIP)*" }
								}
							}
						}
					}
					
					if ($RelatedPasswords) {
						$FlexAssetBody.attributes.traits."password" = @($RelatedPasswords.id)
					}
				} else {
					$FlexAssetBody.attributes.traits."password" = @($ITGFirewall.attributes.traits."password".values.id)
				}

				# If the model is not set, try setting it
				if (!$ITGFirewall.attributes.traits.model) {
					$ModelCode = ($Firewall.firmwareVersion -split '_')[0]
					$ModelCode -match "^(.+?)(\d+.*)$"
					$Model = $Matches[1] + " " + $Matches[2]
					if ("Sophos $($Model)" -in $FAModelOptions) {
						$FlexAssetBody.attributes.traits.model = "Sophos $($Model)"
					} else {
						# Model is not an option, try to add it
						$Success = Add-FAModelField -Model "Sophos $($Model)"
						if (!$Success) {
							Write-Host "Could not set the model: Sophos $($Model)" -ForegroundColor Red
						}
					}
				}

				# If there is a related configuration, update it as well
				if ($ITGFirewall.attributes.traits."configuration-item" -and $ITGFirewall.attributes.traits."configuration-item".values) {
					foreach ($Config in $ITGFirewall.attributes.traits."configuration-item".values) {
						if ($Config.name.Trim() -like $Name -or ($Config.'serial-number' -and $Config.'serial-number'.Trim() -like $ITGFirewall.attributes.traits."serial-number")) {
							$ITGModel = $ITGSophosModels | Where-Object { $_.attributes.name -like ($FlexAssetBody.attributes.traits.model -replace "Sophos ", '') } | Select-Object -First 1
							$UpdatedConfigData = 
							@{
								type = 'configurations'
								attributes = @{
									'name' = $Name
									'serial-number' = $Firewall.serialNumber
									'hostname' = $Firewall.hostname

									'configuration-type-id' = $FirewallConfigType
									'manufacturer-id' = $SophosManufacturerID
									'model-id' = if ($ITGModel) { $ITGModel.id } else { '' }
									'location-id' = ''
								}
							}

							if ($FlexAssetBody.attributes.traits.location) {
								$UpdatedConfigData.attributes.'location-id' = $FlexAssetBody.attributes.traits.location[0]
							}

							($UpdatedConfigData.attributes.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
								$UpdatedConfigData.attributes.Remove($_.Name) 
							}

							# Update configuration
							try {
								$UpdatedConfig = Set-ITGlueConfigurations -id $Config.id -data $UpdatedConfigData
								if ($UpdatedConfig) {
									Write-Host "Updated Configuration: $($Name) (Org: $($Match.itgName)) (ID: $($Config.id))" -ForegroundColor DarkYellow
								}
							} catch {
								Write-Warning "Could not update configuration: $($Name)"
							}
						}
					}
				}
			} else {
				# This is an auxiliary FW in a cluster, dont update
				if ($ITGFirewall.attributes.traits.location -and $ITGFirewall.attributes.traits.location.values) {
					$FlexAssetBody.attributes.traits.location = @($ITGFirewall.attributes.traits.location.values.id)
				}
				if ($ITGFirewall.attributes.traits."configuration-item" -and $ITGFirewall.attributes.traits."configuration-item".values) {
					$FlexAssetBody.attributes.traits."configuration-item" = @($ITGFirewall.attributes.traits."configuration-item".values.id)
				}
				if ($ITGFirewall.attributes.traits.password -and $ITGFirewall.attributes.traits.password.values) {
					$FlexAssetBody.attributes.traits.password = @($ITGFirewall.attributes.traits.password.values.id)
				}
			}
			
			# Filter out empty values
			($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
				$FlexAssetBody.attributes.traits.Remove($_.Name) 
			}

			Set-ITGlueFlexibleAssets -id $ITGFirewall.id -data $FlexAssetBody
			Write-Host "Updated Firewall: $($Name) (Org: $($Match.itgName))" -ForegroundColor Yellow
		} else {
			## NEW
			if ($Match.sophosName -in $Orgs_PreventConfigCreation -or $Match.sophosId -in $Orgs_PreventConfigCreation -or $Match.itgName -in $Orgs_PreventConfigCreation -or $Match.itgId -in $Orgs_PreventConfigCreation) {
				Write-Host "Skipping firewall creation: $($Firewall.hostname) (Org: $($Match.itgName)) (Org Ignored)" -ForegroundColor Yellow
				continue
			}

			if ($Firewall.status.suspended -or !$Firewall.status.connected) {
				# FW is suspended or not connected, lets skip creating it
				if ($Firewall.status.suspended) {
					Write-Host "Skipping firewall creation: $($Firewall.hostname) (Org: $($Match.itgName)) (Suspended)" -ForegroundColor Yellow
				} else {
					Write-Host "Skipping firewall creation: $($Firewall.hostname) (Org: $($Match.itgName)) (Not Connected)" -ForegroundColor Yellow
				}
				continue
			}

			# Create a new firewall entry
			$ModelCode = ($Firewall.firmwareVersion -split '_')[0]
			$ModelCode -match "^(.+?)(\d+.*)$"
			$Model = $Matches[1] + " " + $Matches[2]

			if ($Firewall.hostname -notlike $Firewall.serialNumber) {
				$Name = $Firewall.hostname
			} else {
				$Name = $Firewall.name
			}

			$FlexAssetBody = 
			@{
				type = 'flexible-assets'
				attributes = @{
					'organization-id' = $Match.itgId
					'flexible-asset-type-id' = $FilterID.id
					traits = @{
						"name" = $Name
						"location" = @()
						"configuration-item" = @()
						"model" = ""
						"serial-number" = $Firewall.serialNumber

						"external-ip" = ($Firewall.externalIpv4Addresses | Where-Object { $_ -notin $IgnoreExternalIPs }) -join ", "
						"cloud-managed" = "Sophos Cloud"
						"password" = @()

						"ssl-vpn-license-count" = 999
					}
				}
			}

			if ("Sophos $($Model)" -in $FAModelOptions) {
				$FlexAssetBody.attributes.traits.model = "Sophos $($Model)"
			} else {
				# Model is not an option, try to add it
				$Success = Add-FAModelField -Model "Sophos $($Model)"
				if (!$Success) {
					Write-Host "Could not set the model: Sophos $($Model)" -ForegroundColor Red
				}
			}

			# Get location
			if ($Firewall.externalIpv4Addresses -and $LocationIPs) {
				$PossibleLocations = @()
				foreach ($ExternalIP in $Firewall.externalIpv4Addresses) {
					if ($ExternalIP -in $IgnoreExternalIPs) {
						continue
					}
					$PossibleLocations += $LocationIPs | Where-Object { $_.ExternalIPs -contains $ExternalIP }
				}

				if ($PossibleLocations) {
					$FlexAssetBody.attributes.traits.location = @($PossibleLocations.ITGLocation)
				}
			}

			# Get all passwords for filtering if we haven't already
			if (!$ITGPasswords) {
				$ITGPasswords = Get-ITGluePasswords -page_size 1000 -organization_id $Match.itgId
				$i = 1
				while ($ITGPasswords.links.next) {
					$i++
					$Passwords_Next = Get-ITGluePasswords -page_size 1000 -page_number $i -organization_id $Match.itgId
					$ITGPasswords.data += $Passwords_Next.data
					$ITGPasswords.links = $Passwords_Next.links
				}
				if ($ITGPasswords -and $ITGPasswords.data) {
					$ITGPasswords = $ITGPasswords.data
				}
			}

			# See if we can find any related passwords
			$RelatedPasswords = $ITGPasswords | Where-Object { $_.attributes.name -like "*$($Firewall.hostname)*" -or $_.attributes.name -like "*$($Firewall.name)*" }
			if ($Firewall.externalIpv4Addresses -and !$RelatedPasswords) {
				$RelatedPasswords = @()
				foreach ($ExternalIP in $Firewall.externalIpv4Addresses) {
					if ($ExternalIP -in $IgnoreExternalIPs) {
						continue
					}
					$RelatedPasswords += $ITGPasswords | Where-Object { $_.attributes.url -like "*$($ExternalIP.Trim())*" }
				}
			}
			if ($RelatedPasswords) {
				$FlexAssetBody.attributes.traits."password" = @($RelatedPasswords.id)
			}

			# See if we can find any related configuration, if not, create a new one
			$RelatedConfigurations = Get-ITGlueConfigurations -organization_id $Match.itgId -filter_serial_number $Firewall.serialNumber
			if (!$RelatedConfigurations -or !$RelatedConfigurations.data) {
				$RelatedConfigurations = Get-ITGlueConfigurations -organization_id $Match.itgId -filter_name $Firewall.hostname
			}
			$RelatedConfigurations = $RelatedConfigurations.data

			if ($RelatedConfigurations) {
				# Narrow down if more than 1
				if (($RelatedConfigurations | Measure-Object).Count -gt 1) {
					$RelatedConfigurations_Temp = $RelatedConfigurations | Where-Object { 
						($_.attributes.name -like $Firewall.hostname -or $_.attributes.hostname -like $Firewall.hostname -or
						$_.attributes.name -like $Firewall.name -or $_.attributes.hostname -like $Firewall.name) -and
						$_.attributes.'serial-number' -like $Firewall.serialNumber
					}
					if (($RelatedConfigurations_Temp | Measure-Object).Count -gt 0) {
						$RelatedConfigurations = $RelatedConfigurations_Temp
					}
				}
				if (($RelatedConfigurations | Measure-Object).Count -gt 1) {
					$RelatedConfigurations_Temp = $RelatedConfigurations | Where-Object { 
						$_.attributes.name -like $Firewall.hostname -or $_.attributes.hostname -like $Firewall.hostname -or
						$_.attributes.name -like $Firewall.name -or $_.attributes.hostname -like $Firewall.name
					}
					if (($RelatedConfigurations_Temp | Measure-Object).Count -gt 0) {
						$RelatedConfigurations = $RelatedConfigurations_Temp
					}
				}
				if (($RelatedConfigurations | Measure-Object).Count -gt 1) {
					$RelatedConfigurations_Temp = $RelatedConfigurations | Where-Object { $_.attributes.'serial-number' -like $Firewall.serialNumber }
					if (($RelatedConfigurations_Temp | Measure-Object).Count -gt 0) {
						$RelatedConfigurations = $RelatedConfigurations_Temp
					}
				}

				$FlexAssetBody.attributes.traits."configuration-item" = @($RelatedConfigurations.id)
			} else {
				# No existing configuration, create a new one
				$ITGModel = $ITGSophosModels | Where-Object { $_.attributes.name -like $Model }
				if (!$ITGModel) {
					$ITGModel = $ITGSophosModels | Where-Object { $_.attributes.name -like $ModelCode }
				}
				if (!$ITGModel) {
					$NewModelData = @{
						type = "models"
						attributes = @{
							name = $Model
							"manufacturer-id" = $SophosManufacturerID
						}
					}
					$ITGModel = New-ITGlueModels -manufacturer_id $SophosManufacturerID -data $NewModelData

					if ($ITGModel -and $ITGModel.data) {
						$ITGModel = $ITGModel.data[0]
						$ITGSophosModels += $ITGModel
					} else {
						$ITGModel = $false
					}
				}

				$NewConfigData = 
				@{
					type = 'configurations'
					attributes = @{
						'name' = $Name
						'serial-number' = $Firewall.serialNumber
						'hostname' = $Firewall.hostname

						'configuration-type-id' = $FirewallConfigType
						'configuration-status-id' = $ConfigurationStatusID
						'manufacturer-id' = $SophosManufacturerID
						'model-id' = if ($ITGModel) { $ITGModel } else { $false }
						'location-id' = $false
					}
				}

				if ($FlexAssetBody.attributes.traits.location) {
					$NewConfigData.attributes.'location-id' = $FlexAssetBody.attributes.traits.location[0]
				}

				# Make configuration then add to flexible asset
				try {
					$NewConfig = New-ITGlueConfigurations -organization_id $Match.itgId -data $NewConfigData
					if ($NewConfig) {
						$FlexAssetBody.attributes.traits."configuration-item" = @($NewConfig.id)
						Write-Host "Created New Configuration: $($Name) (Org: $($Match.itgName)) (ID: $($NewConfig.id))" -ForegroundColor DarkGreen
					}
				} catch {
					Write-Warning "Could not create new configuration: $($Name)"
				}
			}
			
			# Filter out empty values
			($FlexAssetBody.attributes.traits.GetEnumerator() | Where-Object { -not $_.Value }) | Foreach-Object { 
				$FlexAssetBody.attributes.traits.Remove($_.Name) 
			}

			New-ITGlueFlexibleAssets -data $FlexAssetBody
			Write-Host "Created New Firewall: $($Name) (Org: $($Match.itgName))" -ForegroundColor Green
		}
	}
	
}
