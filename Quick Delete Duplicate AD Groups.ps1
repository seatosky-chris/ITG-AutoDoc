# A simple helper script for mass deleting duplicate AD groups as there were a few issues with duplicates when creating the AD Groups autodoc script

$FlexAssetName = "AD Security Groups"
$FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data


$ITGOrganizations = Get-ITGlueOrganizations -page_size 1000

foreach ($ITGOrg in $ITGOrganizations.data) {
	$orgID = $ITGOrg.id

	$ExistingGroups = @()
	$i = 1
	while ($i -le 10 -and ($ExistingGroups | Measure-Object).Count -eq (($i-1) * 200)) {
		$ExistingGroups_Partial = Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID
		if (!$ExistingGroups_Partial -or $ExistingGroups_Partial.Error) {
			# We got an error querying groups, wait and try again
			Start-Sleep -Seconds 2
			$ExistingGroups_Partial = Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID

			if (!$ExistingGroups_Partial -or $ExistingGroups_Partial.Error) {
				Write-Error "An error occurred trying to get the existing AD groups from ITG. Exiting..."
				Write-Error $ExistingGroups_Partial.Error
				exit 1
			}
		}
		$ExistingGroups += ($ExistingGroups_Partial).data

		Write-Host "- Got group set $i"
		$TotalGroups = ($ExistingGroups | Measure-Object).Count
		Write-Host "- Total: $TotalGroups"
		$i++
	}

	if (!$ExistingGroups) {
		Write-Warning "No AD groups found for: $($ITGOrg.attributes.name)"
		continue
	}

	$GUIDs = $ExistingGroups.attributes.traits.guid | Sort-Object -Unique
	$Removed = @()

	foreach ($GUID in $GUIDs) {
		$Groups = $ExistingGroups | Where-Object { $_.attributes.traits.guid -like $GUID } | Sort-Object { Get-Date($_.attributes.'updated-at') }
		if (($Groups | Measure-Object).Count -gt 1) {
			$DeleteGroup = $Groups | Select-Object -Skip 1 | Select-Object -First 1
			if ($DeleteGroup.id) {
				Remove-ITGlueFlexibleAssets -id $DeleteGroup.id -Confirm:$false
				$Removed += 1
				Write-Host "Removed: "$DeleteGroup.id
			}
		}
	}

	$DeletedCount = $Removed.Count
	Write-Host "Removed $DeletedCount groups for: $($ITGOrg.attributes.name)" -ForegroundColor Green
}