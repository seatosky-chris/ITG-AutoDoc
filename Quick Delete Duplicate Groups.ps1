# A simple helper script for mass deleting duplicate AD groups as there were a few issues with duplicates when creating the AD Groups autodoc script

$ExistingGroups = @()
for ($i = 1; $i -le 7; $i++) {
	$ExistingGroups += (Get-ITGlueFlexibleAssets -page_size 200 -page_number $i -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID).data
	Write-Host "Got group set $i"
	$TotalGroups = ($ExistingGroups | Measure-Object).Count
	Write-Host "Total: $TotalGroups"
}

$GUIDs = $ExistingGroups.attributes.traits.guid | Sort-Object -Unique
$Removed = @()

foreach ($GUID in $GUIDs) {
	$Groups = $ExistingGroups | Where-Object { $_.attributes.traits.guid -like $GUID } | Sort-Object { Get-Date($_.attributes.'updated-at') }
	if (($Groups | Measure-Object).Count -gt 1) {
		$DeleteGroup = $Groups | Select-Object -Skip 1 | Select-Object -First 1
		if ($DeleteGroup.id) {
			Remove-ITGlueFlexibleAssets -id $DeleteGroup.id -Confirm:$false
			$Removed += $DeleteGroup.id
			Write-Host "Removed: "$DeleteGroup.id
		}
	}
}

$DeletedCount = $Removed.Count
Write-Host "Removed $DeletedCount groups."