# SPDX-License-Identifier: MPL-2.0
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$sourceRoot = Join-Path $taskRoot '.toolchain/wix-source'
$distributionRoot = Join-Path $taskRoot 'third_party/wix'
[void][IO.Directory]::CreateDirectory($distributionRoot)
$archivePath = Join-Path $distributionRoot 'wix-source-7.0.0-fuze-x64.zip'
$patchPath = Join-Path $distributionRoot 'wix-source-build.patch'
& git -C $sourceRoot diff --binary --output=$patchPath
if ($LASTEXITCODE -ne 0) { throw 'Could not export the exact source patch.' }
& git -C $sourceRoot archive --format=zip '--prefix=.toolchain/wix-source/' --output=$archivePath HEAD
if ($LASTEXITCODE -ne 0) { throw 'Could not archive the pinned upstream source.' }
$modified = @(& git -C $sourceRoot diff --name-only)
if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate source modifications.' }
$entries = @{}
foreach ($relative in $modified) { $entries[".toolchain/wix-source/$relative"] = Join-Path $sourceRoot $relative }
foreach ($relative in @('global.json','Directory.Packages.props','build/SomeVerInfo.cs','build/SomeVerInfo.rc','build/SomeVerInfo.props')) {
  $entries[".toolchain/wix-source/$relative"] = Join-Path $sourceRoot $relative
}
foreach ($relative in @(
  'tools/wix/build-wix-source.ps1',
  'tools/wix/invoke-wix-build.ps1',
  'tools/wix/archive-wix-source.ps1',
  'docs/distribution.md',
  'third_party/wix/wix-source-build.patch',
  'third_party/wix/wix-build-artifacts.csv'
)) {
  $entries[$relative] = Join-Path $taskRoot $relative
}
foreach ($relative in @('FuzeVpnTheme.xml','FuzeVpnTheme.wxl','WiX-MS-RL.txt')) {
  $entries["installer/$relative"] = Join-Path $taskRoot "installer/$relative"
}
$zip = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Update)
try {
  foreach ($entry in $entries.GetEnumerator()) {
    $existing = $zip.GetEntry($entry.Key)
    if ($existing) { $existing.Delete() }
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $entry.Value, $entry.Key, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
  }
} finally { $zip.Dispose() }
$hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -LiteralPath "$archivePath.sha256" -Value "$hash  $([IO.Path]::GetFileName($archivePath))" -Encoding utf8
Write-Output "Archive: $archivePath"
Write-Output "SHA256: $hash"
