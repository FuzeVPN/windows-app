# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$PackageReport,
  [Parameter(Mandatory)][string]$DownloadUrl,
  [Parameter(Mandatory)][string]$OutputPath,
  [ValidateSet('installer','portable')][string]$PackageKind = 'installer',
  [string]$ReleaseNotes = '',
  [Nullable[int]]$MinWindowsBuild
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
$PackageReport = Assert-ProjectPath $PackageReport $projectRoot
$OutputPath = Assert-ProjectPath $OutputPath $projectRoot
$report = Get-Content -LiteralPath $PackageReport -Raw | ConvertFrom-Json
if ($report.public -ne $true -or $report.mode -ne 'production') { throw 'An unsigned DevTest package can never produce a public update manifest.' }
$version = ConvertTo-PublicVersion $report.version
$extension = if ($PackageKind -eq 'portable') { '.zip' } else { '.exe' }
$uri = $null
if ($DownloadUrl.Length -gt 8192 -or $DownloadUrl -match '[\x00-\x20\x7f]' -or
    -not [Uri]::TryCreate($DownloadUrl, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -cne 'https' -or
    -not $uri.Host -or $uri.UserInfo -or $uri.Fragment -or $uri.Port -lt 1 -or $uri.Port -gt 65535 -or
    -not $uri.AbsolutePath.EndsWith($extension, [StringComparison]::OrdinalIgnoreCase)) { throw "A direct HTTPS $extension URL without credentials or fragment is required." }
if ($PackageKind -eq 'portable') {
  $bundle = Assert-ProjectPath $report.zip $projectRoot
  $reportedHash = $report.zip_sha256
} else {
  if (-not $report.signed_by) { throw 'An unsigned DevTest package can never produce a public update manifest.' }
  $bundle = Assert-ProjectPath $report.bundle $projectRoot
  $reportedHash = $report.bundle_sha256
}
if ((Get-Item -LiteralPath $bundle).Length -gt 512MB) { throw 'The updater accepts bundles of at most 512 MiB.' }
$hash = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hash -cne $reportedHash) { throw 'The bundle changed after packaging; regenerate and verify the package report.' }
if ($PackageKind -eq 'portable') {
  if ($report.architecture -notin @('x64','arm64') -or $report.portable_development -ne $false) { throw 'A production portable report with a native Windows architecture is required.' }
  $staging = Assert-ProjectPath (Join-Path ([IO.Path]::GetDirectoryName($bundle)) 'FuzeVPN') $projectRoot
  $inventory = @(Get-ReleaseInventory $staging $projectRoot)
  $actual = @($inventory | ForEach-Object { "$($_.Path)`t$($_.Length)`t$($_.Sha256)" })
  $expected = @($report.files | Sort-Object Path | ForEach-Object { "$($_.Path)`t$($_.Length)`t$($_.Sha256)" })
  if (($actual -join "`n") -cne ($expected -join "`n")) { throw 'Portable staging changed after packaging.' }
  if (-not ($inventory.Path -ccontains 'fuzevpn.portable') -or
      [IO.File]::ReadAllText((Join-Path $staging 'fuzevpn.portable')) -cne "FuzeVPN portable v1`n") { throw 'The portable package marker is missing or invalid.' }
  $runtimeManifest = Join-Path $staging 'portable-runtime.manifest'
  if ((Get-FileHash -LiteralPath $runtimeManifest -Algorithm SHA256).Hash.ToLowerInvariant() -cne $report.manifest_sha256 -or
      (Get-Content -LiteralPath $runtimeManifest -TotalCount 2)[1] -cne "version=$version") { throw 'Portable runtime manifest version/hash mismatch.' }
  $publisher = 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR'
  $policy = [pscustomobject]@{ Mode='artifact-signing'; CertificateThumbprint=''; ExpectedPublisherSubject=$publisher }
  $peFiles = @(Get-ReleasePeFiles $staging $projectRoot)
  [void]@(Get-ReleasePeSigningEvidence $policy $peFiles $report.architecture)
  foreach ($name in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')) {
    $executable = Join-Path $staging $name
    [void](Assert-SignedFile $executable -ExpectedPublisherSubject $publisher -TimestampRequired)
    $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($executable)
    if ($info.ProductName -cne 'FuzeVPN' -or ('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -cne "$version.0") { throw 'Portable executable product/version mismatch.' }
  }
  # Compare archive bytes with the signed staging tree without extracting or
  # following paths supplied by an archive. The root is part of the contract.
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $archive = [IO.Compression.ZipFile]::OpenRead($bundle)
  try {
    $entries = @($archive.Entries | Where-Object { $_.Name -ne '' })
    if ($entries.Count -ne $inventory.Count) { throw 'Portable ZIP inventory mismatch.' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $entries) {
      if (-not $entry.FullName.StartsWith('FuzeVPN/', [StringComparison]::Ordinal) -or $entry.FullName.Contains('\')) { throw 'Unexpected portable ZIP root or separator.' }
      $relative = $entry.FullName.Substring(8).Replace('/','\')
      if (-not $seen.Add($relative)) { throw 'Duplicate portable ZIP entry.' }
      $item = @($inventory | Where-Object Path -CEQ $relative)
      if ($item.Count -ne 1 -or $entry.Length -ne $item[0].Length) { throw 'Portable ZIP entry mismatch.' }
      $stream = $entry.Open(); $hasher = [Security.Cryptography.SHA256]::Create()
      try { $entryHash = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
      finally { $hasher.Dispose(); $stream.Dispose() }
      if ($entryHash -cne $item[0].Sha256) { throw 'Portable ZIP bytes differ from the signed staging tree.' }
    }
  } finally { $archive.Dispose() }
} else {
  [void](Assert-SignedFile $bundle $report.signed_by -TimestampRequired)
  $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($bundle)
  if ($info.ProductName -cne 'FuzeVPN' -or ('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -ne "$version.0") { throw 'Bundle product/version mismatch.' }
}
if ($ReleaseNotes.Contains([char]0) -or [Text.Encoding]::UTF8.GetByteCount($ReleaseNotes) -gt 16384) { throw 'Release notes must be UTF-8 text of at most 16 KiB, without NUL.' }
$manifest = [ordered]@{ version = $version; download_url = $DownloadUrl; sha256 = $hash; release_notes = $ReleaseNotes }
if ($null -ne $MinWindowsBuild) {
  if ($MinWindowsBuild -le 0) { throw 'min_windows_build must be a positive 32-bit integer.' }
  $manifest['min_windows_build'] = $MinWindowsBuild
}
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($OutputPath))
[IO.File]::WriteAllText($OutputPath, ($manifest | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
Write-Host "Publication manifest created from the final verified $PackageKind package: $OutputPath"
