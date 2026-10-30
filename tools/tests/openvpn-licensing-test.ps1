# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../BuildSupport.psm1') -Force
$root = Get-FuzeProjectRoot
$core = Join-Path $root 'third_party/openvpn3-core'
$evidence = Join-Path $core 'fuzevpn-license-provenance'
$provenance = Get-Content -LiteralPath (Join-Path $evidence 'provenance.json') -Raw | ConvertFrom-Json
$expression = 'MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception'
if ($provenance.SPDX -cne $expression -or $null -ne $provenance.OfficialPatchCommit -or @($provenance.Files).Count -ne 4) {
  throw 'The downstream licensing correction must identify exactly four files without claiming an upstream patch commit.'
}
$historical = Join-Path $evidence $provenance.HistoricalNoticesArchive
Assert-FuzeHash -Path $historical -Hash $provenance.HistoricalNoticesSha256
Add-Type -AssemblyName System.IO.Compression.FileSystem
$originals = [IO.Compression.ZipFile]::OpenRead($historical)
$utf8 = [Text.UTF8Encoding]::new($false)
try {
  foreach ($record in $provenance.Files) {
    $path = Join-Path $core $record.Path
    Assert-FuzeHash -Path $path -Hash $record.CorrectedSha256
    $text = [IO.File]::ReadAllText($path)
    $marker = '//    SPDX-License-Identifier: ' + $expression
    $start = $text.IndexOf($marker)
    if ($start -lt 0 -or $text.Contains('GNU General Public License Version 3')) { throw "Contradictory OpenVPN licensing notice: $path" }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $tailHash = [Convert]::ToHexString($sha.ComputeHash($utf8.GetBytes($text.Substring($start + $marker.Length)))).ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($tailHash -cne $record.UnchangedTailSha256) { throw "Software content changed outside the licensing metadata: $path" }
    $entry = $originals.GetEntry($record.HistoricalNoticeEntry)
    if (-not $entry) { throw "Historical notice missing: $path" }
    $reader = [IO.StreamReader]::new($entry.Open())
    try { $oldHeader = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $oldPrefix = $oldHeader.Substring(0, $oldHeader.IndexOf('//    This program is free software:'))
    if ($text.Substring(0,$start) -cne $oldPrefix) { throw "OpenVPN author/copyright attribution changed: $path" }
  }
} finally { $originals.Dispose() }
$fixture = Join-Path $root ('build/openvpn-licensing-tests/' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
$tools = Get-FuzeVisualStudioTools
Invoke-FuzeChecked $tools.CMake @("-DSOURCE_ROOT=$root", "-DBUNDLE_DIR=$fixture", '-DOPENVPN_ENABLED=ON',
  '-P', (Join-Path $root 'tools/package-native-notices.cmake'))
$packaged = [IO.Compression.ZipFile]::OpenRead((Join-Path $fixture 'licenses/OpenVPN3-corresponding-source.zip'))
try {
  foreach ($name in @('FUZEVPN-LICENSING-CLARIFICATION.md', 'fuzevpn-license-provenance/provenance.json',
      'fuzevpn-license-provenance/downstream-header-metadata.patch', 'fuzevpn-license-provenance/original-header-notices-2026-10-19.zip')) {
    if (-not $packaged.GetEntry($name)) { throw "Licensing evidence missing from corresponding-source archive: $name" }
  }
  foreach ($record in $provenance.Files) {
    $entry = $packaged.GetEntry($record.Path)
    if (-not $entry) { throw "Corrected source missing from archive: $($record.Path)" }
    $stream = $entry.Open(); $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = [Convert]::ToHexString($sha.ComputeHash($stream)).ToLowerInvariant() }
    finally { $sha.Dispose(); $stream.Dispose() }
    if ($hash -cne $record.CorrectedSha256) { throw "Packaged source differs from corrected licensing provenance: $($record.Path)" }
  }
} finally { $packaged.Dispose() }
$pins = Get-FuzeDependencyPins
Assert-FuzeHash -Path (Join-Path $fixture ('openvpn-dco/source-' + $pins.openvpn_dco.version + '.zip')) -Hash $pins.openvpn_dco.source_hash
Write-Host 'OpenVPN licensing verified: four canonical headers, authors and software content preserved, original notice archive, downstream provenance and current DCO source included in actual package output.'
