# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [ValidateSet('x64','arm64')][string]$Architecture='x64',
  # Compile Release first. This packaging script never runs the application.
  [string]$ReleaseDirectory,
  [string]$SourceBuildCache,
  [string]$OutputDirectory,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
  [string]$ArtifactSigningMetadataPath,
  [string]$ArtifactSigningDlibPath,
  [string]$ExpectedPublisherSubject,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ArtifactSigningCertificateThumbprint,
  [string]$TimestampUrl,
  [switch]$DevTest
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
$policy = New-ReleaseSigningPolicy -CertificateThumbprint $CertificateThumbprint -ArtifactSigningMetadataPath $ArtifactSigningMetadataPath -ArtifactSigningDlibPath $ArtifactSigningDlibPath -ExpectedPublisherSubject $ExpectedPublisherSubject -ArtifactSigningCertificateThumbprint $ArtifactSigningCertificateThumbprint -TimestampUrl $TimestampUrl -DevTest:$DevTest
if ($policy.Mode -eq 'artifact-signing') { [void](Assert-ArtifactSigningInputs $policy $projectRoot) }
if (-not $ReleaseDirectory) { $ReleaseDirectory = Join-Path $projectRoot "build\windows\$Architecture\runner\Release" }
$ReleaseDirectory = Assert-ProjectPath $ReleaseDirectory $projectRoot
$SourceBuildCache = & (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') -Architecture $Architecture -CheckBuildModeOnly -ReleaseDirectory $ReleaseDirectory -SourceBuildCache $SourceBuildCache -DevTest:$DevTest
[void](Assert-ReleasePeArchitecture $ReleaseDirectory $projectRoot $Architecture)
Assert-DcoPayload $ReleaseDirectory -Architecture $Architecture
$expectedFlag = if ($DevTest) { 'ON' } else { 'OFF' }
$publicVersion = Get-ProjectPublicVersion $projectRoot
$mode = if ($DevTest) { 'devtest' } else { 'production' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot "dist\$mode\portable\$publicVersion\$Architecture" }
$OutputDirectory = Assert-ProjectPath $OutputDirectory $projectRoot
if ($OutputDirectory.StartsWith($ReleaseDirectory.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -or $OutputDirectory -ieq $ReleaseDirectory) { throw 'Portable output must be outside the source Release directory.' }
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory; existing portable artifacts are never overwritten.' }
$sourceInventory = @(Get-ReleaseInventory $ReleaseDirectory $projectRoot)
foreach ($required in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe',
    'flutter_windows.dll','fuzevpn_tray.ico','THIRD_PARTY_NOTICES.md','data\icudtl.dat','data\flutter_assets\AssetManifest.bin')) {
  if (-not ($sourceInventory.Path -contains $required)) { throw "Incomplete portable frontend: $required" }
}
if ($sourceInventory.Path -contains 'fuzevpn.portable') { throw 'Source Release must remain an ordinary build; the portable marker is added only to staging.' }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$staging = Assert-ProjectPath (Join-Path $OutputDirectory 'FuzeVPN') $projectRoot
[void][IO.Directory]::CreateDirectory($staging)
foreach ($entry in $sourceInventory) {
  $source = Assert-ProjectPath (Join-Path $ReleaseDirectory $entry.Path) $projectRoot
  $destination = Assert-ProjectPath (Join-Path $staging $entry.Path) $projectRoot
  [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination))
  Copy-Item -LiteralPath $source -Destination $destination
  if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ine $entry.Sha256) { throw "Release changed while being copied: $($entry.Path)" }
}
$sign = Get-ReleaseSigningParameters $policy
$sign['ReleaseDirectory']=$staging
$sign['Architecture']=$Architecture
if (-not $DevTest) { & (Join-Path $PSScriptRoot 'sign-windows-release.ps1') @sign }
$prepare = @{ ReleaseDirectory = $staging; DevTest = $DevTest; Architecture=$Architecture }
if ($policy.CertificateThumbprint) { $prepare['CertificateThumbprint'] = $policy.CertificateThumbprint }
if ($policy.ExpectedPublisherSubject) { $prepare['ExpectedPublisherSubject'] = $policy.ExpectedPublisherSubject }
if ($DevTest) { & (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') @prepare | Out-Host }
& (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') @prepare -VerifyOnly | Out-Host
[IO.File]::WriteAllText((Join-Path $staging 'fuzevpn.portable'), "FuzeVPN portable v1`n", [Text.UTF8Encoding]::new($false))
$readme = @"
FuzeVPN $publicVersion - Windows 10/11 $Architecture portable

Extract the complete FuzeVPN folder before starting fuzevpn_windows.exe.
Keep all files together. Close FuzeVPN and wait for VPN cleanup before moving
or deleting this folder. User settings remain in the Windows user profile.

The frontend can be moved. Connecting requires administrator approval (UAC).
The verified VPN engine is copied into a protected, versioned cache under
Program Files\FuzeVPN Runtime. The portable broker stops with the frontend;
it does not register the persistent FuzeVPNService service. VPN drivers can
still require administrator installation and are shared Windows components.
This mode is therefore not a zero-footprint or administrator-free application.

Portable updates download a complete ZIP from the package=portable release
route. FuzeVPN verifies the archive hash, architecture, version, signatures and
embedded runtime manifest before asking to close the application and replace
its folder. The previous folder is retained beside the new one as a backup,
including any local files you added. Windows user-profile settings are kept.
If replacement fails, the updater attempts to restore and restart the old
folder. Unsafe locations or open files can prevent replacement; use manual
extraction in that case. Cache generations are retained; do not delete an
active cache. A portable version older than 1.0.2 requires one manual update
to gain this ZIP update flow.
Automatic folder replacement requires a local volume with persistent ACLs,
such as NTFS or ReFS. On FAT/exFAT, close FuzeVPN and manually extract the
complete new package instead.

$(if ($DevTest) { 'DEVTEST - UNSIGNED LOCAL VALIDATION ONLY. DO NOT PUBLISH OR DISTRIBUTE.' } else { 'Production package: application binaries and the embedded runtime manifest are signed.' })
Third-party notices and corresponding source are included in this folder.
"@
[IO.File]::WriteAllText((Join-Path $staging 'README-PORTABLE.txt'), $readme, [Text.UTF8Encoding]::new($false))
$inventory = @(Get-ReleaseInventory $staging $projectRoot)
$zipPath = Join-Path $OutputDirectory "FuzeVPN-$publicVersion-windows-$Architecture-portable-$mode.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[IO.Compression.ZipFile]::CreateFromDirectory($staging, $zipPath, [IO.Compression.CompressionLevel]::Optimal, $true)
$after = @(Get-ReleaseInventory $staging $projectRoot)
if (($inventory | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)) { throw 'Portable staging changed during archive creation; discard this output.' }
$archive = [IO.Compression.ZipFile]::OpenRead($zipPath)
try {
  $archived = @($archive.Entries | Where-Object { $_.Name -ne '' })
  if ($archived.Count -ne $inventory.Count) { throw 'Portable ZIP is incomplete.' }
  foreach ($entry in $archived) {
    $relative = $entry.FullName.Replace('/','\')
    if (-not $relative.StartsWith('FuzeVPN\', [StringComparison]::Ordinal)) { throw 'Unexpected ZIP root.' }
    $relative = $relative.Substring(8)
    $expected = @($inventory | Where-Object Path -CEQ $relative)
    if ($expected.Count -ne 1 -or $entry.Length -ne $expected[0].Length) { throw "ZIP entry mismatch: $relative" }
    $stream = $entry.Open(); $hasher = [Security.Cryptography.SHA256]::Create()
    try { $hash = ([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','') }
    finally { $hasher.Dispose(); $stream.Dispose() }
    if ($hash -ine $expected[0].Sha256) { throw "ZIP entry hash mismatch: $relative" }
  }
} finally { $archive.Dispose() }
$sourceAfter = @(Get-ReleaseInventory $ReleaseDirectory $projectRoot)
if (($sourceInventory | ConvertTo-Json -Compress) -cne ($sourceAfter | ConvertTo-Json -Compress)) { throw 'Source Release changed during packaging; discard this output.' }
$signatures = @(Get-ReleaseSigningEvidence $policy @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe' | ForEach-Object { Join-Path $staging $_ }))
$peSignatures = @(Get-ReleasePeSigningEvidence $policy @(Get-ReleasePeFiles $staging $projectRoot) $Architecture)
$effectiveThumbprint = if ($DevTest) { '' } else { @($signatures | Where-Object { [IO.Path]::GetFileName($_.File) -eq 'fuzevpn_windows.exe' })[0].Thumbprint }
[ordered]@{
  public = (-not $DevTest); mode = $mode; version = $publicVersion; architecture=$Architecture; source_release = $ReleaseDirectory;
  source_cmake_cache = $SourceBuildCache; portable_development = ($expectedFlag -eq 'ON');
  manifest_sha256 = (Get-FileHash -LiteralPath (Join-Path $staging 'portable-runtime.manifest') -Algorithm SHA256).Hash.ToLowerInvariant();
  zip = $zipPath; zip_sha256 = (Get-FileHash -LiteralPath $zipPath -Algorithm SHA256).Hash.ToLowerInvariant();
  certificate_thumbprint = $effectiveThumbprint;
  signing = @{ backend=$policy.Mode; expected_publisher_subject=$policy.ExpectedPublisherSubject; configured_certificate_pin=$policy.CertificateThumbprint;
    metadata=$(if ($policy.Mode -eq 'artifact-signing') { Read-ArtifactSigningMetadata $policy.MetadataPath } else { $null }); file_signatures=$signatures; pe_signatures=$peSignatures };
  files = $inventory; executed_or_installed = $false
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'portable-package-report.json') -Encoding UTF8
Write-Host "Portable package created and inspected without execution: $zipPath"
