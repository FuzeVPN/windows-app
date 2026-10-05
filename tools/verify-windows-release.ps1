# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Version,
 [Parameter(Mandatory)][ValidateSet('x64','arm64')][string]$Architecture,
 [string]$BaselineDirectory,
 [string]$OutputDirectory,
 [string]$InstallerDirectory,
 [string]$WixPath,
 [string]$DotNetPath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$taskProject=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $taskProject 'installer/InstallerTools.psm1') -Force
$Version=ConvertTo-PublicVersion $Version
if (-not $BaselineDirectory) {$BaselineDirectory=Join-Path $taskProject "build/release-$Version/signing/unsigned-baseline-$Architecture"}
$BaselineDirectory=Assert-ProjectPath $BaselineDirectory $taskProject
if (-not $OutputDirectory) {$OutputDirectory=Join-Path $taskProject "build/release-$Version/deep-verification/$Architecture"}
$OutputDirectory=Assert-ProjectPath $OutputDirectory $taskProject
if (Test-Path -LiteralPath $OutputDirectory) {throw 'Choose a new audit directory; existing extraction evidence is never overwritten.'}
$taskSource=Join-Path $taskProject "build/windows/$Architecture/runner/Release"
$taskPortable=Join-Path $taskProject "dist/production/portable/$Version/$Architecture"
$taskInstaller=if($InstallerDirectory){Assert-ProjectPath $InstallerDirectory $taskProject}else{Join-Path $taskProject "dist/production/installer/$Version/$Architecture"}
$taskStaging=Join-Path $taskPortable 'FuzeVPN'
$taskPolicy=[pscustomobject]@{Mode='artifact-signing';CertificateThumbprint='';ExpectedPublisherSubject='CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR'}
$portableReport=Get-Content -LiteralPath (Join-Path $taskPortable 'portable-package-report.json') -Raw | ConvertFrom-Json
$installerReport=Get-Content -LiteralPath (Join-Path $taskInstaller 'package-report.json') -Raw | ConvertFrom-Json
$baseline=Get-Content -LiteralPath (Join-Path $BaselineDirectory 'release-inventory.json') -Raw | ConvertFrom-Json
$peBaseline=Get-Content -LiteralPath (Join-Path $BaselineDirectory 'pe-inventory.json') -Raw | ConvertFrom-Json
function Require([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Hash([string]$Path) { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function File-Id([string]$Name) {
 if ($Name -ieq 'fuzevpn-service.exe') { return 'VpnServiceExe' }
 $hasher=[Security.Cryptography.SHA256]::Create()
 try { return 'File_'+(([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($Name.ToLowerInvariant())))).Replace('-','').ToLowerInvariant()).Substring(0,24) }
 finally { $hasher.Dispose() }
}
foreach ($report in @($portableReport,$installerReport)) {
 Require ($report.public -and $report.mode -ceq 'production' -and $report.version -ceq $Version -and $report.architecture -ceq $Architecture) 'Incorrect release mode/version/architecture.'
 Require ($report.signing.backend -ceq 'artifact-signing' -and $report.signing.expected_publisher_subject -ceq $taskPolicy.ExpectedPublisherSubject) 'Incorrect recorded signing policy.'
}
Require (-not $portableReport.portable_development -and -not $portableReport.executed_or_installed -and -not $installerReport.installed_on_this_machine) 'No developer bypass or product execution may be reported.'
& (Join-Path $taskProject 'tools/prepare-portable-runtime.ps1') -Architecture $Architecture -ReleaseDirectory $taskSource -CheckBuildModeOnly | Out-Null
$artifacts=@([pscustomobject]@{Kind='EXE';Path=$installerReport.bundle;Expected=$installerReport.bundle_sha256},
 [pscustomobject]@{Kind='MSI';Path=$installerReport.msi;Expected=$installerReport.msi_sha256},
 [pscustomobject]@{Kind='PortableZIP';Path=$portableReport.zip;Expected=$portableReport.zip_sha256})
foreach ($artifact in $artifacts) { $actual=Hash $artifact.Path; Require ($actual -ceq $artifact.Expected) 'An artifact differs from its package report.'; $artifact | Add-Member SHA256 $actual }
foreach ($pair in @(@{Report=$portableReport;Directory=$taskStaging},@{Report=$installerReport;Directory=$taskSource})) {
 $actualInventory=@(Get-ReleaseInventory $pair.Directory $taskProject)
 Require ($actualInventory.Count -eq $pair.Report.files.Count) 'Inventory count mismatch.'
 foreach ($entry in $pair.Report.files) { $file=Join-Path $pair.Directory $entry.Path; Require ((Get-Item -LiteralPath $file).Length -eq $entry.Length -and (Hash $file) -ceq $entry.Sha256) ('Inventory hash mismatch: '+$entry.Path) }
 Assert-DcoPayload $pair.Directory -Architecture $Architecture
}
. (Join-Path $taskProject 'tools/prepare-portable-runtime.ps1') -FunctionsOnly -Architecture $Architecture
Initialize-PortableResourceApi
foreach ($directory in @($taskStaging,$taskSource)) {
 $payload=@(Get-PortableRuntimePaths @(Get-ReleaseInventory $directory $taskProject) $Architecture)
 $expectedManifest=ConvertTo-PortableManifest $Version $payload
 $embeddedManifest=[FuzeVpnPortableResource]::Read((Join-Path $directory 'fuzevpn-runtime.exe'))
 Require ([Convert]::ToBase64String($embeddedManifest) -ceq [Convert]::ToBase64String($expectedManifest)) 'The signed runtime helper manifest does not describe the final payload.'
 Require ([Convert]::ToBase64String([IO.File]::ReadAllBytes((Join-Path $directory 'portable-runtime.manifest'))) -ceq [Convert]::ToBase64String($expectedManifest)) 'The standalone runtime manifest does not describe the final payload.'
 foreach ($name in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')) {
  $file=Join-Path $directory $name
  $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($file)
  Require ($info.ProductName -ceq 'FuzeVPN' -and $info.OriginalFilename -ieq $name -and ('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -ceq "$Version.0") 'The FuzeVPN executable resources differ from the release contract.'
 }
 $aot=[IO.File]::ReadAllBytes((Join-Path $directory 'data/app.so'))
 $elfMachine=if($Architecture -eq 'x64'){62}else{183}
 Require ($aot.Length -ge 20 -and [BitConverter]::ToUInt32($aot,0) -eq 0x464c457f -and $aot[4] -eq 2 -and [BitConverter]::ToUInt16($aot,18) -eq $elfMachine) 'The Flutter AOT ELF architecture differs from the release target.'
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive=[IO.Compression.ZipFile]::OpenRead($portableReport.zip)
$zipHashes=@{}
try {
 $zipFiles=@($archive.Entries | Where-Object Name -ne '')
 Require ($zipFiles.Count -eq $portableReport.files.Count) 'Portable ZIP file count mismatch.'
 foreach ($entry in $zipFiles) {
  Require ($entry.FullName.StartsWith('FuzeVPN/',[StringComparison]::Ordinal) -and -not $entry.FullName.Contains('\')) 'Unexpected ZIP root/separator.'
  $relative=$entry.FullName.Replace('/','\')
  $relative=$relative.Substring(8); $expected=@($portableReport.files | Where-Object Path -CEQ $relative)
  Require (-not $zipHashes.ContainsKey($relative)) 'Duplicate ZIP path.'
  Require ($expected.Count -eq 1 -and $entry.Length -eq $expected[0].Length) 'ZIP entry inventory mismatch.'
  $stream=$entry.Open(); $hasher=[Security.Cryptography.SHA256]::Create()
  try { $hash=([BitConverter]::ToString($hasher.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
  finally { $hasher.Dispose(); $stream.Dispose() }
  Require ($hash -ceq $expected[0].Sha256) ('ZIP byte mismatch: '+$relative); $zipHashes[$relative]=$hash
 }
} finally { $archive.Dispose() }
Require ([IO.File]::ReadAllText((Join-Path $taskStaging 'fuzevpn.portable')) -ceq "FuzeVPN portable v1`n") 'Portable marker contract mismatch.'
Require (-not (Test-Path -LiteralPath (Join-Path $taskSource 'fuzevpn.portable'))) 'Installer source contains a portable marker.'
$payloadProvenance=@()
foreach ($entry in @($installerReport.files | Where-Object {[IO.Path]::GetExtension($_.Path) -notin @('.exe','.dll','.sys') -and $_.Path -cne 'portable-runtime.manifest'})) {
 $relative=$entry.Path
 $before=@($baseline | Where-Object Path -CEQ $relative); $hash=Hash (Join-Path $taskSource $relative)
 Require ($before.Count -eq 1 -and $hash -ceq $before[0].Sha256 -and $hash -ceq (Hash (Join-Path $taskStaging $relative)) -and $hash -ceq $zipHashes[$relative]) ('AOT/asset provenance mismatch: '+$relative)
 $payloadProvenance += [pscustomobject]@{Path=$relative;SHA256=$hash;BaselineSourcePortableZIPIdentical=$true}
}
$fonts=Get-Content -LiteralPath (Join-Path $taskSource 'data/flutter_assets/FontManifest.json') -Raw | ConvertFrom-Json
Require (@($fonts | Where-Object family -CEQ Archivo).Count -eq 1) 'Archivo font manifest missing.'
$inspection=Get-MsiInspection $installerReport.msi
Assert-MsiInspection $inspection $Version ($installerReport.files.Count+2) $Architecture
Require (@($inspection.File | Where-Object FileName -match 'fuzevpn\.portable').Count -eq 0) 'MSI contains a portable marker.'
$deepRoot=$OutputDirectory
if (Test-Path -LiteralPath $deepRoot) { throw 'Use a new verification directory; extraction evidence is never overwritten.' }
[void][IO.Directory]::CreateDirectory($deepRoot)
$burnContents=Assert-ProjectPath (Join-Path $deepRoot 'burn') $taskProject
$baContents=Assert-ProjectPath (Join-Path $deepRoot 'bootstrapper') $taskProject
$msiContents=Assert-ProjectPath (Join-Path $deepRoot 'msi') $taskProject
$working=Assert-ProjectPath (Join-Path $deepRoot 'intermediate') $taskProject
[void][IO.Directory]::CreateDirectory($working)
# WiX reads cabinets and PE resources as data. No setup, MSI custom action,
# application, VPN service or ARM64 executable is ever launched.
$dotnet=if($DotNetPath){Assert-ProjectPath $DotNetPath $taskProject}else{Join-Path $taskProject '.toolchain/dotnet-sdk/dotnet.exe'}
$wix=if($WixPath){Assert-ProjectPath $WixPath $taskProject}else{Assert-ProjectPath $installerReport.wix_path $taskProject}
Require ((Hash $wix) -ceq $installerReport.wix_sha256) 'The data extraction tool does not match the packaging report.'
& $dotnet $wix burn extract $installerReport.bundle -o $burnContents -oba $baContents -intermediateFolder $working *> (Join-Path $deepRoot 'burn-extract.log')
if ($LASTEXITCODE -ne 0) { throw 'Burn data extraction failed; inspect burn-extract.log.' }
$embeddedMsi=@(Get-ChildItem -LiteralPath $burnContents -Recurse -File -Filter '*.msi')
Require ($embeddedMsi.Count -eq 1 -and (Hash $embeddedMsi[0].FullName) -ceq $installerReport.msi_sha256) 'Burn embedded MSI differs from the standalone signed MSI.'
& $dotnet $wix msi decompile $installerReport.msi -x $msiContents -o (Join-Path $deepRoot 'decompiled.wxs') -intermediateFolder $working *> (Join-Path $deepRoot 'msi-decompile.log')
if ($LASTEXITCODE -ne 0) { throw 'MSI data extraction failed; inspect msi-decompile.log.' }
$msiHashes=@()
foreach ($entry in $installerReport.files) {
 $id=File-Id $entry.Path; $rows=@($inspection.File | Where-Object File -CEQ $id)
 Require ($rows.Count -eq 1 -and [long]$rows[0].FileSize -eq $entry.Length) 'MSI file table contract mismatch.'
 $extracted=Join-Path $msiContents "File/$id"
 Require ((Get-Item -LiteralPath $extracted).Length -eq $entry.Length -and (Hash $extracted) -ceq $entry.Sha256) ('MSI compressed payload hash mismatch: '+$entry.Path)
 $msiHashes += [pscustomobject]@{Path=$entry.Path;FileID=$id;ExtractedPath=$extracted;SHA256=$entry.Sha256}
}
$wixSource=Join-Path $taskInstaller 'WiX-corresponding-source.zip'
Require ((Hash $wixSource) -ceq $installerReport.wix_sources_sha256 -and (Hash (Join-Path $msiContents 'File/WiXSourceFile')) -ceq $installerReport.wix_sources_sha256) 'The MSI corresponding WiX sources differ from the package provenance.'
Require ((Hash (Join-Path $msiContents 'File/WiXLicenseFile')) -ceq (Hash (Join-Path $taskInstaller 'WiX-MS-RL.txt'))) 'The embedded WiX license differs from the distributed notice.'
$customAction=Join-Path $taskProject "build/installer-native-$Architecture/Release/fuzevpn_installer_actions.dll"
$embeddedAction=Join-Path $msiContents 'Binary/InstallerActions'
Require ((Hash $embeddedAction) -ceq (Hash $customAction)) 'MSI embedded custom action differs from the signed native DLL.'
foreach ($ownFile in @($installerReport.bundle,(Join-Path $taskInstaller 'burn-engine.exe'),$customAction,$embeddedAction)) {
 [void](Assert-SignedFile $ownFile -ExpectedPublisherSubject $taskPolicy.ExpectedPublisherSubject -TimestampRequired)
}
$bundleInfo=[Diagnostics.FileVersionInfo]::GetVersionInfo($installerReport.bundle)
Require ($bundleInfo.ProductName -ceq 'FuzeVPN' -and ('{0}.{1}.{2}.{3}' -f $bundleInfo.FileMajorPart,$bundleInfo.FileMinorPart,$bundleInfo.FileBuildPart,$bundleInfo.FilePrivatePart) -ceq "$Version.0") 'The setup version/product resources differ from the release contract.'
$signatures=@(Get-ReleasePeSigningEvidence $taskPolicy (@(Get-ReleasePeFiles $taskStaging $taskProject)+@(Get-ReleasePeFiles $taskSource $taskProject)+@($installerReport.bundle,(Join-Path $taskInstaller 'burn-engine.exe'),$customAction)) $Architecture)
$embeddedPe=@(Get-ReleasePeSigningEvidence $taskPolicy (@(Get-ReleasePeFiles $baContents $taskProject)+@(Get-ReleasePeFiles $msiContents $taskProject)) $Architecture)
$msiSignature=@(Get-ReleaseSigningEvidence $taskPolicy @($installerReport.msi))
$baPeFiles=@(Get-ReleasePeFiles $baContents $taskProject)
Require ($baPeFiles.Count -eq 1 -and [IO.Path]::GetFileName($baPeFiles[0]) -ieq 'wixstdba.exe') 'The bundle must contain exactly its native standard bootstrapper; registry searches are built into Burn.'
foreach ($file in $baPeFiles) {
 [void](Assert-SignedFile $file -ExpectedPublisherSubject $taskPolicy.ExpectedPublisherSubject -TimestampRequired)
 $name=[IO.Path]::GetFileName($file)
 $original=if ($name -ieq 'utilbe.dll') { Join-Path $taskProject ".toolchain/wix-source/build/Util.wixext/Release/$Architecture/utilbe.dll" } elseif ($name -ieq 'wixstdba.exe') { Join-Path $taskProject ".toolchain/wix-source/build/Bal.wixext/Release/$Architecture/wixstdba.exe" } else { throw "Unexpected embedded bootstrapper PE: $name" }
 Require ((Hash $file) -ceq (Hash $original)) 'Embedded bootstrapper differs from its signed source.'
}
$vendorUnchanged=@()
foreach ($vendor in @($peBaseline | Where-Object { $_.Status -eq 'Valid' -and $_.Subject -cne $taskPolicy.ExpectedPublisherSubject })) {
 $relative=$vendor.File.Substring($taskSource.TrimEnd('\','/').Length+1)
 Require ((Hash (Join-Path $taskSource $relative)) -ceq $vendor.Sha256 -and (Hash (Join-Path $taskStaging $relative)) -ceq $vendor.Sha256) ('A vendor binary was changed: '+$relative)
 $vendorUnchanged += [pscustomobject]@{Path=$relative;Subject=$vendor.Subject;SHA256=$vendor.Sha256;VendorBytesUnchanged=$true}
}
foreach ($recorded in @($portableReport.signing.pe_signatures)+@($installerReport.signing.pe_signatures)) {
 $actual=@($signatures | Where-Object File -CEQ $recorded.File)
 Require ($actual.Count -eq 1 -and $actual[0].Sha256 -ceq $recorded.Sha256 -and $actual[0].Thumbprint -ceq $recorded.Thumbprint) 'Recorded PE signing evidence does not match final bytes.'
}
$result=[ordered]@{Status='PASS';Version=$Version;Architecture=$Architecture;VerifiedUtc=[DateTime]::UtcNow.ToString('o');Artifacts=$artifacts;
 PortableFiles=$portableReport.files.Count;InstallerSourceFiles=$installerReport.files.Count;ZIPFiles=$zipFiles.Count;MSITemplate=$inspection.SummaryTemplate;MSIFileRows=$inspection.File.Count;
 MSICompressedPayloadHashes=$msiHashes;EmbeddedCustomActionHashMatches=$true;EmbeddedMSIHashMatches=$true;EmbeddedBootstrapperHashesMatch=$true;
 DistributedPESignatures=$signatures;ExtractedPESignatures=$embeddedPe;MSISignature=$msiSignature;VendorBytesUnchanged=$vendorUnchanged;AOTAndAssetProvenance=$payloadProvenance;
 DeepDataExtractionDirectory=$deepRoot;PortableRuntimeDevelopment=$false;FlutterAotMachine=$elfMachine;SignedRuntimeManifestVerified=$true;ProductExecuted=$false;InstallerExecuted=$false;CustomActionsExecuted=$false;Arm64ExecutableRun=$false}
$result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $deepRoot 'verification.json') -Encoding UTF8
[pscustomobject]@{Status='PASS';Architecture=$Architecture;PortableFiles=$portableReport.files.Count;InstallerFiles=$installerReport.files.Count;MSIFileRows=$inspection.File.Count;DistributedPEChecks=$signatures.Count;ExtractedPEChecks=$embeddedPe.Count;VendorsPreserved=$vendorUnchanged.Count;Artifacts=$artifacts} | ConvertTo-Json -Depth 5
