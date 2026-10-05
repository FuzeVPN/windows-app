# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [ValidateSet('x64','arm64')][string]$Architecture='x64',
  [Parameter(Mandatory)][string]$WixPath,
  [Parameter(Mandatory)][string]$BalExtensionPath,
  [Parameter(Mandatory)][string]$UtilExtensionPath,
  [string]$DotNetPath = 'C:\Program Files\dotnet\dotnet.exe',
  [string]$ReleaseDirectory,
  [string]$OutputDirectory,
  [string]$CMakePath,
  [string]$WixSourceArchive,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
  [string]$ArtifactSigningMetadataPath,
  [string]$ArtifactSigningDlibPath,
  [string]$ExpectedPublisherSubject,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ArtifactSigningCertificateThumbprint,
  [string]$TimestampUrl,
  [switch]$DevTest,
  [switch]$SkipNativeBuild
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
$policy = New-ReleaseSigningPolicy -CertificateThumbprint $CertificateThumbprint -ArtifactSigningMetadataPath $ArtifactSigningMetadataPath -ArtifactSigningDlibPath $ArtifactSigningDlibPath -ExpectedPublisherSubject $ExpectedPublisherSubject -ArtifactSigningCertificateThumbprint $ArtifactSigningCertificateThumbprint -TimestampUrl $TimestampUrl -DevTest:$DevTest
if ($policy.Mode -eq 'artifact-signing') { [void](Assert-ArtifactSigningInputs $policy $projectRoot) }
$verification = Get-ReleaseVerificationParameters $policy
if (-not $ReleaseDirectory) { $ReleaseDirectory = Join-Path $projectRoot "build\windows\$Architecture\runner\Release" }
$publicVersion = Get-ProjectPublicVersion $projectRoot
$mode = if ($DevTest) { 'devtest' } else { 'production' }
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot "dist\$mode\installer\$publicVersion\$Architecture" }
$ReleaseDirectory = Assert-ProjectPath $ReleaseDirectory $projectRoot
$OutputDirectory = Assert-ProjectPath $OutputDirectory $projectRoot
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Choose a new output directory; existing installer artifacts are never overwritten.' }
$WixPath = Assert-ProjectPath $WixPath $projectRoot
$BalExtensionPath = Assert-ProjectPath $BalExtensionPath $projectRoot
$UtilExtensionPath = Assert-ProjectPath $UtilExtensionPath $projectRoot
if (-not $WixSourceArchive) { $WixSourceArchive = Join-Path $projectRoot 'third_party\wix\wix-source-7.0.0-fuze-x64.zip' }
$WixSourceArchive = Assert-ProjectPath $WixSourceArchive $projectRoot
if (-not (Test-Path -LiteralPath $WixSourceArchive -PathType Leaf)) { throw 'Exact corresponding WiX sources are required for redistribution.' }
foreach ($tool in @($WixPath, $BalExtensionPath, $UtilExtensionPath)) { if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Self-built WiX tool missing: $tool" } }
if (-not $CMakePath) {
  $cache = Join-Path $projectRoot "build\windows\$Architecture\CMakeCache.txt"
  $match = if (Test-Path -LiteralPath $cache) { Select-String -LiteralPath $cache -Pattern '^CMAKE_COMMAND:INTERNAL=(.*)$' | Select-Object -First 1 } else { $null }
  if ($null -ne $match) { $CMakePath = $match.Matches[0].Groups[1].Value }
  else { $CMakePath = (Get-Command cmake.exe -ErrorAction Stop).Source }
}
if (-not (Test-Path -LiteralPath $CMakePath -PathType Leaf)) { throw 'CMake is unavailable.' }
$runtime = Assert-ProjectPath (Join-Path $projectRoot '.toolchain\installer-runtime') $projectRoot
$nativeBuild = Assert-ProjectPath (Join-Path $projectRoot "build\installer-native-$Architecture") $projectRoot
foreach ($directory in @($runtime, $nativeBuild)) { [void][IO.Directory]::CreateDirectory($directory) }
$savedEnvironment = @{}
$localEnvironment = @{
  TEMP = (Join-Path $runtime 'temp'); TMP = (Join-Path $runtime 'temp');
  DOTNET_CLI_HOME = (Join-Path $runtime 'dotnet'); NUGET_PACKAGES = (Join-Path $runtime 'nuget');
  NUGET_HTTP_CACHE_PATH = (Join-Path $runtime 'nuget-http'); NUGET_PLUGINS_CACHE_PATH = (Join-Path $runtime 'nuget-plugins');
  WIX_EXTENSIONS = (Join-Path $runtime 'wix-extensions')
}
foreach ($key in $localEnvironment.Keys) {
  [void][IO.Directory]::CreateDirectory((Assert-ProjectPath $localEnvironment[$key] $projectRoot))
}
$localEnvironment['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
$localEnvironment['DOTNET_SKIP_FIRST_TIME_EXPERIENCE'] = '1'
$localEnvironment['DOTNET_GENERATE_ASPNET_CERTIFICATE'] = 'false'
$localEnvironment['MSBUILDDISABLENODEREUSE'] = '1'
function Invoke-Checked([string]$Executable, [string[]]$Arguments) {
  & $Executable @Arguments | ForEach-Object { Write-Host $_ }
  if ($LASTEXITCODE -ne 0) { throw "Build tool failed ($LASTEXITCODE): $Executable" }
}
function Invoke-Wix([string[]]$Arguments) {
  if ([IO.Path]::GetExtension($WixPath) -ieq '.dll') { Invoke-Checked $DotNetPath (@($WixPath) + $Arguments) }
  else { Invoke-Checked $WixPath $Arguments }
}
function Sign-Files([string[]]$Files, [switch]$Application) {
  $parameters = Get-ReleaseSigningParameters $policy
  $parameters['ReleaseDirectory']=$ReleaseDirectory
  $parameters['Architecture']=$Architecture
  if (-not $Application) { $parameters['OnlyAdditionalFiles'] = $true; $parameters['AdditionalFiles'] = $Files }
  & (Join-Path $PSScriptRoot 'sign-windows-release.ps1') @parameters
}
try {
  foreach ($key in $localEnvironment.Keys) {
    $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    [Environment]::SetEnvironmentVariable($key, $localEnvironment[$key], 'Process')
  }
  Push-Location $projectRoot
  $wixVersion = if ([IO.Path]::GetExtension($WixPath) -ieq '.dll') { & $DotNetPath $WixPath --version } else { & $WixPath --version }
  if ($LASTEXITCODE -ne 0 -or ($wixVersion -join '') -notmatch '^7\.0\.0(?:\D|$)') { throw "WiX v7.0.0 compiled from source is required; found $wixVersion" }
  & (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') -Architecture $Architecture -CheckBuildModeOnly -ReleaseDirectory $ReleaseDirectory -DevTest:$DevTest | Out-Null
  [void](Assert-ReleasePeArchitecture $ReleaseDirectory $projectRoot $Architecture)
  Assert-DcoPayload $ReleaseDirectory -Architecture $Architecture
  if (Test-Path -LiteralPath (Join-Path $ReleaseDirectory 'fuzevpn.portable')) { throw 'An installer cannot contain the portable archive marker.' }
  foreach ($required in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe','flutter_windows.dll','wireguard.dll','tunnel.dll',
      'fuzevpn_tray.ico','THIRD_PARTY_NOTICES.md','licenses\OpenVPN3-corresponding-source.zip','licenses\OpenVPN3-MPL-2.0.txt',
      'data\icudtl.dat','data\flutter_assets\AssetManifest.bin','openvpn-dco\win10\ovpn-dco.cat','openvpn-dco\win10\ovpn-dco.sys','openvpn-dco\win10\ovpn-dco.inf',
      'openvpn-dco\win11\ovpn-dco.cat','openvpn-dco\win11\ovpn-dco.sys','openvpn-dco\win11\ovpn-dco.inf')) {
    if (-not (Test-Path -LiteralPath (Join-Path $ReleaseDirectory $required) -PathType Leaf)) { throw "Incomplete application release: $required" }
  }
  $gui = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $ReleaseDirectory 'fuzevpn_windows.exe'))
  $resourceVersion = '{0}.{1}.{2}.{3}' -f $gui.FileMajorPart,$gui.FileMinorPart,$gui.FileBuildPart,$gui.FilePrivatePart
  if ($resourceVersion -ne "$publicVersion.0") { throw "GUI resource version $resourceVersion must equal public version $publicVersion.0. Rebuild the release." }
  foreach ($applicationFile in @('fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')) {
    $info = [Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $ReleaseDirectory $applicationFile))
    if (('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -ne "$publicVersion.0" -or $info.OriginalFilename -ine $applicationFile) {
      throw "Application resource version/name mismatch: $applicationFile"
    }
  }
  & (Join-Path $projectRoot 'installer\l10n\generate.ps1') -Check
  if (-not $SkipNativeBuild) {
    $cmakeArchitecture = if ($Architecture -eq 'arm64') { 'ARM64' } else { 'x64' }
    Invoke-Checked $CMakePath @('-S', (Join-Path $projectRoot 'installer'), '-B', $nativeBuild, '-A', $cmakeArchitecture)
    $nativeArguments = @('--build', $nativeBuild, '--config', 'Release', '--parallel', '2')
    if ($Architecture -eq 'arm64') { $nativeArguments += @('--target','fuzevpn_installer_actions') }
    Invoke-Checked $CMakePath $nativeArguments
    $ctest = Join-Path ([IO.Path]::GetDirectoryName($CMakePath)) 'ctest.exe'
    # ARM64 executables cannot run on this x64 build host. The host test build
    # explicitly checks both architecture policies without loading the ARM64 DLL.
    $testBuild = if ($Architecture -eq 'arm64') { Join-Path $projectRoot 'build\installer-native-x64' } else { $nativeBuild }
    if ($Architecture -eq 'arm64') {
      Invoke-Checked $CMakePath @('-S', (Join-Path $projectRoot 'installer'), '-B', $testBuild, '-A', 'x64')
      Invoke-Checked $CMakePath @('--build', $testBuild, '--config', 'Release', '--parallel', '2')
    }
    Invoke-Checked $ctest @('--test-dir', $testBuild, '-C', 'Release', '--output-on-failure', '--timeout', '15')
  }
  $customAction = Join-Path $nativeBuild 'Release\fuzevpn_installer_actions.dll'
  if (-not (Test-Path -LiteralPath $customAction -PathType Leaf)) { throw 'Installer custom-action DLL was not built.' }
  [void](Assert-PeArchitecture $customAction $Architecture)
  if (-not $DevTest) {
    Sign-Files -Application
    Sign-Files @($customAction)
    foreach ($file in @('wireguard.dll','tunnel.dll','openvpn-dco\win10\ovpn-dco.cat','openvpn-dco\win11\ovpn-dco.cat')) {
      [void](Assert-SignedFile (Join-Path $ReleaseDirectory $file))
    }
  } else {
    & (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') -Architecture $Architecture -ReleaseDirectory $ReleaseDirectory -DevTest
  }
  $inventory = @(Get-ReleaseInventory $ReleaseDirectory $projectRoot)
  [void][IO.Directory]::CreateDirectory($OutputDirectory)
  $payload = Join-Path $OutputDirectory 'ReleasePayload.wxs'
  Write-ReleasePayload $inventory $payload $Architecture
  $suffix = if ($DevTest) { '-DEVTEST-UNSIGNED' } else { '' }
  $stem = "FuzeVPN-$publicVersion-$Architecture$suffix"
  $msi = Join-Path $OutputDirectory "$stem.msi"
  $bundle = Join-Path $OutputDirectory "$stem.exe"
  $description = if ($DevTest) { "FuzeVPN $Architecture $suffix" } else { "FuzeVPN - Windows $Architecture" }
  $productIdentity = if ($Architecture -eq 'x64') { 'product:' + $publicVersion } else { 'product:arm64:' + $publicVersion }
  Invoke-Wix @('build', (Join-Path $projectRoot 'installer\Package.wxs'), $payload, '-arch', $Architecture,
    '-loc', (Join-Path $projectRoot 'installer\l10n\generated\msi.en.wxl'),
    '-d', "PublicVersion=$publicVersion", '-d', "ReleaseDir=$ReleaseDirectory", '-d', "CustomActionDll=$customAction",
    '-d', "InstallerDir=$(Join-Path $projectRoot 'installer')", '-d', "WixSourceArchive=$WixSourceArchive",
    '-d', "ProductCode=$(Get-StableGuid $productIdentity)", '-d', "PackageDescription=$description",
    '-intermediateFolder', (Join-Path $OutputDirectory 'intermediate-msi'), '-o', $msi)
  $inspection = Get-MsiInspection $msi
  Assert-MsiInspection $inspection $publicVersion ($inventory.Count + 2) $Architecture
  $inspection | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'msi-tables.json') -Encoding UTF8
  if (-not $DevTest) { Sign-Files @($msi) }
  Invoke-Wix @('build', (Join-Path $projectRoot 'installer\Bundle.wxs'), (Join-Path $projectRoot 'installer\l10n\generated\LocalizationPayloads.wxs'), '-arch', $Architecture, '-ext', $BalExtensionPath, '-ext', $UtilExtensionPath,
    '-d', "PublicVersion=$publicVersion", '-d', "ReleaseDir=$ReleaseDirectory", '-d', "MsiPath=$msi",
    '-d', "InstallerDir=$(Join-Path $projectRoot 'installer')", '-d', "ProjectRoot=$projectRoot",
    '-d', "BuildNotice=$(if ($DevTest) { "- $Architecture DEVTEST-UNSIGNED" } else { "- Windows $Architecture" })",
    '-intermediateFolder', (Join-Path $OutputDirectory 'intermediate-bundle'), '-o', $bundle)
  [void](Assert-PeArchitecture $bundle $Architecture)
  if (-not $DevTest) {
    $engine = Join-Path $OutputDirectory 'burn-engine.exe'
    Invoke-Wix @('burn', 'detach', $bundle, '-engine', $engine)
    [void](Assert-PeArchitecture $engine $Architecture)
    Sign-Files @($engine)
    $attached = Join-Path $OutputDirectory 'burn-reattached.exe'
    Invoke-Wix @('burn', 'reattach', $bundle, '-engine', $engine, '-o', $attached)
    Move-Item -LiteralPath $attached -Destination $bundle -Force
    Sign-Files @($bundle)
    foreach ($file in @($bundle,$msi,$customAction,(Join-Path $ReleaseDirectory 'fuzevpn_windows.exe'),(Join-Path $ReleaseDirectory 'fuzevpn-service.exe'),(Join-Path $ReleaseDirectory 'fuzevpn-update.exe'),(Join-Path $ReleaseDirectory 'fuzevpn-runtime.exe'))) {
      [void](Assert-SignedFile $file @verification)
    }
  }
  $bundleInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($bundle)
  $bundleVersion = '{0}.{1}.{2}.{3}' -f $bundleInfo.FileMajorPart,$bundleInfo.FileMinorPart,$bundleInfo.FileBuildPart,$bundleInfo.FilePrivatePart
  if ($bundleInfo.ProductName -cne 'FuzeVPN' -or $bundleVersion -ne "$publicVersion.0") { throw "Bundle resource contract mismatch: $($bundleInfo.ProductName) $bundleVersion" }
  if ((Get-Item -LiteralPath $bundle).Length -gt 512MB) { throw 'The updater accepts bundles of at most 512 MiB.' }
  $after = @(Get-ReleaseInventory $ReleaseDirectory $projectRoot)
  if (($inventory | ConvertTo-Json -Compress) -cne ($after | ConvertTo-Json -Compress)) { throw 'Release changed while packaging; discard this output and rebuild.' }
  $signatureFiles = @($bundle,$msi,$customAction) + @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe' | ForEach-Object { Join-Path $ReleaseDirectory $_ })
  $signatures = @(Get-ReleaseSigningEvidence $policy $signatureFiles)
  $extraPeFiles = @($bundle,$customAction)
  if (-not $DevTest) { $extraPeFiles += $engine }
  $peSignatures = @(Get-ReleasePeSigningEvidence $policy (@(Get-ReleasePeFiles $ReleaseDirectory $projectRoot) + $extraPeFiles) $Architecture)
  $effectiveThumbprint = if ($DevTest) { '' } else { @($signatures | Where-Object File -eq $bundle)[0].Thumbprint }
  $report = [ordered]@{
    public = (-not $DevTest); mode = $mode; version = $publicVersion; architecture=$Architecture; resource_version = $bundleVersion;
    wix_version = ($wixVersion -join '').Trim(); wix_path = $WixPath; wix_sha256 = (Get-FileHash -LiteralPath $WixPath -Algorithm SHA256).Hash.ToLowerInvariant();
    bal_extension_sha256 = (Get-FileHash -LiteralPath $BalExtensionPath -Algorithm SHA256).Hash.ToLowerInvariant();
    util_extension_sha256 = (Get-FileHash -LiteralPath $UtilExtensionPath -Algorithm SHA256).Hash.ToLowerInvariant();
    wix_sources_sha256 = (Get-FileHash -LiteralPath $WixSourceArchive -Algorithm SHA256).Hash.ToLowerInvariant();
    bundle = $bundle; bundle_sha256 = (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant();
    msi = $msi; msi_sha256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant();
    signed_by = $effectiveThumbprint;
    signing = @{ backend=$policy.Mode; expected_publisher_subject=$policy.ExpectedPublisherSubject; configured_certificate_pin=$policy.CertificateThumbprint;
      metadata=$(if ($policy.Mode -eq 'artifact-signing') { Read-ArtifactSigningMetadata $policy.MetadataPath } else { $null }); file_signatures=$signatures; pe_signatures=$peSignatures };
    files = $inventory; installed_on_this_machine = $false
  }
  $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'package-report.json') -Encoding UTF8
  Copy-Item -LiteralPath $WixSourceArchive -Destination (Join-Path $OutputDirectory 'WiX-corresponding-source.zip') -Force
  Copy-Item -LiteralPath (Join-Path $projectRoot 'installer\WiX-MS-RL.txt') -Destination (Join-Path $OutputDirectory 'WiX-MS-RL.txt') -Force
  if ($DevTest) { 'VALIDATION LOCALE NON SIGNEE. Ne pas publier ni distribuer. Aucun MSI/EXE produit execute ou installe par ce script.' | Set-Content -LiteralPath (Join-Path $OutputDirectory 'DEVTEST-NOT-FOR-DISTRIBUTION.txt') -Encoding UTF8 }
  Write-Host "Installer built and inspected without installation: $bundle"
} finally {
  if ((Get-Location).Path -eq $projectRoot) { Pop-Location }
  foreach ($key in $savedEnvironment.Keys) {
    if ($null -eq $savedEnvironment[$key]) {
      if (Test-Path -LiteralPath "Env:$key") { Remove-Item -LiteralPath "Env:$key" }
    } else {
      [Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key], 'Process')
    }
  }
}
