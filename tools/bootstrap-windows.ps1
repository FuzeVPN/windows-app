# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [ValidateSet('x64','arm64','both')][string]$Architecture = 'x64',
  [switch]$IncludeInstaller,
  # Used only to coordinate independent native dependency work with a caller
  # already initializing the pinned Flutter SDK. Normal bootstrap includes it.
  [switch]$SkipFlutter,
  [switch]$Offline,
  [string[]]$DownloadSeeds = @(),
  [ValidateRange(1,32)][int]$Parallel = 6
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'BuildSupport.psm1') -Force
$root = Get-FuzeProjectRoot
$pins = Get-FuzeDependencyPins
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -and $env:PROCESSOR_ARCHITEW6432 -ne 'AMD64') { throw 'The public build tools require a Windows x64 host; ARM64 is a cross-compilation target.' }
$architectures = if ($Architecture -eq 'both') {@('x64','arm64')} else {@($Architecture)}
foreach ($arch in $architectures) { [void](Get-FuzeVisualStudioTools -Architecture $arch) }
$toolchain = Join-Path $root '.toolchain'
[void][IO.Directory]::CreateDirectory($toolchain)
$saved = @{}
foreach ($name in @('PUB_CACHE','CI','FLUTTER_SUPPRESS_ANALYTICS','DART_SUPPRESS_ANALYTICS','GIT_TERMINAL_PROMPT','VCPKG_DOWNLOADS','VCPKG_DEFAULT_BINARY_CACHE','VCPKG_MAX_CONCURRENCY','DOTNET_CLI_HOME','NUGET_PACKAGES','DOTNET_CLI_TELEMETRY_OPTOUT')) { $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location $root
try {
  $env:PUB_CACHE = Join-Path $toolchain 'pub-cache'
  $env:CI = 'true'
  $env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
  $env:DART_SUPPRESS_ANALYTICS = 'true'
  $env:GIT_TERMINAL_PROMPT = '0'
  if (-not $SkipFlutter) {
  $flutterRoot = Join-Path $toolchain 'flutter'
  Initialize-FuzeGitDependency -Repository $pins.flutter.repository -Commit $pins.flutter.commit -Tag $pins.flutter.tag -Directory $flutterRoot -Offline:$Offline
  $flutter = Join-Path $flutterRoot 'bin/flutter.bat'
  if ($Offline -and -not (Test-Path -LiteralPath (Join-Path $flutterRoot 'bin/cache/flutter_tools.snapshot'))) { throw 'Offline bootstrap requires the already initialized pinned Flutter tool cache.' }
  # Flutter's official source tool bootstraps its Dart SDK at the pinned engine
  # revision. The SDK is verified before it can resolve project dependencies.
  Invoke-FuzeChecked $flutter @('--version')
  $versionOutput = @(& $flutter --version --machine)
  if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the pinned Flutter SDK.' }
  $version = ($versionOutput -join "`n") | ConvertFrom-Json
  if ($version.frameworkVersion -cne $pins.flutter.version -or $version.dartSdkVersion -cne $pins.flutter.dart_version -or $version.engineRevision -cne $pins.flutter.engine) { throw 'Pinned Flutter, Dart or engine version mismatch. No alternate SDK was selected.' }
  if (-not $Offline) { Invoke-FuzeChecked $flutter @('precache','--windows') }
  if ('arm64' -in $architectures) {
    foreach ($artifact in $pins.arm64_engine_artifacts) {
      $archive = Get-FuzePinnedDownload -Pin $artifact -Offline:$Offline -DownloadSeeds $DownloadSeeds
      Expand-FuzeZip -Archive $archive -Destination (Join-Path $flutterRoot ('bin/cache/artifacts/engine/' + $artifact.destination))
    }
  }
  $pubArguments = @('pub','get','--enforce-lockfile')
  if ($Offline) { $pubArguments += '--offline' }
  Invoke-FuzeChecked $flutter $pubArguments
  }

  $vcpkgRoot = Join-Path $toolchain 'vcpkg'
  Initialize-FuzeGitDependency -Repository $pins.vcpkg.repository -Commit $pins.vcpkg.commit -Directory $vcpkgRoot -Offline:$Offline
  $vcpkg = Join-Path $vcpkgRoot 'vcpkg.exe'
  if (-not (Test-Path -LiteralPath $vcpkg)) {
    if ($Offline) { throw 'Offline bootstrap requires the pinned vcpkg executable cache.' }
    Invoke-FuzeChecked (Join-Path $vcpkgRoot 'bootstrap-vcpkg.bat') @('-disableMetrics')
  }
  $env:VCPKG_DOWNLOADS = Join-Path $toolchain 'downloads'
  $env:VCPKG_DEFAULT_BINARY_CACHE = Join-Path $toolchain 'vcpkg-binary-cache'
  $env:VCPKG_MAX_CONCURRENCY = "$Parallel"
  [void][IO.Directory]::CreateDirectory($env:VCPKG_DEFAULT_BINARY_CACHE)
  if ('arm64' -in $architectures) {
    # vcpkg extracts this NSIS archive as data; no LLVM installer is launched.
    $llvmArchive = Get-FuzePinnedDownload -Pin $pins.llvm -Offline:$Offline -DownloadSeeds $DownloadSeeds
    $llvmDirectory = Join-Path $env:VCPKG_DOWNLOADS 'tools/clang-21.1.8-windows'
    $clang = Join-Path $llvmDirectory 'bin/clang.exe'
    if (-not (Test-Path -LiteralPath $clang)) {
      $sevenZip = Get-Command 7z.exe -ErrorAction SilentlyContinue
      if ($sevenZip) { $extractor = $sevenZip.Source }
      else {
        if ($Offline) { throw 'Offline LLVM extraction needs 7z.exe on PATH or a previously extracted LLVM cache.' }
        $extractor = @(& $vcpkg fetch 7zip --x-stderr-status) | Select-Object -Last 1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $extractor)) { throw 'vcpkg could not acquire 7-Zip; install 7-Zip on PATH and retry.' }
      }
      Invoke-FuzeChecked $extractor @('x',$llvmArchive,"-o$llvmDirectory",'-y','-bso0','-bsp0')
    }
    $clangVersion = @(& $clang --version) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $clangVersion -notmatch ('(?m)^clang version ' + [regex]::Escape($pins.llvm.version) + '(?:\s|$)')) { throw 'The pinned LLVM ARM64 assembler was not extracted correctly.' }
  }
  $core = Join-Path $root 'third_party/openvpn3-core'
  foreach ($arch in $architectures) {
    $installRoot = Join-Path $toolchain "vcpkg-installed-$arch"
    $arguments = @('install',"--triplet=$arch-windows",'--host-triplet=x64-windows',"--x-manifest-root=$core", "--x-install-root=$installRoot", "--x-buildtrees-root=$toolchain/vcpkg-buildtrees-$arch", "--x-packages-root=$toolchain/vcpkg-packages-$arch", '--disable-metrics')
    if ($Offline) { $arguments += '--no-downloads' }
    Invoke-FuzeChecked $vcpkg $arguments
    Publish-FuzeNativeTriplet -InstallRoot $installRoot -Architecture $arch
    $openssl = Join-Path $core "vcpkg_installed/$arch-windows/share/openssl/OpenSSLConfigVersion.cmake"
    if (-not (Test-Path -LiteralPath $openssl) -or (Get-Content -LiteralPath $openssl -Raw) -notmatch 'set\(PACKAGE_VERSION 3\.6\.5\)') { throw "The pinned OpenSSL 3.6.5 build is missing for $arch." }
  }
  if ($IncludeInstaller) {
    $dotnetArchive = Get-FuzePinnedDownload -Pin $pins.dotnet -Offline:$Offline -DownloadSeeds $DownloadSeeds
    $dotnetRoot = Join-Path $toolchain 'dotnet-sdk'
    if (-not (Test-Path -LiteralPath (Join-Path $dotnetRoot ('sdk/' + $pins.dotnet.version)))) { Expand-FuzeZip -Archive $dotnetArchive -Destination $dotnetRoot }
    $dotnet = Join-Path $dotnetRoot 'dotnet.exe'
    $env:DOTNET_CLI_HOME = Join-Path $toolchain 'installer-runtime/dotnet'
    $env:NUGET_PACKAGES = Join-Path $toolchain 'installer-runtime/nuget'
    $env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
    [void][IO.Directory]::CreateDirectory($env:DOTNET_CLI_HOME)
    $actualDotnet = (& $dotnet --version).Trim()
    if ($LASTEXITCODE -ne 0 -or $actualDotnet -cne $pins.dotnet.version) { throw 'Pinned .NET SDK version mismatch.' }
    $wixArchive = Join-Path $root $pins.wix.source_archive
    Assert-FuzeHash -Path $wixArchive -Hash $pins.wix.hash
    $wixRoot = Join-Path $toolchain 'wix-source'
    if (-not (Test-Path -LiteralPath (Join-Path $wixRoot 'global.json'))) { Expand-FuzeZip -Archive $wixArchive -Destination $wixRoot -Prefix $pins.wix.prefix }
    if ($Offline) {
      # Offline uses tools previously built from these exact archived sources.
      # It cannot populate a fresh NuGet cache or silently use installed WiX.
      $required = @('build/wix/Release/publish/wix/wix.dll',
        'build/Bal.wixext/Release/netstandard2.0/WixToolset.BootstrapperApplications.wixext.dll',
        'build/Util.wixext/Release/netstandard2.0/WixToolset.Util.wixext.dll')
      if ('arm64' -in $architectures) { $required += 'build/wix/Release/publish/wix/arm64/burn.exe' }
      foreach ($relative in $required) {
        if (-not (Test-Path -LiteralPath (Join-Path $wixRoot $relative))) { throw 'Offline installer bootstrap requires a previously completed online -IncludeInstaller build and its NuGet cache.' }
      }
    } else {
      foreach ($phase in @('Packages','Native','Cli','Bal','Util')) { & (Join-Path $PSScriptRoot 'wix/build-wix-source.ps1') -Phase $phase }
      if ('arm64' -in $architectures) { & (Join-Path $root 'installer/build-wix-architectures.ps1') -Phase Native }
    }
  }
  Write-Host "Pinned bootstrap complete for $($architectures -join ', '). No application, VPN or installer was executed."
} finally {
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
  Pop-Location
}
