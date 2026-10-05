# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [ValidateSet('x64','arm64','both')][string]$Architecture = 'x64',
  [switch]$DevTest,
  [switch]$Offline,
  [switch]$SkipBootstrap,
  [switch]$SkipTests,
  [ValidateRange(1,16)][int]$Parallel = 6
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'BuildSupport.psm1') -Force
$projectRoot = Get-FuzeProjectRoot
$architectures = if ($Architecture -eq 'both') { @('x64','arm64') } else { @($Architecture) }
if (-not $SkipBootstrap) {
  & (Join-Path $PSScriptRoot 'bootstrap-windows.ps1') -Architecture $Architecture -Offline:$Offline -Parallel $Parallel
}
$flutter = Join-Path $projectRoot '.toolchain/flutter/bin/flutter.bat'
if (-not (Test-Path -LiteralPath $flutter)) { throw 'The pinned Flutter SDK is missing. Run bootstrap-windows.ps1 first.' }
$saved = @{}
foreach ($name in @('PUB_CACHE','CI','FLUTTER_SUPPRESS_ANALYTICS','DART_SUPPRESS_ANALYTICS','LOCALAPPDATA','TEMP','TMP')) { $saved[$name] = [Environment]::GetEnvironmentVariable($name,'Process') }
Push-Location $projectRoot
try {
  $env:PUB_CACHE = Join-Path $projectRoot '.toolchain/pub-cache'
  $env:CI = 'true'
  $env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
  $env:DART_SUPPRESS_ANALYTICS = 'true'
  $pubArguments = @('pub','get','--enforce-lockfile')
  if ($Offline) { $pubArguments += '--offline' }
  Invoke-FuzeChecked $flutter $pubArguments
  Invoke-FuzeChecked $flutter @('analyze','--no-pub')
  if (-not $SkipTests) {
    # Diagnostic test doubles must never write into real FuzeVPN user data.
    $env:LOCALAPPDATA = Join-Path $projectRoot 'build/test-runtime'
    $env:TEMP = Join-Path $env:LOCALAPPDATA 'temp'
    $env:TMP = $env:TEMP
    [void][IO.Directory]::CreateDirectory($env:TEMP)
    try { Invoke-FuzeChecked $flutter @('test','--no-pub') }
    finally { foreach ($name in @('LOCALAPPDATA','TEMP','TMP')) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') } }
  }
  # Flutter plugin and AOT staging directories are shared. Build serially.
  foreach ($arch in $architectures) {
    & (Join-Path $PSScriptRoot 'build-windows-multiarch.ps1') -Architecture $arch -DevTest:$DevTest -Offline:$Offline -Parallel $Parallel
    if (-not $SkipTests) {
      $tools = Get-FuzeVisualStudioTools -Architecture $arch
      $nativeBuild = Join-Path $projectRoot "build/windows/$arch"
      $targets = @('fuzevpn_native_security_test','fuzevpn_network_runtime_test','fuzevpn_network_filter_test',
        'fuzevpn_tray_icon_test','fuzevpn_openvpn_safety_test','fuzevpn_update_security_test',
        'fuzevpn_portable_update_test','fuzevpn_portable_runtime_test','fuzevpn_distribution_mode_test',
        'fuzevpn_api_resolver_adapter_test','fuzevpn_diagnostics_snapshot_test','fuzevpn_diagnostics_store_test',
        'fuzevpn_window_geometry_test','fuzevpn_runtime_architecture_test')
      Invoke-FuzeChecked $tools.CMake (@('--build',$nativeBuild,'--config','Release','--target') + $targets + @('--parallel',"$Parallel"))
      if ($arch -eq 'x64') {
        Invoke-FuzeChecked $tools.CTest @('--test-dir',$nativeBuild,'-C','Release','--output-on-failure','--no-tests=error')
      } else { Write-Host 'ARM64 native fixtures compiled; execute them on an ARM64 Windows test machine.' }
    }
  }
  Write-Host 'Builds completed without signing, launching an application, installing a service or activating a VPN.'
  if ($DevTest) { Write-Warning 'Development test builds use explicit portable test policy. Never publish them as FuzeVPN releases.' }
} finally {
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name,$saved[$name],'Process') }
  Pop-Location
}