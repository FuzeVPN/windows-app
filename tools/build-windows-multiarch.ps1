# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
  [switch]$DevTest,
  [switch]$Offline,
  [ValidateRange(1, 16)][int]$Parallel = 6
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'BuildSupport.psm1') -Force
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$flutter = Join-Path $projectRoot '.toolchain\flutter\bin\flutter.bat'
$tools = Get-FuzeVisualStudioTools -Architecture $Architecture
$visualStudio = $tools.Installation
if (-not (Test-Path -LiteralPath $flutter -PathType Leaf)) { throw 'Run tools/bootstrap-windows.ps1 before building. This script never selects a different Flutter SDK.' }
$pins = Get-FuzeDependencyPins
$actualRevision = (& git.exe -C (Join-Path $projectRoot '.toolchain/flutter') rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $actualRevision -cne $pins.flutter.commit) { throw 'The Flutter source revision does not match dependency-pins.json.' }
if ($Architecture -eq 'arm64') {
  foreach ($required in @('windows-arm64\icudtl.dat', 'windows-arm64\cpp_client_wrapper\include\flutter\flutter_engine.h', 'windows-arm64-release\flutter_windows.dll', 'windows-arm64-release\gen_snapshot.exe')) {
    if (-not (Test-Path -LiteralPath (Join-Path $projectRoot ('.toolchain\flutter\bin\cache\artifacts\engine\' + $required)))) {
      throw "Missing pinned Flutter ARM64 artifact: $required"
    }
  }
}
$cmake = Join-Path $visualStudio 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
if (-not (Test-Path -LiteralPath $cmake)) { throw 'Visual Studio CMake is required.' }
$buildRoot = Join-Path $projectRoot ('build\windows\' + $Architecture)
$targetPlatform = 'windows-' + $Architecture
$generatorPlatform = if ($Architecture -eq 'arm64') { 'ARM64' } else { 'x64' }
$runtimeRoot = Join-Path $projectRoot '.toolchain\build-runtime'
[void][IO.Directory]::CreateDirectory((Join-Path $runtimeRoot 'temp'))

function Invoke-TaskChecked([string]$FilePath, [string[]]$Arguments) {
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$FilePath failed with exit code $LASTEXITCODE" }
}

Push-Location $projectRoot
$savedEnvironment = @{}
foreach ($name in @('TEMP','TMP','PUB_CACHE','CI','FLUTTER_SUPPRESS_ANALYTICS','DART_SUPPRESS_ANALYTICS')) {
  $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
  $env:TEMP = Join-Path $runtimeRoot 'temp'
  $env:TMP = $env:TEMP
  $env:PUB_CACHE = Join-Path $projectRoot '.toolchain\pub-cache'
  $env:CI = 'true'
  $env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
  $env:DART_SUPPRESS_ANALYTICS = 'true'
  $pubArguments = @('pub', 'get', '--enforce-lockfile')
  if ($Offline) { $pubArguments += '--offline' }
  Invoke-TaskChecked $flutter $pubArguments
  # Flutter's Windows CLI chooses the host architecture. It generates common
  # project/plugin/version metadata; CMake and the stock tool backend select
  # the explicit target below. Shared ephemeral assets require serial builds.
  Invoke-TaskChecked $flutter @('build', 'windows', '--release', '--no-pub', '--config-only')
  $developmentFlag = if ($DevTest) { 'ON' } else { 'OFF' }
  Invoke-TaskChecked $cmake @('-S', (Join-Path $projectRoot 'windows'), '-B', $buildRoot,
    '-G', 'Visual Studio 18 2026', '-A', $generatorPlatform,
    "-DFLUTTER_TARGET_PLATFORM=$targetPlatform", "-DFUZEVPN_TARGET_ARCH=$Architecture",
    "-DFUZEVPN_ALLOW_PORTABLE_DEV=$developmentFlag")
  Invoke-TaskChecked $cmake @('--build', $buildRoot, '--config', 'Release',
    '--target', 'INSTALL', '--parallel', "$Parallel")
  $policy = if ($DevTest) { 'Development test' } else { 'Unsigned production-policy' }
  Write-Output "$policy $Architecture build ready: $(Join-Path $buildRoot 'runner\Release')"
} finally {
  foreach ($name in $savedEnvironment.Keys) {
    [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
  }
  Pop-Location
}
