# SPDX-License-Identifier: MPL-2.0
[CmdletBinding(DefaultParameterSetName = 'Project')]
param(
  [Parameter(Mandatory, ParameterSetName = 'Project')][string]$Project,
  [Parameter(ParameterSetName = 'Project')][string]$Target = 'Build',
  [Parameter(ParameterSetName = 'Project')][switch]$Native,
  [Parameter(ParameterSetName = 'Project')][string[]]$Properties = @(),
  [Parameter(Mandatory, ParameterSetName = 'Cli')][string[]]$WixArguments
)
$ErrorActionPreference = 'Stop'
$taskRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$sourceRoot = Join-Path $taskRoot '.toolchain\wix-source'
$runtime = Join-Path $taskRoot '.toolchain\installer-runtime'
$dotnetRoot = Join-Path $taskRoot '.toolchain\dotnet-sdk'
$dotnet = Join-Path $dotnetRoot 'dotnet.exe'
if (-not (Test-Path -LiteralPath $dotnet -PathType Leaf)) { throw "Local .NET SDK missing: $dotnet" }
if (-not (Test-Path -LiteralPath $sourceRoot -PathType Container)) { throw "WiX source directory missing: $sourceRoot" }

if ($Native) {
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
  if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
    $vswhere = (Get-Command vswhere.exe -ErrorAction Stop).Source
  }
  $msbuildPaths = @(& $vswhere -latest -products '*' -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'MSBuild\Current\Bin\MSBuild.exe')
  if ($LASTEXITCODE -ne 0 -or $msbuildPaths.Count -eq 0) { throw 'Visual Studio MSBuild with the C++ build tools was not found by vswhere.' }
  $msbuild = $msbuildPaths[0]
  if (-not (Test-Path -LiteralPath $msbuild -PathType Leaf)) { throw "Visual Studio MSBuild missing: $msbuild" }
}

# Keep the real Windows profile folders available for SDK discovery. Only
# temporary files, CLI state and package caches use the project runtime.
$localEnvironment = @{
  TEMP = (Join-Path $runtime 'temp')
  TMP = (Join-Path $runtime 'temp')
  DOTNET_CLI_HOME = (Join-Path $runtime 'dotnet')
  NUGET_PACKAGES = (Join-Path $runtime 'nuget')
  NUGET_HTTP_CACHE_PATH = (Join-Path $runtime 'http-cache')
  NUGET_PLUGINS_CACHE_PATH = (Join-Path $runtime 'plugins-cache')
}
foreach ($directory in $localEnvironment.Values) { [void][IO.Directory]::CreateDirectory($directory) }
$localEnvironment['DOTNET_ROOT'] = $dotnetRoot
$localEnvironment['DOTNET_CLI_TELEMETRY_OPTOUT'] = '1'
$localEnvironment['DOTNET_SKIP_FIRST_TIME_EXPERIENCE'] = '1'
$localEnvironment['DOTNET_GENERATE_ASPNET_CERTIFICATE'] = 'false'
$localEnvironment['DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE'] = 'true'
$localEnvironment['MSBUILDDISABLENODEREUSE'] = '1'
$localEnvironment['PATH'] = "$dotnetRoot;$env:PATH"
$savedEnvironment = @{}
$locationPushed = $false
try {
  foreach ($key in $localEnvironment.Keys) {
    $savedEnvironment[$key] = [Environment]::GetEnvironmentVariable($key, 'Process')
    [Environment]::SetEnvironmentVariable($key, $localEnvironment[$key], 'Process')
  }
  Push-Location $sourceRoot
  $locationPushed = $true
  if ($PSCmdlet.ParameterSetName -eq 'Cli') {
    & $dotnet @WixArguments
    if ($LASTEXITCODE -ne 0) { throw "WiX CLI failed ($LASTEXITCODE)" }
  } else {
    $arguments = @($Project, '-restore', "-t:$Target", '-nologo', '-verbosity:minimal', '-p:Configuration=Release')
    foreach ($property in $Properties) { $arguments += "-p:$property" }
    if ($Native) { & $msbuild @arguments }
    else { & $dotnet msbuild @arguments }
    if ($LASTEXITCODE -ne 0) { throw "WiX source build failed ($LASTEXITCODE): $Project" }
  }
} finally {
  try { if ($locationPushed) { Pop-Location } }
  finally {
    foreach ($key in $savedEnvironment.Keys) {
      if ($null -eq $savedEnvironment[$key]) {
        # Preserve absence rather than creating an empty variable on newer .NET.
        if (Test-Path -LiteralPath "Env:$key") { Remove-Item -LiteralPath "Env:$key" }
      } else {
        [Environment]::SetEnvironmentVariable($key, $savedEnvironment[$key], 'Process')
      }
    }
  }
}
