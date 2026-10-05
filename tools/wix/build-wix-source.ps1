# SPDX-License-Identifier: MPL-2.0
param([ValidateSet('Packages','Native','Cli','Bal','Util')][string]$Phase = 'Packages')
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$sourceRoot = Join-Path $taskRoot '.toolchain/wix-source'
$launcher = Join-Path $PSScriptRoot 'invoke-wix-build.ps1'
$artifacts = Join-Path $sourceRoot 'build/artifacts'
New-Item -ItemType Directory -Path $artifacts -Force | Out-Null

function Invoke-WixProject([string]$Project, [string]$Target = 'Build', [switch]$Native, [string[]]$Extra = @()) {
  $properties = @('PlatformToolset=v145', 'WixNativeSdkLibraryToolset=v145', 'NCrunch=true', 'FuzeSourceBuild=true') + $Extra
  if ($Native) { $properties += 'Platform=x64' }
  & $launcher -Project $Project -Target $Target -Native:$Native -Properties $properties
}

# Only locally compiled x64 assets enter these private packages. This does not
# download or repackage the official WiX binary distributions.
function New-NativePackage([string]$Id, [hashtable]$Files, [string]$Dependencies = '') {
  $packagePath = Join-Path $artifacts "$Id.7.0.0.nupkg"
  $stream = [IO.File]::Open($packagePath, [IO.FileMode]::Create)
  $zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create)
  try {
    $metadata = @"
<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd"><metadata><id>$Id</id><version>7.0.0</version><authors>FuzeVPN local source build</authors><description>Private x64 build from WiX source v7.0.0.</description><license type="file">LICENSE.TXT</license>$Dependencies</metadata></package>
"@
    $writer = [IO.StreamWriter]::new($zip.CreateEntry("$Id.nuspec").Open())
    try { $writer.Write($metadata) } finally { $writer.Dispose() }
    $Files['LICENSE.TXT'] = Join-Path $sourceRoot 'LICENSE.TXT'
    foreach ($entry in $Files.GetEnumerator()) {
      [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $entry.Value, $entry.Key, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
  } finally { $zip.Dispose(); $stream.Dispose() }
}

switch ($Phase) {
  'Packages' {
    Invoke-WixProject 'src/api/wix/WixToolset.Data/WixToolset.Data.csproj' 'Pack' -Extra @('TargetFrameworks=netstandard2.0')
    Invoke-WixProject 'src/api/wix/WixToolset.Extensibility/WixToolset.Extensibility.csproj' 'Pack' -Extra @('TargetFrameworks=netstandard2.0')
    Invoke-WixProject 'src/libs/WixToolset.Versioning/WixToolset.Versioning.csproj' 'Pack'
    Invoke-WixProject 'src/dtf/WixToolset.Dtf.Resources/WixToolset.Dtf.Resources.csproj' 'Pack' -Extra @('TargetFrameworks=netstandard2.0')
  }
  'Native' {
    Invoke-WixProject 'src/libs/dutil/WixToolset.DUtil/dutil.vcxproj' -Native
    $files = @{
      'build/WixToolset.DUtil.props' = Join-Path $sourceRoot 'src/libs/dutil/WixToolset.DUtil/build/WixToolset.DUtil.props'
      'build/native/v14/x64/dutil.lib' = Join-Path $sourceRoot 'build/libs/Release/v145/x64/dutil.lib'
    }
    Get-ChildItem (Join-Path $sourceRoot 'src/libs/dutil/WixToolset.DUtil/inc') -File | ForEach-Object { $files["build/native/include/$($_.Name)"] = $_.FullName }
    New-NativePackage 'WixToolset.DUtil' $files
    Invoke-WixProject 'src/burn/stub/stub.vcxproj' -Native
    New-NativePackage 'WixToolset.Burn' @{
      'buildTransitive/WixToolset.Burn.props' = Join-Path $sourceRoot 'src/burn/stub/WixToolset.Burn.props'
      'tools/x64/burn.exe' = Join-Path $sourceRoot 'build/burn/Release/x64/burn.exe'
    }
    Invoke-WixProject 'src/wix/wixnative/wixnative.vcxproj' -Native
    Invoke-WixProject 'src/api/burn/balutil/balutil.vcxproj' -Native
    $files = @{
      'build/WixToolset.BootstrapperApplicationApi.props' = Join-Path $sourceRoot 'src/api/burn/WixToolset.BootstrapperApplicationApi/build/WixToolset.BootstrapperApplicationApi.props'
      'build/native/v14/x64/balutil.lib' = Join-Path $sourceRoot 'build/api/Release/v145/x64/balutil.lib'
      'build/native/include/BootstrapperApplicationTypes.h' = Join-Path $sourceRoot 'src/api/burn/inc/BootstrapperApplicationTypes.h'
      'build/native/include/BootstrapperEngineTypes.h' = Join-Path $sourceRoot 'src/api/burn/inc/BootstrapperEngineTypes.h'
    }
    Get-ChildItem (Join-Path $sourceRoot 'src/api/burn/balutil/inc') -File | ForEach-Object { $files["build/native/include/$($_.Name)"] = $_.FullName }
    New-NativePackage 'WixToolset.BootstrapperApplicationApi' $files '<dependencies><group targetFramework="native"><dependency id="WixToolset.DUtil" version="[7.0.0]" /></group></dependencies>'
    foreach ($name in @('wixstdba','wixprqba','wixiuiba')) { Invoke-WixProject "src/ext/Bal/$name/$name.vcxproj" -Native }
  }
  'Cli' {
    Invoke-WixProject 'src/wix/wix/wix.csproj' 'Publish' -Extra @('RuntimeIdentifier=win-x64',"PublishDir=$sourceRoot/build/wix/Release/publish/wix/")
  }
  'Bal' {
    # Restore project dependencies before building the x64 bootstrapper library.
    Invoke-WixProject 'src/ext/Bal/wixext/WixToolset.BootstrapperApplications.wixext.csproj' 'Restore'
    $wix = Join-Path $sourceRoot 'build/wix/Release/publish/wix/wix.dll'
    $baOutput = Join-Path $sourceRoot 'build/Bal.wixext/Release'
    $baSources = Join-Path $sourceRoot 'src/ext/Bal/wixlib'
    $arguments = @($wix, 'build', '-outputtype', 'library', '-bf', '-arch', 'x64', '-o', "$baOutput/bas.wixlib", '-intermediateFolder', "$baOutput/obj/bas", '-b', "$sourceRoot/src/ext/Bal/stdbas/Resources")
    foreach ($name in @('wixstdba','wixprqba','wixiuiba')) { $arguments += @('-b', "$name.x64=$baOutput/x64") }
    foreach ($name in @('bas_x64','wixstdba','wixprqba','wixiuiba')) { $arguments += "$baSources/$name.wxs" }
    & $launcher -WixArguments $arguments
    Invoke-WixProject 'src/ext/Bal/wixext/WixToolset.BootstrapperApplications.wixext.csproj'
  }
  'Util' {
    Invoke-WixProject 'src/api/burn/bextutil/bextutil.vcxproj' -Native
    $files = @{
      'build/WixToolset.BootstrapperExtensionApi.props' = Join-Path $sourceRoot 'src/api/burn/bextutil/build/WixToolset.BootstrapperExtensionApi.props'
      'build/native/v14/x64/bextutil.lib' = Join-Path $sourceRoot 'build/api/Release/v145/x64/bextutil.lib'
      'build/native/include/BootstrapperExtensionTypes.h' = Join-Path $sourceRoot 'src/api/burn/inc/BootstrapperExtensionTypes.h'
      'build/native/include/BootstrapperExtensionEngineTypes.h' = Join-Path $sourceRoot 'src/api/burn/inc/BootstrapperExtensionEngineTypes.h'
    }
    Get-ChildItem (Join-Path $sourceRoot 'src/api/burn/bextutil/inc') -File | ForEach-Object { $files["build/native/include/$($_.Name)"] = $_.FullName }
    New-NativePackage 'WixToolset.BootstrapperExtensionApi' $files '<dependencies><group targetFramework="native"><dependency id="WixToolset.DUtil" version="[7.0.0]" /></group></dependencies>'
    Invoke-WixProject 'src/ext/Util/be/utilbe.vcxproj' -Native
    $wix = Join-Path $sourceRoot 'build/wix/Release/publish/wix/wix.dll'
    $utilOutput = Join-Path $sourceRoot 'build/Util.wixext/Release'
    $arguments = @($wix, 'build', '-outputtype', 'library', '-bf', '-arch', 'x64', '-o', "$utilOutput/util.wixlib", '-intermediateFolder', "$utilOutput/obj/util", '-b', "utilbe.x64=$utilOutput/x64/", "$sourceRoot/src/ext/Util/wixlib/UtilBootstrapperExtension_x64.wxs")
    & $launcher -WixArguments $arguments
    Invoke-WixProject 'src/ext/Util/wixext/WixToolset.Util.wixext.csproj'
  }
}
