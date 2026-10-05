[CmdletBinding()]
param([ValidateSet('Native','SignedExtensions','SourceArchive')][string]$Phase='Native',
  [string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $PSScriptRoot 'InstallerTools.psm1') -Force
$version=Get-ProjectPublicVersion $projectRoot
if (-not $OutputDirectory) { $OutputDirectory=Join-Path $projectRoot "build\release-$version\wix" }
$OutputDirectory=Assert-ProjectPath $OutputDirectory $projectRoot
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$sourceRoot=Join-Path $projectRoot '.toolchain\wix-source'
$launcher=Join-Path $projectRoot 'tools\wix\invoke-wix-build.ps1'
$wix=Join-Path $sourceRoot 'build\wix\Release\publish\wix\wix.dll'
$packageCache=Join-Path $projectRoot '.toolchain\installer-runtime\nuget'
function Build-Native([string]$Project) {
  & $launcher -Project $Project -Native -Properties @('Platform=ARM64','PlatformToolset=v145','WixNativeSdkLibraryToolset=v145','NCrunch=true','FuzeSourceBuild=true')
}
function Add-NativeCacheAsset([string]$Source,[string]$Package,[string]$Relative) {
  $target=Assert-ProjectPath (Join-Path $packageCache "$Package\7.0.0\$Relative") $projectRoot
  [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
  Copy-Item -LiteralPath (Join-Path $sourceRoot $Source) -Destination $target -Force
}
if ($Phase -eq 'Native') {
  # Retain the original private x64 assets. Add only source-built ARM64 objects
  # to their private build cache; no official WiX binaries are redistributed.
  Build-Native 'src/libs/dutil/WixToolset.DUtil/dutil.vcxproj'
  Add-NativeCacheAsset 'build/libs/Release/v145/ARM64/dutil.lib' 'wixtoolset.dutil' 'build/native/v14/ARM64/dutil.lib'
  Build-Native 'src/burn/stub/stub.vcxproj'
  Build-Native 'src/api/burn/balutil/balutil.vcxproj'
  Add-NativeCacheAsset 'build/api/Release/v145/ARM64/balutil.lib' 'wixtoolset.bootstrapperapplicationapi' 'build/native/v14/ARM64/balutil.lib'
  foreach ($name in @('wixstdba','wixprqba','wixiuiba')) { Build-Native "src/ext/Bal/$name/$name.vcxproj" }
  Build-Native 'src/api/burn/bextutil/bextutil.vcxproj'
  Add-NativeCacheAsset 'build/api/Release/v145/ARM64/bextutil.lib' 'wixtoolset.bootstrapperextensionapi' 'build/native/v14/ARM64/bextutil.lib'
  Build-Native 'src/ext/Util/be/utilbe.vcxproj'
  $burn=Join-Path $sourceRoot 'build/burn/Release/ARM64/burn.exe'
  [void](Assert-PeArchitecture $burn 'arm64')
  $stubDirectory=Join-Path ([IO.Path]::GetDirectoryName($wix)) 'arm64'
  [void][IO.Directory]::CreateDirectory($stubDirectory)
  Copy-Item -LiteralPath $burn -Destination (Join-Path $stubDirectory 'burn.exe') -Force
  $nativeEvidence=@()
  foreach ($arch in @('x64','arm64')) {
    $assets=@((Join-Path $sourceRoot "build/Bal.wixext/Release/$arch/wixstdba.exe"),
      (Join-Path $sourceRoot "build/Bal.wixext/Release/$arch/wixprqba.exe"),
      (Join-Path $sourceRoot "build/Bal.wixext/Release/$arch/wixiuiba.exe"),
      (Join-Path $sourceRoot "build/Util.wixext/Release/$arch/utilbe.dll"))
    foreach ($asset in $assets) {
      [void](Assert-PeArchitecture $asset $arch)
      $nativeEvidence += [pscustomobject]@{ File=$asset; Architecture=$arch; Sha256=(Get-FileHash -LiteralPath $asset -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
  }
  $nativeEvidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'native-assets-before-signing.json') -Encoding UTF8
} elseif ($Phase -eq 'SignedExtensions') {
  foreach ($arch in @('x64','arm64')) {
    $balAssets=Join-Path $sourceRoot "build/Bal.wixext/Release/$arch"
    $utilAssets=Join-Path $sourceRoot "build/Util.wixext/Release/$arch"
    foreach ($file in @('wixstdba.exe','wixprqba.exe','wixiuiba.exe')) {
      [void](Assert-SignedFile (Join-Path $balAssets $file) -ExpectedPublisherSubject 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR' -TimestampRequired)
    }
    [void](Assert-SignedFile (Join-Path $utilAssets 'utilbe.dll') -ExpectedPublisherSubject 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR' -TimestampRequired)
    $balOutput=Join-Path $OutputDirectory "Bal/$arch"
    $utilOutput=Join-Path $OutputDirectory "Util/$arch"
    foreach ($directory in @($balOutput,$utilOutput)) { [void][IO.Directory]::CreateDirectory($directory) }
    $balArguments=@($wix,'build','-outputtype','library','-bf','-arch',$arch,'-o',"$balOutput/bas.wixlib",'-intermediateFolder',"$balOutput/obj",'-b',"$sourceRoot/src/ext/Bal/stdbas/Resources")
    foreach ($name in @('wixstdba','wixprqba','wixiuiba')) { $balArguments += @('-b',"$name.$arch=$balAssets") }
    foreach ($name in @("bas_$arch",'wixstdba','wixprqba','wixiuiba')) { $balArguments += "$sourceRoot/src/ext/Bal/wixlib/$name.wxs" }
    & $launcher -WixArguments $balArguments
    & $launcher -Project 'src/ext/Bal/wixext/WixToolset.BootstrapperApplications.wixext.csproj' -Properties @('NCrunch=true','FuzeSourceBuild=true',"OutputPath=$balOutput/netstandard2.0/",'AppendTargetFrameworkToOutputPath=false')
    & $launcher -WixArguments @($wix,'build','-outputtype','library','-bf','-arch',$arch,'-o',"$utilOutput/util.wixlib",'-intermediateFolder',"$utilOutput/obj",'-b',"utilbe.$arch=$utilAssets/","$sourceRoot/src/ext/Util/wixlib/UtilBootstrapperExtension_$arch.wxs")
    & $launcher -Project 'src/ext/Util/wixext/WixToolset.Util.wixext.csproj' -Properties @('NCrunch=true','FuzeSourceBuild=true',"OutputPath=$utilOutput/netstandard2.0/",'AppendTargetFrameworkToOutputPath=false')
  }
} else {
  # The ARM64 build changes no upstream source; include its exact recipe beside
  # the previously archived complete corresponding v7.0.0 sources and patches.
  $archive=Join-Path $OutputDirectory 'wix-source-7.0.0-fuze-x64-arm64.zip'
  if (Test-Path -LiteralPath $archive) { throw 'Corresponding-source archives are never overwritten.' }
  Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party/wix/wix-source-7.0.0-fuze-x64.zip') -Destination $archive
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip=[IO.Compression.ZipFile]::Open($archive,[IO.Compression.ZipArchiveMode]::Update)
  try { [void][IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$PSCommandPath,'installer/build-wix-architectures.ps1',[IO.Compression.CompressionLevel]::Optimal) }
  finally { $zip.Dispose() }
  (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() | Set-Content -LiteralPath "$archive.sha256" -Encoding UTF8
}
Write-Host "WiX $Phase completed from the pinned source; no installer or application was executed."
