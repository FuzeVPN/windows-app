# SPDX-License-Identifier: MPL-2.0
Set-StrictMode -Version Latest

function Get-FuzeProjectRoot {
  [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
}

function Get-FuzeDependencyPins {
  Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dependency-pins.json') -Raw | ConvertFrom-Json
}

function Invoke-FuzeChecked {
  param([Parameter(Mandatory)][string]$FilePath, [string[]]$Arguments = @())
  & $FilePath @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Build tool failed with exit code ${LASTEXITCODE}: $FilePath" }
}

function Assert-FuzeHash {
  param([Parameter(Mandatory)][string]$Path, [ValidateSet('SHA256','SHA512')][string]$Algorithm = 'SHA256', [Parameter(Mandatory)][string]$Hash)
  $length = if ($Algorithm -eq 'SHA256') {64} else {128}
  if ($Hash -notmatch "^[0-9a-fA-F]{$length}$" -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Missing file or invalid expected hash: $Path"
  }
  if ((Get-FileHash -LiteralPath $Path -Algorithm $Algorithm).Hash -ine $Hash) {
    throw "Dependency hash mismatch: $Path. The file was not used; remove the corrupt cached download before retrying."
  }
}

function Get-FuzePinnedDownload {
  param([Parameter(Mandatory)]$Pin, [switch]$Offline, [string[]]$DownloadSeeds = @())
  $root = Get-FuzeProjectRoot
  $directory = Join-Path $root '.toolchain/downloads'
  [void][IO.Directory]::CreateDirectory($directory)
  if ([IO.Path]::GetFileName($Pin.name) -cne $Pin.name -or ([uri]$Pin.url).Scheme -ne 'https') { throw 'Invalid pinned dependency URL/name.' }
  $file = Join-Path $directory $Pin.name
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
    foreach ($seed in $DownloadSeeds) {
      $candidate = Join-Path $seed $Pin.name
      if (Test-Path -LiteralPath $candidate -PathType Leaf) {
        Assert-FuzeHash -Path $candidate -Algorithm $Pin.algorithm -Hash $Pin.hash
        Copy-Item -LiteralPath $candidate -Destination $file
        break
      }
    }
  }
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
    if ($Offline) { throw "Offline bootstrap is missing cached dependency $($Pin.name). Run once without -Offline, or provide -DownloadSeeds." }
    Write-Host "Downloading pinned dependency $($Pin.name)..."
    $temporary = "$file.download"
    $progress = $ProgressPreference
    try {
      $ProgressPreference = 'SilentlyContinue'
      Invoke-WebRequest -Uri $Pin.url -OutFile $temporary -UseBasicParsing -MaximumRedirection 10
      Assert-FuzeHash -Path $temporary -Algorithm $Pin.algorithm -Hash $Pin.hash
      Move-Item -LiteralPath $temporary -Destination $file
    } finally {
      $ProgressPreference = $progress
      if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    }
  }
  Assert-FuzeHash -Path $file -Algorithm $Pin.algorithm -Hash $Pin.hash
  return $file
}

function Expand-FuzeZip {
  param([Parameter(Mandatory)][string]$Archive, [Parameter(Mandatory)][string]$Destination, [string]$Prefix = '')
  $root = [IO.Path]::GetFullPath((Get-FuzeProjectRoot)) + [IO.Path]::DirectorySeparatorChar
  $destinationRoot = [IO.Path]::GetFullPath($Destination)
  if (-not $destinationRoot.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { throw 'Dependency extraction must stay inside this checkout.' }
  [void][IO.Directory]::CreateDirectory($destinationRoot)
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  $count = 0
  try {
    foreach ($entry in $zip.Entries) {
      if ($Prefix -and -not $entry.FullName.StartsWith($Prefix, [StringComparison]::Ordinal)) { continue }
      $relative = $entry.FullName.Substring($Prefix.Length)
      if (-not $relative -or $relative.EndsWith('/')) { continue }
      if ($relative.Contains('\') -or $relative.Contains(':') -or ($relative.Split('/') -contains '..')) { throw 'Unsafe dependency archive path.' }
      $target = [IO.Path]::GetFullPath((Join-Path $destinationRoot $relative))
      if (-not $target.StartsWith($destinationRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or -not $seen.Add($target)) { throw 'Unsafe or duplicate dependency archive path.' }
      [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
      [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
      $count++
    }
  } finally { $zip.Dispose() }
  if (-not $count) { throw 'No matching files were extracted from the pinned dependency archive.' }
}

function Initialize-FuzeGitDependency {
  param([Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][string]$Commit, [Parameter(Mandatory)][string]$Directory, [string]$Tag, [switch]$Offline)
  $git = (Get-Command git.exe -ErrorAction Stop).Source
  if (-not (Test-Path -LiteralPath (Join-Path $Directory '.git'))) {
    if ($Offline) { throw "Offline bootstrap is missing source checkout $Directory." }
    if (Test-Path -LiteralPath $Directory) { throw "Dependency folder already exists without Git metadata: $Directory" }
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Directory))
    $arguments = @('-c','credential.helper=','-c','core.longpaths=true','clone','--filter=blob:none')
    if ($Tag) { $arguments += @('--depth','1','--branch',$Tag) }
    $arguments += @($Repository,$Directory)
    Invoke-FuzeChecked $git $arguments
    Invoke-FuzeChecked $git @('-C',$Directory,'config','--local','core.longpaths','true')
    if (-not $Tag) { Invoke-FuzeChecked $git @('-C',$Directory,'checkout','--detach',$Commit) }
  }
  $actual = (& $git -C $Directory rev-parse HEAD).Trim()
  if ($LASTEXITCODE -ne 0 -or $actual -cne $Commit) { throw "Pinned source revision mismatch in $Directory. Existing checkouts are never reset automatically." }
  $changed = @(& $git -C $Directory status --porcelain --untracked-files=no)
  if ($LASTEXITCODE -ne 0 -or $changed.Count) { throw "Tracked dependency sources are modified: $Directory" }
}

function Get-FuzeVisualStudioTools {
  param([ValidateSet('x64','arm64')][string]$Architecture = 'x64')
  $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
  if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio 2026 Build Tools with Desktop development with C++, Windows SDK and optional ARM64 C++ tools.' }
  $requires = @('Microsoft.VisualStudio.Component.VC.Tools.x86.x64')
  if ($Architecture -eq 'arm64') { $requires += 'Microsoft.VisualStudio.Component.VC.Tools.ARM64' }
  $installation = @(& $vswhere -latest -version '[18.0,19.0)' -products '*' -requires $requires -property installationPath)
  if ($LASTEXITCODE -ne 0 -or $installation.Count -ne 1) { throw "Visual Studio 2026 C++ and Windows SDK tools are required for $Architecture." }
  $tools = Join-Path $installation[0] 'Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin'
  foreach ($name in @('cmake.exe','ctest.exe')) { if (-not (Test-Path -LiteralPath (Join-Path $tools $name))) { throw "Missing Visual Studio build tool $name." } }
  return @{ CMake = (Join-Path $tools 'cmake.exe'); CTest = (Join-Path $tools 'ctest.exe'); Installation = $installation[0] }
}

function Publish-FuzeNativeTriplet {
  param([Parameter(Mandatory)][string]$InstallRoot,[ValidateSet('x64','arm64')][string]$Architecture)
  # Separate vcpkg manifest install roots prevent its prune phase from
  # removing the other architecture. Publish only the selected built triplet.
  $root = Get-FuzeProjectRoot
  $triplet = "$Architecture-windows"
  $source = [IO.Path]::GetFullPath((Join-Path $InstallRoot $triplet))
  $checkoutPrefix = $root + [IO.Path]::DirectorySeparatorChar
  if (-not $source.StartsWith($checkoutPrefix,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $source -PathType Container)) { throw 'A native dependency triplet must be built inside this checkout.' }
  $publishRoot = Join-Path $root 'third_party/openvpn3-core/vcpkg_installed'
  [void][IO.Directory]::CreateDirectory($publishRoot)
  if ((Get-Item -LiteralPath $publishRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Native dependency publication cannot target a reparse directory.' }
  $id = [guid]::NewGuid().ToString('N')
  $candidate = Join-Path $publishRoot "$triplet.fuze-bootstrap-$id"
  $target = Join-Path $publishRoot $triplet
  $backupRoot = Join-Path $root '.toolchain/vcpkg-published-previous'
  [void][IO.Directory]::CreateDirectory($backupRoot)
  $backup = Join-Path $backupRoot "$triplet-$id"
  Copy-Item -LiteralPath $source -Destination $candidate -Recurse
  if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $backup }
  try { Move-Item -LiteralPath $candidate -Destination $target }
  catch {
    if (-not (Test-Path -LiteralPath $target) -and (Test-Path -LiteralPath $backup)) { Move-Item -LiteralPath $backup -Destination $target }
    throw
  }
}

Export-ModuleMember -Function Get-FuzeProjectRoot,Get-FuzeDependencyPins,Invoke-FuzeChecked,Assert-FuzeHash,Get-FuzePinnedDownload,Expand-FuzeZip,Initialize-FuzeGitDependency,Get-FuzeVisualStudioTools,Publish-FuzeNativeTriplet
