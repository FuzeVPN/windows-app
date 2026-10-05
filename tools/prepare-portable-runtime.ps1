# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [ValidateSet('x64','arm64')][string]$Architecture='x64',
  [string]$ReleaseDirectory,
  [string]$ManifestPath,
  [string]$SourceBuildCache,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$CertificateThumbprint,
  [string]$ExpectedPublisherSubject,
  [switch]$DevTest,
  [switch]$ReplaceExistingSignature,
  [switch]$VerifyOnly,
  [switch]$CheckBuildModeOnly,
  # Exposes pure manifest helpers to the isolated packaging tests.
  [switch]$FunctionsOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force

function Assert-PortableBuildMode {
  param([Parameter(Mandatory)][string]$Directory, [string]$Cache, [switch]$Development,
    [ValidateSet('x64','arm64')][string]$TargetArchitecture='x64')
  $release = Assert-ProjectPath $Directory $projectRoot
  if (-not $Cache) { $Cache = Join-Path $release '..\..\CMakeCache.txt' }
  $Cache = Assert-ProjectPath $Cache $projectRoot
  if (-not (Test-Path -LiteralPath $Cache -PathType Leaf)) { throw 'The corresponding source CMakeCache.txt is required.' }
  $expectedRelease = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetDirectoryName($Cache)) 'runner\Release'))
  if ($release -ine $expectedRelease) { throw 'ReleaseDirectory must be the runner\Release directory of SourceBuildCache.' }
  $flag = [regex]::Match([IO.File]::ReadAllText($Cache), '(?m)^FUZEVPN_ALLOW_PORTABLE_DEV:BOOL=(ON|OFF)\s*$')
  $expectedFlag = if ($Development) { 'ON' } else { 'OFF' }
  if (-not $flag.Success -or $flag.Groups[1].Value -cne $expectedFlag) { throw "Compile with FUZEVPN_ALLOW_PORTABLE_DEV=$expectedFlag for this packaging mode." }
  $target = [regex]::Match([IO.File]::ReadAllText($Cache), '(?m)^CMAKE_GENERATOR_PLATFORM:INTERNAL=([^\r\n]+)\s*$')
  if (-not $target.Success -or $target.Groups[1].Value.Trim() -ine $TargetArchitecture) { throw 'The source CMake cache architecture must match the requested package.' }
  return $Cache
}

function Get-PortableRuntimePaths {
  param([Parameter(Mandatory)][object[]]$Inventory, [ValidateSet('x64','arm64')][string]$Architecture='x64')
  $opensslSuffix = if ($Architecture -eq 'arm64') { 'arm64' } else { 'x64' }
  $required = @(
    'fuzevpn-service.exe','lz4.dll',"libssl-3-$opensslSuffix.dll","libcrypto-3-$opensslSuffix.dll",'tunnel.dll','wireguard.dll',
    'concrt140.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll',
    'msvcp140_codecvt_ids.dll','vcruntime140.dll',
    'openvpn-dco/NOTICE.md','openvpn-dco/win10/ovpn-dco.inf','openvpn-dco/win10/ovpn-dco.cat',
    'openvpn-dco/win10/ovpn-dco.sys','openvpn-dco/win11/ovpn-dco.inf','openvpn-dco/win11/ovpn-dco.cat',
    'openvpn-dco/win11/ovpn-dco.sys','THIRD_PARTY_NOTICES.md','WIREGUARD_NOTICE.md',
    'licenses/OpenVPN3-corresponding-source.zip'
  )
  if ($Architecture -eq 'x64') { $required += 'vcruntime140_1.dll' }
  $entries = @{}
  foreach ($entry in $Inventory) {
    $name = $entry.Path.Replace('\','/')
    if ($entries.ContainsKey($name)) { throw "Duplicate release path: $name" }
    $entries[$name] = $entry
  }
  foreach ($name in $required) { if (-not $entries.ContainsKey($name)) { throw "Missing portable engine payload: $name" } }
  $selected = @($entries.Keys | Where-Object { $_ -in $required -or $_.StartsWith('licenses/', [StringComparison]::OrdinalIgnoreCase) })
  # Ordinal order is deterministic regardless of the developer's locale.
  [Array]::Sort($selected, [StringComparer]::OrdinalIgnoreCase)
  foreach ($name in $selected) {
    $entry = $entries[$name]
    [pscustomobject]@{ Path = $name; Length = $entry.Length; Sha256 = $entry.Sha256 }
  }
}

function ConvertTo-PortableManifest {
  param([Parameter(Mandatory)][string]$Version, [Parameter(Mandatory)][object[]]$Files)
  $versionText = ConvertTo-PublicVersion $Version
  if ($Files.Count -lt 1 -or $Files.Count -gt 128) { throw 'Portable manifest supports 1 to 128 files.' }
  $lines = [Collections.Generic.List[string]]::new()
  $lines.Add('FUZEVPN_RUNTIME_V1'); $lines.Add("version=$versionText"); $lines.Add('ipc=1')
  $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
  [uint64]$total = 0
  foreach ($file in $Files) {
    $name = [string]$file.Path
    if ($name.Length -gt 240 -or $name -notmatch '^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+){0,7}$' -or -not $seen.Add($name)) { throw "Invalid portable relative path: $name" }
    foreach ($part in $name.Split('/')) {
      if ($part -in @('.','..') -or $part.EndsWith('.') -or $part.Split('.')[0] -match '^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])$') { throw "Invalid portable path component: $part" }
    }
    [uint64]$size = $file.Length
    if ($size -eq 0 -or $size -gt 512MB -or $total -gt 512MB - $size -or $file.Sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw "Invalid portable payload size/hash: $name" }
    $total += $size
    $lines.Add(('file={0}' -f $size) + "`t" + $file.Sha256.ToLowerInvariant() + "`t" + $name)
  }
  foreach ($name in $seen) {
    $parent = $name
    while ($parent.Contains('/')) {
      $parent = $parent.Substring(0, $parent.LastIndexOf('/'))
      if ($seen.Contains($parent)) { throw "A portable file is also used as a directory: $parent" }
    }
  }
  $bytes = [Text.Encoding]::ASCII.GetBytes(($lines -join "`n") + "`n")
  if ($bytes.Length -gt 65536) { throw 'Portable manifest exceeds 64 KiB.' }
  return ,$bytes
}

function Initialize-PortableResourceApi {
  if ('FuzeVpnPortableResource' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class FuzeVpnPortableResource {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr BeginUpdateResourceW(string path, bool deleteExisting);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateResourceW(IntPtr update, IntPtr type, IntPtr name, ushort language, byte[] data, uint bytes);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool EndUpdateResourceW(IntPtr update, bool discard);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr LoadLibraryExW(string path, IntPtr reserved, uint flags);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr FindResourceExW(IntPtr module, IntPtr type, IntPtr name, ushort language);
  [DllImport("kernel32.dll", SetLastError=true)] static extern uint SizeofResource(IntPtr module, IntPtr resource);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr LoadResource(IntPtr module, IntPtr resource);
  [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
  [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
  public static void Write(string path, byte[] bytes) {
    IntPtr update = BeginUpdateResourceW(path, false);
    if (update == IntPtr.Zero) throw new Win32Exception();
    bool complete = false;
    try {
      if (!UpdateResourceW(update, new IntPtr(10), new IntPtr(300), 0, bytes, (uint)bytes.Length)) throw new Win32Exception();
      complete = true;
    } finally {
      if (!EndUpdateResourceW(update, !complete) && complete) throw new Win32Exception();
    }
  }
  public static byte[] Read(string path) {
    // Datafile only: no entry point, imports or application code is executed.
    IntPtr module = LoadLibraryExW(path, IntPtr.Zero, 0x60);
    if (module == IntPtr.Zero) throw new Win32Exception();
    try {
      IntPtr resource = FindResourceExW(module, new IntPtr(10), new IntPtr(300), 0);
      uint length = SizeofResource(module, resource);
      if (resource == IntPtr.Zero || length == 0 || length > 65536) throw new InvalidOperationException("Missing or oversized portable manifest.");
      IntPtr data = LockResource(LoadResource(module, resource));
      if (data == IntPtr.Zero) throw new Win32Exception();
      byte[] bytes = new byte[length]; Marshal.Copy(data, bytes, 0, (int)length); return bytes;
    } finally { FreeLibrary(module); }
  }
}
'@
}

function Remove-PortableHelperSignature {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Verification,
    [ValidateSet('x64','arm64')][string]$TargetArchitecture='x64')
  $Path=Assert-ProjectPath $Path $projectRoot
  if ([IO.Path]::GetFileName($Path) -cne 'fuzevpn-runtime.exe') { throw 'Only the FuzeVPN runtime helper signature may be replaced for resource embedding.' }
  [void](Assert-PeArchitecture $Path $TargetArchitecture)
  $version=Get-ProjectPublicVersion $projectRoot
  $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
  if ($info.OriginalFilename -cne 'fuzevpn-runtime.exe' -or $info.ProductName -cne 'FuzeVPN' -or
      ('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -cne "$version.0") {
    throw 'Only the current, validated FuzeVPN helper may have its old signature removed.'
  }
  [void](Assert-SignedFile $Path @Verification)
  $kitsRoot=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
  $tool=Get-ChildItem -LiteralPath $kitsRoot -Filter signtool.exe -Recurse |
    Where-Object FullName -Match '\\x64\\signtool\.exe$' | Sort-Object FullName -Descending | Select-Object -First 1
  if ($null -eq $tool) { throw 'The Windows SDK x64 signing tool is required to replace an existing helper signature.' }
  & $tool.FullName remove /s $Path | ForEach-Object { Write-Host $_ }
  if ($LASTEXITCODE -ne 0 -or (Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'NotSigned') { throw 'The previous helper signature could not be removed safely.' }
  [void](Assert-PeArchitecture $Path $TargetArchitecture)
}

if ($FunctionsOnly) { return }
if ($CheckBuildModeOnly) {
  if (-not $ReleaseDirectory) { $ReleaseDirectory = Join-Path $projectRoot "build\windows\$Architecture\runner\Release" }
  Assert-PortableBuildMode $ReleaseDirectory $SourceBuildCache -Development:$DevTest -TargetArchitecture $Architecture
  return
}
if (-not $DevTest -and -not $CertificateThumbprint -and -not $ExpectedPublisherSubject) { throw 'Production preparation requires a certificate pin or the validated Artifact Signing publisher.' }
if ($DevTest -and ($CertificateThumbprint -or $ExpectedPublisherSubject)) { throw 'DevTest and production signing are mutually exclusive.' }
if ($ExpectedPublisherSubject -and $ExpectedPublisherSubject -cne 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR') { throw 'Production preparation requires the complete validated FuzeVPN publisher subject.' }
$verification = @{ TimestampRequired=$true }
if ($CertificateThumbprint) { $verification['Thumbprint']=$CertificateThumbprint }
if ($ExpectedPublisherSubject) { $verification['ExpectedPublisherSubject']=$ExpectedPublisherSubject }
if (-not $ReleaseDirectory) { $ReleaseDirectory = Join-Path $projectRoot "build\windows\$Architecture\runner\Release" }
$ReleaseDirectory = Assert-ProjectPath $ReleaseDirectory $projectRoot
[void](Assert-ReleasePeArchitecture $ReleaseDirectory $projectRoot $Architecture)
if (-not $ManifestPath) { $ManifestPath = Join-Path $ReleaseDirectory 'portable-runtime.manifest' }
$ManifestPath = Assert-ProjectPath $ManifestPath $projectRoot
$publicVersion = Get-ProjectPublicVersion $projectRoot
$helper = Join-Path $ReleaseDirectory 'fuzevpn-runtime.exe'
foreach ($name in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')) {
  $file = Assert-ProjectPath (Join-Path $ReleaseDirectory $name) $projectRoot
  if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing portable application: $name" }
  $info = [Diagnostics.FileVersionInfo]::GetVersionInfo($file)
  if (('{0}.{1}.{2}.{3}' -f $info.FileMajorPart,$info.FileMinorPart,$info.FileBuildPart,$info.FilePrivatePart) -ne "$publicVersion.0" -or $info.OriginalFilename -ine $name -or $info.ProductName -cne 'FuzeVPN') { throw "Portable executable resource mismatch: $name" }
  $signature = Get-AuthenticodeSignature -LiteralPath $file
  if ($DevTest) {
    if ($signature.Status -ne 'NotSigned') { throw "DevTest requires genuinely unsigned paired binaries: $name ($($signature.Status))" }
  } elseif ($name -ne 'fuzevpn-runtime.exe' -or $VerifyOnly) {
    [void](Assert-SignedFile $file @verification)
  } elseif ($signature.Status -ne 'NotSigned') {
    if (-not $ReplaceExistingSignature) { throw 'The runtime helper must be unsigned before embedding, or replacement must be explicitly authorized.' }
    [void](Assert-SignedFile $file @verification)
  }
}
$inventory = @(Get-ReleaseInventory $ReleaseDirectory $projectRoot)
$payload = @(Get-PortableRuntimePaths $inventory $Architecture)
$manifest = ConvertTo-PortableManifest $publicVersion $payload
if (-not $VerifyOnly -and -not $DevTest -and (Get-AuthenticodeSignature -LiteralPath $helper).Status -eq 'Valid') {
  # UpdateResource removes the certificate bytes but leaves the old security
  # directory in a signed PE. Strip that signature with the official SDK first.
  if (-not $ReplaceExistingSignature) { throw 'Explicit replacement is required before removing the old helper signature.' }
  Remove-PortableHelperSignature $helper $verification $Architecture
}
$tempDirectory = Assert-ProjectPath (Join-Path $projectRoot '.toolchain\portable-resource-temp') $projectRoot
[void][IO.Directory]::CreateDirectory($tempDirectory)
$previousTemp = $env:TEMP; $previousTmp = $env:TMP
try {
  $env:TEMP = $tempDirectory; $env:TMP = $tempDirectory
  Initialize-PortableResourceApi
  if (-not $VerifyOnly) {
    [IO.File]::WriteAllBytes($ManifestPath, $manifest)
    [FuzeVpnPortableResource]::Write($helper, $manifest)
  }
  $embedded = [FuzeVpnPortableResource]::Read($helper)
  if ([Convert]::ToBase64String($embedded) -cne [Convert]::ToBase64String($manifest)) { throw 'The embedded portable manifest differs from the current payload.' }
} finally { $env:TEMP = $previousTemp; $env:TMP = $previousTmp }
[pscustomobject]@{ Helper = $helper; Manifest = $ManifestPath; Version = $publicVersion; Files = $payload.Count; Bytes = $manifest.Length; Verified = [bool]$VerifyOnly }
