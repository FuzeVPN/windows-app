# SPDX-License-Identifier: MPL-2.0
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $script:projectRoot 'installer/InstallerTools.psm1')
$script:applicationNames=@('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')

function Initialize-FuzeBuildProvenanceApi {
  if ('FuzeBuildProvenance' -as [type]) { return }
  Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
public static class FuzeBuildProvenance {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryExW(string path,IntPtr file,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr FindResourceExW(IntPtr module,IntPtr type,IntPtr name,ushort language);
  delegate bool LanguageCallback(IntPtr module,IntPtr type,IntPtr name,ushort language,IntPtr parameter);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool EnumResourceLanguagesW(IntPtr module,IntPtr type,IntPtr name,LanguageCallback callback,IntPtr parameter);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint SizeofResource(IntPtr module,IntPtr resource);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr LoadResource(IntPtr module,IntPtr resource);
  [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
  [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
  public static byte[] ReadPolicy(string path) {
    IntPtr module=LoadLibraryExW(path,IntPtr.Zero,0x60); // resources only; no image code or imports
    if(module==IntPtr.Zero) throw new InvalidDataException("Cannot map compiled build policy.");
    try {
      int languages=0;bool neutral=false;
      LanguageCallback callback=(m,t,n,l,p)=>{languages++;neutral=l==0;return true;};
      if(!EnumResourceLanguagesW(module,new IntPtr(10),new IntPtr(302),callback,IntPtr.Zero)||languages!=1||!neutral)
        throw new InvalidDataException("Exactly one neutral compiled build policy resource is required.");
      IntPtr resource=FindResourceExW(module,new IntPtr(10),new IntPtr(302),0);
      uint length=resource==IntPtr.Zero?0:SizeofResource(module,resource);
      if(length==0||length>256) throw new InvalidDataException("Missing neutral compiled build policy resource 302; rebuild the application.");
      IntPtr bytes=LockResource(LoadResource(module,resource));
      if(bytes==IntPtr.Zero) throw new InvalidDataException("Cannot read compiled build policy.");
      byte[] result=new byte[length];Marshal.Copy(bytes,result,0,result.Length);return result;
    }finally{FreeLibrary(module);}
  }
  // Authenticode changes checksum/security-directory/certificate bytes. Runtime
  // preparation replaces only the root runtime's .rsrc (inventories 300/301).
  // Resource growth may move the relocation table itself, while its contents
  // and all executable/data sections and addresses must remain unchanged.
  public static string CodeHash(string path,bool runtimeResources) {
    using(var stream=File.OpenRead(path)) using(var reader=new BinaryReader(stream)) using(var hash=SHA256.Create()) {
      if(stream.Length<64||reader.ReadUInt16()!=0x5a4d)throw new InvalidDataException("Invalid PE DOS header.");
      stream.Position=0x3c;uint pe=reader.ReadUInt32();
      if(pe<64||pe>stream.Length-24)throw new InvalidDataException("Invalid PE offset.");
      stream.Position=pe;if(reader.ReadUInt32()!=0x4550)throw new InvalidDataException("Invalid PE signature.");
      ushort machine=reader.ReadUInt16(),count=reader.ReadUInt16();
      stream.Position=pe+20;ushort optionalSize=reader.ReadUInt16(),characteristics=reader.ReadUInt16();
      long optional=pe+24,sections=optional+optionalSize;
      if(optionalSize<72||count==0||count>96||sections+count*40L>stream.Length)throw new InvalidDataException("Invalid PE section table.");
      stream.Position=optional;ushort format=reader.ReadUInt16();
      if(format!=0x20b)throw new InvalidDataException("A native PE32+ image is required.");
      stream.Position=optional+16;uint entry=reader.ReadUInt32();
      stream.Position=optional+24;ulong imageBase=reader.ReadUInt64();
      stream.Position=optional+68;ushort subsystem=reader.ReadUInt16(),dllFlags=reader.ReadUInt16();
      Action<byte[]> add=data=>{hash.TransformBlock(data,0,data.Length,data,0);};
      add(BitConverter.GetBytes(machine));add(BitConverter.GetBytes(characteristics));add(BitConverter.GetBytes(entry));add(BitConverter.GetBytes(imageBase));add(BitConverter.GetBytes(subsystem));add(BitConverter.GetBytes(dllFlags));
      int included=0;byte[] buffer=new byte[65536];
      for(int i=0;i<count;i++) {
        stream.Position=sections+i*40L;byte[] name=reader.ReadBytes(8);string text=System.Text.Encoding.ASCII.GetString(name).TrimEnd('\0');
        uint virtualSize=reader.ReadUInt32(),address=reader.ReadUInt32(),size=reader.ReadUInt32(),offset=reader.ReadUInt32();
        stream.Position=sections+i*40L+36;uint flags=reader.ReadUInt32();
        if((ulong)offset+size>(ulong)stream.Length)throw new InvalidDataException("Truncated PE section.");
        if(runtimeResources&&text==".rsrc")continue;
        included++;add(name);add(BitConverter.GetBytes(virtualSize));add(BitConverter.GetBytes(runtimeResources&&text==".reloc"?0u:address));add(BitConverter.GetBytes(size));add(BitConverter.GetBytes(flags));
        stream.Position=offset;long remaining=size;
        while(remaining>0){int read=stream.Read(buffer,0,(int)Math.Min(buffer.Length,remaining));if(read==0)throw new EndOfStreamException();hash.TransformBlock(buffer,0,read,buffer,0);remaining-=read;}
      }
      if(included==0)throw new InvalidDataException("No compiled PE sections.");
      hash.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
    }
  }
}
'@
}

function ConvertFrom-FuzeBuildPolicy {
  param([Parameter(Mandatory)][byte[]]$Bytes)
  $text=[Text.Encoding]::ASCII.GetString($Bytes)
  $match=[regex]::Match($text,'\AFUZEVPN_BUILD_POLICY_V1\nportable_dev=(0|1)\narchitecture=(x64|arm64)\n\z')
  if (-not $match.Success) { throw 'Invalid compiled build policy resource.' }
  return [pscustomobject]@{Development=($match.Groups[1].Value -ceq '1');Architecture=$match.Groups[2].Value}
}

function Get-FuzeCompiledBuildPolicy {
  param([Parameter(Mandatory)][string]$Path)
  $Path=Assert-ProjectPath $Path $script:projectRoot
  Initialize-FuzeBuildProvenanceApi
  return ConvertFrom-FuzeBuildPolicy -Bytes ([FuzeBuildProvenance]::ReadPolicy($Path))
}

function Assert-FuzeCompiledBuildPolicy {
  param([Parameter(Mandatory)][string]$ReleaseDirectory,[ValidateSet('x64','arm64')][string]$Architecture='x64',[switch]$Development)
  $release=Assert-ProjectPath $ReleaseDirectory $script:projectRoot
  foreach ($name in $script:applicationNames) {
    $file=Join-Path $release $name
    [void](Assert-PeArchitecture $file $Architecture)
    $policy=Get-FuzeCompiledBuildPolicy $file
    if ($policy.Architecture -cne $Architecture -or $policy.Development -ne [bool]$Development) { throw "Compiled architecture/development mode mismatch: $name. Rebuild before packaging." }
  }
}

function Get-FuzeProvenanceInventory {
  param([Parameter(Mandatory)][string]$ReleaseDirectory)
  Initialize-FuzeBuildProvenanceApi
  foreach ($entry in @(Get-ReleaseInventory $ReleaseDirectory $script:projectRoot)) {
    if ($entry.Path -cin @('portable-runtime.manifest','fuzevpn.portable','README-PORTABLE.txt')) { continue }
    $file=Join-Path $ReleaseDirectory $entry.Path
    $pe=$false
    if ($entry.Length -ge 2) {
      $stream=[IO.File]::OpenRead($file)
      try { $pe=$stream.ReadByte() -eq 0x4d -and $stream.ReadByte() -eq 0x5a } finally { $stream.Dispose() }
    }
    [pscustomobject]@{Path=$entry.Path;Length=$entry.Length;Sha256=$entry.Sha256;PeCodeSha256=$(if($pe){[FuzeBuildProvenance]::CodeHash($file,($entry.Path -ceq 'fuzevpn-runtime.exe'))}else{''})}
  }
}

function Assert-FuzeReceiptInventory {
  param([Parameter(Mandatory)][object[]]$Expected,[Parameter(Mandatory)][object[]]$Actual,[switch]$SigningChanges)
  $map=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
  foreach ($entry in $Expected) { if($map.ContainsKey($entry.Path)){throw 'Duplicate build receipt path.'};$map.Add($entry.Path,$entry) }
  if ($map.Count -ne $Actual.Count) { throw 'The build receipt file set differs from the release.' }
  foreach ($entry in $Actual) {
    if (-not $map.ContainsKey($entry.Path)) { throw "A release file is absent from its build receipt: $($entry.Path)" }
    $before=$map[$entry.Path]
    if ($SigningChanges -and $before.PeCodeSha256) {
      if ($before.PeCodeSha256 -cne $entry.PeCodeSha256) { throw "Compiled PE sections changed during signing: $($entry.Path)" }
    } elseif ($before.Sha256 -cne $entry.Sha256 -or [long]$before.Length -ne [long]$entry.Length) { throw "Release bytes differ from the successful build receipt: $($entry.Path)" }
  }
}

function Read-FuzeBuildReceipt {
  param([Parameter(Mandatory)][string]$ReceiptPath,[Parameter(Mandatory)][string]$ReleaseDirectory,
    [ValidateSet('x64','arm64')][string]$Architecture='x64',[switch]$Development)
  $ReceiptPath=Assert-ProjectPath $ReceiptPath $script:projectRoot
  $release=Assert-ProjectPath $ReleaseDirectory $script:projectRoot
  if ($ReceiptPath.StartsWith($release.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Build receipts must remain outside the signed release payload.' }
  if (-not (Test-Path -LiteralPath $ReceiptPath -PathType Leaf) -or (Get-Item -LiteralPath $ReceiptPath).Length -gt 16MB) { throw 'A successful build receipt is required; rebuild before packaging.' }
  $receipt=Get-Content -LiteralPath $ReceiptPath -Raw | ConvertFrom-Json
  if ($receipt.schema -ne 1 -or $receipt.architecture -cne $Architecture -or $receipt.portable_development -isnot [bool] -or $receipt.portable_development -ne [bool]$Development -or $receipt.phase -cnotin @('compiled','signed')) { throw 'Build receipt configuration does not match this packaging mode.' }
  $cache=Assert-ProjectPath $receipt.source_cmake_cache $script:projectRoot
  if ((Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash.ToLowerInvariant() -cne $receipt.cmake_cache_sha256) { throw 'CMake configuration changed after the recorded successful build; rebuild before packaging.' }
  [void](Assert-FuzeCompiledBuildPolicy -ReleaseDirectory $release -Architecture $Architecture -Development:$Development)
  return $receipt
}

function Write-FuzeBuildReceiptFile {
  param([Parameter(Mandatory)]$Receipt,[Parameter(Mandatory)][string]$ReceiptPath)
  $ReceiptPath=Assert-ProjectPath $ReceiptPath $script:projectRoot
  [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ReceiptPath))
  $temporary=$ReceiptPath+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
  try {
    [IO.File]::WriteAllText($temporary,($Receipt | ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary,$ReceiptPath,$true)
  } finally { if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary} }
}

function New-FuzeBuildReceipt {
  param([Parameter(Mandatory)][string]$ReleaseDirectory,[Parameter(Mandatory)][string]$SourceBuildCache,
    [string]$ReceiptPath,[ValidateSet('x64','arm64')][string]$Architecture='x64',[switch]$Development)
  $release=Assert-ProjectPath $ReleaseDirectory $script:projectRoot
  $cache=Assert-ProjectPath $SourceBuildCache $script:projectRoot
  if ($release -ine [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetDirectoryName($cache)) 'runner/Release'))) { throw 'The build receipt must describe its source CMake build directory.' }
  if (-not $ReceiptPath) { $ReceiptPath=Join-Path ([IO.Path]::GetDirectoryName($cache)) 'build-provenance.json' }
  $ReceiptPath=Assert-ProjectPath $ReceiptPath $script:projectRoot
  if ($ReceiptPath.StartsWith($release.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'Build receipts must remain outside the signed release payload.' }
  [void](Assert-FuzeCompiledBuildPolicy -ReleaseDirectory $release -Architecture $Architecture -Development:$Development)
  $inventory=@(Get-FuzeProvenanceInventory $release)
  $receipt=[ordered]@{schema=1;phase='compiled';architecture=$Architecture;portable_development=[bool]$Development;
    source_release=$release;source_cmake_cache=$cache;cmake_cache_sha256=(Get-FileHash -LiteralPath $cache -Algorithm SHA256).Hash.ToLowerInvariant();
    compiled=[ordered]@{completed_utc=[DateTime]::UtcNow.ToString('o');files=$inventory};signed=$null}
  Write-FuzeBuildReceiptFile $receipt $ReceiptPath
  return $ReceiptPath
}

function Suspend-FuzeBuildReceipt {
  param([Parameter(Mandatory)][string]$SourceBuildCache)
  $cache=Assert-ProjectPath $SourceBuildCache $script:projectRoot
  $receiptPath=Assert-ProjectPath (Join-Path ([IO.Path]::GetDirectoryName($cache)) 'build-provenance.json') $script:projectRoot
  if(Test-Path -LiteralPath $receiptPath -PathType Leaf){
    $previous=Assert-ProjectPath (Join-Path ([IO.Path]::GetDirectoryName($cache)) ('build-provenance.previous-'+[guid]::NewGuid().ToString('N')+'.json')) $script:projectRoot
    # Preserve previous evidence while making a failed new build unpackageable.
    Move-Item -LiteralPath $receiptPath -Destination $previous
  }
}

function Assert-FuzeBuildReceipt {
  param([Parameter(Mandatory)][string]$ReleaseDirectory,[Parameter(Mandatory)][string]$ReceiptPath,
    [ValidateSet('x64','arm64')][string]$Architecture='x64',[switch]$Development)
  $receipt=Read-FuzeBuildReceipt -ReceiptPath $ReceiptPath -ReleaseDirectory $ReleaseDirectory -Architecture $Architecture -Development:$Development
  $expected=if($receipt.phase -ceq 'signed'){@($receipt.signed.files)}else{@($receipt.compiled.files)}
  Assert-FuzeReceiptInventory -Expected $expected -Actual @(Get-FuzeProvenanceInventory $ReleaseDirectory) -SigningChanges:($receipt.phase -ceq 'compiled')
  return $receipt
}

function Update-FuzeSignedBuildReceipt {
  param([Parameter(Mandatory)][string]$ReleaseDirectory,[Parameter(Mandatory)][string]$ReceiptPath,
    [ValidateSet('x64','arm64')][string]$Architecture='x64')
  $receipt=Read-FuzeBuildReceipt -ReceiptPath $ReceiptPath -ReleaseDirectory $ReleaseDirectory -Architecture $Architecture
  $inventory=@(Get-FuzeProvenanceInventory $ReleaseDirectory)
  Assert-FuzeReceiptInventory -Expected @($receipt.compiled.files) -Actual $inventory -SigningChanges
  $receipt.phase='signed'
  $receipt.signed=[pscustomobject]@{completed_utc=[DateTime]::UtcNow.ToString('o');files=$inventory}
  Write-FuzeBuildReceiptFile $receipt $ReceiptPath
}

Export-ModuleMember -Function ConvertFrom-FuzeBuildPolicy,Get-FuzeCompiledBuildPolicy,Assert-FuzeCompiledBuildPolicy,New-FuzeBuildReceipt,Suspend-FuzeBuildReceipt,Assert-FuzeBuildReceipt,Update-FuzeSignedBuildReceipt,Get-FuzeProvenanceInventory,Assert-FuzeReceiptInventory
