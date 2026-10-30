# SPDX-License-Identifier: MPL-2.0
# Synthetic resource DLLs have no entry point and are mapped only as data.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$script:fixtureProject=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))

function New-FuzePolicyTestPe {
  param([Parameter(Mandatory)][string]$Path,[ValidateSet('x64','arm64')][string]$Architecture='x64',[switch]$Development)
  $vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
  $vs=(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath) -join ''
  if($LASTEXITCODE -ne 0 -or -not $vs){throw 'The resource fixture requires Visual Studio C++ tools.'}
  $msvc=Get-ChildItem -LiteralPath (Join-Path $vs 'VC/Tools/MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1
  $tools=Join-Path $msvc.FullName "bin/Hostx64/$Architecture"
  $kits=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10'
  $sdk=Get-ChildItem -LiteralPath (Join-Path $kits 'Include') -Directory | Where-Object Name -Match '^10\.[0-9.]+$' | Sort-Object Name -Descending | Select-Object -First 1
  $rc=Join-Path $kits ("bin/"+$sdk.Name+'/x64/rc.exe')
  $directory=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Path))
  [void][IO.Directory]::CreateDirectory($directory)
  $source=Join-Path $directory 'policy-fixture.c'
  $object=Join-Path $directory 'policy-fixture.obj'
  $resource=Join-Path $directory 'policy-fixture.res'
  [IO.File]::WriteAllText($source,'__declspec(dllexport) int fixture_value=1; __declspec(dllexport) int* fixture_pointer=&fixture_value; __declspec(dllexport) int fixture(void){return *fixture_pointer;}')
  & (Join-Path $tools 'cl.exe') /nologo /c /O1 /GS- /Zl "/Fo$object" $source | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Synthetic policy fixture compilation failed.'}
  Push-Location (Join-Path $script:fixtureProject 'windows/runner')
  try {
    $devFlag=if($Development){'1'}else{'0'}
    $archFlag=if($Architecture -eq 'arm64'){'1'}else{'0'}
    & $rc /nologo "/dFUZEVPN_ALLOW_PORTABLE_DEV=$devFlag" "/dFUZEVPN_BUILD_ARCH_ARM64=$archFlag" /I (Join-Path $sdk.FullName 'um') /I (Join-Path $sdk.FullName 'shared') /fo $resource 'Runner.rc' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Synthetic policy resource compilation failed.'}
  }finally{Pop-Location}
  & (Join-Path $tools 'link.exe') /nologo /DLL /NOENTRY /NODEFAULTLIB "/MACHINE:$Architecture" "/OUT:$Path" $object $resource | Out-Null
  if($LASTEXITCODE -ne 0){throw 'Synthetic policy resource linking failed.'}
  return [IO.Path]::GetFullPath($Path)
}

function Set-FuzePolicyFixtureResource {
  param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][byte[]]$Bytes,[int]$Id=302,[uint16]$Language=0)
  if(-not ('FuzePolicyFixtureResource' -as [type])) {
    Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class FuzePolicyFixtureResource {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr BeginUpdateResourceW(string path,bool delete);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool UpdateResourceW(IntPtr update,IntPtr type,IntPtr name,ushort language,byte[] data,uint length);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool EndUpdateResourceW(IntPtr update,bool discard);
 public static void Write(string path,byte[] bytes,int id,ushort language){IntPtr update=BeginUpdateResourceW(path,false);if(update==IntPtr.Zero)throw new Exception("Resource fixture open failed.");bool complete=false;try{if(!UpdateResourceW(update,new IntPtr(10),new IntPtr(id),language,bytes,(uint)(bytes==null?0:bytes.Length)))throw new Exception("Resource fixture write failed.");complete=true;}finally{if(!EndUpdateResourceW(update,!complete)&&complete)throw new Exception("Resource fixture commit failed.");}}
}
'@
  }
  [FuzePolicyFixtureResource]::Write([IO.Path]::GetFullPath($Path),$Bytes,$Id,$Language)
}

Export-ModuleMember -Function New-FuzePolicyTestPe,Set-FuzePolicyFixtureResource
