$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Import-Module (Join-Path $projectRoot 'installer/InstallerTools.psm1') -Force
function Check([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Reject([scriptblock]$Action,[string]$Message) {
  $failed=$false; try { & $Action | Out-Null } catch { $failed=$true }
  Check $failed $Message
}
$temporary=Assert-ProjectPath (Join-Path $projectRoot '.toolchain/installer-runtime/temp/package-architecture-test') $projectRoot
[void][IO.Directory]::CreateDirectory($temporary)
function New-PeFixture([string]$Name,[uint16]$Machine) {
  $bytes=[byte[]]::new(128)
  [BitConverter]::GetBytes([uint16]0x5a4d).CopyTo($bytes,0)
  [BitConverter]::GetBytes([uint32]64).CopyTo($bytes,0x3c)
  [BitConverter]::GetBytes([uint32]0x00004550).CopyTo($bytes,64)
  [BitConverter]::GetBytes($Machine).CopyTo($bytes,68)
  $path=Join-Path $temporary $Name; [IO.File]::WriteAllBytes($path,$bytes); return $path
}
$x64=New-PeFixture 'x64.dll' 0x8664
$arm64=New-PeFixture 'arm64.dll' 0xaa64
Check ((Assert-PeArchitecture $x64 x64) -eq 0x8664) 'x64 header recognition failed.'
Check ((Assert-PeArchitecture $arm64 arm64) -eq 0xaa64) 'ARM64 header recognition failed.'
$unusualPeDirectory=Join-Path $temporary 'unusual-pe'
[void][IO.Directory]::CreateDirectory($unusualPeDirectory)
$unusualPe=Join-Path $unusualPeDirectory 'native-payload.bin'
Copy-Item -LiteralPath $arm64 -Destination $unusualPe -Force
Check (@(Get-ReleasePeFiles $unusualPeDirectory $projectRoot).Count -eq 1) 'PE detection must inspect headers, even for nonstandard file extensions.'
Reject { Assert-PeArchitecture $x64 arm64 } 'An x64 payload must never enter an ARM64 package.'
Reject { Assert-PeArchitecture $arm64 x64 } 'An ARM64 payload must never enter an x64 package.'
$x86=New-PeFixture 'x86.dll' 0x14c
Reject { Assert-PeArchitecture $x86 x64 } 'x86 is not the x64 package target.'
$corrupt=Join-Path $temporary 'truncated.dll'; [IO.File]::WriteAllBytes($corrupt,[byte[]](0x4d,0x5a))
Reject { Get-PeMachine $corrupt } 'A truncated image must fail closed.'
$corruptBytes=[IO.File]::ReadAllBytes($x64); [BitConverter]::GetBytes([uint32]4294967280).CopyTo($corruptBytes,0x3c)
[IO.File]::WriteAllBytes($corrupt,$corruptBytes)
Reject { Get-PeMachine $corrupt } 'An out-of-bounds PE header must fail closed.'
$inventory=@([pscustomobject]@{ Path='lz4.dll'; Length=128; Sha256=('a'*64) })
$x64Payload=Join-Path $temporary 'x64.wxs'; $armPayload=Join-Path $temporary 'arm64.wxs'
Write-ReleasePayload $inventory $x64Payload x64
Write-ReleasePayload $inventory $armPayload arm64
[xml]$x64Xml=[IO.File]::ReadAllText($x64Payload); [xml]$armXml=[IO.File]::ReadAllText($armPayload)
$x64Component=$x64Xml.Wix.Fragment.ComponentGroup.Component
$armComponent=$armXml.Wix.Fragment.ComponentGroup.Component
Check ($x64Component.Guid -ceq (Get-StableGuid 'component:lz4.dll')) 'The shipped x64 component identity must remain stable for upgrades.'
Check ($x64Component.Guid -cne $armComponent.Guid) 'Different architecture components must use different MSI identities.'
Check ($x64Component.Bitness -eq 'always64' -and $armComponent.Bitness -eq 'always64') 'Both targets require 64-bit MSI components.'
. (Join-Path $projectRoot 'tools/prepare-portable-runtime.ps1') -FunctionsOnly
Initialize-PortableResourceApi
$vendorFixture=Join-Path $temporary 'vendor-signature-protection'
[void][IO.Directory]::CreateDirectory($vendorFixture)
$vendorRenamed=Join-Path $vendorFixture 'fuzevpn-runtime.exe'
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party/wireguard/1.1/amd64/wireguard.dll') -Destination $vendorRenamed -Force
$vendorHash=(Get-FileHash -LiteralPath $vendorRenamed -Algorithm SHA256).Hash
Reject { Remove-PortableHelperSignature $vendorRenamed @{ExpectedPublisherSubject='CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR';TimestampRequired=$true} x64 } 'A renamed vendor DLL must never have its signature removed.'
Check ((Get-FileHash -LiteralPath $vendorRenamed -Algorithm SHA256).Hash -ceq $vendorHash -and (Get-AuthenticodeSignature -LiteralPath $vendorRenamed).Status -eq 'Valid') 'Refusing resource preparation must leave vendor signatures and bytes unchanged.'
$cacheDirectory=Join-Path $temporary 'cache-x64'
$cacheRelease=Join-Path $cacheDirectory 'runner/Release'
[void][IO.Directory]::CreateDirectory($cacheRelease)
$cacheFile=Join-Path $cacheDirectory 'CMakeCache.txt'
[IO.File]::WriteAllText($cacheFile,"FUZEVPN_ALLOW_PORTABLE_DEV:BOOL=OFF`nCMAKE_GENERATOR_PLATFORM:INTERNAL=x64`n")
$receiptFailure=''
try { Assert-PortableBuildMode $cacheRelease $cacheFile -TargetArchitecture x64 | Out-Null } catch { $receiptFailure=$_.Exception.Message }
Check ($receiptFailure -ceq 'A successful build receipt is required; rebuild before packaging.') 'A CMake cache alone must not authorize packaging.'
# Exercise the architecture/mode routing here without compiling a PE fixture in
# every installer test. The separate provenance suite checks real resource-302
# DLL fixtures and receipt contents; this double verifies the exact call boundary.
$originalReceiptAssertion=(Get-Command Assert-FuzeBuildReceipt).ScriptBlock
$script:receiptCalls=0
function Assert-FuzeBuildReceipt {
  param([string]$ReleaseDirectory,[string]$ReceiptPath,[string]$Architecture,[switch]$Development)
  Check ($ReleaseDirectory -ceq $cacheRelease) 'Build receipt must inspect the selected release.'
  Check ($ReceiptPath -ceq (Join-Path $cacheDirectory 'build-provenance.json')) 'Build receipt must remain beside the source cache.'
  Check ($Architecture -ceq $script:receiptArchitecture -and [bool]$Development -eq $script:receiptDevelopment) 'Build receipt must receive the exact architecture and mode.'
  $script:receiptCalls++
}
try {
  foreach ($architecture in @('x64','arm64')) {
    foreach ($development in @($false,$true)) {
      $script:receiptArchitecture=$architecture
      $script:receiptDevelopment=$development
      $cacheFlag=if ($development) {'ON'} else {'OFF'}
      $cachePlatform=if ($architecture -ceq 'arm64') {'ARM64'} else {'x64'}
      [IO.File]::WriteAllText($cacheFile,"FUZEVPN_ALLOW_PORTABLE_DEV:BOOL=$cacheFlag`nCMAKE_GENERATOR_PLATFORM:INTERNAL=$cachePlatform`n")
      Check ((Assert-PortableBuildMode $cacheRelease $cacheFile -Development:$development -TargetArchitecture $architecture) -ceq $cacheFile) 'Matching cache must be checked against its build receipt.'
      $otherArchitecture=if ($architecture -ceq 'x64') {'arm64'} else {'x64'}
      Reject { Assert-PortableBuildMode $cacheRelease $cacheFile -Development:$development -TargetArchitecture $otherArchitecture } 'A source cache cannot authorize the other architecture.'
      Reject { Assert-PortableBuildMode $cacheRelease $cacheFile -Development:(-not $development) -TargetArchitecture $architecture } 'Production and developer runtime modes must remain distinct.'
    }
  }
  Check ($script:receiptCalls -eq 4) 'Only matching architecture/mode pairs may reach the receipt check.'
} finally {
  Set-Item -Path Function:Assert-FuzeBuildReceipt -Value $originalReceiptAssertion
}
$runtimeCommon=@('fuzevpn-service.exe','lz4.dll','tunnel.dll','wireguard.dll','concrt140.dll','msvcp140.dll','msvcp140_1.dll','msvcp140_2.dll','msvcp140_atomic_wait.dll','msvcp140_codecvt_ids.dll','vcruntime140.dll',
 'openvpn-dco/NOTICE.md','openvpn-dco/win10/ovpn-dco.inf','openvpn-dco/win10/ovpn-dco.cat','openvpn-dco/win10/ovpn-dco.sys','openvpn-dco/win11/ovpn-dco.inf','openvpn-dco/win11/ovpn-dco.cat','openvpn-dco/win11/ovpn-dco.sys','THIRD_PARTY_NOTICES.md','WIREGUARD_NOTICE.md','licenses/OpenVPN3-corresponding-source.zip')
function Runtime-Fixture([string]$Arch) {
  $names=$runtimeCommon + @("libssl-3-$Arch.dll","libcrypto-3-$Arch.dll")
  if ($Arch -eq 'x64') { $names += 'vcruntime140_1.dll' }
  return @($names | ForEach-Object { [pscustomobject]@{Path=$_;Length=12;Sha256=('a'*64)} })
}
$armRuntime=@(Get-PortableRuntimePaths (Runtime-Fixture arm64) arm64)
$x64Runtime=@(Get-PortableRuntimePaths (Runtime-Fixture x64) x64)
Check ($armRuntime.Path -contains 'libssl-3-arm64.dll' -and $armRuntime.Path -notcontains 'vcruntime140_1.dll') 'ARM64 must use its native dependencies, not the x64 exception runtime.'
Check ($x64Runtime.Path -contains 'libssl-3-x64.dll' -and $x64Runtime.Path -contains 'vcruntime140_1.dll') 'x64 must keep its original dependency contract.'
Reject { Get-PortableRuntimePaths (Runtime-Fixture x64) arm64 } 'A runtime manifest must reject dependencies from the other architecture.'
Write-Host 'Architecture packaging policy passed: PE headers, incompatible payload rejection, MSI component identities and runtime manifests; no binaries were loaded or signed.'
