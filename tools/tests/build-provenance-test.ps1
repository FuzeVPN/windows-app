# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Import-Module (Join-Path $projectRoot 'tools/BuildProvenance.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'BuildProvenanceFixtures.psm1') -Force
if(-not $OutputDirectory){$OutputDirectory=Join-Path $projectRoot ('build/build-provenance-tests/'+[guid]::NewGuid().ToString('N'))}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action|Out-Null}catch{$failed=$true};Check $failed $Message}
$fixtures=@{}
foreach($arch in @('x64','arm64')){
  foreach($dev in @($false,$true)){
    $mode=if($dev){'dev'}else{'prod'}
    $fixtureDir=Join-Path $OutputDirectory "$arch-$mode"
    $pe=New-FuzePolicyTestPe -Path (Join-Path $fixtureDir 'policy.dll') -Architecture $arch -Development:$dev
    $policy=Get-FuzeCompiledBuildPolicy $pe
    Check ($policy.Architecture -ceq $arch -and $policy.Development -eq $dev) 'Compiled RC resource 302 must match target architecture and broker mode.'
    $fixtures["$arch-$mode"]=$pe
  }
}
$production=[Text.Encoding]::ASCII.GetBytes("FUZEVPN_BUILD_POLICY_V1`nportable_dev=0`narchitecture=x64`n")
Reject {ConvertFrom-FuzeBuildPolicy ([Text.Encoding]::ASCII.GetBytes("FUZEVPN_BUILD_POLICY_V1`nportable_dev=2`narchitecture=x64`n"))} 'An invalid development flag must fail.'
Reject {ConvertFrom-FuzeBuildPolicy ([Text.Encoding]::ASCII.GetBytes("FUZEVPN_BUILD_POLICY_V1`nportable_dev=0`narchitecture=x86`n"))} 'An unsupported architecture must fail.'
Reject {ConvertFrom-FuzeBuildPolicy ($production+[byte]0)} 'Trailing resource bytes must fail.'
$localized=Join-Path $OutputDirectory 'localized-policy.dll'
Copy-Item -LiteralPath $fixtures['x64-prod'] -Destination $localized
Set-FuzePolicyFixtureResource -Path $localized -Bytes $production -Language 0x409
Reject {Get-FuzeCompiledBuildPolicy $localized} 'A locale-specific duplicate must not override or ambiguate neutral policy.'

$build=Join-Path $OutputDirectory 'receipt-fixture'
$release=Join-Path $build 'runner/Release'
[void][IO.Directory]::CreateDirectory($release)
$names=@('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')
foreach($name in $names){Copy-Item -LiteralPath $fixtures['x64-prod'] -Destination (Join-Path $release $name)}
$asset=Join-Path $release 'app.so'
[IO.File]::WriteAllText($asset,'synthetic AOT data; never executable')
$cache=Join-Path $build 'CMakeCache.txt'
[IO.File]::WriteAllText($cache,"FUZEVPN_ALLOW_PORTABLE_DEV:BOOL=OFF`nCMAKE_GENERATOR_PLATFORM:INTERNAL=x64`n")
$receiptPath=Join-Path $build 'build-provenance.json'
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath} 'A missing successful build receipt must fail.'
[void](New-FuzeBuildReceipt -ReleaseDirectory $release -SourceBuildCache $cache)
[void](Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath)
Check $true 'A successful compiled receipt must match real resource fixtures and assets.'
[IO.File]::WriteAllText($cache,"FUZEVPN_ALLOW_PORTABLE_DEV:BOOL=ON`nCMAKE_GENERATOR_PLATFORM:INTERNAL=x64`n")
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath -Development} 'A cache-only mode change must not qualify retained executables.'
[IO.File]::WriteAllText($cache,"FUZEVPN_ALLOW_PORTABLE_DEV:BOOL=OFF`nCMAKE_GENERATOR_PLATFORM:INTERNAL=x64`n")
Copy-Item -LiteralPath $fixtures['x64-dev'] -Destination (Join-Path $release 'fuzevpn-service.exe') -Force
Reject {New-FuzeBuildReceipt -ReleaseDirectory $release -SourceBuildCache $cache} 'A production cache must not attest an executable compiled for development.'
Copy-Item -LiteralPath $fixtures['x64-prod'] -Destination (Join-Path $release 'fuzevpn-service.exe') -Force
Copy-Item -LiteralPath $fixtures['arm64-prod'] -Destination (Join-Path $release 'fuzevpn-update.exe') -Force
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath} 'A mismatched actual PE architecture must fail.'
Copy-Item -LiteralPath $fixtures['x64-prod'] -Destination (Join-Path $release 'fuzevpn-update.exe') -Force
[void](Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath)
$codePath=Join-Path $release 'fuzevpn-service.exe'
$stream=[IO.File]::Open($codePath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$reader=[IO.BinaryReader]::new($stream)
try {
  $stream.Position=0x3c;$peOffset=$reader.ReadUInt32()
  $stream.Position=$peOffset+20;$optionalSize=$reader.ReadUInt16()
  $stream.Position=$peOffset+24+$optionalSize+20;$codeOffset=$reader.ReadUInt32()
  $stream.Position=$codeOffset;$first=$stream.ReadByte();$stream.Position=$codeOffset;$stream.WriteByte($first -bxor 1)
}finally{$reader.Dispose();$stream.Dispose()}
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath} 'Changed executable section bytes must fail the successful build receipt.'
Copy-Item -LiteralPath $fixtures['x64-prod'] -Destination $codePath -Force
[IO.File]::WriteAllText($asset,'altered synthetic AOT payload')
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath} 'Modified AOT/asset bytes must fail the compiled receipt.'
[IO.File]::WriteAllText($asset,'synthetic AOT data; never executable')

# Exercise real resource growth on the synthetic no-entry-point runtime DLL.
$runtime=Join-Path $release 'fuzevpn-runtime.exe'
Set-FuzePolicyFixtureResource -Path $runtime -Bytes ([Text.Encoding]::ASCII.GetBytes(('runtime fixture inventory'+('x'*24000)))) -Id 300
Set-FuzePolicyFixtureResource -Path $runtime -Bytes ([Text.Encoding]::ASCII.GetBytes(('frontend fixture inventory'+('x'*24000)))) -Id 301
[void](Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath)
Check $true 'Runtime inventory resource growth must preserve the compiled code receipt.'
# Other application resources are invariant: only the runtime is allowed to
# receive inventories after compilation, even before final signing evidence.
$gui=Join-Path $release 'fuzevpn_windows.exe'
Set-FuzePolicyFixtureResource -Path $gui -Bytes ([Text.Encoding]::ASCII.GetBytes('unexpected GUI resource change')) -Id 300
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath} 'Resource changes in other PEs must fail the compiled receipt.'
Copy-Item -LiteralPath $fixtures['x64-prod'] -Destination $gui -Force

Update-FuzeSignedBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath
$receipt=Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath
Check ($receipt.phase -ceq 'signed' -and $receipt.compiled.files.Count -eq $receipt.signed.files.Count) 'Final receipt must retain compiled hashes and record final bytes.'
$staging=Join-Path $OutputDirectory 'staged/FuzeVPN'
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($staging))
Copy-Item -LiteralPath $release -Destination $staging -Recurse
$stagedReceipt=Join-Path $OutputDirectory 'staged/build-provenance.json'
Copy-Item -LiteralPath $receiptPath -Destination $stagedReceipt
[void](Assert-FuzeBuildReceipt -ReleaseDirectory $staging -ReceiptPath $stagedReceipt)
Check $true 'An identical staged payload must retain its original compilation receipt outside the payload.'
# This test only exercises bookkeeping; the caller separately requires real
# publisher signatures before this transition. No signing service is invoked.
Set-FuzePolicyFixtureResource -Path $runtime -Bytes ([Text.Encoding]::ASCII.GetBytes('changed final runtime resource')) -Id 301
Reject {Assert-FuzeBuildReceipt -ReleaseDirectory $release -ReceiptPath $receiptPath} 'Any final signed-phase byte change must invalidate its receipt.'
$savedReceiptHash=(Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash
Suspend-FuzeBuildReceipt -SourceBuildCache $cache
Check (-not (Test-Path -LiteralPath $receiptPath)) 'A new build attempt must invalidate the active successful receipt before it can fail.'
$previous=@(Get-ChildItem -LiteralPath $build -Filter 'build-provenance.previous-*.json' -File)
Check ($previous.Count -eq 1 -and (Get-FileHash -LiteralPath $previous[0].FullName -Algorithm SHA256).Hash -ceq $savedReceiptHash) 'The prior successful receipt must be preserved as historical evidence.'

Write-Host "Compiled policy and build receipt tests passed ($checks checks; x64/ARM64, production/development, neutral resource language). Only synthetic no-entry-point DLLs were built, never loaded as code."
