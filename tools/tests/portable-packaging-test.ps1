# SPDX-License-Identifier: MPL-2.0
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\prepare-portable-runtime.ps1') -FunctionsOnly
function Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function MustReject([scriptblock]$Action, [string]$Message) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  Check $rejected $Message
}
$cpp = [IO.File]::ReadAllText((Join-Path $projectRoot 'windows\runner\portable_runtime.cpp'))
$requiredBlock = [regex]::Match($cpp, '(?s)constexpr const char\* required\[\] = \{(.*?)\};')
Check $requiredBlock.Success 'Native required-payload contract was not found.'
$commonRequired = @([regex]::Matches($requiredBlock.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
Check ($requiredBlock.Groups[1].Value.Contains('fuzevpn_architecture::kOpenSslDll') -and $requiredBlock.Groups[1].Value.Contains('fuzevpn_architecture::kOpenCryptoDll')) 'Native OpenSSL payload must follow the selected architecture.'
Check ($cpp.Contains('if constexpr (fuzevpn_architecture::kBuildMachine == fuzevpn_architecture::kX64Machine)')) 'The x64 exception CRT must remain architecture-specific.'
$required = $commonRequired + @('libssl-3-x64.dll','libcrypto-3-x64.dll','vcruntime140_1.dll')
$fixture = @($required | ForEach-Object { [pscustomobject]@{ Path = $_.Replace('/','\'); Length = 12; Sha256 = ('a' * 64) } })
$fixture += [pscustomobject]@{ Path = 'licenses\Other-License.txt'; Length = 20; Sha256 = ('b' * 64) }
$fixture += [pscustomobject]@{ Path = 'fuzevpn-runtime.exe'; Length = 40; Sha256 = ('c' * 64) }
$selected = @(Get-PortableRuntimePaths $fixture)
Check ($selected.Count -eq $required.Count + 1) 'Include all notices/licenses, exclude the self-referential bootstrap.'
$bytes = ConvertTo-PortableManifest '1.2.3' $selected
$text = [Text.Encoding]::ASCII.GetString($bytes)
Check ($text.StartsWith("FUZEVPN_RUNTIME_V1`nversion=1.2.3`nipc=1`n") -and $text.EndsWith("`n")) 'Native manifest framing.'
Check (-not $text.Contains("`r") -and -not $text.Contains([string][char]0) -and $bytes[0] -eq 70) 'No BOM/CR/NUL.'
$reverse = @($fixture); [Array]::Reverse($reverse)
Check ([Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String((ConvertTo-PortableManifest '1.2.3' @(Get-PortableRuntimePaths $reverse)))) 'Manifest order is deterministic.'
MustReject { Get-PortableRuntimePaths @($fixture | Where-Object Path -ne 'fuzevpn-service.exe') } 'Missing service must fail.'
MustReject { Get-PortableRuntimePaths @($fixture + $fixture[0]) } 'Duplicate case-insensitive payload path must fail.'
$armFixture = @($commonRequired + @('libssl-3-arm64.dll','libcrypto-3-arm64.dll') | ForEach-Object { [pscustomobject]@{ Path=$_; Length=12; Sha256=('a'*64) } })
$armSelected = @(Get-PortableRuntimePaths $armFixture arm64)
Check ($armSelected.Count -eq $commonRequired.Count + 2) 'ARM64 includes both native OpenSSL libraries without the x64 exception CRT.'
MustReject { Get-PortableRuntimePaths $armFixture x64 } 'ARM64 files cannot satisfy the x64 runtime contract.'
MustReject { Get-PortableRuntimePaths $fixture arm64 } 'x64 files cannot satisfy the ARM64 runtime contract.'
foreach ($path in @('../escape.dll','C:/file.dll','a\\b.dll','x//b.dll','NUL.txt','LPT1.dll','a./b.dll','a b.dll','é.dll')) {
  $bad = [pscustomobject]@{ Path = $path; Length = 12; Sha256 = ('a' * 64) }
  MustReject { ConvertTo-PortableManifest '1.2.3' @($bad) } "Invalid path must fail: $path"
}
MustReject { ConvertTo-PortableManifest '256.0.0' $selected } 'MSI version bound must fail.'
MustReject { ConvertTo-PortableManifest '1.2.3' @([pscustomobject]@{ Path='large.dll'; Length=536870913; Sha256=('a'*64) }) } 'Payload size bound must fail.'
MustReject { ConvertTo-PortableManifest '1.2.3' @([pscustomobject]@{ Path='empty.dll'; Length=0; Sha256=('a'*64) }) } 'Empty runtime file must fail.'
$badParent = @([pscustomobject]@{ Path='a'; Length=1; Sha256=('a'*64) }, [pscustomobject]@{ Path='a/b'; Length=1; Sha256=('a'*64) })
MustReject { ConvertTo-PortableManifest '1.2.3' $badParent } 'File/directory overlap must fail.'
Write-Host 'Portable packaging contract tests passed (no binaries, certificates, services or machine state changed).'
