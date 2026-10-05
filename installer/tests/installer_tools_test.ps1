$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Reject([scriptblock]$Action, [string]$Message) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  Assert $rejected $Message
}
foreach ($version in @('0.0.0','0.1.0','255.255.65535')) { Assert ((ConvertTo-PublicVersion $version) -ceq $version) "Version failed: $version" }
foreach ($version in @('1.2','1.2.3.4','1.2.3+1','256.2.3','1.256.3','1.2.65536','1.-2.3','1.2.3 ','01.2.3','1..3','1.2.x')) {
  Reject { ConvertTo-PublicVersion $version } "Invalid version accepted: $version"
}
Assert ((Get-StableGuid 'product:0.1.0') -ceq (Get-StableGuid 'product:0.1.0')) 'ProductCode must be deterministic.'
Assert ((Get-StableGuid 'product:0.1.0') -cne (Get-StableGuid 'product:0.1.1')) 'New public version must produce a new ProductCode.'
Reject { Assert-ProjectPath (Join-Path $projectRoot '..\outside.txt') $projectRoot } 'Out-of-scope path accepted.'
Reject { Assert-ProjectPath ($projectRoot + '-lookalike\outside.txt') $projectRoot } 'Prefix lookalike accepted.'
$temporary = Assert-ProjectPath (Join-Path $projectRoot '.toolchain\installer-runtime\temp\installer-tools-test') $projectRoot
[void][IO.Directory]::CreateDirectory($temporary)
$inventory = @(
  [pscustomobject]@{Path='fuzevpn_windows.exe';Length=1;Sha256='a'},
  [pscustomobject]@{Path='fuzevpn-service.exe';Length=1;Sha256='b'},
  [pscustomobject]@{Path='fuzevpn-update.exe';Length=1;Sha256='c'},
  [pscustomobject]@{Path='data\flutter_assets\A & B.txt';Length=1;Sha256='d'},
  [pscustomobject]@{Path='licenses\source.zip';Length=1;Sha256='e'}
)
$payloadPath = Join-Path $temporary 'payload.wxs'
Write-ReleasePayload $inventory $payloadPath
[xml]$payload = Get-Content -LiteralPath $payloadPath -Raw
$manager = [Xml.XmlNamespaceManager]::new($payload.NameTable)
$manager.AddNamespace('w','http://wixtoolset.org/schemas/v4/wxs')
$components = @($payload.SelectNodes('//w:Component', $manager))
Assert ($components.Count -eq 4) 'Only the separately authored service may be excluded from generated payload.'
Assert (@($components | ForEach-Object Guid | Select-Object -Unique).Count -eq 4) 'Component GUIDs must be unique.'
Assert (@($payload.SelectNodes('//w:File', $manager) | Where-Object Source -like '*A & B.txt').Count -eq 1) 'Payload must safely XML-encode filenames.'
$before = [IO.File]::ReadAllText($payloadPath)
Write-ReleasePayload $inventory $payloadPath
Assert ($before -ceq [IO.File]::ReadAllText($payloadPath)) 'Identical inputs must produce identical payload authoring.'
$fakeReport = Join-Path $temporary 'devtest-report.json'
'{"public":false,"mode":"devtest","signed_by":null}' | Set-Content -LiteralPath $fakeReport -Encoding UTF8
$manifestScript = Join-Path $projectRoot 'tools\new-windows-update-manifest.ps1'
Assert (Test-Path -LiteralPath $manifestScript -PathType Leaf) 'Manifest generator must exist before testing its refusal policy.'
$failure = ''
try { & $manifestScript -PackageReport $fakeReport -DownloadUrl 'https://example.com/FuzeVPN.exe' -OutputPath (Join-Path $temporary 'must-not-exist.json') } catch { $failure = $_.Exception.Message }
Assert ($failure -eq 'An unsigned DevTest package can never produce a public update manifest.') 'DevTest must fail for the expected publication policy, not an unrelated script error.'
Assert (-not (Test-Path -LiteralPath (Join-Path $temporary 'must-not-exist.json'))) 'Rejected manifest must not be written.'
$signingFixture = Join-Path $temporary 'runtime-signing'
[void][IO.Directory]::CreateDirectory($signingFixture)
$runtimeLibrary = Join-Path $signingFixture 'tunnel.dll'
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\wireguard\1.1\amd64\tunnel.dll') -Destination $runtimeLibrary -Force
Assert ((Get-AuthenticodeSignature -LiteralPath $runtimeLibrary).Status -eq 'NotSigned') 'The local source-built tunnel fixture must be unsigned.'
$targets = @(Get-UnsignedRuntimeSigningFiles $signingFixture $projectRoot)
Assert ($targets.Count -eq 1 -and $targets[0] -ceq $runtimeLibrary) 'The locally built unsigned runtime must be selected for signing.'
$unsignedDependency = Join-Path $signingFixture 'flutter_windows.dll'
Copy-Item -LiteralPath $runtimeLibrary -Destination $unsignedDependency -Force
$expandedTargets = @(Get-UnsignedRuntimeSigningFiles $signingFixture $projectRoot)
Assert ($expandedTargets.Count -eq 2 -and $expandedTargets -contains $unsignedDependency) 'Unsigned third-party dependencies must also be signed for Store distribution.'
Remove-Item -LiteralPath $unsignedDependency
$vendorRuntime = Join-Path $projectRoot 'third_party\wireguard\1.1\amd64\wireguard.dll'
Copy-Item -LiteralPath $vendorRuntime -Destination $runtimeLibrary -Force
[void](Assert-SignedFile $runtimeLibrary)
$vendorHash = (Get-FileHash -LiteralPath $runtimeLibrary -Algorithm SHA256).Hash
Assert (@(Get-UnsignedRuntimeSigningFiles $signingFixture $projectRoot).Count -eq 0) 'A valid vendor signature must be retained, not selected for replacement.'
Assert ((Get-FileHash -LiteralPath $runtimeLibrary -Algorithm SHA256).Hash -ceq $vendorHash) 'Choosing signing targets must not change a signed vendor runtime.'
$tampered = [IO.File]::ReadAllBytes($runtimeLibrary)
$tampered[128] = $tampered[128] -bxor 1
[IO.File]::WriteAllBytes($runtimeLibrary, $tampered)
Assert ((Get-AuthenticodeSignature -LiteralPath $runtimeLibrary).Status -ne 'Valid') 'The signed fixture must be invalid after tampering.'
Reject { Get-UnsignedRuntimeSigningFiles $signingFixture $projectRoot } 'An invalid runtime signature must never be replaced by application signing.'
Write-Host 'Installer tooling tests passed. No installer, service, driver or network operation was executed.'
