# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../BuildSupport.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../../installer/InstallerTools.psm1') -Force
$root = Get-FuzeProjectRoot
$pins = Get-FuzeDependencyPins
Assert-FuzeDcoDependency
$fixture = Join-Path $root ('build/dco-dependency-tests/' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixture)
foreach ($arch in @('x64','arm64')) {
  $vendorArch = if ($arch -eq 'x64') { 'amd64' } else { 'arm64' }
  $release = Join-Path $fixture $arch
  [void][IO.Directory]::CreateDirectory($release)
  Copy-Item -LiteralPath (Join-Path (Join-Path $root $pins.openvpn_dco.directory) $vendorArch) -Destination (Join-Path $release 'openvpn-dco') -Recurse
  Assert-DcoPayload -ReleaseDirectory $release -Architecture $arch
  foreach ($variant in @('win10','win11')) {
    [void](Assert-PeArchitecture (Join-Path $release "openvpn-dco/$variant/ovpn-dco.sys") $arch)
  }
}
# A real, previously signed vendor package must still be refused after the
# minimum supported DCO version changes; a valid signature alone is insufficient.
$legacy = Join-Path $fixture 'legacy'
[void][IO.Directory]::CreateDirectory($legacy)
Copy-Item -LiteralPath (Join-Path $root 'third_party/openvpn-dco/2.8.7/amd64') -Destination (Join-Path $legacy 'openvpn-dco') -Recurse
$rejected = $false
try { Assert-DcoPayload -ReleaseDirectory $legacy -Architecture x64 } catch { $rejected = $true }
if (-not $rejected) { throw 'The signed but vulnerable DCO 2.8.7 package must be refused.' }
# Also refuse a stale signed SYS paired with a current INF: the binary version
# has to satisfy the pin independently of the text in its INF.
$mixed = Join-Path $fixture 'x64'
Copy-Item -LiteralPath (Join-Path $legacy 'openvpn-dco/win10/ovpn-dco.sys') -Destination (Join-Path $mixed 'openvpn-dco/win10/ovpn-dco.sys') -Force
$rejected = $false
try { Assert-DcoPayload -ReleaseDirectory $mixed -Architecture x64 } catch { $rejected = $true }
if (-not $rejected) { throw 'A stale DCO SYS paired with a current INF must be refused.' }
Write-Host 'DCO dependency verified: pinned source and 12 payload hashes, signed x64/ARM64 packages, PE architecture, legacy and mixed-version rejection. No driver was installed or executed.'
