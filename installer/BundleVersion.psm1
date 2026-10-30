# SPDX-License-Identifier: MPL-2.0
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Initialize-BundleVersionApi {
  if (-not ('FuzeBundleVersionResource' -as [type])) {
    Add-Type -LiteralPath (Join-Path $PSScriptRoot 'BundleVersionResource.cs')
  }
}
function Repair-BundleVersionStrings {
  param([Parameter(Mandatory)][string]$Path)
  $Path = [IO.Path]::GetFullPath($Path)
  if ((Get-AuthenticodeSignature -LiteralPath $Path).Status -ne 'NotSigned') {
    throw 'Only a newly built unsigned bundle may have its version resource normalized.'
  }
  Initialize-BundleVersionApi
  return [FuzeBundleVersionResource]::RepairUnsignedBundle($Path)
}
function Assert-BundleUpdaterVersion {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Version)
  Initialize-BundleVersionApi
  [FuzeBundleVersionResource]::AssertUpdaterVersion([IO.Path]::GetFullPath($Path), $Version)
}
Export-ModuleMember -Function Initialize-BundleVersionApi,Repair-BundleVersionStrings,Assert-BundleUpdaterVersion
