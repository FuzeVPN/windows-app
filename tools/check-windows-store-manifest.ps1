# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [string]$ManifestPath,
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$endpoint = 'https://storeedgefd.dsx.mp.microsoft.com/v9.0/packageManifests/XPFM3116NCW2W8'
$manifest = if ($ManifestPath) {
  Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json
} else {
  Invoke-RestMethod -Uri $endpoint -Headers @{
    Version = '1.0.0'
    'Windows-Package-Manager' = 'winget'
  }
}
if ($manifest.Data.PackageIdentifier -cne 'XPFM3116NCW2W8') {
  throw 'The manifest is not the FuzeVPN Microsoft Store product.'
}

$rows = @(
  foreach ($version in $manifest.Data.Versions) {
    foreach ($installer in $version.Installers) {
      [pscustomobject]@{
        Version = $version.PackageVersion
        Architecture = $installer.Architecture
        Type = $installer.InstallerType
        Url = $installer.InstallerUrl
        Sha256 = $installer.InstallerSha256
        Silent = $installer.InstallerSwitches.Silent
      }
    }
  }
)
if ($rows.Count -eq 0) { throw 'The Store returned no installers.' }
$problems = [Collections.Generic.List[string]]::new()
foreach ($architecture in @('x64', 'arm64')) {
  if (@($rows | Where-Object Architecture -EQ $architecture).Count -eq 0) {
    $problems.Add("Missing $architecture installer.")
  }
}
foreach ($row in $rows) {
  if ($row.Type -cne 'msi') {
    $problems.Add("Unexpected installer type: $($row.Type). Review its separate EXE command contract.")
  } elseif (($row.Silent.Trim() -replace '\s+', ' ') -cne '/quiet /norestart') {
    $problems.Add("$($row.Architecture) $($row.Version): expected MSI switches '/quiet /norestart', received '$($row.Silent)'.")
  }
}
$report = [pscustomobject]@{
  ProductId = $manifest.Data.PackageIdentifier
  Source = $(if ($ManifestPath) { [IO.Path]::GetFullPath($ManifestPath) } else { $endpoint })
  CheckedAtUtc = [DateTime]::UtcNow.ToString('o')
  Status = $(if ($problems.Count) { 'FAIL' } else { 'PASS' })
  InstallerEntries = $rows.Count
  Packages = @($rows | Sort-Object Version, Architecture, Type, Url, Sha256, Silent -Unique)
  Problems = @($problems | Sort-Object -Unique)
}
if ($OutputPath) {
  $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
$report.Packages | Format-Table Version, Architecture, Type, Silent
if ($problems.Count) { throw ($report.Problems -join [Environment]::NewLine) }
Write-Output "PASS: $($rows.Count) Store installer entries use the FuzeVPN MSI switch contract."
