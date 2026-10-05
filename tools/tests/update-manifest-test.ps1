# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param([string]$FixtureVersion)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if (-not $FixtureVersion) {
  $versionMatch = [regex]::Match((Get-Content -LiteralPath (Join-Path $projectRoot 'pubspec.yaml') -Raw),'(?m)^version:\s*([^+\s]+)')
  if (-not $versionMatch.Success) { throw 'Cannot read the current public fixture version from pubspec.yaml.' }
  $FixtureVersion = $versionMatch.Groups[1].Value
}
$generator=Join-Path $projectRoot 'tools/new-windows-update-manifest.ps1'
$temporary=Join-Path $projectRoot 'build/update-manifest-tests'
[void][IO.Directory]::CreateDirectory($temporary)
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Reject([scriptblock]$Action,[string]$Message){
  $failed=$false
  try {& $Action | Out-Null} catch {$failed=$true}
  Check $failed $Message
}
$fakeReport=Join-Path $temporary 'unsigned.json'
[IO.File]::WriteAllText($fakeReport,'{"public":false,"mode":"devtest"}')
foreach($kind in @('installer','portable')){
  Reject {& $generator -PackageKind $kind -PackageReport $fakeReport -DownloadUrl 'https://example.com/FuzeVPN.zip' -OutputPath (Join-Path $temporary 'rejected.json')} "Unsigned $kind publication accepted."
}
$verified=0
foreach($arch in @('x64','arm64')){
  foreach($kind in @('installer','portable')){
    $name=if($kind -eq 'portable'){'portable-package-report.json'}else{'package-report.json'}
    $fixture=Join-Path $projectRoot "dist/production/$kind/$FixtureVersion/$arch/$name"
    if(-not (Test-Path -LiteralPath $fixture)){continue}
    $report=Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json
    $filename=if($kind -eq 'portable'){[IO.Path]::GetFileName($report.zip)}else{[IO.Path]::GetFileName($report.bundle)}
    $url="https://fuzevpn.com/download/windows/$FixtureVersion/$filename"
    $output=Join-Path $temporary "$kind-$arch.json"
    & $generator -PackageKind $kind -PackageReport $fixture -DownloadUrl $url -OutputPath $output -ReleaseNotes 'Signed release test.'
    $manifest=Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    $expectedHash=if($kind -eq 'portable'){$report.zip_sha256}else{$report.bundle_sha256}
    Check ($manifest.version -ceq $FixtureVersion -and $manifest.download_url -ceq $url -and $manifest.sha256 -ceq $expectedHash) 'Publication must describe the final package bytes.'
    $wrongExtension=if($kind -eq 'portable'){'.exe'}else{'.zip'}
    Reject {& $generator -PackageKind $kind -PackageReport $fixture -DownloadUrl "https://example.com/FuzeVPN$wrongExtension" -OutputPath $output} 'Wrong package extension accepted.'
    Reject {& $generator -PackageKind $kind -PackageReport $fixture -DownloadUrl "http://example.com/$filename" -OutputPath $output} 'HTTP publication URL accepted.'
    Reject {& $generator -PackageKind $kind -PackageReport $fixture -DownloadUrl "https://user:password@example.com/$filename" -OutputPath $output} 'Credential-bearing publication URL accepted.'
    Reject {& $generator -PackageKind $kind -PackageReport $fixture -DownloadUrl ($url+'#fragment') -OutputPath $output} 'Fragment publication URL accepted.'
    $tamperedReport=Join-Path $temporary "tampered-$kind-$arch.json"
    if($kind -eq 'portable'){$report.zip_sha256='0'*64}else{$report.bundle_sha256='0'*64}
    [IO.File]::WriteAllText($tamperedReport,($report|ConvertTo-Json -Depth 10))
    Reject {& $generator -PackageKind $kind -PackageReport $tamperedReport -DownloadUrl $url -OutputPath $output} 'A package whose final hash disagrees with the report was accepted.'
    if($kind -eq 'portable'){
      $report=Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json
      $report.files[0].Sha256='0'*64
      [IO.File]::WriteAllText($tamperedReport,($report|ConvertTo-Json -Depth 10))
      Reject {& $generator -PackageKind portable -PackageReport $tamperedReport -DownloadUrl $url -OutputPath $output} 'Portable inventory mismatch was accepted.'
      $report=Get-Content -LiteralPath $fixture -Raw | ConvertFrom-Json
      $report.version='254.254.65434'
      [IO.File]::WriteAllText($tamperedReport,($report|ConvertTo-Json -Depth 10))
      Reject {& $generator -PackageKind portable -PackageReport $tamperedReport -DownloadUrl $url -OutputPath $output} 'Portable report version differing from signed payload was accepted.'
    }
    $verified++
  }
}
Check ($verified -eq 4) 'Provide signed installer and portable fixtures for both architectures; no successful validation may be skipped.'
Write-Host 'Four signed publication manifests verified; malformed URLs, unsigned reports, hash/inventory changes and portable version mismatch rejected. No package was modified or executed.'
