# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../BuildSupport.psm1') -Force
$root = Get-FuzeProjectRoot
$pins = Get-FuzeDependencyPins
function Check([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Reject([scriptblock]$Action,[string]$Message) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  Check $rejected $Message
}
$manifest = Get-Content -LiteralPath (Join-Path $root $pins.vcpkg.manifest) -Raw | ConvertFrom-Json
Check ($manifest.'builtin-baseline' -ceq $pins.vcpkg.commit) 'Bootstrap must use the native manifest baseline.'
Check ($pins.flutter.commit -match '^[0-9a-f]{40}$' -and $pins.flutter.engine -match '^[0-9a-f]{40}$') 'Flutter source and engine must be pinned by commit.'
Assert-FuzeHash -Path (Join-Path $root $pins.wix.source_archive) -Hash $pins.wix.hash
foreach ($file in Get-ChildItem (Join-Path $root 'tools') -Recurse -File | Where-Object Extension -in '.ps1','.psm1') {
  $tokens = $null; $errors = $null
  [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
  Check (-not $errors.Count) "PowerShell syntax error in $($file.Name)."
}
$run = [guid]::NewGuid().ToString('N')
$fixture = Join-Path $root "build/bootstrap-tools-tests/$run"
$seed = Join-Path $fixture 'seed'
[void][IO.Directory]::CreateDirectory($seed)
$name = "bootstrap-fixture-$run.bin"
$seedFile = Join-Path $seed $name
[IO.File]::WriteAllText($seedFile,'Test data, not a downloadable executable.')
$pin = [pscustomobject]@{ name = $name; url = "https://example.invalid/$name"; algorithm = 'SHA256'; hash = (Get-FileHash -LiteralPath $seedFile).Hash }
$cached = Get-FuzePinnedDownload -Pin $pin -Offline -DownloadSeeds @($seed)
Check ((Get-FileHash -LiteralPath $cached).Hash -ceq $pin.hash) 'An offline verified seed must become a matching cache file.'
[IO.File]::WriteAllText($cached,'Changed bytes')
Reject { Get-FuzePinnedDownload -Pin $pin -Offline } 'A corrupt cache must never be used.'
Reject { Assert-FuzeHash -Path $seedFile -Hash ('0'*64) } 'An incorrect seed hash must be rejected.'
$missing = [pscustomobject]@{ name = "missing-$run.bin"; url = 'https://example.invalid/missing'; algorithm = 'SHA256'; hash = ('0'*64) }
Reject { Get-FuzePinnedDownload -Pin $missing -Offline } 'Offline mode must never substitute or download a missing artifact.'
Add-Type -AssemblyName System.IO.Compression.FileSystem
function MakeZip([string]$Path,[string[]]$Names) {
  $stream = [IO.File]::Create($Path)
  $zip = [IO.Compression.ZipArchive]::new($stream,[IO.Compression.ZipArchiveMode]::Create)
  try {
    foreach ($name in $Names) {
      $writer = [IO.StreamWriter]::new($zip.CreateEntry($name).Open())
      try { $writer.Write('fixture') } finally { $writer.Dispose() }
    }
  } finally { $zip.Dispose(); $stream.Dispose() }
}
$good = Join-Path $fixture 'good.zip'
MakeZip $good @('source/file.txt','ignored.txt')
Expand-FuzeZip -Archive $good -Destination (Join-Path $fixture 'output') -Prefix 'source/'
Check ((Test-Path -LiteralPath (Join-Path $fixture 'output/file.txt')) -and -not (Test-Path -LiteralPath (Join-Path $fixture 'output/ignored.txt'))) 'ZIP prefix extraction must strip only the requested source prefix.'
$unsafe = Join-Path $fixture 'unsafe.zip'
MakeZip $unsafe @('../outside.txt')
Reject { Expand-FuzeZip -Archive $unsafe -Destination (Join-Path $fixture 'unsafe-output') } 'ZIP traversal must be rejected.'
$duplicate = Join-Path $fixture 'duplicate.zip'
MakeZip $duplicate @('same.txt','SAME.TXT')
Reject { Expand-FuzeZip -Archive $duplicate -Destination (Join-Path $fixture 'duplicate-output') } 'Windows case-colliding ZIP paths must be rejected.'
Reject { Expand-FuzeZip -Archive $good -Destination ([IO.Path]::GetDirectoryName($root)) } 'Dependency extraction must remain in this checkout.'
Write-Host 'Bootstrap tools verified: pins, syntax, offline hashes, missing artifacts and ZIP path validation. No product or network operation was executed.'
