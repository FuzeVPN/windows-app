# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param([string]$OutputDirectory)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
Import-Module (Join-Path $projectRoot 'tools/ReleaseAudit.psm1') -Force
if (-not $OutputDirectory) { $OutputDirectory=Join-Path $projectRoot ('build/release-audit-tests/'+[guid]::NewGuid().ToString('N')) }
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$checks=0
function Check([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message};$script:checks++}
function Reject([scriptblock]$Action,[string]$Message){$failed=$false;try{& $Action | Out-Null}catch{$failed=$true};Check $failed $Message}
function Commit([string]$Repo,[string]$Message){[void](Invoke-ReleaseGitChecked $Repo @('add','--all'));[void](Invoke-ReleaseGitChecked $Repo @('-c','user.name=Release audit fixture','-c','user.email=audit@example.invalid','commit','--quiet','-m',$Message))}
$repo=Join-Path $OutputDirectory 'repository'
[void][IO.Directory]::CreateDirectory($repo)
[void](Invoke-ReleaseGitChecked $repo @('init','--quiet'))
[IO.File]::WriteAllText((Join-Path $repo 'app.txt'),'baseline application')
Commit $repo 'Baseline fixture'
Reject {Get-ReleaseGitProvenance $repo 'v1.0.8'} 'A missing release tag must fail closed.'
Reject {Invoke-ReleaseGitChecked $repo @('not-a-git-command')} 'A native Git error must not become an empty successful result.'
Reject {Get-ReleaseGitProvenance $OutputDirectory 'v1.0.8'} 'A non-repository must fail closed.'
[void](Invoke-ReleaseGitChecked $repo @('tag','v1.0.8'))
$proof=Get-ReleaseGitProvenance $repo 'v1.0.8'
Check ($proof.SourceCommit -ceq $proof.ReleaseCommit -and $proof.Changes.Count -eq 0) 'A clean exact reference must pass.'
[IO.File]::WriteAllText((Join-Path $repo 'README.md'),'allowed documentation fixture')
Commit $repo 'Allowed fixture metadata'
$proof=Get-ReleaseGitProvenance $repo 'v1.0.8' @('README.md')
Check ($proof.Changes.Count -eq 1 -and $proof.Changes[0] -ceq 'README.md') 'Explicit allowed metadata changes must pass.'
[IO.File]::WriteAllText((Join-Path $repo 'app.txt'),'modified application')
Reject {Get-ReleaseGitProvenance $repo 'v1.0.8' @('README.md')} 'An uncommitted application change must fail.'
Commit $repo 'Changed fixture application'
Reject {Get-ReleaseGitProvenance $repo 'v1.0.8' @('README.md')} 'A committed application change must fail.'

$assetA=[pscustomobject]@{Path='data\app.so';Length=3;Sha256=('a'*64)}
$assetB=[pscustomobject]@{Path='data\flutter_assets\image.png';Length=5;Sha256=('b'*64)}
$pe=[pscustomobject]@{Path='fuzevpn-service.exe';Length=10;Sha256=('c'*64)}
$manifest=[pscustomobject]@{Path='portable-runtime.manifest';Length=2;Sha256=('d'*64)}
Assert-ReleaseAssetBaseline @($assetA,$assetB,$pe) @($assetA,$assetB,$manifest)
Check $true 'PE signatures and the generated runtime manifest may differ outside the asset baseline.'
Reject {Assert-ReleaseAssetBaseline @($assetA,$assetB) @($assetA)} 'A deleted baseline asset must fail.'
Reject {Assert-ReleaseAssetBaseline @($assetA) @($assetA,$assetB)} 'An added final asset must fail.'
$changed=[pscustomobject]@{Path=$assetB.Path;Length=$assetB.Length;Sha256=('e'*64)}
Reject {Assert-ReleaseAssetBaseline @($assetA,$assetB) @($assetA,$changed)} 'Changed asset bytes must fail.'
$renamed=[pscustomobject]@{Path=$assetB.Path.ToUpperInvariant();Length=$assetB.Length;Sha256=$assetB.Sha256}
Reject {Assert-ReleaseAssetBaseline @($assetA,$assetB) @($assetA,$renamed)} 'Asset path casing is part of the inventory contract.'
Reject {Assert-ReleaseAssetBaseline @($assetA,$assetB) @($assetA,$assetB,$assetB)} 'Duplicate assets must fail.'

$stub=Join-Path $OutputDirectory 'record-stage.ps1'
$record=Join-Path $OutputDirectory 'stage-arguments.jsonl'
[IO.File]::WriteAllText($stub,@'
param([string]$Stage,[string]$BuildArchitecture,[string]$ProjectRoot)
[ordered]@{Stage=$Stage;BuildArchitecture=$BuildArchitecture;ProjectRoot=$ProjectRoot} | ConvertTo-Json -Compress | Add-Content -LiteralPath $env:FUZEVPN_AUDIT_STAGE_LOG
'@)
$saved=[Environment]::GetEnvironmentVariable('FUZEVPN_AUDIT_STAGE_LOG','Process')
try {
  $env:FUZEVPN_AUDIT_STAGE_LOG=$record
  foreach($arch in @('x64','arm64','both')){Invoke-ReleaseRebuildStages -ScriptPath $stub -ProjectRoot $repo -BuildArchitecture $arch}
}finally{[Environment]::SetEnvironmentVariable('FUZEVPN_AUDIT_STAGE_LOG',$saved,'Process')}
$calls=@(Get-Content -LiteralPath $record | ForEach-Object {$_ | ConvertFrom-Json})
Check ($calls.Count -eq 18) 'Every selected architecture must be forwarded to all six stages.'
foreach($arch in @('x64','arm64','both')){
  $selected=@($calls | Where-Object BuildArchitecture -CEQ $arch)
  Check ($selected.Count -eq 6 -and @($selected | Where-Object Stage -CEQ 'Build').Count -eq 1 -and @($selected | Where-Object ProjectRoot -CNE $repo).Count -eq 0) 'The rebuild dispatcher must preserve architecture and project arguments.'
}
Write-Host "Release provenance and orchestration tests passed ($checks checks). No product, signing or network operation ran."
