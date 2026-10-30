# SPDX-License-Identifier: MPL-2.0
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Invoke-ReleaseGitChecked {
  param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string[]]$Arguments)
  $output=@(& git.exe -C $ProjectRoot @Arguments 2>&1)
  if ($LASTEXITCODE -ne 0) { throw "Git verification failed with exit code $LASTEXITCODE ($($Arguments[0]))." }
  return @($output | ForEach-Object { [string]$_ })
}

function Get-ReleaseGitProvenance {
  param([Parameter(Mandatory)][string]$ProjectRoot, [Parameter(Mandatory)][string]$ReleaseTag,
    [string[]]$AllowedChanges=@())
  $source=(Invoke-ReleaseGitChecked $ProjectRoot @('rev-parse','--verify','HEAD^{commit}')) -join ''
  $tag=(Invoke-ReleaseGitChecked $ProjectRoot @('rev-parse','--verify',"refs/tags/$ReleaseTag^{commit}")) -join ''
  if ($source -notmatch '^[a-f0-9]{40}(?:[a-f0-9]{24})?$' -or $tag -notmatch '^[a-f0-9]{40}(?:[a-f0-9]{24})?$') { throw 'Git references must resolve to commit identifiers.' }
  $changed=@(Invoke-ReleaseGitChecked $ProjectRoot @('status','--porcelain'))
  if ($changed.Count) { throw 'The rebuilt checkout has uncommitted changes.' }
  $differences=@(Invoke-ReleaseGitChecked $ProjectRoot @('diff','--name-only',$tag,$source,'--'))
  if (@($differences | Where-Object { $_ -cnotin $AllowedChanges }).Count) { throw "The application source differs from the $ReleaseTag reference." }
  return [pscustomobject]@{SourceCommit=$source;ReleaseCommit=$tag;Changes=$differences}
}

function Assert-ReleaseAssetBaseline {
  param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Baseline,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$FinalInventory)
  $maps=@()
  foreach ($inventory in @(@{Items=$Baseline},@{Items=$FinalInventory})) {
    $map=[Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $caseInsensitive=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $inventory.Items) {
      if ([IO.Path]::GetExtension($entry.Path) -in @('.exe','.dll','.sys') -or $entry.Path -ceq 'portable-runtime.manifest') { continue }
      if (-not $caseInsensitive.Add([string]$entry.Path)) { throw "Duplicate baseline/final asset path: $($entry.Path)" }
      $map.Add([string]$entry.Path,$entry)
    }
    $maps+=,$map
  }
  if ($maps[0].Count -ne $maps[1].Count) { throw 'The complete unsigned asset baseline must be preserved (file count mismatch).' }
  foreach ($path in $maps[0].Keys) {
    if (-not $maps[1].ContainsKey($path)) { throw "An unsigned baseline asset is missing or renamed: $path" }
    if ($maps[0][$path].Sha256 -cne $maps[1][$path].Sha256 -or [long]$maps[0][$path].Length -ne [long]$maps[1][$path].Length) { throw "An unsigned baseline asset changed: $path" }
  }
}

function Invoke-ReleaseRebuildStages {
  param([Parameter(Mandatory)][string]$ScriptPath,[Parameter(Mandatory)][string]$ProjectRoot,
    [ValidateSet('both','x64','arm64')][string]$BuildArchitecture='both')
  foreach ($stage in @('Bootstrap','Checks','Build','SigningTools','Packages','Verify')) {
    Write-Host "Release stage: $stage"
    & $ScriptPath -Stage $stage -BuildArchitecture $BuildArchitecture -ProjectRoot $ProjectRoot
  }
}

Export-ModuleMember -Function Invoke-ReleaseGitChecked,Get-ReleaseGitProvenance,Assert-ReleaseAssetBaseline,Invoke-ReleaseRebuildStages
