param(
  [Parameter(Mandatory)][string]$Path,
  [string]$AuthoredBy
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$utf8 = [Text.UTF8Encoding]::new($false)
$batch = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
$code = $batch.locale
$appPath = Join-Path $root "lib/l10n/catalogs/$code.json"
$installerPath = Join-Path $root "installer/l10n/catalogs/$code.json"
$app = Get-Content -LiteralPath $appPath -Raw -Encoding UTF8 | ConvertFrom-Json -AsHashtable
$installer = if(Test-Path -LiteralPath $installerPath){Get-Content -LiteralPath $installerPath -Raw -Encoding UTF8|ConvertFrom-Json -AsHashtable}else{[ordered]@{}}
$appSource = Get-Content -LiteralPath (Join-Path $root 'lib/l10n/catalogs/source.json') -Raw -Encoding UTF8|ConvertFrom-Json -AsHashtable
$installerSource = Get-Content -LiteralPath (Join-Path $root 'installer/l10n/source.json') -Raw -Encoding UTF8|ConvertFrom-Json -AsHashtable
function Tokens([string]$value) { (([regex]::Matches($value,'\{[A-Za-z_][A-Za-z0-9_]*\}|\[[A-Za-z0-9_]+\]')|ForEach-Object Value|Sort-Object -CaseSensitive)-join '|') }
$seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach($entry in $batch.entries) {
  if(-not $seen.Add($entry.id)){throw "Duplicate ID $($entry.id)"}
  if([string]::IsNullOrWhiteSpace($entry.target)){throw "Missing $code / $($entry.id)"}
  $isApp=$entry.id.StartsWith('app.')
  $key=$entry.id.Substring($(if($isApp){4}else{10}))
  $expected=if($isApp){$appSource[$key]}else{$installerSource[$key]}
  if(-not $expected -or $expected -cne $entry.source){throw "Invalid source $code / $($entry.id)"}
  if((Tokens $entry.target) -cne (Tokens $entry.source)){throw "Placeholder mismatch $code / $($entry.id)"}
  if($entry.target.Contains([char]0xFFFD)){throw "Invalid UTF-8 $code / $($entry.id)"}
  if($code -ne 'fr' -and $entry.source.Length -gt 45 -and $entry.target -ceq $entry.source){throw "Untranslated sentence $code / $($entry.id)"}
  foreach($brand in @('FuzeVPN','OpenVPN','WireGuard','Windows')) {
    if($entry.source.Contains($brand) -and -not $entry.target.Contains($brand)){throw "Lost product name $brand / $code / $($entry.id)"}
  }
  $sourceTags=([regex]::Matches($entry.source,'<[^>]+>')|ForEach-Object Value)-join '|'
  $targetTags=([regex]::Matches($entry.target,'<[^>]+>')|ForEach-Object Value)-join '|'
  if($sourceTags -cne $targetTags){throw "Changed markup $code / $($entry.id)"}
  if($code -ne 'fr' -and $entry.target -match "n[’']a pas pu|n[’']ont pas|sur cet ordinateur|à votre compte|Réessayez|déconnexion|connexion|interrompue|Choisissez|Impossible de") {throw "French fragment $code / $($entry.id)"}
  if($isApp){$app[$key]=$entry.target}else{$installer[$key]=$entry.target}
}
foreach($group in ($batch.entries|Group-Object target|Where-Object Count -gt 2)) {
  $distinct=@($group.Group.source|Sort-Object -Unique)
  if($distinct.Count -gt 2 -and @($distinct|Where-Object Length -gt 30).Count -gt 0){throw "Generic replacement repeated $($group.Count) times: $($group.Name)"}
}
$countryTargets=@($app.Keys|Where-Object {$_.StartsWith('@country:')}|ForEach-Object {$app[$_]})
foreach($key in $app.Keys) {
  if(-not $key.StartsWith('@country:') -and $app[$key] -cin $countryTargets){throw "Translation alignment error: country name used for UI text $code / $key"}
}
[IO.File]::WriteAllText($appPath,($app|ConvertTo-Json -Depth 10),$utf8)
[IO.File]::WriteAllText($installerPath,($installer|ConvertTo-Json -Depth 10),$utf8)
$reviewDir=Join-Path $root 'build/l10n/reviewed'
New-Item -ItemType Directory -Force -Path $reviewDir|Out-Null
$record=[ordered]@{batch=[IO.Path]::GetFileName($Path);locale=$code;entries=$batch.entries.Count;sha256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash;checked='source, placeholders, product names, markup, untranslated fragments, generic replacements'}
if (-not [string]::IsNullOrWhiteSpace($AuthoredBy)) { $record['authoredBy'] = $AuthoredBy.Trim() }
[IO.File]::WriteAllText((Join-Path $reviewDir ([IO.Path]::GetFileName($Path))),($record|ConvertTo-Json),$utf8)
Write-Output "$([IO.Path]::GetFileName($Path)): $($batch.entries.Count) entries imported ($($app.Count) app keys)."
