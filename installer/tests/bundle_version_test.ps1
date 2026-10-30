# SPDX-License-Identifier: MPL-2.0
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../BundleVersion.psm1') -Force
Initialize-BundleVersionApi
function Assert([bool]$Value, [string]$Message) { if (-not $Value) { throw $Message } }
function Block([string]$Key, [byte[]]$Data, [bool]$Text, [byte[][]]$Children = @()) {
  $stream = [IO.MemoryStream]::new()
  $writer = [IO.BinaryWriter]::new($stream)
  try {
    $writer.Write([ushort]0)
    $writer.Write([ushort]($Data.Length / $(if ($Text) { 2 } else { 1 })))
    $writer.Write([ushort][int]$Text)
    $writer.Write([Text.Encoding]::Unicode.GetBytes($Key + [char]0))
    while ($stream.Position % 4) { $writer.Write([byte]0) }
    $writer.Write($Data)
    while ($stream.Position % 4) { $writer.Write([byte]0) }
    foreach ($child in $Children) { $writer.Write($child); while ($stream.Position % 4) { $writer.Write([byte]0) } }
    $size = $stream.Length
    $stream.Position = 0; $writer.Write([ushort]$size)
    return ,$stream.ToArray()
  } finally { $writer.Dispose(); $stream.Dispose() }
}
function Resource([bool]$Text, [string]$Name = 'FuzeVPN') {
  $nameBlock = Block 'ProductName' ([Text.Encoding]::Unicode.GetBytes($Name + [char]0)) $Text
  $versionBlock = Block 'FileVersion' ([Text.Encoding]::Unicode.GetBytes('1.0.10.0' + [char]0)) $Text
  $table = Block '04090000' @() $true @($nameBlock,$versionBlock)
  $strings = Block 'StringFileInfo' @() $true @(,$table)
  return ,(Block 'VS_VERSION_INFO' ([byte[]]::new(52)) $false @(,$strings))
}
$broken = Resource $false
$canonical = Resource $true
$size = $broken.Length
Assert ([FuzeBundleVersionResource]::NormalizeVersionData($broken) -eq 2) 'Both binary-encoded string headers must be repaired.'
Assert ($broken.Length -eq $size) 'Resource repair must not move Burn container offsets.'
Assert ([Convert]::ToBase64String($broken) -ceq [Convert]::ToBase64String($canonical)) 'Repair must produce the canonical UTF-16 resource with unchanged text and fixed version data.'
Assert ([FuzeBundleVersionResource]::NormalizeVersionData($broken) -eq 0) 'Canonical resources must remain unchanged.'
$wrong = Resource $false 'AnotherPublisher'
[void][FuzeBundleVersionResource]::NormalizeVersionData($wrong)
Assert ([Text.Encoding]::Unicode.GetString($wrong).Contains('AnotherPublisher')) 'Normalization must never replace a product identity.'
foreach ($bad in @([byte[]]::new(0), [byte[]]::new(8), $canonical[0..($canonical.Length-2)])) {
  $rejected = $false
  try { [void][FuzeBundleVersionResource]::NormalizeVersionData([byte[]]$bad) } catch { $rejected = $true }
  Assert $rejected 'Malformed or truncated version resources must be rejected.'
}
Write-Output 'Bundle version resource normalization regressions passed.'
