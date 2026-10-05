$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Assert([bool]$condition, [string]$message) { if (-not $condition) { throw $message } }
& (Join-Path $root 'l10n\generate.ps1') -Check
$locales = @(Get-Content (Join-Path $root 'l10n\locales.json') -Raw -Encoding UTF8 | ConvertFrom-Json)
Assert ($locales.Count -eq 30) 'Installer must expose all 30 languages.'
[xml]$theme = Get-Content (Join-Path $root 'FuzeVpnTheme.xml') -Raw -Encoding UTF8
# Measure authored button text at the theme's 96-DPI, 12-pixel font size.
# This creates only an in-memory bitmap; it never opens a window.
Add-Type -AssemblyName System.Drawing
$bitmap = [Drawing.Bitmap]::new(1, 1)
$bitmap.SetResolution(96, 96)
$graphics = [Drawing.Graphics]::FromImage($bitmap)
$font = [Drawing.Font]::new('Segoe UI', 12, [Drawing.FontStyle]::Regular, [Drawing.GraphicsUnit]::Pixel)
try {
  foreach ($locale in $locales) {
    $catalog = Get-Content (Join-Path $root "l10n\catalogs\$($locale.code).json") -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($button in $theme.SelectNodes('//*[local-name()="Button"]')) {
      foreach ($match in [regex]::Matches($button.InnerText, '#\(loc\.([A-Za-z0-9_]+)\)')) {
        $key = 'theme.' + $match.Groups[1].Value
        $text = $catalog.$key.Replace('&','')
        $width = $graphics.MeasureString($text, $font).Width
        Assert ($width -le [int]$button.Width - 12) "Button translation needs more space: $($locale.code)/$key ($width pixels)."
      }
    }
  }
} finally {
  $font.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
}
foreach ($node in $theme.SelectNodes('//*[local-name()="Label" or local-name()="Checkbox" or local-name()="Button" or local-name()="Hypertext" or local-name()="Text"]')) {
  foreach ($text in $node.ChildNodes | Where-Object NodeType -eq Text) {
    Assert ($text.Value.Trim() -eq '' -or $text.Value.Trim() -match '^#\(loc\.[A-Za-z0-9_]+\)$') 'Installer theme contains untranslated literal text.'
  }
}
$payloadPath = Join-Path $root 'l10n\generated\LocalizationPayloads.wxs'
[xml]$payload = Get-Content $payloadPath -Raw -Encoding UTF8
$lcids = @($locales | ForEach-Object { $_.lcids })
Assert (@($lcids | Select-Object -Unique).Count -eq $lcids.Count) 'Duplicate installer LCID mapping.'
Assert ($payload.SelectNodes('//*[local-name()="Payload"]').Count -eq $lcids.Count * 2) 'Each LCID needs both theme and translated strings.'
foreach ($locale in $locales) {
  $rtl = $null -ne $locale.PSObject.Properties['rtl'] -and $locale.rtl
  foreach ($lcid in $locale.lcids) {
    [xml]$localized = Get-Content (Join-Path $root "l10n\generated\$lcid\thm.xml") -Raw -Encoding UTF8
    [xml]$strings = Get-Content (Join-Path $root "l10n\generated\$lcid\thm.wxl") -Raw -Encoding UTF8
    Assert ($strings.DocumentElement.Language -eq [string]$lcid) "Wrong language identifier: $lcid"
    $window = $localized.SelectSingleNode('//*[local-name()="Window"]')
    $windowWidth = [int]$window.Width
    $windowHeight = [int]$window.Height
    foreach ($control in $localized.SelectNodes('//*[@X and @Y and @Width and @Height]')) {
      $x = [int]$control.X; $y = [int]$control.Y; $w = [int]$control.Width; $h = [int]$control.Height
      # Same anchor calculations as WiX thmutil.cpp GetControlDimensions.
      if ($w -le 0) { $w += $windowWidth - [Math]::Max(0, $x) }
      if ($h -le 0) { $h += $windowHeight - [Math]::Max(0, $y) }
      if ($x -lt 0) { $x += $windowWidth - $w }
      if ($y -lt 0) { $y += $windowHeight - $h }
      Assert ($x -ge 0 -and $y -ge 0 -and $w -gt 0 -and $h -gt 0 -and $x+$w -le $windowWidth -and $y+$h -le $windowHeight) "Out of bounds control in $lcid`: $($control.Name)"
      if ($control.LocalName -eq 'Button') { Assert ($w -ge 145 -and $h -ge 30) "Translated button too small: $lcid/$($control.Name)" }
      if ($rtl -and $control.LocalName -eq 'Label') { Assert ($control.GetAttribute('HexStyle') -eq '00000002') "RTL label is not aligned right: $lcid" }
    }
    $image = $localized.SelectSingleNode('//*[local-name()="ImageControl"]')
    Assert ($image.ImageFile -eq '..\logo.png') 'Satellite themes must resolve the shared logo from the BA root.'
  }
}
[xml]$package = Get-Content (Join-Path $root 'Package.wxs') -Raw -Encoding UTF8
Assert ($package.Wix.Package.MajorUpgrade.IgnoreLanguage -eq 'yes') 'Updates must recognize the previous French MSI and block downgrades across languages.'
foreach ($sequence in @('InstallUISequence','InstallExecuteSequence')) {
  $action = $package.SelectSingleNode("//*[local-name()='$sequence']/*[@Action='InitializeLocalization']")
  Assert ($null -ne $action -and $action.Before -eq 'LaunchConditions') "Localization must precede launch conditions in $sequence."
}
Write-Host 'Installer localization sources, payloads, placeholders and layout checks passed. No installer was executed.'
