[CmdletBinding()]
param([switch]$Check)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
$output = Join-Path $PSScriptRoot 'generated'
$locales = @(Get-Content (Join-Path $PSScriptRoot 'locales.json') -Raw -Encoding UTF8 | ConvertFrom-Json)
$reference = Get-Content (Join-Path $PSScriptRoot 'source.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$keys = @($reference.PSObject.Properties.Name | Sort-Object -CaseSensitive)
$nativeKeys = @((1..14 | ForEach-Object { "native.$_" }) + @('native.WindowsCode','native.WarningFormat','msi.Downgrade','msi.WindowsX64','msi.Rollback','msi.ServiceDisplayName','msi.ServiceDescription'))
$utf8 = [Text.UTF8Encoding]::new($false)
function Xml([string]$value) { [Security.SecurityElement]::Escape($value) }
function EscapeCppString([string]$value) { 'L"' + $value.Replace('\','\\').Replace('"','\"').Replace("`r",'\r').Replace("`n",'\n').Replace("`t",'\t') + '"' }
function Tokens([string]$value) { (@([regex]::Matches($value, '\{[A-Za-z_][A-Za-z0-9_]*\}|\[[A-Za-z0-9_]+\]') | ForEach-Object { $_.Value } | Sort-Object -CaseSensitive) -join '|') }
function Write-Generated([string]$relative, [string]$content) {
  $path = Join-Path $output $relative
  $content = $content.Replace("`r`n", "`n")
  if ($Check) {
    if (-not (Test-Path -LiteralPath $path) -or [IO.File]::ReadAllText($path) -cne $content) { throw "Generated installer file is stale: $relative" }
  } else {
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path))
    [IO.File]::WriteAllText($path, $content, $utf8)
  }
}
$theme = [IO.File]::ReadAllText((Join-Path $root 'FuzeVpnTheme.xml'))
$themeIds = @([regex]::Matches($theme, '#\(loc\.([A-Za-z0-9_]+)\)') | ForEach-Object { 'theme.' + $_.Groups[1].Value } | Sort-Object -Unique)
foreach ($key in @($themeIds + $nativeKeys)) { if ($key -cnotin $keys) { throw "Missing source installer key: $key" } }
$catalogs = @{}
$payloads = [Collections.Generic.List[string]]::new()
$rows = [Collections.Generic.List[string]]::new()
$aliases = [Collections.Generic.List[string]]::new()
foreach ($locale in $locales) {
  $code = $locale.code
  $catalog = Get-Content (Join-Path $PSScriptRoot "catalogs\$code.json") -Raw -Encoding UTF8 | ConvertFrom-Json
  $actualKeys = @($catalog.PSObject.Properties.Name | Sort-Object -CaseSensitive)
  if (($actualKeys -join "`n") -cne ($keys -join "`n")) { throw "Installer catalog $code has missing or extra keys." }
  foreach ($key in $keys) {
    $value = $catalog.$key
    if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value) -or $value.Contains([char]0xFFFD)) { throw "Invalid installer translation $code/$key" }
    if ((Tokens $value) -cne (Tokens $reference.$key)) { throw "Installer placeholders differ: $code/$key" }
  }
  $catalogs[$code] = $catalog
}
# Validate every locale before writing any output, so partial inputs cannot replace
# a previously complete installer catalog.
foreach ($locale in $locales) {
  $code = $locale.code
  $catalog = $catalogs[$code]
  $nativeValues = @($nativeKeys | ForEach-Object { EscapeCppString $catalog.$_ }) -join ",`n      "
  $rows.Add("  { $($locale.lcids[0]), $(EscapeCppString $code), {`n      $nativeValues`n  } },")
  $rtl = $null -ne $locale.PSObject.Properties['rtl'] -and $locale.rtl
  foreach ($lcid in $locale.lcids) {
    $aliases.Add("  { $lcid, $(EscapeCppString $code) },")
    $strings = @($keys | Where-Object { $_.StartsWith('theme.') } | ForEach-Object { "  <String Id=`"$($_.Substring(6))`" Value=`"$(Xml $catalog.$_)`" />" }) -join "`n"
    $wxl = "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<WixLocalization Culture=`"$($locale.culture)`" Language=`"$lcid`" xmlns=`"http://wixtoolset.org/schemas/v4/wxl`">`n$strings`n</WixLocalization>`n"
    Write-Generated "$lcid\thm.wxl" $wxl
    [xml]$layout = $theme
    foreach ($image in $layout.SelectNodes('//*[@ImageFile]')) { $image.SetAttribute('ImageFile', '..\' + $image.GetAttribute('ImageFile')) }
    if ($rtl) {
      # ThmUtil has no Window extended-style attribute. Mirror authored rectangles
      # and right-align text using supported native control styles instead.
      foreach ($control in $layout.SelectNodes('//*[@X and @Width]')) {
        $x = [int]$control.GetAttribute('X'); $width = [int]$control.GetAttribute('Width')
        if ($width -gt 0) { $control.SetAttribute('X', [string](-$x)) }
        else { $control.SetAttribute('X', [string](-$width)); $control.SetAttribute('Width', [string](-$x)) }
        if ($control.LocalName -eq 'Label') { $control.SetAttribute('HexStyle', '00000002') }
        elseif ($control.LocalName -in @('Checkbox','RadioButton')) { $control.SetAttribute('HexStyle', '00000220') }
        elseif ($control.LocalName -eq 'Hypertext') { $control.SetAttribute('HexStyle', '00000020') }
      }
    }
    Write-Generated "$lcid\thm.xml" ($layout.OuterXml + "`n")
    foreach ($file in @('thm.wxl','thm.xml')) {
      $id = 'Localization_' + $lcid + '_' + $file.Replace('.','_')
      $payloads.Add("      <Payload Id=`"$id`" Name=`"$lcid\$file`" SourceFile=`"`$(var.InstallerDir)\l10n\generated\$lcid\$file`" />")
    }
  }
}
$english = $catalogs['en']
$englishStrings = @($keys | Where-Object { $_.StartsWith('theme.') } | ForEach-Object { "  <String Id=`"$($_.Substring(6))`" Value=`"$(Xml $english.$_)`" />" }) -join "`n"
Write-Generated 'thm.wxl' "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<WixLocalization Culture=`"en-US`" Language=`"1033`" xmlns=`"http://wixtoolset.org/schemas/v4/wxl`">`n$englishStrings`n</WixLocalization>`n"
$msiStrings = @($keys | Where-Object { $_.StartsWith('msi.') } | ForEach-Object { "  <String Id=`"$($_.Replace('.','_'))`" Value=`"$(Xml $english.$_)`" />" }) -join "`n"
Write-Generated 'msi.en.wxl' "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<WixLocalization Culture=`"en-US`" Language=`"1033`" xmlns=`"http://wixtoolset.org/schemas/v4/wxl`">`n$msiStrings`n</WixLocalization>`n"
Write-Generated 'LocalizationPayloads.wxs' "<?xml version=`"1.0`" encoding=`"utf-8`"?>`n<Wix xmlns=`"http://wixtoolset.org/schemas/v4/wxs`">`n  <Fragment>`n    <PayloadGroup Id=`"InstallerLocalizations`">`n$($payloads -join "`n")`n    </PayloadGroup>`n  </Fragment>`n</Wix>`n"
$header = @"
// Generated from installer/l10n/catalogs by generate.ps1. Do not edit.
#pragma once
#include <string_view>
namespace fuzevpn::installer::l10n {
enum class Message { Native1, Native2, Native3, Native4, Native5, Native6, Native7,
  Native8, Native9, Native10, Native11, Native12, Native13, Native14, WindowsCode,
  WarningFormat, Downgrade, WindowsX64, Rollback, ServiceDisplayName, ServiceDescription };
struct Catalog { unsigned language_id; const wchar_t* code; const wchar_t* text[21]; };
inline constexpr Catalog catalogs[] = {
$($rows -join "`n")
};
struct Alias { unsigned language_id; const wchar_t* code; };
inline constexpr Alias aliases[] = {
$($aliases -join "`n")
};
inline const Catalog* Find(std::wstring_view code) {
  for (const auto& catalog : catalogs) if (code == catalog.code) return &catalog;
  return nullptr;
}
inline const Catalog& Resolve(unsigned language_id) {
  for (const auto& alias : aliases) if (alias.language_id == language_id) return *Find(alias.code);
  const auto primary = language_id & 0x3ff;
  // Chinese regions/scripts are explicit aliases: unknown Chinese uses simplified.
  if (primary == 4) return *Find(L"zh_Hans");
  for (const auto& catalog : catalogs) if ((catalog.language_id & 0x3ff) == primary) return catalog;
  return *Find(L"en");
}
inline const wchar_t* Text(const Catalog& catalog, Message message) {
  return catalog.text[static_cast<unsigned>(message)];
}
} // namespace fuzevpn::installer::l10n
"@
Write-Generated 'installer_catalogs.h' ($header + "`n")
Write-Host "Installer catalogs: $($locales.Count) locales, $($keys.Count) keys; generated files validated."
