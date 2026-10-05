$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$installerRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
[xml]$bundle = Get-Content -LiteralPath (Join-Path $installerRoot 'Bundle.wxs') -Raw -Encoding UTF8
[xml]$package = Get-Content -LiteralPath (Join-Path $installerRoot 'Package.wxs') -Raw -Encoding UTF8
[xml]$theme = Get-Content -LiteralPath (Join-Path $installerRoot 'FuzeVpnTheme.xml') -Raw -Encoding UTF8
$product = $bundle.SelectSingleNode('//*[local-name()="ProductSearch"]')
Assert ($product.UpgradeCode -eq $package.Wix.Package.UpgradeCode -and $product.Result -eq 'exists' -and $product.Variable -eq 'InstallLocationExists') 'Upgrade UX must use public MSI product registration with the existing UpgradeCode.'
Assert ($bundle.Wix.Bundle.UpgradeCode -eq '{FD69A760-5D2E-4D83-833A-98C0294356BC}') 'Existing bundle upgrade identity must remain compatible.'
foreach ($document in @($bundle, $package)) {
  Assert ($document.SelectNodes('//*[local-name()="RegistrySearch" and @Key="Software\FuzeVPN\Installer"]').Count -eq 0) 'Detection must not depend on opening the protected private Installer key.'
}
$service = $package.SelectSingleNode('//*[local-name()="Component" and @Id="VpnServiceComponent"]')
$folder = $bundle.SelectSingleNode('//*[local-name()="ComponentSearch" and @Id="InstalledFolder"]')
Assert ($folder.Guid -eq $service.Guid -and $folder.Result -eq 'directory' -and $folder.After -eq $product.Id -and $folder.Condition -eq 'InstallLocationExists') 'Upgrade folder must come from the installed service component metadata.'
Assert ($service.SelectSingleNode('*[local-name()="File"][@KeyPath="yes"]').Id -eq 'VpnServiceExe') 'Folder detection requires the stable service file key path.'
$previousFolder = $package.SelectSingleNode('//*[local-name()="Property" and @Id="PREVIOUS_INSTALLFOLDER"]/*[local-name()="ComponentSearch"]')
Assert ($previousFolder.Guid -eq $service.Guid -and $previousFolder.Type -eq 'file' -and $previousFolder.SelectNodes('*').Count -eq 0) 'Direct MSI must search the registered file key path without a FileSearch signature, returning its containing directory.'
$desktopComponent = $package.SelectSingleNode('//*[local-name()="Component" and @Id="DesktopShortcut"]')
$desktopSearch = $bundle.SelectSingleNode('//*[local-name()="ComponentSearch" and @Id="InstalledDesktopShortcut"]')
Assert ($desktopSearch.Guid -eq $desktopComponent.Guid -and $desktopSearch.Result -eq 'state' -and $desktopSearch.Variable -eq 'PreviousDesktopShortcutState') 'MSI component state must be read into a separate variable, never directly into a checkbox.'
Assert ($desktopSearch.Condition -eq 'InstallLocationExists AND DesktopShortcut = -1') 'Desktop detection must preserve explicit command-line preferences.'
$desktopVariable = $bundle.SelectSingleNode('//*[local-name()="Variable" and @Name="DesktopShortcut"]')
Assert ($desktopVariable.Value -eq '-1' -and $desktopVariable.GetAttribute('Overridable', 'http://wixtoolset.org/schemas/v4/wxs/bal') -eq 'yes') 'Desktop default must distinguish unspecified from explicit false.'
$restore = $bundle.SelectSingleNode('//*[local-name()="SetVariable" and @Id="RestoreDesktopShortcut"]')
$default = $bundle.SelectSingleNode('//*[local-name()="SetVariable" and @Id="DefaultDesktopShortcut"]')
Assert ($restore.Variable -eq 'DesktopShortcut' -and $restore.Value -eq '1' -and $restore.Condition -eq 'DesktopShortcut = -1 AND PreviousDesktopShortcutState = 3' -and $restore.After -eq $desktopSearch.Id) 'Only a locally installed desktop component may restore an unspecified preference.'
Assert ($default.Variable -eq 'DesktopShortcut' -and $default.Value -eq '0' -and $default.Condition -eq 'DesktopShortcut = -1' -and $default.After -eq $restore.Id) 'Fresh/absent desktop preference must resolve to false after metadata restoration.'
foreach ($sequence in @('InstallUISequence', 'InstallExecuteSequence')) {
  $action = $package.SelectSingleNode("//*[local-name()='$sequence']/*[@Action='InitializeDesktopShortcut']")
  Assert ($action.Before -eq 'CostFinalize' -and $action.Condition -eq 'DESKTOP_SHORTCUT = -1') "Direct MSI must restore desktop preferences before costing in $sequence."
}
$button = $theme.SelectSingleNode('//*[local-name()="Button" and @Name="InstallButton"]')
Assert ($button.SelectSingleNode('*[local-name()="Text" and @Condition="InstallLocationExists"]').InnerText -eq '#(loc.UpdateButton)') 'An existing installation must show the localized update action.'
Assert ($bundle.SelectSingleNode('//*[local-name()="MsiPackage"]').Visible -eq 'no') 'Bundle installs must hide the chained MSI registration to avoid duplicate app entries.'
Assert ($null -eq $package.SelectSingleNode('//*[local-name()="Property" and @Id="ARPSYSTEMCOMPONENT"]')) 'Direct MSI distribution must remain independently discoverable and uninstallable.'
Write-Host 'Installer upgrade detection, public metadata, caller preferences and registration checks passed. No installer or service was executed.'
