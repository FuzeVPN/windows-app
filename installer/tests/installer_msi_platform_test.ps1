[CmdletBinding()]
param(
  [Parameter(Mandatory)][string]$MsiPath,
  [Parameter(Mandatory)][string]$LogPath
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
$MsiPath = Assert-ProjectPath $MsiPath $projectRoot
$LogPath = Assert-ProjectPath $LogPath $projectRoot
[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($LogPath))
$temporary = Assert-ProjectPath (Join-Path ([IO.Path]::GetDirectoryName($LogPath)) 'temp') $projectRoot
[void][IO.Directory]::CreateDirectory($temporary)
$previousTemp = $env:TEMP
$previousTmp = $env:TMP
$installer = $null
$session = $null
$sourceHash = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash
$fixtureProductCode = [Guid]::NewGuid().ToString('B').ToUpperInvariant()
$fixturePath = Assert-ProjectPath (Join-Path $temporary ('initializer-fixture-' + $fixtureProductCode.Trim('{}') + '.msi')) $projectRoot
try {
  $env:TEMP = $temporary
  $env:TMP = $temporary
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $installer.UILevel = 2
  # Give only this disposable fixture a fresh product identity: OpenPackage(0)
  # otherwise refuses a rebuilt package whose ProductCode is already installed.
  # The shipped MSI is never opened for writing. This one Property UPDATE leaves
  # all other rows, embedded action DLLs, cabinets and summary properties intact.
  Copy-Item -LiteralPath $MsiPath -Destination $fixturePath
  $database = $null
  $view = $null
  try {
    $database = $installer.OpenDatabase($fixturePath, 1) # MSIDBOPEN_TRANSACT
    $view = $database.OpenView("UPDATE ``Property`` SET ``Value`` = '$fixtureProductCode' WHERE ``Property`` = 'ProductCode'")
    $view.Execute()
    $view.Close()
    $database.Commit()
  } finally {
    if ($null -ne $view) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view) }
    if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database) }
  }
  $installer.EnableLog('voicewarmupx', $LogPath, $false)
  # Only our immediate, read-only initializer is called. There is no INSTALL,
  # InstallInitialize, BeginMaintenance, file copy or service operation here.
  # Flag 1 (IGNOREMACHINESTATE) restricts the engine and skips DLL actions;
  # use a normal session and require proof that the real DLL actually ran.
  $session = $installer.OpenPackage($fixturePath, 0)
  if ($session.Property('ProductCode') -ne $fixtureProductCode) {
    throw 'The MSI host did not open the isolated product fixture.'
  }
  # Exercise localization through the real MSI host without running an install
  # sequence. This action only sets session properties; it never touches the VPN.
  $locales = Get-Content -LiteralPath (Join-Path $projectRoot 'installer/l10n/locales.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  foreach ($locale in $locales) {
    $catalog = Get-Content -LiteralPath (Join-Path $projectRoot ("installer/l10n/catalogs/" + $locale.code + '.json')) -Raw -Encoding UTF8 | ConvertFrom-Json
    $session.Property('FUZEVPN_LANGUAGE') = [string]$locale.lcids[0]
    if ($session.DoAction('InitializeLocalization') -ne 1) { throw "MSI localization failed: $($locale.code)" }
    foreach ($mapping in @(
      @('FUZEVPN_DOWNGRADE', 'msi.Downgrade'),
      @('FUZEVPN_WINDOWS_X64', 'msi.WindowsX64'),
      @('FUZEVPN_ROLLBACK', 'msi.Rollback'),
      @('FUZEVPN_SERVICE_NAME', 'msi.ServiceDisplayName'),
      @('FUZEVPN_SERVICE_DESCRIPTION', 'msi.ServiceDescription')
    )) {
      if ($session.Property($mapping[0]) -cne $catalog.($mapping[1])) {
        throw "MSI localization mismatch: $($locale.code)/$($mapping[0])"
      }
    }
  }
  $session.Property('INSTALLFOLDER') = Join-Path $env:ProgramFiles 'FuzeVPN'
  $result = $session.DoAction('InitializeMaintenance')
  if ($result -ne 1) { throw "InitializeMaintenance failed in the MSI host (result $result). See $LogPath" }
  if ([string]::IsNullOrEmpty($session.Property('BeginMaintenance'))) {
    throw 'MSI did not execute the real initialization action.'
  }
  if (($session.Property('BeginMaintenance') -split "`n")[-1] -ne $locales[-1].code) {
    throw 'MSI did not preserve the selected language for deferred maintenance messages.'
  }
  # Exercise the real immediate action with a custom absolute path; the folder
  # is deliberately not created and no elevated maintenance action is invoked.
  $customDirectory = Join-Path $projectRoot 'build\validation\msi-custom-path-not-created'
  if (Test-Path -LiteralPath $customDirectory) { throw 'Custom MSI test path must not already exist.' }
  $session.Property('INSTALLFOLDER') = $customDirectory + '\'
  if ($session.DoAction('InitializeMaintenance') -ne 1 -or
      -not $session.Property('BeginMaintenance').Contains($customDirectory)) {
    throw 'The MSI initializer did not preserve a custom installation directory.'
  }
  if (Test-Path -LiteralPath $customDirectory) { throw 'Read-only MSI initialization unexpectedly created a folder.' }
} finally {
  if ($null -ne $session) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($session) }
  if ($null -ne $installer) {
    $installer.EnableLog('', '', $false)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
  }
  $env:TEMP = $previousTemp
  $env:TMP = $previousTmp
  if ((Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash -ne $sourceHash) {
    throw 'The original MSI changed during the read-only host test.'
  }
}
$log = [IO.File]::ReadAllText($LogPath)
if ($log -notmatch 'FuzeVPN platform:' -or $log -match 'Doing action: (INSTALL|InstallInitialize|BeginMaintenance|InstallExecute)(?:\r|\n)') {
  throw 'Unexpected diagnostic log: missing platform evidence or an installation action ran.'
}
Write-Host 'The actual MSI initialization DLL accepted this machine. No installation or VPN maintenance was executed.'
Write-Host "Isolated fixture: $fixturePath (ProductCode $fixtureProductCode); original MSI SHA256 unchanged: $sourceHash"
