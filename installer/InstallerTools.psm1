Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ProjectPath {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$ProjectRoot)
  $full = [IO.Path]::GetFullPath($Path)
  $root = [IO.Path]::GetFullPath($ProjectRoot).TrimEnd('\')
  if (-not $full.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw "Path must be inside the Windows project: $full"
  }
  # Check existing ancestors before creating anything; never follow a junction.
  $current = $full
  while ($current.Length -ge $root.Length) {
    if (Test-Path -LiteralPath $current) {
      if (((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Reparse points are not permitted in installer inputs/outputs: $current"
      }
    }
    if ($current -eq $root) { break }
    $current = [IO.Path]::GetDirectoryName($current)
    if ([string]::IsNullOrEmpty($current)) { break }
  }
  return $full
}

function ConvertTo-PublicVersion {
  param([Parameter(Mandatory)][string]$Value)
  if ($Value -notmatch '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$') {
    throw 'Public version must be exactly major.minor.patch, with no leading zero or build revision.'
  }
  $parts = @($Value.Split('.') | ForEach-Object { [int]$_ })
  if ($parts[0] -gt 255 -or $parts[1] -gt 255 -or $parts[2] -gt 65535) {
    throw 'MSI public version limits are 255.255.65535.'
  }
  return ($parts -join '.')
}

function Get-ProjectPublicVersion {
  param([Parameter(Mandatory)][string]$ProjectRoot)
  $text = [IO.File]::ReadAllText((Join-Path $ProjectRoot 'pubspec.yaml'))
  $match = [regex]::Match($text, '(?m)^version:\s*([0-9.]+)(?:\+[0-9]+)?\s*$')
  if (-not $match.Success) { throw 'pubspec.yaml must declare a stable three-part version, optionally followed by +build.' }
  return ConvertTo-PublicVersion $match.Groups[1].Value
}

function Get-StableHex {
  param([Parameter(Mandatory)][string]$Value)
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Get-StableGuid {
  param([Parameter(Mandatory)][string]$Value)
  $hex = Get-StableHex ('FuzeVPN-installer-v1:' + $Value.ToLowerInvariant())
  return ('{' + $hex.Substring(0,8) + '-' + $hex.Substring(8,4) + '-8' + $hex.Substring(13,3) + '-a' + $hex.Substring(17,3) + '-' + $hex.Substring(20,12) + '}').ToUpperInvariant()
}

function Get-ReleaseInventory {
  param([Parameter(Mandatory)][string]$ReleaseDirectory, [Parameter(Mandatory)][string]$ProjectRoot)
  $release = Assert-ProjectPath $ReleaseDirectory $ProjectRoot
  if (-not (Test-Path -LiteralPath $release -PathType Container)) { throw 'Release directory does not exist.' }
  $entries = @(Get-ChildItem -LiteralPath $release -Recurse -Force)
  foreach ($entry in $entries) {
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Release contains a reparse point: $($entry.FullName)" }
  }
  foreach ($file in @($entries | Where-Object { -not $_.PSIsContainer } | Sort-Object FullName)) {
    $relative = $file.FullName.Substring($release.TrimEnd('\').Length + 1)
    if ($relative -match '[\r\n]' -or $relative.Contains('$(')) { throw "Invalid installer file name: $relative" }
    [pscustomobject]@{ Path = $relative; Length = $file.Length; Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
  }
}

function Write-ReleasePayload {
  param([Parameter(Mandatory)][object[]]$Inventory, [Parameter(Mandatory)][string]$Path,
    [ValidateSet('x64','arm64')][string]$Architecture='x64')
  $directories = @{' ' = 'INSTALLFOLDER'}
  $lines = [Collections.Generic.List[string]]::new()
  $lines.Add('<?xml version="1.0" encoding="utf-8"?>')
  $lines.Add('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs"><Fragment>')
  foreach ($entry in $Inventory) {
    $parent = [IO.Path]::GetDirectoryName($entry.Path)
    if ([string]::IsNullOrEmpty($parent)) { continue }
    $accumulated = ''
    $parentId = 'INSTALLFOLDER'
    foreach ($part in $parent.Split('\')) {
      $accumulated = if ($accumulated) { $accumulated + '\' + $part } else { $part }
      if (-not $directories.ContainsKey($accumulated)) {
        $id = 'Dir_' + (Get-StableHex $accumulated.ToLowerInvariant()).Substring(0,24)
        $directories[$accumulated] = $id
        $lines.Add(('<DirectoryRef Id="{0}"><Directory Id="{1}" Name="{2}" /></DirectoryRef>' -f $parentId, $id, [Security.SecurityElement]::Escape($part)))
      }
      $parentId = $directories[$accumulated]
    }
  }
  $lines.Add('<ComponentGroup Id="ReleasePayload">')
  foreach ($entry in $Inventory) {
    if ($entry.Path -ieq 'fuzevpn-service.exe') { continue }
    $hash = (Get-StableHex $entry.Path.ToLowerInvariant()).Substring(0,24)
    $parent = [IO.Path]::GetDirectoryName($entry.Path)
    $directoryId = if ([string]::IsNullOrEmpty($parent)) { 'INSTALLFOLDER' } else { $directories[$parent] }
    $source = [Security.SecurityElement]::Escape('$(var.ReleaseDir)\' + $entry.Path)
    $guid = Get-StableGuid ($(if ($Architecture -eq 'x64') { 'component:' } else { 'component:arm64:' }) + $entry.Path)
    $lines.Add(('<Component Id="Cmp_{0}" Directory="{1}" Guid="{2}" Bitness="always64"><File Id="File_{0}" Source="{3}" KeyPath="yes" /></Component>' -f $hash, $directoryId, $guid, $source))
  }
  $lines.Add('</ComponentGroup></Fragment></Wix>')
  [IO.File]::WriteAllLines($Path, $lines, [Text.UTF8Encoding]::new($false))
}

function New-ReleaseSigningPolicy {
  param([string]$CertificateThumbprint, [string]$ArtifactSigningMetadataPath,
    [string]$ArtifactSigningDlibPath, [string]$ExpectedPublisherSubject,
    [string]$ArtifactSigningCertificateThumbprint, [string]$TimestampUrl, [switch]$DevTest)
  $cloud = $ArtifactSigningMetadataPath -or $ArtifactSigningDlibPath -or $ExpectedPublisherSubject -or $ArtifactSigningCertificateThumbprint
  if ($DevTest) {
    if ($CertificateThumbprint -or $cloud) { throw 'DevTest and production signing are mutually exclusive.' }
    return [pscustomobject]@{ Mode='devtest'; CertificateThumbprint=''; ExpectedPublisherSubject=''; TimestampUrl=''; MetadataPath=''; DlibPath='' }
  }
  if ($CertificateThumbprint -and $cloud) { throw 'Select either a local certificate or Artifact Signing, never both.' }
  if ($cloud) {
    if (-not $ArtifactSigningMetadataPath -or -not $ArtifactSigningDlibPath -or -not $ExpectedPublisherSubject) {
      throw 'Artifact Signing requires metadata, an x64 dlib and the complete expected publisher subject.'
    }
    # This project is authorized to publish as this exact validated identity.
    # A cloud account/profile name alone is never an acceptable publisher pin.
    if ($ExpectedPublisherSubject -cne 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR') {
      throw 'Artifact Signing must use the complete validated FuzeVPN publisher subject.'
    }
    if ($ArtifactSigningCertificateThumbprint -and $ArtifactSigningCertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
      throw 'An optional Artifact Signing certificate pin must be a SHA1 certificate thumbprint.'
    }
    $mode = 'artifact-signing'
    $pin = $ArtifactSigningCertificateThumbprint
    if (-not $TimestampUrl) { $TimestampUrl = 'http://timestamp.acs.microsoft.com' }
  } else {
    if (-not $CertificateThumbprint -or $CertificateThumbprint -notmatch '^[A-Fa-f0-9]{40}$') {
      throw 'Production signing requires a local certificate thumbprint or an Artifact Signing configuration.'
    }
    $mode = 'local-certificate'
    $pin = $CertificateThumbprint
    if (-not $TimestampUrl) { $TimestampUrl = 'http://timestamp.digicert.com' }
  }
  $timestamp = $null
  if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestamp) -or
      $timestamp.Scheme -notin @('http','https') -or -not $timestamp.Host -or $timestamp.UserInfo -or $timestamp.Fragment) {
    throw 'A timestamp service HTTP(S) URL without credentials or fragment is required.'
  }
  return [pscustomobject]@{ Mode=$mode; CertificateThumbprint=$pin; ExpectedPublisherSubject=$ExpectedPublisherSubject;
    TimestampUrl=$TimestampUrl; MetadataPath=$ArtifactSigningMetadataPath; DlibPath=$ArtifactSigningDlibPath }
}

function Get-ReleaseSigningParameters {
  param([Parameter(Mandatory)]$Policy)
  if ($Policy.Mode -eq 'devtest') { return @{} }
  $parameters = @{ TimestampUrl=$Policy.TimestampUrl }
  if ($Policy.Mode -eq 'local-certificate') { $parameters['CertificateThumbprint']=$Policy.CertificateThumbprint }
  elseif ($Policy.Mode -eq 'artifact-signing') {
    $parameters['ArtifactSigningMetadataPath']=$Policy.MetadataPath
    $parameters['ArtifactSigningDlibPath']=$Policy.DlibPath
    $parameters['ExpectedPublisherSubject']=$Policy.ExpectedPublisherSubject
    if ($Policy.CertificateThumbprint) { $parameters['ArtifactSigningCertificateThumbprint']=$Policy.CertificateThumbprint }
  } else { throw 'Unknown release signing policy.' }
  return $parameters
}

function Get-ReleaseVerificationParameters {
  param([Parameter(Mandatory)]$Policy)
  $parameters = @{ TimestampRequired=$true }
  if ($Policy.CertificateThumbprint) { $parameters['Thumbprint']=$Policy.CertificateThumbprint }
  if ($Policy.ExpectedPublisherSubject) { $parameters['ExpectedPublisherSubject']=$Policy.ExpectedPublisherSubject }
  return $parameters
}

function Read-ArtifactSigningMetadata {
  param([Parameter(Mandatory)][string]$Path)
  if ((Get-Item -LiteralPath $Path).Length -gt 65536) { throw 'Artifact Signing metadata must be at most 64 KiB.' }
  $metadata = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  foreach ($name in @('Endpoint','CodeSigningAccountName','CertificateProfileName')) {
    $property = $metadata.PSObject.Properties[$name]
    if ($null -eq $property -or $property.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($property.Value) -or
        $property.Value.Length -gt 4096 -or $property.Value -match '[\x00-\x20\x7f]') {
      throw "Artifact Signing metadata requires a valid $name."
    }
  }
  $endpoint = $null
  if (-not [Uri]::TryCreate($metadata.Endpoint, [UriKind]::Absolute, [ref]$endpoint) -or
      $endpoint.Scheme -cne 'https' -or $endpoint.Host -notmatch '^[a-z0-9]+\.codesigning\.azure\.net$' -or
      $endpoint.Port -ne 443 -or $endpoint.UserInfo -or $endpoint.Query -or $endpoint.Fragment -or $endpoint.AbsolutePath -ne '/') {
    throw 'Artifact Signing requires its regional HTTPS codesigning.azure.net endpoint.'
  }
  return [pscustomobject]@{ Endpoint=$endpoint.AbsoluteUri; CodeSigningAccountName=$metadata.CodeSigningAccountName;
    CertificateProfileName=$metadata.CertificateProfileName }
}

function Assert-ArtifactSigningInputs {
  param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string]$ProjectRoot)
  if ($Policy.Mode -ne 'artifact-signing') { return }
  $metadataPath = Assert-ProjectPath $Policy.MetadataPath $ProjectRoot
  $dlibPath = Assert-ProjectPath $Policy.DlibPath $ProjectRoot
  foreach ($path in @($metadataPath,$dlibPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Artifact Signing input not found: $path" }
  }
  if ([IO.Path]::GetFileName($dlibPath) -cne 'Azure.CodeSigning.Dlib.dll' -or [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($dlibPath)) -cne 'x64') {
    throw 'Artifact Signing requires the official x64 Azure.CodeSigning.Dlib.dll.'
  }
  $signature = Get-AuthenticodeSignature -LiteralPath $dlibPath
  if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or
      $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -cne 'Microsoft Corporation') {
    throw 'The Artifact Signing dlib must have a valid Microsoft Corporation signature.'
  }
  $metadata = Read-ArtifactSigningMetadata $metadataPath
  # Preserve validated absolute paths when packaging later changes directory
  # or the signer recurses to sign the embedded runtime helper.
  $Policy.MetadataPath=$metadataPath
  $Policy.DlibPath=$dlibPath
  return $metadata
}

function Assert-SignaturePolicy {
  param([Parameter(Mandatory)]$Signature, [string]$Path='signature', [string]$Thumbprint,
    [string]$ExpectedPublisherSubject, [switch]$TimestampRequired)
  if ($Signature.Status -ne 'Valid' -or $null -eq $Signature.SignerCertificate) { throw "Valid Authenticode signature required: $Path ($($Signature.Status))" }
  if ($Thumbprint -and $Signature.SignerCertificate.Thumbprint -ine $Thumbprint) { throw "Unexpected signing certificate: $Path" }
  if ($ExpectedPublisherSubject) {
    if ($ExpectedPublisherSubject -cne 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR' -or
        $Signature.SignerCertificate.Subject -cne $ExpectedPublisherSubject) { throw "Unexpected complete publisher subject: $Path" }
    $eku = @($Signature.SignerCertificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } |
      ForEach-Object { $_.EnhancedKeyUsages } | ForEach-Object Value)
    if ($eku -notcontains '1.3.6.1.5.5.7.3.3') { throw "Code signing EKU required: $Path" }
  }
  if ($TimestampRequired -and $null -eq $Signature.TimeStamperCertificate) { throw "Timestamp required: $Path" }
  return $Signature
}

function Assert-SignedFile {
  param([Parameter(Mandatory)][string]$Path, [string]$Thumbprint, [switch]$TimestampRequired, [string]$ExpectedPublisherSubject)
  $signature = Get-AuthenticodeSignature -LiteralPath $Path
  return Assert-SignaturePolicy $signature -Path $Path -Thumbprint $Thumbprint -ExpectedPublisherSubject $ExpectedPublisherSubject -TimestampRequired:$TimestampRequired
}

function Get-ReleaseSigningEvidence {
  param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string[]]$Files)
  if ($Policy.Mode -eq 'devtest') { return }
  $verify = Get-ReleaseVerificationParameters $Policy
  foreach ($file in @($Files | Select-Object -Unique)) {
    $signature = Assert-SignedFile $file @verify
    [pscustomobject]@{ File=$file; Subject=$signature.SignerCertificate.Subject; Thumbprint=$signature.SignerCertificate.Thumbprint;
      CertificateNotBeforeUtc=$signature.SignerCertificate.NotBefore.ToUniversalTime().ToString('o');
      CertificateNotAfterUtc=$signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('o');
      Timestamped=($null -ne $signature.TimeStamperCertificate);
      Sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
  }
}

function Get-UnsignedRuntimeSigningFiles {
  param([Parameter(Mandatory)][string]$ReleaseDirectory, [Parameter(Mandatory)][string]$ProjectRoot)
  $tunnel = Assert-ProjectPath (Join-Path $ReleaseDirectory 'tunnel.dll') $ProjectRoot
  if (-not (Test-Path -LiteralPath $tunnel -PathType Leaf)) { throw "Runtime library not found: $tunnel" }
  # Sign every unsigned redistributable PE before recording runtime hashes.
  # Valid vendor signatures (including kernel drivers) remain byte-for-byte intact.
  foreach ($file in @(Get-ReleasePeFiles $ReleaseDirectory $ProjectRoot)) {
    if ([IO.Path]::GetFileName($file) -in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')) { continue }
    $signature = Get-AuthenticodeSignature -LiteralPath $file
    if ($signature.Status -eq 'NotSigned') {
      if ([IO.Path]::GetExtension($file) -ieq '.sys') { throw "A kernel driver must already carry its vendor signature: $file" }
      $file
    } elseif ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) {
      throw "Refusing to sign an invalid existing runtime signature: $file ($($signature.Status))."
    }
  }
}

function Get-PeMachine {
  param([Parameter(Mandatory)][string]$Path)
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  $reader = [IO.BinaryReader]::new($stream)
  try {
    if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5a4d) { throw "Invalid DOS header: $Path" }
    $stream.Position=0x3c; $offset=$reader.ReadUInt32()
    if ($offset -lt 64 -or $offset -gt $stream.Length - 24) { throw "Invalid PE header offset: $Path" }
    $stream.Position=$offset
    if ($reader.ReadUInt32() -ne 0x00004550) { throw "Invalid PE signature: $Path" }
    return $reader.ReadUInt16()
  } finally { $reader.Dispose(); $stream.Dispose() }
}

function Assert-PeArchitecture {
  param([Parameter(Mandatory)][string]$Path, [ValidateSet('x64','arm64')][string]$Architecture='x64')
  $expected = if ($Architecture -eq 'arm64') { 0xaa64 } else { 0x8664 }
  $actual = Get-PeMachine $Path
  if ($actual -ne $expected) { throw ('Wrong PE architecture for {0}: expected {1}, found 0x{2:x4}' -f $Path,$Architecture,$actual) }
  return $actual
}

function Get-ReleasePeFiles {
  param([Parameter(Mandatory)][string]$ReleaseDirectory, [Parameter(Mandatory)][string]$ProjectRoot)
  foreach ($entry in @(Get-ReleaseInventory $ReleaseDirectory $ProjectRoot)) {
    $path=Assert-ProjectPath (Join-Path $ReleaseDirectory $entry.Path) $ProjectRoot
    $isPe=[IO.Path]::GetExtension($entry.Path) -in @('.exe','.dll','.sys')
    if (-not $isPe -and $entry.Length -ge 2) {
      $stream=[IO.File]::OpenRead($path)
      try { $isPe=$stream.ReadByte() -eq 0x4d -and $stream.ReadByte() -eq 0x5a }
      finally { $stream.Dispose() }
    }
    if ($isPe) { $path }
  }
}

function Assert-ReleasePeArchitecture {
  param([Parameter(Mandatory)][string]$ReleaseDirectory, [Parameter(Mandatory)][string]$ProjectRoot,
    [ValidateSet('x64','arm64')][string]$Architecture='x64')
  $files = @(Get-ReleasePeFiles $ReleaseDirectory $ProjectRoot)
  if ($files.Count -eq 0) { throw 'The release must contain PE binaries.' }
  foreach ($file in $files) { [void](Assert-PeArchitecture $file $Architecture) }
  return $files
}

function Get-ReleasePeSigningEvidence {
  param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)][string[]]$Files,
    [ValidateSet('x64','arm64')][string]$Architecture='x64')
  if ($Policy.Mode -eq 'devtest') { return }
  $verification = Get-ReleaseVerificationParameters $Policy
  foreach ($file in @($Files | Select-Object -Unique)) {
    $machine = Assert-PeArchitecture $file $Architecture
    $signature = Assert-SignedFile $file -TimestampRequired
    $isFuze = $signature.SignerCertificate.Subject -ceq 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR'
    if ($isFuze -or [IO.Path]::GetFileName($file) -in @('fuzevpn_windows.exe','fuzevpn-service.exe','fuzevpn-update.exe','fuzevpn-runtime.exe')) {
      [void](Assert-SignedFile $file @verification)
    }
    [pscustomobject]@{ File=$file; Architecture=$Architecture; Machine=('0x{0:x4}' -f $machine);
      Subject=$signature.SignerCertificate.Subject; Thumbprint=$signature.SignerCertificate.Thumbprint;
      Publisher=$(if ($isFuze) { 'FuzeVPN' } else { 'vendor' });
      Timestamped=($null -ne $signature.TimeStamperCertificate);
      Sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
  }
}

function Assert-DcoPayload {
  param([Parameter(Mandatory)][string]$ReleaseDirectory, [ValidateSet('2.8.7')][string]$Version='2.8.7',
    [ValidateSet('x64','arm64')][string]$Architecture='x64')
  foreach ($variant in @('win10','win11')) {
    $inf = Join-Path $ReleaseDirectory "openvpn-dco\$variant\ovpn-dco.inf"
    $text = [IO.File]::ReadAllText($inf)
    if ($text -notmatch ('(?im)^DriverVer\s*=\s*[^,]+,\s*' + [regex]::Escape($Version) + '\.\d+\s*$')) {
      throw "DCO $Version is required: $inf"
    }
    $platform = if ($Architecture -eq 'arm64') { 'NTARM64' } else { 'NTamd64' }
    if ($text -notmatch ('(?im)^%ovpn-dco\.CompanyName%\s*=\s*%ovpn-dco\.Name%,\s*' + $platform + '\s*$')) { throw "DCO INF architecture mismatch: $inf" }
    [void](Assert-SignedFile (Join-Path $ReleaseDirectory "openvpn-dco\$variant\ovpn-dco.cat"))
    [void](Assert-SignedFile (Join-Path $ReleaseDirectory "openvpn-dco\$variant\ovpn-dco.sys"))
  }
}

function Get-MsiInspection {
  param([Parameter(Mandatory)][string]$Path)
  $installer = New-Object -ComObject WindowsInstaller.Installer
  $database = $null
  try {
    $database = $installer.OpenDatabase($Path, 0) # MSIDBOPEN_READONLY; never execute an MSI.
    $result = [ordered]@{}
    $summary = $database.SummaryInformation(0)
    try { $result['SummaryTemplate'] = $summary.GetType().InvokeMember('Property', [Reflection.BindingFlags]::GetProperty, $null, $summary, @(7)) }
    finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($summary) }
    $availableTables = @{}
    $tableView = $database.OpenView('SELECT `Name` FROM `_Tables`')
    try {
      [void]$tableView.Execute()
      while ($null -ne ($record = $tableView.Fetch())) {
        try {
          $name = $record.GetType().InvokeMember('StringData', [Reflection.BindingFlags]::GetProperty, $null, $record, @(1))
          $availableTables[$name] = $true
        } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($record) }
      }
    } finally { [void]$tableView.Close(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($tableView) }
    foreach ($table in @('Property','Directory','File','Component','ServiceInstall','ServiceControl','InstallExecuteSequence','InstallUISequence','CustomAction','Upgrade','MsiLockPermissionsEx','Shortcut','Media','LaunchCondition','AppSearch','RegLocator','CompLocator','Signature')) {
      if (-not $availableTables.ContainsKey($table)) { $result[$table] = @(); continue }
      $view = $database.OpenView('SELECT * FROM `' + $table + '`')
      try {
        [void]$view.Execute()
        $columns = $view.ColumnInfo(0)
        $count = $columns.GetType().InvokeMember('FieldCount', [Reflection.BindingFlags]::GetProperty, $null, $columns, $null)
        $names = @(); for ($i = 1; $i -le $count; ++$i) { $names += $columns.GetType().InvokeMember('StringData', [Reflection.BindingFlags]::GetProperty, $null, $columns, @($i)) }
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($columns)
        $rows = @()
        while ($null -ne ($record = $view.Fetch())) {
          try {
            $row = [ordered]@{}
            for ($i = 1; $i -le $count; ++$i) { $row[$names[$i-1]] = $record.GetType().InvokeMember('StringData', [Reflection.BindingFlags]::GetProperty, $null, $record, @($i)) }
            $rows += [pscustomobject]$row
          } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($record) }
        }
        $result[$table] = $rows
      } finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($view) }
    }
    return [pscustomobject]$result
  } finally {
    if ($null -ne $database) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database) }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
  }
}

function Assert-MsiInspection {
  param([Parameter(Mandatory)]$Inspection, [Parameter(Mandatory)][string]$PublicVersion, [Parameter(Mandatory)][int]$FileCount,
    [ValidateSet('x64','arm64')][string]$Architecture='x64')
  $expectedTemplate = if ($Architecture -eq 'arm64') { 'Arm64' } else { 'x64' }
  if ($Inspection.SummaryTemplate.Split(';')[0] -cne $expectedTemplate) { throw 'MSI summary architecture does not match the payload.' }
  $properties = @{}; foreach ($row in $Inspection.Property) { $properties[$row.Property] = $row.Value }
  if ($properties['ProductVersion'] -ne $PublicVersion -or $properties['ALLUSERS'] -ne '1') { throw 'MSI version/scope validation failed.' }
  if ($Inspection.Upgrade.Count -lt 2 -or @($Inspection.Upgrade | Where-Object { -not [string]::IsNullOrEmpty($_.Language) }).Count -gt 0) {
    throw 'MSI upgrade and downgrade detection must also recognize the previous French-language package.'
  }
  foreach ($name in @('FUZEVPN_DOWNGRADE','FUZEVPN_WINDOWS_X64','FUZEVPN_ROLLBACK','FUZEVPN_SERVICE_NAME','FUZEVPN_SERVICE_DESCRIPTION')) {
    if ([string]::IsNullOrWhiteSpace($properties[$name])) { throw "Missing localized MSI fallback property: $name" }
  }
  if (@($Inspection.LaunchCondition | Where-Object Condition -eq 'NOT RollbackDisabled').Count -ne 1) { throw 'MSI must refuse operation when rollback is disabled.' }
  if ($Inspection.File.Count -ne $FileCount) { throw 'MSI does not contain exactly the complete Release inventory.' }
  if (@($Inspection.AppSearch | Where-Object { $_.Property -eq 'PREVIOUS_INSTALLFOLDER' -and $_.Signature_ -eq 'PreviousInstallFolder' }).Count -ne 1 -or
      @($Inspection.CompLocator | Where-Object { $_.Signature_ -eq 'PreviousInstallFolder' -and $_.ComponentId -eq '{7BFDFB64-AEB8-4957-8C31-F4B4C62EE911}' -and $_.Type -eq '1' }).Count -ne 1 -or
      @($Inspection.Signature | Where-Object { $_.Signature -eq 'PreviousInstallFolder' }).Count -ne 0 -or
      @($Inspection.RegLocator | Where-Object { $_.Key -eq 'Software\FuzeVPN\Installer' }).Count -ne 0) {
    throw 'MSI must restore the installed folder from public Windows Installer component metadata.'
  }
  if (@($Inspection.CustomAction | Where-Object { $_.Action -eq 'RestoreInstallFolder' -and $_.Source -eq 'INSTALLFOLDER' -and $_.Target -eq '[PREVIOUS_INSTALLFOLDER]' }).Count -ne 1) {
    throw 'MSI folder restoration must target INSTALLFOLDER.'
  }
  foreach ($table in @('InstallUISequence','InstallExecuteSequence')) {
    $actions = @{}; foreach ($row in $Inspection.$table) { $actions[$row.Action] = $row }
    if (-not $actions.ContainsKey('InitializeLocalization') -or -not $actions.ContainsKey('LaunchConditions') -or
        [int]$actions['InitializeLocalization'].Sequence -ge [int]$actions['LaunchConditions'].Sequence) {
      throw "MSI must select localized messages before launch conditions ($table)."
    }
    if (-not $actions.ContainsKey('AppSearch') -or -not $actions.ContainsKey('RestoreInstallFolder') -or
        -not $actions.ContainsKey('CostFinalize') -or
        [int]$actions['AppSearch'].Sequence -ge [int]$actions['RestoreInstallFolder'].Sequence -or
        [int]$actions['RestoreInstallFolder'].Sequence -ge [int]$actions['CostFinalize'].Sequence -or
        $actions['RestoreInstallFolder'].Condition -ne 'PREVIOUS_INSTALLFOLDER') {
      throw "MSI must restore the installed folder before costing ($table)."
    }
    if (-not $actions.ContainsKey('InitializeDesktopShortcut') -or
        [int]$actions['InitializeDesktopShortcut'].Sequence -ge [int]$actions['CostFinalize'].Sequence -or
        $actions['InitializeDesktopShortcut'].Condition -ne 'DESKTOP_SHORTCUT = -1') {
      throw "MSI must restore the desktop preference before costing and preserve explicit overrides ($table)."
    }
  }
  $sequence = @{}; foreach ($row in $Inspection.InstallExecuteSequence) { $sequence[$row.Action] = [int]$row.Sequence }
  foreach ($action in @('InitializeMaintenance','RollbackMaintenance','BeginMaintenance','StopServices','InstallFiles','InstallExecute','RemoveExistingProducts','CommitMaintenance','InstallFinalize')) {
    if (-not $sequence.ContainsKey($action)) { throw "Missing MSI action: $action" }
  }
  if (-not ($sequence['RollbackMaintenance'] -lt $sequence['BeginMaintenance'] -and
            $sequence['BeginMaintenance'] -lt $sequence['StopServices'] -and
            $sequence['StopServices'] -lt $sequence['InstallFiles'] -and
            $sequence['InstallFiles'] -lt $sequence['InstallExecute'] -and
            $sequence['InstallExecute'] -lt $sequence['RemoveExistingProducts'] -and
            $sequence['RemoveExistingProducts'] -lt $sequence['CommitMaintenance'] -and
            $sequence['CommitMaintenance'] -lt $sequence['InstallFinalize'])) { throw 'Unsafe MSI maintenance/upgrade sequence.' }
  foreach ($action in @('RollbackMaintenance','BeginMaintenance','CommitMaintenance')) {
    $record = @($Inspection.CustomAction | Where-Object Action -eq $action)
    if ($record.Count -ne 1 -or (([int]$record[0].Type -band 3072) -ne 3072)) { throw "MSI action must run deferred/rollback/commit without impersonation: $action" }
  }
  if (@($Inspection.ServiceInstall | Where-Object { $_.Name -eq 'FuzeVPNService' -and $_.StartType -eq '4' -and $_.Arguments -eq '--fuzevpn-vpn-service' }).Count -ne 1) { throw 'MSI service must remain disabled until maintenance commits.' }
  if (@($Inspection.Component | Where-Object { ([int]$_.Attributes -band 256) -eq 0 }).Count -ne 0) { throw 'Every component must target a 64-bit platform.' }
}

Export-ModuleMember -Function Assert-ProjectPath,ConvertTo-PublicVersion,Get-ProjectPublicVersion,Get-StableGuid,Get-ReleaseInventory,Write-ReleasePayload,New-ReleaseSigningPolicy,Get-ReleaseSigningParameters,Get-ReleaseVerificationParameters,Read-ArtifactSigningMetadata,Assert-ArtifactSigningInputs,Assert-SignaturePolicy,Assert-SignedFile,Get-ReleaseSigningEvidence,Get-UnsignedRuntimeSigningFiles,Get-PeMachine,Assert-PeArchitecture,Get-ReleasePeFiles,Assert-ReleasePeArchitecture,Get-ReleasePeSigningEvidence,Assert-DcoPayload,Get-MsiInspection,Assert-MsiInspection
