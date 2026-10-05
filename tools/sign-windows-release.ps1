# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param(
  [ValidateSet('x64','arm64')][string]$Architecture='x64',
  [ValidatePattern('^[A-Fa-f0-9]{40}$')]
  [string]$CertificateThumbprint,

  [string]$ArtifactSigningMetadataPath,
  [string]$ArtifactSigningDlibPath,
  [string]$ExpectedPublisherSubject,
  [ValidatePattern('^[A-Fa-f0-9]{40}$')][string]$ArtifactSigningCertificateThumbprint,
  [string]$TimestampUrl,

  [string]$ReleaseDirectory,

  [string[]]$AdditionalFiles = @(),

  [switch]$OnlyAdditionalFiles,

  # Resource embedding deliberately invalidates an earlier helper signature.
  # Callers must opt in to replacing it; other invalid input is never resigned.
  [switch]$ReplaceExistingSignature
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
$policy = New-ReleaseSigningPolicy -CertificateThumbprint $CertificateThumbprint -ArtifactSigningMetadataPath $ArtifactSigningMetadataPath -ArtifactSigningDlibPath $ArtifactSigningDlibPath -ExpectedPublisherSubject $ExpectedPublisherSubject -ArtifactSigningCertificateThumbprint $ArtifactSigningCertificateThumbprint -TimestampUrl $TimestampUrl
if ($policy.Mode -eq 'artifact-signing') { [void](Assert-ArtifactSigningInputs $policy $projectRoot) }
$verification = Get-ReleaseVerificationParameters $policy
if ([string]::IsNullOrWhiteSpace($ReleaseDirectory)) {
  $ReleaseDirectory = Join-Path $projectRoot "build\windows\$Architecture\runner\Release"
}
$ReleaseDirectory = [System.IO.Path]::GetFullPath($ReleaseDirectory)
$executables = @()
if (-not $OnlyAdditionalFiles) {
  [void](Assert-ReleasePeArchitecture $ReleaseDirectory $projectRoot $Architecture)
  $executables += @(Get-UnsignedRuntimeSigningFiles $ReleaseDirectory $projectRoot)
  $executables += @(
    (Join-Path $ReleaseDirectory 'fuzevpn_windows.exe'),
    (Join-Path $ReleaseDirectory 'fuzevpn-service.exe'),
    (Join-Path $ReleaseDirectory 'fuzevpn-update.exe')
  )
}
$executables += $AdditionalFiles
$executables = @($executables | Select-Object -Unique)
if ($executables.Count -eq 0) { throw 'No files were selected for signing.' }
$preflight = @($executables)
if (-not $OnlyAdditionalFiles) {
  if (@($AdditionalFiles | Where-Object { [IO.Path]::GetFileName($_) -ieq 'fuzevpn-runtime.exe' }).Count -ne 0) {
    throw 'The runtime helper is signed automatically after manifest embedding; do not list it in AdditionalFiles.'
  }
  $preflight += Join-Path $ReleaseDirectory 'fuzevpn-runtime.exe'
}
foreach ($executable in $preflight) {
  [void](Assert-ProjectPath $executable $projectRoot)
  if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw "Release executable not found: $executable"
  }
  if ([IO.Path]::GetExtension($executable) -in @('.exe','.dll','.sys')) { [void](Assert-PeArchitecture $executable $Architecture) }
  $existing = Get-AuthenticodeSignature -LiteralPath $executable
  if ($existing.Status -ne 'NotSigned' -and $existing.Status -ne 'Valid' -and -not $ReplaceExistingSignature) {
    throw "Refusing to sign an invalid existing signature: $executable ($($existing.Status)). Only an intentional resource replacement pipeline may use -ReplaceExistingSignature."
  }
}

$certificate = $null
$certificateInMachineStore = $false
if ($policy.Mode -eq 'local-certificate') {
  foreach ($certificateStore in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
    $certificate = Get-ChildItem -Path $certificateStore |
      Where-Object { $_.Thumbprint -eq $CertificateThumbprint.ToUpperInvariant() -and $_.HasPrivateKey } |
      Select-Object -First 1
    if ($null -ne $certificate) {
      $certificateInMachineStore = $certificateStore -eq 'Cert:\LocalMachine\My'
      break
    }
  }
  if ($null -eq $certificate) {
    throw 'The requested code-signing certificate was not found in the Windows certificate store.'
  }
  if (-not $certificate.HasPrivateKey) {
    throw 'The code-signing certificate does not expose its private key.'
  }
  $codeSigningOid = '1.3.6.1.5.5.7.3.3'
  if (-not ($certificate.EnhancedKeyUsageList.ObjectId.Value -contains $codeSigningOid)) {
    throw 'The selected certificate is not valid for code signing.'
  }
}

$kitsRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$signTool = Get-ChildItem -LiteralPath $kitsRoot -Filter signtool.exe -Recurse |
  Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
  Sort-Object FullName -Descending |
  Select-Object -First 1
if ($null -eq $signTool) {
  throw 'signtool.exe x64 was not found. Install the Windows SDK signing tools.'
}

$signedFiles = foreach ($executable in $executables) {
  # A valid signature by the selected publisher already satisfies this release.
  # Keeping it avoids needless service calls and preserves final runtime bytes.
  $existing = Get-AuthenticodeSignature -LiteralPath $executable
  if ($existing.Status -eq 'Valid' -and -not $ReplaceExistingSignature) {
    [void](Assert-SignedFile $executable @verification)
    [pscustomobject]@{ File=$executable; Subject=$existing.SignerCertificate.Subject;
      Thumbprint=$existing.SignerCertificate.Thumbprint;
      Sha256=(Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash; Timestamped=$true }
    continue
  }
  $signArguments = @('sign')
  if ($policy.Mode -eq 'local-certificate') {
    $signArguments += @('/s', 'My')
    if ($certificateInMachineStore) { $signArguments += '/sm' }
    $signArguments += @('/sha1', $certificate.Thumbprint)
  } else {
    $signArguments += @('/dlib', $policy.DlibPath, '/dmdf', $policy.MetadataPath)
  }
  $signArguments += @('/fd', 'SHA256', '/td', 'SHA256', '/tr', $policy.TimestampUrl, '/d', 'FuzeVPN', $executable)
  & $signTool.FullName @signArguments
  if ($LASTEXITCODE -ne 0) {
    throw "signtool sign failed for $executable with exit code $LASTEXITCODE"
  }
  & $signTool.FullName verify /pa /all /v $executable
  if ($LASTEXITCODE -ne 0) {
    throw "signtool verification failed for $executable with exit code $LASTEXITCODE"
  }

  $signature = Assert-SignedFile $executable @verification

  $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $executable
  [pscustomobject]@{
    File = $executable
    Subject = $signature.SignerCertificate.Subject
    Thumbprint = $signature.SignerCertificate.Thumbprint
    Sha256 = $hash.Hash
    Timestamped = $null -ne $signature.TimeStamperCertificate
  }
}
$signedFiles | Format-List
if (-not $OnlyAdditionalFiles) {
  # The service hash must describe its final signed bytes. Authenticate that
  # inventory by embedding it into the bootstrap and signing the bootstrap last.
  $prepare = @{ ReleaseDirectory=$ReleaseDirectory; Architecture=$Architecture }
  if ($policy.CertificateThumbprint) { $prepare['CertificateThumbprint']=$policy.CertificateThumbprint }
  if ($policy.ExpectedPublisherSubject) { $prepare['ExpectedPublisherSubject']=$policy.ExpectedPublisherSubject }
  & (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') @prepare -ReplaceExistingSignature | Out-Host
  $signing = Get-ReleaseSigningParameters $policy
  & $PSCommandPath -Architecture $Architecture -ReleaseDirectory $ReleaseDirectory @signing -OnlyAdditionalFiles -AdditionalFiles (Join-Path $ReleaseDirectory 'fuzevpn-runtime.exe') -ReplaceExistingSignature
  & (Join-Path $PSScriptRoot 'prepare-portable-runtime.ps1') @prepare -VerifyOnly | Out-Host
  [void]@(Get-ReleasePeSigningEvidence $policy @(Get-ReleasePeFiles $ReleaseDirectory $projectRoot) $Architecture)
}
