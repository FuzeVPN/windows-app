$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
Import-Module (Join-Path $projectRoot 'installer\InstallerTools.psm1') -Force
$checks = 0
function Check([bool]$Condition, [string]$Message) {
  if (-not $Condition) { throw $Message }
  $script:checks++
}
function Reject([scriptblock]$Action, [string]$Message) {
  $rejected = $false
  try { & $Action | Out-Null } catch { $rejected = $true }
  Check $rejected $Message
}
$publisher = 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR'
$local = New-ReleaseSigningPolicy -CertificateThumbprint ('a' * 40)
Check ($local.Mode -eq 'local-certificate' -and $local.CertificateThumbprint -eq ('a' * 40)) 'Local certificate identity must remain pinned.'
Check ($local.TimestampUrl -eq 'http://timestamp.digicert.com') 'The legacy local timestamp default must remain unchanged.'
Reject { New-ReleaseSigningPolicy } 'An unconfigured production signer must fail closed.'
Reject { New-ReleaseSigningPolicy -CertificateThumbprint 'bad' } 'Malformed local thumbprint must be rejected.'
Reject { New-ReleaseSigningPolicy -DevTest -CertificateThumbprint ('a' * 40) } 'DevTest must never accept a production certificate.'
$cloudArguments = @{ ArtifactSigningMetadataPath='metadata.json'; ArtifactSigningDlibPath='bin/x64/Azure.CodeSigning.Dlib.dll'; ExpectedPublisherSubject=$publisher }
$cloud = New-ReleaseSigningPolicy @cloudArguments
Check ($cloud.Mode -eq 'artifact-signing' -and -not $cloud.CertificateThumbprint) 'Cloud signing must not assume a permanent certificate thumbprint.'
Check ($cloud.TimestampUrl -eq 'http://timestamp.acs.microsoft.com') 'Cloud signing must default to the Microsoft RFC3161 timestamp service.'
Reject { New-ReleaseSigningPolicy @cloudArguments -CertificateThumbprint ('a' * 40) } 'Local and cloud credential paths must be mutually exclusive.'
Reject { New-ReleaseSigningPolicy @cloudArguments -DevTest } 'DevTest must never accept a cloud configuration.'
Reject { New-ReleaseSigningPolicy -ArtifactSigningMetadataPath 'metadata.json' -ExpectedPublisherSubject $publisher } 'Missing dlib must not select cloud signing.'
Reject { New-ReleaseSigningPolicy -ArtifactSigningMetadataPath 'metadata.json' -ArtifactSigningDlibPath 'dlib.dll' -ExpectedPublisherSubject 'CN=FuzeVPN' } 'A common name alone must never authorize a publisher.'
Reject { New-ReleaseSigningPolicy -ArtifactSigningMetadataPath 'metadata.json' -ArtifactSigningDlibPath 'dlib.dll' -ExpectedPublisherSubject 'CN=Other, O=Other, L=Valenciennes, S=Nord, C=FR' } 'A different identity must be refused before signing.'
Reject { New-ReleaseSigningPolicy @cloudArguments -ArtifactSigningCertificateThumbprint 'bad' } 'An optional cloud leaf pin must be a complete thumbprint.'
$cloudPinned = New-ReleaseSigningPolicy @cloudArguments -ArtifactSigningCertificateThumbprint ('b' * 40)
$cloudSign = Get-ReleaseSigningParameters $cloud
$cloudVerify = Get-ReleaseVerificationParameters $cloud
Check ($cloudSign.ExpectedPublisherSubject -ceq $publisher -and $cloudSign.ArtifactSigningMetadataPath -eq 'metadata.json') 'Cloud forwarding must carry the complete publisher and metadata.'
Check (-not $cloudSign.ContainsKey('CertificateThumbprint')) 'Cloud forwarding must not accidentally select the Windows certificate store.'
Check ($cloudVerify.TimestampRequired -and $cloudVerify.ExpectedPublisherSubject -ceq $publisher -and -not $cloudVerify.ContainsKey('Thumbprint')) 'Cloud verification must require publisher plus timestamp while allowing leaf rotation.'
$cloudPinnedVerify = Get-ReleaseVerificationParameters $cloudPinned
Check ($cloudPinnedVerify.Thumbprint -eq ('b' * 40)) 'An explicitly configured cloud leaf pin must remain enforced.'
Reject { New-ReleaseSigningPolicy @cloudArguments -TimestampUrl 'file:///tmp/timestamp' } 'Timestamp URLs must not permit non-network schemes.'

function New-FixtureSignature([string]$Thumbprint, [string]$Subject=$publisher, [string]$Eku='1.3.6.1.5.5.7.3.3') {
  [pscustomobject]@{
    Status='Valid'; TimeStamperCertificate=[pscustomobject]@{ Subject='Fixture RFC3161 TSA' };
    SignerCertificate=[pscustomobject]@{
      Thumbprint=$Thumbprint; Subject=$Subject; NotBefore=[datetime]'2026-10-01T00:00:00Z'; NotAfter=[datetime]'2026-10-04T00:00:00Z';
      Extensions=@([pscustomobject]@{ Oid=[pscustomobject]@{ Value='2.5.29.37' }; EnhancedKeyUsages=@([pscustomobject]@{ Value=$Eku }) })
    }
  }
}
$signature = New-FixtureSignature ('b' * 40)
[void](Assert-SignaturePolicy $signature @cloudVerify)
$checks++
$rotated = New-FixtureSignature ('c' * 40)
[void](Assert-SignaturePolicy $rotated @cloudVerify)
$checks++
Reject { Assert-SignaturePolicy $rotated @cloudPinnedVerify } 'A configured leaf pin must reject a rotated certificate.'
Reject { Assert-SignaturePolicy (New-FixtureSignature ('b' * 40) 'CN=FuzeVPN, O=Other, L=Valenciennes, S=Nord, C=FR') @cloudVerify } 'The same common name with a different organization must be rejected.'
Reject { Assert-SignaturePolicy (New-FixtureSignature ('b' * 40) $publisher '1.3.6.1.5.5.7.3.1') @cloudVerify } 'A TLS-only certificate must not be accepted as a code-signing publisher.'
$untimestamped = New-FixtureSignature ('b' * 40)
$untimestamped.TimeStamperCertificate = $null
Reject { Assert-SignaturePolicy $untimestamped @cloudVerify } 'A valid signature without an RFC3161 timestamp must be rejected.'
$tampered = New-FixtureSignature ('b' * 40)
$tampered.Status = 'HashMismatch'
Reject { Assert-SignaturePolicy $tampered @cloudVerify } 'Publisher matches must never bypass Authenticode digest validation.'
Reject { Assert-SignaturePolicy $signature -Thumbprint ('a' * 40) -TimestampRequired } 'The legacy local path must still reject a wrong thumbprint.'

$fixture = Assert-ProjectPath (Join-Path $projectRoot '.toolchain\installer-runtime\temp\artifact-signing-tests') $projectRoot
[void][IO.Directory]::CreateDirectory($fixture)
$metadataPath = Join-Path $fixture 'metadata.json'
$metadata = [ordered]@{ Endpoint='https://neu.codesigning.azure.net/'; CodeSigningAccountName='FuzeVPN'; CertificateProfileName='FuzeVPN' }
$metadata | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding utf8
$parsed = Read-ArtifactSigningMetadata $metadataPath
Check ($parsed.Endpoint -ceq 'https://neu.codesigning.azure.net/' -and $parsed.CodeSigningAccountName -ceq 'FuzeVPN') 'Valid public service metadata must round-trip without requiring credentials.'
foreach ($badEndpoint in @('http://neu.codesigning.azure.net/','https://neu.codesigning.azure.net.evil.test/','https://user:secret@neu.codesigning.azure.net/','https://neu.codesigning.azure.net/?token=secret','https://neu.codesigning.azure.net/not-the-service')) {
  $metadata.Endpoint=$badEndpoint
  $metadata | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding utf8
  Reject { Read-ArtifactSigningMetadata $metadataPath } 'Endpoint validation must reject redirection, credentials and query data.'
}
$metadata.Endpoint='https://neu.codesigning.azure.net/'
$metadata.Remove('CertificateProfileName')
$metadata | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding utf8
Reject { Read-ArtifactSigningMetadata $metadataPath } 'Signing metadata must identify a certificate profile.'

# The evidence path is exercised with public signature fixtures, never keys or
# a signing operation. Hashing still reads real fixture bytes from disk.
$firstFile = Join-Path $fixture 'first.bin'
$secondFile = Join-Path $fixture 'second.bin'
[IO.File]::WriteAllBytes($firstFile, [byte[]]@(1,2,3))
[IO.File]::WriteAllBytes($secondFile, [byte[]]@(4,5,6))
$module = Get-Module InstallerTools
& $module {
  param($First, $Second, $FirstSignature, $SecondSignature)
  $script:signatureFixtures = @{ $First=$FirstSignature; $Second=$SecondSignature }
  function script:Get-AuthenticodeSignature { param([string]$LiteralPath) return $script:signatureFixtures[$LiteralPath] }
} $firstFile $secondFile $signature $rotated
$evidence = @(Get-ReleaseSigningEvidence $cloud @($firstFile,$secondFile))
Check ($evidence.Count -eq 2 -and $evidence[0].Thumbprint -eq ('b' * 40) -and $evidence[1].Thumbprint -eq ('c' * 40)) 'Reports must record each actual certificate rather than inventing a permanent shared leaf.'
Check ($evidence[0].Timestamped -and $evidence[1].Timestamped -and $evidence[0].Subject -ceq $publisher) 'Report evidence must retain publisher and timestamp checks.'
Check ($evidence[0].Sha256 -eq (Get-FileHash -LiteralPath $firstFile -Algorithm SHA256).Hash.ToLowerInvariant()) 'Reported hashes must describe the final actual file bytes.'
Reject { Get-ReleaseSigningEvidence $cloudPinned @($firstFile,$secondFile) } 'Reporting must not bypass an explicitly configured leaf pin.'
Write-Host "Artifact Signing policy tests passed ($checks checks). No key, login, signing request or network account was used."
