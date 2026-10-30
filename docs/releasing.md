# Build and verify signed releases

This procedure builds one EXE, one MSI and one portable ZIP for each of x64 and
ARM64 from a Windows source checkout. Compilation, signing and package
verification do not install or launch FuzeVPN or connect a VPN. Rebuilding a
released version for verification is a local operation; use a new version for
a new public publication instead of replacing existing release assets.

The public version is defined in `pubspec.yaml`. When incrementing it, update
the diagnostic fallback in `lib/core/diagnostics_controller.dart` and its
corresponding version assertions. The build scripts generate native version
resources; the package verifier requires their agreement with the public version.

Installer version strings must also satisfy the updater already shipped in
1.0.6--1.0.8. WiX 7 DTF can encode text fields as binary and return a byte count
through `VerQueryValueW`. The installer builder normalizes these resource
headers in place before signing, preserving all Burn container offsets. Build,
release verification and update manifest generation check the exact native
ProductName/version contract; .NET FileVersionInfo alone is insufficient.
The native `fuzevpn_update_bundle_probe` target uses the unchanged updater code
to check signed bundles without executing them. Run its x64 binary with bundle
path and public version for metadata checks; append SHA-256 and a signed
FuzeVPN application path for the full architecture/hash/signature/publisher
verification of an x64 installer. ARM64 metadata can be read on x64 as data.

The source is rebuildable, but the final signed files are not byte-for-byte
reproducible: a new certificate or timestamp changes their hashes. Check the
source revision, product versions, architectures, payload inventories,
timestamped publisher signatures and embedded runtime manifests.

## Prepare the checkout

Use the host prerequisites in [development](development.md): Windows x64,
PowerShell 7, Git, Visual Studio 2026 with x64 and ARM64 C++ tools and a Windows
SDK. The bootstrap obtains the pinned Flutter, Dart, native dependencies,
.NET SDK and source-built WiX tools. A release build additionally requires
authorized access to the FuzeVPN Artifact Signing account.

```powershell
git -c core.longpaths=true clone https://github.com/FuzeVPN/windows-app.git windows-app
Set-Location windows-app
git config core.longpaths true
.\tools\bootstrap-windows.ps1 -Architecture both -IncludeInstaller
```

Do not copy old application binaries or previous `build` directories into the
checkout. Downloads and native caches created by the bootstrap can be reused
on subsequent builds with `-Offline`.

Generated Flutter and installer files have LF checkout rules in `.gitattributes`.
They must retain these rules even when Windows Git uses `core.autocrlf=true`.
If applying this rule change to an existing checkout, refresh generated installer
outputs with their generator and then check them:

```powershell
.\installer\l10n\generate.ps1
.\installer\l10n\generate.ps1 -Check
```

Run the Flutter analysis, translation check and tests in the isolated profile
described in [development](development.md). Use a separate shell for those
tests so their temporary `LOCALAPPDATA` setting does not affect Azure
authentication during signing.

## Configure Artifact Signing

Keep private configuration outside Git. Place the metadata JSON and the
official Microsoft Artifact Signing client SDK under the ignored directory
`.toolchain/artifact-signing/` in this checkout. The signing scripts require
their input files to remain within the project. The SDK's x64
`Azure.CodeSigning.Dlib.dll` must have a valid Microsoft signature.

The metadata contains `Endpoint`, `CodeSigningAccountName` and
`CertificateProfileName`. Its credential selection must match the authorized
authentication method. The private FuzeVPN configuration uses
`AzurePowerShellCredential`; make its saved `Az.Accounts` module available on
`PSModulePath` and connect the authorized account if required. Private signing
keys remain in Azure and are not part of the source checkout.

Set these variables in the release shell, adapting the SDK directory to the
version in the private signing bundle:

```powershell
$projectRoot = (Get-Location).Path
$sign = @{
  ArtifactSigningMetadataPath = Join-Path $projectRoot '.toolchain/artifact-signing/metadata.json'
  ArtifactSigningDlibPath = Join-Path $projectRoot '.toolchain/artifact-signing/Microsoft.ArtifactSigning.Client.1.0.128/bin/x64/Azure.CodeSigning.Dlib.dll'
  ExpectedPublisherSubject = 'CN=FuzeVPN, O=FuzeVPN, L=Valenciennes, S=Nord, C=FR'
  TimestampUrl = 'http://timestamp.acs.microsoft.com'
}
$dependencyPins = Get-Content (Join-Path $projectRoot 'tools/dependency-pins.json') -Raw | ConvertFrom-Json
$env:DOTNET_ROOT = Join-Path $projectRoot ('.toolchain/dotnet-sdk-' + $dependencyPins.dotnet.version)
$env:DOTNET_ROOT_X64 = $env:DOTNET_ROOT
Import-Module .\installer\InstallerTools.psm1 -Force
$version = Get-ProjectPublicVersion $projectRoot
```

`pwsh.exe` must be available on `PATH` for the Azure PowerShell credential
provider. Verify authentication without printing a token:

```powershell
Import-Module Az.Accounts
$signingToken = Get-AzAccessToken -ResourceUrl 'https://codesigning.azure.net'
$signingToken.ExpiresOn
```

## Compile production binaries and record their baseline

Build architectures sequentially because they share Flutter-generated assets.
Production uses the build script without `-DevTest`; its
`FUZEVPN_ALLOW_PORTABLE_DEV` cache value must be `OFF`.

Each successful build also writes `build/windows/<arch>/build-provenance.json`
outside the distributable payload. Packaging requires this receipt and the
neutral compiled policy resource in all four application executables. Changing
the CMake cache without rebuilding cannot qualify retained development binaries
for production. Signing preserves the compiled receipt, verifies unchanged
executable sections and asset hashes, then records the final signed bytes.
The portable package keeps its own receipt beside its staging folder.

Capture the unsigned inventory before packaging. The final verifier uses it
to prove that AOT and data assets have not been substituted during signing:

```powershell
foreach ($arch in @('x64', 'arm64')) {
  .\tools\build-windows-multiarch.ps1 -Architecture $arch -Offline
  $release = Join-Path $projectRoot "build/windows/$arch/runner/Release"
  $baseline = Join-Path $projectRoot "build/release-$version/signing/unsigned-baseline-$arch"
  if (Test-Path -LiteralPath $baseline) { throw 'Use a new baseline directory.' }
  New-Item -ItemType Directory -Path $baseline | Out-Null
  @(Get-ReleaseInventory $release $projectRoot) | ConvertTo-Json -Depth 8 |
    Set-Content (Join-Path $baseline 'release-inventory.json') -Encoding utf8
  $pe = @(Get-ReleasePeFiles $release $projectRoot | ForEach-Object {
    $signature = Get-AuthenticodeSignature -LiteralPath $_
    [pscustomobject]@{
      File = $_
      Status = $signature.Status.ToString()
      Subject = $(if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { '' })
      Sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  })
  $pe | ConvertTo-Json -Depth 8 |
    Set-Content (Join-Path $baseline 'pe-inventory.json') -Encoding utf8
}
```

## Sign and rebuild WiX extensions

The bootstrap compiles WiX's native assets for both architectures. Sign the
bootstrapper executables and extension DLLs before rebuilding the extension
libraries that embed them:

```powershell
foreach ($arch in @('x64', 'arm64')) {
  $wixBuild = Join-Path $projectRoot '.toolchain/wix-source/build'
  $native = @(
    (Join-Path $wixBuild "Bal.wixext/Release/$arch/wixstdba.exe"),
    (Join-Path $wixBuild "Bal.wixext/Release/$arch/wixprqba.exe"),
    (Join-Path $wixBuild "Bal.wixext/Release/$arch/wixiuiba.exe"),
    (Join-Path $wixBuild "Util.wixext/Release/$arch/utilbe.dll")
  )
  .\tools\sign-windows-release.ps1 @sign -Architecture $arch -AdditionalFiles $native -OnlyAdditionalFiles
}
.\installer\build-wix-architectures.ps1 -Phase SignedExtensions
.\installer\build-wix-architectures.ps1 -Phase SourceArchive
```

The new extension DLLs and matching source archive are in
`build/release-<version>/wix/`. Use those extensions rather than the unsigned
bootstrap outputs. Keep the existing vendor signatures on the original
WireGuard, driver and Microsoft runtime binaries.

## Package all six artifacts

```powershell
foreach ($arch in @('x64', 'arm64')) {
  $release = Join-Path $projectRoot "build/windows/$arch/runner/Release"
  $wixOutput = Join-Path $projectRoot "build/release-$version/wix"
  $installer = $sign.Clone()
  $installer.Architecture = $arch
  $installer.ReleaseDirectory = $release
  $installer.WixPath = Join-Path $projectRoot '.toolchain/wix-source/build/wix/Release/publish/wix/wix.dll'
  $installer.BalExtensionPath = Join-Path $wixOutput "Bal/$arch/netstandard2.0/WixToolset.BootstrapperApplications.wixext.dll"
  $installer.UtilExtensionPath = Join-Path $wixOutput "Util/$arch/netstandard2.0/WixToolset.Util.wixext.dll"
  $installer.WixSourceArchive = Join-Path $wixOutput 'wix-source-7.0.0-fuze-x64-arm64.zip'
  $installer.DotNetPath = Join-Path $env:DOTNET_ROOT 'dotnet.exe'
  .\tools\build-windows-installer.ps1 @installer
  .\tools\build-windows-portable.ps1 @sign -Architecture $arch -ReleaseDirectory $release `
    -SourceBuildCache (Join-Path $projectRoot "build/windows/$arch/CMakeCache.txt")
}
```

Packaging signs the application and helper payloads and verifies their embedded
runtime inventories. The installer script also runs the host installer tests.
Outputs are in `dist/production/installer/<version>/<arch>/` and
`dist/production/portable/<version>/<arch>/`. Existing output directories are
not overwritten.

## Verify before publication

```powershell
foreach ($arch in @('x64', 'arm64')) {
  .\tools\verify-windows-release.ps1 -Version $version -Architecture $arch
}
```

Both `build/release-<version>/deep-verification/<arch>/verification.json`
reports must say `PASS`. The verifier checks PE and AOT architectures, versions,
signed runtime manifests, timestamped signatures, vendor preservation and
the bytes extracted from each EXE, MSI and ZIP. It reads installer data without
executing installation or custom actions. ARM64 execution on real hardware
requires separate qualification.

Generate checksums only after signing and verification. Provide all six
packages, checksum files, `WiX-corresponding-source.zip`, `WiX-MS-RL.txt` and
third-party notices as described in [distribution](distribution.md).
Do not add intermediate or leftover files from older Flutter builds: the
current Windows native-assets manifest is packaged as
`data/flutter_assets/NativeAssetsManifest.json`.

GitHub release publication and updating the live update API are separate
operations. `tools/new-windows-update-manifest.ps1` creates metadata from a
verified installer or portable package report; each architecture and package
kind needs its own matching URL and SHA-256.
