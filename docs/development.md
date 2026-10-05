# Development

## Prerequisites

Use an x64 Windows 10 or 11 build host with PowerShell, Git and Visual Studio 2026 (version 18)
with the C++ desktop workload and a Windows SDK. Install x64 C++ build tools
for x64 builds and ARM64 C++ build tools for ARM64 builds. The pinned SDK is
Flutter 3.44.9 with Dart 3.12.2. WiX source builds additionally use .NET 9.
ARM64 packages are cross-compiled on the x64 host; the public build scripts do
not support an ARM64 host.

The dependency versions and integrity pins are recorded in
`tools/dependency-pins.json`, `pubspec.yaml`, `pubspec.lock` and the vendored
OpenVPN build definitions. Bootstrap uses official upstream sources and checks
their pinned identities. It does not require a FuzeVPN account, signing secrets
or a VPN connection.

## Prepare and build

Run from the repository root:

```powershell
.\tools\bootstrap-windows.ps1 -Architecture x64
.\tools\build-windows-multiarch.ps1 -Architecture x64 -DevTest
.\tools\build-windows-portable.ps1 -Architecture x64 -DevTest
```

The last command stages a complete unsigned development portable package under
`dist/devtest/portable/`. Run the frontend from that complete staged folder;
the packaging step supplies the explicit development runtime metadata and
portable marker. Building the raw Release directory alone does not supply them.

For ARM64, replace `x64` with `arm64`. To prepare both dependency sets in one
run, use `-Architecture both` with the bootstrap. Add `-IncludeInstaller` to
prepare WiX source-build dependencies when an installer build is needed.

`-DevTest` creates a local unsigned development build with explicit development
policy. Without this flag the build retains production policy, but building
alone does not sign the output. Production-policy files need the release
signing and packaging steps before distribution or normal production use.
Do not use development packages as replacements for signed public releases.

Bootstrap and build support `-Offline` once all required dependencies have been
prepared locally. Missing dependencies cause an error; offline mode does not
silently substitute versions. Local caches belong under `.toolchain/` and the
OpenVPN `vcpkg_installed/` tree. Generated output belongs under `build/` and
`dist/`; none of those directories belongs in a source commit.

## Flutter checks

Use the pinned Flutter SDK on `PATH`. On a workstation, isolate the test profile
so diagnostic files and temporary test data cannot mix with normal app data:

```powershell
$testProfile = Join-Path $PWD 'build/test-runtime'
$testTemp = Join-Path $testProfile 'temp'
New-Item -ItemType Directory -Force $testTemp | Out-Null
$env:LOCALAPPDATA = $testProfile
$env:TEMP = $testTemp
$env:TMP = $testTemp
$env:CI = 'true'
$env:FLUTTER_SUPPRESS_ANALYTICS = 'true'
$env:DART_SUPPRESS_ANALYTICS = 'true'
flutter pub get
flutter analyze --no-pub
dart run tool/l10n/generate_catalogs.dart --check
flutter test --no-pub
```

Use a dedicated PowerShell session for these commands, then close it to restore
your normal environment. Flutter tests use mocks or synthetic fixtures; they
do not need production credentials or a live VPN service.

## Native checks and CI

The Windows CMake projects define C++ tests for native parsers, networking
policies, service boundaries and update validation. Use the build scripts for
the selected architecture and run the relevant test targets after native
changes. State the tested architecture when submitting a change.

The public CI workflow pins `actions/checkout` by full commit SHA and checks
out Flutter 3.44.9 by its verified upstream commit. It runs analysis, translation
checks and Flutter tests with a read-only repository token. It does not sign,
publish or install packages, change Windows services, or connect a VPN.

Public source builds do not include a production signing key. Read
[distribution](distribution.md) before creating packages for other users.

## Historical WiX build dependency

The corresponding WiX 7.0.0 source archive retains its original SourceLink
8.0.0 dependency. NuGet reports advisory
[GHSA-23fw-v26w-5fgq](https://github.com/dotnet/sourcelink/security/advisories/GHSA-23fw-v26w-5fgq)
for `Microsoft.Build.Tasks.Git 8.0.0`. The pinned .NET 9.0.318 SDK is patched,
but the explicitly referenced historical NuGet package still raises the warning.
This dependency generates build metadata; it is not a VPN runtime component.
Public CI does not build WiX. Keep credentials out of Git remote URLs and build
inputs. The 1.0.6 signed packages and their corresponding-source archives are
published unchanged; any tooling update must be validated separately.
