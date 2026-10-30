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

For ARM64, replace `x64` with `arm64` in the build commands and bootstrap with
`-Architecture both`: Flutter's configuration pass targets the x64 host, so an
ARM64 build also needs the x64 native dependencies. Add `-IncludeInstaller` to
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

### Browser sign-in checks

The focused browser suite uses real local loopback sockets and synthetic
account, storage and window bridges. It covers callback validation, PKCE,
replay, cancellation, timeouts, logout races, the token request contract and
the account dialog in both themes and compact layouts:

```powershell
flutter test --no-pub test/browser_auth_test.dart test/browser_sign_in_api_test.dart test/browser_sign_in_controller_test.dart test/browser_sign_in_ui_test.dart test/browser_diagnostic_contract_test.dart
```

Source and widget tests do not prove that the hosted sign-in page is deployed.
An end-to-end check also needs the Web `/desktop/connect` page and the API
desktop authorization routes enabled together. Use an isolated local API,
disposable accounts and the actual Web consent flow. Confirm that the app
receives its own session, the Web session still works, a reused code is denied,
and cancellation returns to the form. Never put production tokens or browser
authorization URLs in test fixtures. The Windows repository does not deploy
the API or Web application.

## Native checks and CI

The Windows CMake projects define isolated C++ tests for native parsers,
networking policies, service boundaries and update validation. Build the
`fuzevpn_native_tests` aggregate before CTest, including when reusing a previous
build directory. Each `fuzevpn_add_native_test` declaration registers the test
and adds its executable to the aggregate. Configuration rejects a raw native
CTest registration that would escape this build dependency. Manual administrator
and startup probes are kept outside this aggregate.
Host-side PowerShell contracts use `fuzevpn_add_native_script_test`; they are
interpreted by CTest without building a product executable. The x64 registry
includes release-audit and build-provenance checks using synthetic fixtures.

After preparing the pinned dependencies, run a complete development build and
the checks for both architectures:

```powershell
.\tools\rebuild-from-zero.ps1 -Architecture both -DevTest -Offline -SkipBootstrap
```

This compiles every registered native test for both architectures and executes
the x64 tests. ARM64 tests must execute separately on an ARM64 Windows machine.
`-SkipTests` skips both Flutter tests and native test compilation/execution.
State the tested architecture when submitting a change.

For focused native checks after a development application build:

```powershell
Import-Module .\tools\BuildSupport.psm1 -Force
$tools = Get-FuzeVisualStudioTools -Architecture x64
Invoke-FuzeChecked $tools.CMake @('--build','build/windows/x64','--config','Release','--target','fuzevpn_native_tests','--parallel','6')
Invoke-FuzeChecked $tools.CTest @('--test-dir','build/windows/x64','-C','Release','--output-on-failure','--no-tests=error')
.\tools\tests\native-test-registry-test.ps1
.\tools\tests\bootstrap-tools-test.ps1
.\tools\tests\portable-packaging-test.ps1
.\tools\tests\dco-dependency-test.ps1
.\tools\tests\openvpn-licensing-test.ps1
```

The registry regression builds a fresh synthetic project, executes its registered
fixtures, proves that manual probes stay excluded, and rejects an orphan CTest
registration. These checks do not install a package, driver or Windows service.
The OpenVPN licensing check also exercises the real notice/archive generation
with isolated fixtures after the x64 native dependencies have been bootstrapped.

The public CI workflow pins `actions/checkout` and `actions/cache` by full commit
SHA and checks out Flutter 3.44.9 by its verified upstream commit. It runs
analysis, translation checks and Flutter tests with a read-only repository
token. Separate x64 and ARM64 jobs bootstrap pinned public dependencies, then
build development-policy application binaries and the complete native test
aggregate offline on the `windows-2025-vs2026` image with Visual Studio 2026
and ARM64 C++ tools. The x64 job executes native tests, isolated installer policy
tests and the PowerShell contracts above. ARM64 is a compilation check, not
hardware qualification. The dependency cache holds public downloads, vcpkg
binaries keyed by ABI and the Dart package cache; it excludes signing material
and previously built application binaries. CI does not sign, publish or install
packages, change Windows services, or connect a VPN. The signed publication
manifest tests still require independently prepared signed release fixtures and
are not part of this credential-free CI.

Public source builds do not include a production signing key. Read
[distribution](distribution.md) before creating packages for other users.

## Historical WiX build dependency

The corresponding WiX 7.0.0 source archive retains its original SourceLink
8.0.0 dependency. NuGet reports advisory
[GHSA-23fw-v26w-5fgq](https://github.com/dotnet/sourcelink/security/advisories/GHSA-23fw-v26w-5fgq)
for `Microsoft.Build.Tasks.Git 8.0.0`. The pinned .NET 9.0.319 SDK is patched,
but the explicitly referenced historical NuGet package still raises the warning.
This dependency generates build metadata; it is not a VPN runtime component.
Public CI does not build WiX. Keep credentials out of Git remote URLs and build
inputs. The 1.0.6 signed packages and their corresponding-source archives are
published unchanged; any tooling update must be validated separately.
