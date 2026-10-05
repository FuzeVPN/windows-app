# FuzeVPN for Windows

[Français](README.fr.md) · [Releases](https://github.com/FuzeVPN/windows-app/releases) · [Website](https://fuzevpn.com)

FuzeVPN is a Windows VPN client built with Flutter and native C++. It supports
Windows 10 and 11 on x64 and ARM64, with WireGuard and OpenVPN, installed and
portable versions, and an interface translated into 30 languages. Connecting
to the FuzeVPN service requires a FuzeVPN account and an eligible subscription.
Publishing this client does not include the service backend.

The Windows packages include the VPN engines and required drivers. The interface
runs as a regular user; privileged network operations use a separate Windows
service or an elevated portable helper. Features include network protection,
automatic reconnection, server selection, device management and optional
diagnostic reports.

## Downloads

Use the [GitHub Releases page](https://github.com/FuzeVPN/windows-app/releases)
for signed packages. Each release provides x64 and ARM64 installers (`.exe` and
`.msi`) and portable ZIP archives. Choose the architecture of your Windows
installation. Keep the portable folder intact, including its notices, licences
and driver files. Verify downloads against the checksums provided with the release.

Version 1.0.6 is the initial public source snapshot. Its signed packages are
published unchanged. Their corresponding third-party sources and licences
remain included or are provided as companion release assets. ARM64 packages
have been compiled and checked for architecture and signatures; this snapshot
does not claim validation on a physical ARM64 device.

## Development

Flutter 3.44.9 and Dart 3.12.2 are the pinned SDK versions. On an x64 Windows build host, install
Git and Visual Studio 2026 with C++ tools and a Windows SDK. Add the ARM64 C++
tools for ARM64 builds. WiX installer builds additionally require .NET 9.
The build scripts cross-compile ARM64 packages from the x64 host.

```powershell
.\tools\bootstrap-windows.ps1 -Architecture x64
.\tools\build-windows-multiarch.ps1 -Architecture x64 -DevTest
```

The bootstrap downloads pinned public dependencies and verifies them. A local
development build does not require a production signing certificate. See
[development](docs/development.md) for both architectures, offline reuse and
test commands, and [distribution](docs/distribution.md) for package policies.

## Documentation

| Guide | Contents |
| --- | --- |
| [Architecture](docs/architecture.md) | Flutter, native processes, storage and network protection |
| [Development](docs/development.md) | Prerequisites, bootstrap, builds and tests |
| [Distribution](docs/distribution.md) | Installed and portable packages, signatures and updates |
| [Diagnostics](docs/diagnostics.md) | Local traces, consent and safe bug reports |
| [Localization](docs/localization.md) | Catalogs, generation and translation checks |
| [Licensing](LICENSING.md) | MPL-2.0 scope, third-party licences and trademarks |

Contributions are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) first.
Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Licence

FuzeVPN-authored source code is available under the
[Mozilla Public License 2.0](LICENSE). Third-party source, Flutter-derived
templates, fonts and runtime binaries retain their respective licences; see
[LICENSING.md](LICENSING.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
In particular, the original WireGuardNT prebuilt DLL is distributed under its
vendor's Prebuilt Binaries License and is not relicensed under MPL-2.0.

The FuzeVPN name and logos are trademarks. The source licence does not grant
trademark rights or imply endorsement of modified builds.
