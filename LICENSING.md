# Licensing

## FuzeVPN source

The [Mozilla Public License 2.0](LICENSE) applies to the source code,
documentation, tests and build definitions authored for FuzeVPN, except for
the material listed below. FuzeVPN-authored source files may carry
`SPDX-License-Identifier: MPL-2.0`. Generated translation catalogs are covered
by the same licence even when their generator does not emit a per-file header.

MPL-covered files and changes to them must remain available under MPL-2.0 when
distributed. Files containing third-party code keep their original notices and
licence requirements. This repository's root licence does not replace them.
Read the [full licence](LICENSE) and the
[Mozilla FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/) for details.

## Third-party exceptions

| Material | Licence / location |
| --- | --- |
| OpenVPN 3 Core | The MPL-2.0 option is selected for FuzeVPN. Keep `third_party/openvpn3-core/LICENSE.md`, `LICENSES/` and source notices. The upstream alternative AGPL option is not the option selected by this distribution. |
| OpenVPN DCO for Windows | MIT; `third_party/openvpn-dco/2.8.7/LICENSE.txt` and `NOTICE.md` |
| WireGuard Windows embeddable service | MIT with Go, module and LLVM notices; `third_party/wireguard/1.1/NOTICE.md` and the accompanying licence files |
| WireGuardNT original prebuilt DLL | WireGuardNT Prebuilt Binaries License; `third_party/wireguard/1.1/LICENSE-WireGuardNT.txt`. It is not MPL-covered and must not be modified or relicensed. |
| WiX source and local modifications to WiX | Microsoft Reciprocal License (MS-RL); `installer/WiX-MS-RL.txt` and the corresponding-source archive |
| miniz | MIT; `third_party/miniz/LICENSE` |
| tray_manager, including its vendored Windows fixes | MIT; `third_party/tray_manager/LICENSE` and `FUZEVPN-PATCHES.md` |
| Archivo font | SIL Open Font License 1.1; `assets/fonts/Archivo-OFL.txt` |
| Flutter-derived Windows templates | BSD-3-Clause; `licenses/Flutter-BSD-3-Clause.txt` |
| Flutter, Dart and packages resolved by `pubspec.lock` | Their respective licences; Flutter generates the runtime `NOTICES.Z` |
| OpenSSL, Asio, fmt, LZ4, JsonCpp, xxHash and TAP headers | Their respective licences, copied by `tools/package-native-notices.cmake` into binary distributions |
| Microsoft Visual C++ runtime | Microsoft redistribution terms; not covered by MPL-2.0 |

The Flutter-derived template exception includes the Windows runner's
`flutter_window.*`, `win32_window.*`, `utils.*`, `main.cpp`, `resource.h`,
`Runner.rc`, Flutter-generated plugin registration files and template-derived
Flutter/CMake files. Preserve the BSD attribution when redistributing those
files. FuzeVPN's root licence does not remove the upstream BSD grant.

The WireGuardNT source repository uses GPLv2, while its official prebuilt DLLs
use a separate licence. FuzeVPN uses the official prebuilt binaries through the
permitted API; see the
[upstream licence explanation](https://git.zx2c4.com/wireguard-nt/about/).
Do not distribute the vendor DLL as a standalone download or present it as
MPL-licensed. Bundled redistributions must comply with its original licence.

## Binary releases and corresponding source

Keep [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), the runtime `licenses/`
directory, `openvpn-dco/` notices and Flutter's `NOTICES.Z` with each package.
OpenVPN's actual local source is included in
`licenses/OpenVPN3-corresponding-source.zip`. WireGuard Windows and DCO source
archives are included in the packages as described by their notices.

Installer releases also provide `WiX-corresponding-source.zip` and
`WiX-MS-RL.txt`. The source archive includes the WiX modifications and build
recipe. Publish both alongside the installer assets; retain the copies inside
the MSI. Source snapshots corresponding to FuzeVPN releases are available from
the repository's release tags.

The signed 1.0.6 packages are distributed unchanged with this public source
release. Their existing third-party licences continue to apply.

## Names and artwork

The FuzeVPN name, logos and branding assets are reserved to FuzeVPN. They are
not granted under the source-code licence, and MPL-2.0 grants no trademark
rights. Modified builds must not imply that they are official FuzeVPN releases.
Use your own branding when distributing a fork under a different identity.
