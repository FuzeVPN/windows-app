# FuzeVPN Windows — third-party notices

Keep this file, the complete `licenses` directory, the `openvpn-dco` notices
and Flutter's `data/flutter_assets/NOTICES.Z` with every Windows distribution.
Individual source files retain their own copyright and license notices.

The public source repository applies MPL-2.0 to FuzeVPN-authored material only.
Third-party material retains its original licence; see `LICENSING.md` for the
source-repository scope and trademark policy. The signed 1.0.6 packages are
published unchanged with their existing notices and source archives.

| Component | Version/source | License and notice shipped |
|---|---|---|
| WireGuard Windows embeddable service | v1.1.1, f0605c3e3dcc5ff801e19158fd6255378b99e17c; AMD64/ARM64 | MIT, `licenses/WireGuard-NOTICE.md`; Go/module BSD and LLVM runtime notices included |
| WireGuardNT | 1.1, original vendor-signed AMD64/ARM64 DLLs | WireGuardNT Prebuilt Binaries License, `licenses/WireGuardNT-LICENSE.txt` and `WIREGUARD_NOTICE.md` |
| OpenVPN 3 Core | 28469efe3ae770268b2b5c6aa607ed1489e101f0, local build source | MPL-2.0 option, `licenses/OpenVPN3-MPL-2.0.txt` |
| OpenVPN DCO driver | 2.8.7, b530217a0126e89506cee69240ed5a82bcdb8d2c; AMD64/ARM64 | MIT, `openvpn-dco/NOTICE.md` and `openvpn-dco/LICENSE.txt` |
| OpenSSL | 3.6.5 | Apache-2.0, `licenses/openssl-copyright.txt` |
| Asio | 1.36.0 | Boost-1.0, `licenses/asio-copyright.txt` |
| fmt | 12.2.0#1 | MIT, `licenses/fmt-copyright.txt` |
| LZ4 | 1.10.0 | BSD-2-Clause library, `licenses/lz4-copyright.txt` |
| JsonCpp | 1.9.6 | MIT/public domain, `licenses/jsoncpp-copyright.txt` |
| xxHash | 0.8.3 | BSD-2-Clause library, `licenses/xxhash-copyright.txt` |
| TAP headers in the Core build | 9.21.2 | `licenses/tap-windows6-copyright.txt` |
| Flutter, Dart and Flutter packages | exact versions in the build lockfiles | `data/flutter_assets/NOTICES.Z` |
| Flutter-derived Windows templates | pinned Flutter source | BSD-3-Clause, `licenses/Flutter-BSD-3-Clause.txt` in the source repository |
| Archivo font | bundled variable font | SIL OFL-1.1, `assets/fonts/Archivo-OFL.txt` |
| Source-built WiX installer components | 7.0.0 with local build changes | MS-RL, `installer-licenses/WiX-MS-RL.txt` and `WiX-corresponding-source.zip`; companion release assets also supplied |
| Microsoft Visual C++ runtime | version from the selected MSVC compiler | Microsoft Visual Studio redistributable software terms |

## OpenVPN 3 source availability

This distribution uses the Mozilla Public License 2.0 option for OpenVPN 3.
The **actual local Core source used to compile this release**, including its
license notices, modifications and build recipes, is supplied at no additional
charge in `licenses/OpenVPN3-corresponding-source.zip`, beside this notice.
Extract that archive with the standard Windows ZIP tools to obtain the source.
MPL-covered source remains available under MPL-2.0; the executable distribution
does not limit the rights granted by that license.

The upstream reference is [OpenVPN/openvpn3 at the pinned revision](https://github.com/OpenVPN/openvpn3/tree/28469efe3ae770268b2b5c6aa607ed1489e101f0).
`licenses/OpenVPN3-version.txt` records the dependency pins. The archive contains
source rather than the precompiled vcpkg dependencies. Their individual license
texts are included separately above. Components used only by the build may be
listed conservatively even if their code is not linked into the executable.

## miniz

The Windows portable updater statically includes only the low-level Deflate
inflater from miniz 3.1.0 (Rich Geldreich, RAD Game Tools and Valve Software).
The MIT license is supplied in `licenses/miniz-LICENSE.txt`. The ZIP path
policy, bounds, signature checks and directory transaction belong to FuzeVPN.
Upstream source: https://github.com/richgel999/miniz/tree/3.1.0.

## WireGuard and DCO provenance

WireGuardNT is shipped under the exact prebuilt-binaries license included in
the official SDK archive. Its vendor DLLs are preserved and used through the
published WireGuard API. This license differs from the MIT license for the
WireGuard Windows embeddable service source.

The unmodified official WireGuard Windows v1.1.1 source is supplied in
`licenses/wireguard-windows-1.1.1-source.zip`. The full WireGuard, Go and LLVM
notices are retained in `WIREGUARD_NOTICE.md` and `licenses/WireGuard-NOTICE.md`.

The original OpenVPN DCO 2.8.7 source is supplied in
`openvpn-dco/source-2.8.7.zip`. Its SYS/CAT/INF files retain the original vendor
kernel-signing chain. Release 2.8.7 fixes CVE-2026-82325; see the vendor advisory
linked in `openvpn-dco/NOTICE.md`.
