# OpenVPN DCO for Windows runtime notice

FuzeVPN packages the original vendor-signed OpenVPN Data Channel Offload
driver 2.8.13 for Windows 10 and Windows 11, on AMD64 and ARM64.
The driver is staged by FuzeVPN; the OpenVPN desktop client is not included.

Source: https://github.com/OpenVPN/ovpn-dco-win
Release: 2.8.13, published 2026-10-07
Source commit: 62a5db13f93a4b38ac193ee9cdfde1dbe2ab2b03
Source archive: source-2.8.13.zip
Architectures: amd64 (PE 0x8664), arm64 (PE 0xAA64)
Variants: win10, win11
Driver/catalog publisher: Microsoft Windows Hardware Compatibility Publisher

Release 2.8.13 fixes CVE-2026-105390, a locking flaw allowing a local user with
access to the driver's device to deadlock the host. All earlier releases are
affected. It also retains the CVE-2026-82325 fix introduced in 2.8.7.
Security advisory: https://community.openvpn.net/Security%20Announcements/CVE-2026-105390
Release notes: https://github.com/OpenVPN/ovpn-dco-win/releases/tag/2.8.13

The AMD64 and ARM64 ZIP SHA-256 digests were verified against the official
GitHub release asset metadata. See download-provenance.json. The source ZIP
comes from the official commit archive; its locally computed SHA-256 is
recorded in source-provenance.json.

The SYS and CAT retain their original Microsoft kernel signatures. Each SYS
and INF was verified against its corresponding signed CAT using the Windows
SDK SignTool kernel policy. Vendor binaries must not be re-signed with the
FuzeVPN user-mode certificate. See vendor-signature-provenance.json.

The original MIT license from the source archive's COPYRIGHT.MIT is retained
in LICENSE.txt.
