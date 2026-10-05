# OpenVPN DCO for Windows runtime notice

FuzeVPN packages the original vendor-signed OpenVPN Data Channel Offload
driver 2.8.7 for Windows 10 and Windows 11, on AMD64 and ARM64.
The driver is staged by FuzeVPN; the OpenVPN desktop client is not included.

Source: https://github.com/OpenVPN/ovpn-dco-win
Release: 2.8.7
Source commit: b530217a0126e89506cee69240ed5a82bcdb8d2c
Source archive: source-2.8.7.zip
Architectures: amd64 (PE 0x8664), arm64 (PE 0xAA64)
Variants: win10, win11
Driver/catalog publisher: Microsoft Windows Hardware Compatibility Publisher

Release 2.8.7 fixes CVE-2026-82325, a use-after-free in multipeer peer table
handling affecting versions 2.5.0 through 2.8.6.
Security advisory: https://community.openvpn.net/Security%20Announcements/CVE-2026-82325

The SYS and CAT retain their original Microsoft kernel signatures.
The INF and SYS were also verified against their corresponding signed catalog.
Vendor binaries must not be re-signed with the FuzeVPN user-mode certificate.

## License

Copyright 2021 OpenVPN, Inc

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
