# FuzeVPN OpenSSL port

This overlay builds OpenSSL 3.6.5 from its official release archive. The port
and patches originate from Microsoft vcpkg revision
`7e43e0768a5af180a9cf75d87d692dce1b9da34f`; `LICENSE.vcpkg.txt` preserves the
recipe's MIT license. The changes are the release version and the archive
download with its pinned SHA-512. OpenSSL retains its Apache-2.0 license.

Release: <https://github.com/openssl/openssl/releases/tag/openssl-3.6.5>

Official archive SHA-256:
`a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98`

Archive SHA-512, enforced by the port:
`1243d8ef75be54d38233251a06609eef1f1f1085999bfd85d509cc298498d2820956465eed7bba094d940f08c0f7cf9c5247eca78bb978d12a3c3ea16f2afa4e`

`vcpkg-configuration.json` selects this overlay for manifest builds. When
rebuilding only this dependency in classic mode, pass `--overlay-ports` with
the parent overlay directory, and install `openssl:x64-windows`. The optional
`tools` feature installs `openssl.exe` for build-time verification; it is not
part of the application distribution. Use the pinned vcpkg revision above and
the x64 MSVC toolchain. Reinstall an older classic-mode OpenSSL package first:
classic mode otherwise keeps its previously installed version.
