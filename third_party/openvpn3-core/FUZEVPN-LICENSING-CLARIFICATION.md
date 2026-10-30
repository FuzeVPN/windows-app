# Upstream OpenVPN 3 licensing clarification

The base source remains pinned to OpenVPN/openvpn3 commit
`28469efe3ae770268b2b5c6aa607ed1489e101f0`. FuzeVPN selects the MPL-2.0 option
in the upstream repository's LICENSE.md. This note preserves upstream evidence
for four OpenVPN-owned headers whose old GPLv3 notices were missed during the
repository's relicensing:

- `openvpn/crypto/tls_crypt_v2.hpp`
- `openvpn/mbedtls/util/pem.hpp`
- `openvpn/openssl/util/pem.hpp`
- `openvpn/asio/asioresolverres.hpp`

On 19 October 2026, FuzeVPN corrected only these four downstream license
metadata headers to the repository's canonical expression:
`MPL-2.0 OR AGPL-3.0-only WITH openvpn3-openssl-exception`.
All author and copyright lines and all software behavior are preserved. This
note does not relicense third-party code or change FuzeVPN's root license.

Upstream issue: https://github.com/OpenVPN/openvpn3/issues/445

On 8 October 2026, OpenVPN maintainer Frank Lichtenheld identified a missed
license-header update; Arne Schwabe confirmed that analysis. Their comments are
the authoritative clarification retained for this source snapshot:

- https://github.com/OpenVPN/openvpn3/issues/445#issuecomment-6059978285
- https://github.com/OpenVPN/openvpn3/issues/445#issuecomment-6062270333

On 16 October, the maintainer confirmed that the pending correction covers all
four headers, but said the original 3.11.8 branch could not yet be pushed:

- https://github.com/OpenVPN/openvpn3/issues/445#issuecomment-6211547173

As checked on 19 October 2026, no public upstream commit containing that header
correction was available in the reviewed master/hotfix history. This is a
downstream metadata correction based on the maintainers' explicit clarification;
it is not attributed to an unpublished upstream commit.

`fuzevpn-license-provenance/provenance.json` records the authority URLs and
before/after SHA-256 values for all four files. That directory also retains
`downstream-header-metadata.patch` and the original notices in
`original-header-notices-2026-10-19.zip` as historical evidence. The archived
notices describe the inherited metadata before correction; current source
headers use the canonical expression above.

This clarification accompanies the actual local Core source in
`licenses/OpenVPN3-corresponding-source.zip` in newly built distributions.
