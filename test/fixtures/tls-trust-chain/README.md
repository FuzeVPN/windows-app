# Synthetic TLS issuer-callback fixture

The local server presents a synthetic leaf plus intermediate, without its root.
The client initially trusts none of these certificates. This reproduces an
issuer-missing failure where Dart's bad-certificate callback receives the
intermediate CA rather than the peer leaf.

- `root-certificate.pem` and `.der`: identical public, self-signed synthetic CA.
- `intermediate-certificate.pem` and `.der`: identical public intermediate CA.
- `server-certificate.pem`: server leaf for `api-bootstrap.invalid` and
  `api.fuzevpn.com`, signed only by the synthetic intermediate.
- `server-chain.pem`: valid leaf followed by intermediate, with no root.
- `wrong-host-chain.pem`: leaf for `other.fuzevpn.test`, followed by intermediate.
- `expired-chain.pem`: leaf expired in 2019, followed by intermediate.
- `server-private-key.pem`: deliberately public RSA key shared by these three
  synthetic server leaves. Never use this key in production.

SHA-256 checksum:
`BF531E90B8AC14DD870950A2AC59DFD98F6E93DAC470B3E44DE2A854402B2A20`.

All non-expired certificates are valid from 1 January 2020 to 1 January 2040.
Only the synthetic server key is retained; no root or intermediate private key
is stored. No live API certificate or Windows system key was used to generate
these files. Do not install these certificates into Windows stores.

The negative chains verify that recovering a platform-trusted root does not
bypass the second TLS handshake's hostname or validity checks. No fixture has
an AIA or CRL URL; all TLS test traffic stays on localhost.
