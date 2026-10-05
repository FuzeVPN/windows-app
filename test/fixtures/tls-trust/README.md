# Synthetic TLS recovery fixture

This test-only server certificate is signed by a synthetic root that is absent
from the normal trusted-root store. Serving only the leaf reproduces an issuer
missing error without using any live API certificate or external network.

The leaf permits server authentication and contains `api-bootstrap.invalid` and
`api.fuzevpn.com` as synthetic DNS names. Both root and leaf are valid from
1 January 2020 to 1 January 2040. The root is a self-signed CA; the leaf is not a
CA and is not self-signed.

`server-private-key.pem` is a deliberately public RSA key created solely for
this local test server. Never use it in production. No CA private key is stored.
`root-certificate.der` and `root-certificate.pem` encode the same public root.
Tests inject this root as the result of successful platform verification, then
require a new strict TLS handshake to succeed.
