# Synthetic TLS trust fixtures

These public certificates test the Windows TLS verification helper against
exclusive, in-memory root and intermediate stores. They are never installed in
the Windows certificate stores and have no connection to the live FuzeVPN API.

- `root.pem`: synthetic self-signed CA, path length 1.
- `intermediate.pem`: CA signed by the synthetic root, path length 0.
- `expired-intermediate.pem`: CA signed by the root but expired in 2019.
- `valid.pem`: server-authentication certificate for `api.fuzevpn.com`, signed
  exclusively by the synthetic test CA, not any publicly trusted authority.
- `expired.pem`: server certificate expired on 1 January 2019.
- `client-only.pem`: certificate permitting client authentication only.
- `wrong-host.pem`: valid server certificate for a different hostname.
- `self-signed-leaf.pem`: server certificate with `CA=false`, used to ensure a
  leaf can never be returned as a recovered trust anchor.

The non-expired fixtures are valid from 1 January 2020 to 1 January 2049. Tests
inject a fixed verification time of 5 October 2026, avoiding clock-dependent
results. The fixtures contain no AIA or CRL URLs, and the test chain engine uses
cache-only retrieval with AIA disabled, so the tests do not fetch certificates
over a network.

Run `generate_fixtures.py` with Python and `cryptography` to regenerate them.
Private keys are generated in memory, used to sign the certificates, and never
written to disk. Regeneration produces fresh synthetic keys and serial numbers.
No test depends on a particular serial number or fingerprint.
