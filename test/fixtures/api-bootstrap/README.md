# Local HTTPS test identity

This self-signed certificate and matching private key are synthetic public test
fixtures, used only by `api_bootstrap_transport_test.dart` on loopback. They are
not trusted by the system, never installed, and not part of the application
bundle. The client test constructs a separate trust context containing only
this certificate. Its SAN is `api-bootstrap.invalid`; validity is 2025–2040.
