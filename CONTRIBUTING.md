# Contributing

Start with [README.md](README.md) and [the development guide](docs/development.md).
Use a fork and a focused pull request against the default branch. Describe the
user-visible problem, the change and the checks you ran. Use synthetic fixtures
for account, device, tunnel and API tests.

For source changes, run:

```powershell
flutter pub get
flutter analyze --no-pub
dart run tool/l10n/generate_catalogs.dart --check
flutter test --no-pub
```

Redirect the test profile as described in the development guide before testing
on a workstation. For native changes, also run the relevant C++ tests and state
which Windows architecture you tested. CI checks Dart analysis, catalogs and
Flutter tests; it does not sign packages or establish a live VPN connection.

Keep existing third-party notices and generated-file conventions. Update JSON
translation catalogs before regenerating Dart constants. If a contribution
imports new third-party code, include its origin, version and compatible licence.
Do not change dependency pins without explaining and testing the update.

By contributing your original code, you make it available under MPL-2.0.
Changes to third-party files remain subject to their existing licences.
Do not submit credentials, account exports, real tunnel configurations,
production certificates, user logs or private API responses. The certificate
and private key in `test/fixtures/api-bootstrap/` are public, synthetic TLS test
fixtures; they must never be used for production.

Report security vulnerabilities privately through the process in
[SECURITY.md](SECURITY.md), rather than including exploit details in a public issue.
