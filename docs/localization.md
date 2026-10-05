# Localization

The Flutter interface contains 30 translation catalogs, including simplified
and traditional Chinese. Catalogs are stored in `lib/l10n/catalogs/`.
`source.json` defines the message keys and the source wording; each locale
contains the same keys and preserves their placeholders.

Edit the JSON catalogs, then regenerate the committed Dart constants:

```powershell
dart run tool/l10n/generate_catalogs.dart
dart run tool/l10n/generate_catalogs.dart --check
flutter test --no-pub test/catalog_integrity_test.dart test/localization_test.dart
```

The `--check` command is read-only and fails if a catalog is incomplete, has an
unknown key, an empty translation, invalid Unicode, different placeholders, or
if the committed generated file is stale. Do not hand-edit
`lib/l10n/generated_catalogs.dart`.

Preserve tokens such as `{version}` exactly. Use wording appropriate to the
actual action and state. Check long translations at narrow window sizes and
large text scales, and check right-to-left layout when relevant. Installer
localization has separate sources under `installer/l10n/`; changes to the
Flutter catalogs do not update installer text automatically.

Translation contributions follow the licensing and review rules in
[CONTRIBUTING.md](../CONTRIBUTING.md).
