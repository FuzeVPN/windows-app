# Local Windows corrections

Based on tray_manager 0.5.3, copied from the previously pinned offline cache.
The original MIT license is retained in LICENSE. No new package is introduced.

- Initialize Windows notification structures before their first use.
- Check icon loading and Shell notification results; propagate failures.
- Restore a visible window and notify Dart when Explorer recovery fails.
- Preserve icon ownership across failed replacements and release menu resources.
- Add a pure notification-state helper tested with simulated Windows calls.

The root pubspec overrides this package with this directory, so clean builds do
not depend on modifications to a generated symlink or a downloaded package cache.
