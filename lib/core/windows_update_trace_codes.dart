// SPDX-License-Identifier: MPL-2.0

/// Closed references shared by update trace producers and diagnostic exports.
/// Never derive an exported reference from arbitrary failure text.
abstract final class WindowsUpdateTraceCodes {
  static const _operations = {'check', 'prepare', 'install', 'discard'};
  static const _installationModes = {'installed', 'portable', 'unavailable'};
  static const _statuses = {
    'idle': 'idle',
    'checking': 'checking',
    'available': 'available',
    'noUpdate': 'no_update',
    'downloading': 'downloading',
    'ready': 'ready',
    'installing': 'installing',
    'launched': 'launched',
    'error': 'error',
    'unsupported': 'unsupported',
    'disabledForTesting': 'disabled_for_testing',
  };

  static String operation(String name) =>
      _operations.contains(name) ? name : 'unknown';
  static String status(String name) => _statuses[name] ?? 'unknown';
  static String installationMode(String name) =>
      _installationModes.contains(name) ? name : 'unknown';

  static final values = Set<String>.unmodifiable({
    ..._operations,
    ..._installationModes,
    ..._statuses.values,
    // Older application logs used lowercased enum names for these outcomes.
    'noupdate',
    'disabledfortesting',
    'unknown',
    'already_launched',
    'operation_in_progress',
    'disposed',
    'manual_installation',
    'automatic',
    'matched',
    'changed',
    'newer',
    'not_newer',
    'no_release',
    'not_prepared',
    'supported',
    'no_callback',
    'update_application_architecture_mismatch',
    'update_application_open_failed',
    'update_application_signature_invalid',
    'update_archive_extract_failed',
    'update_archive_invalid',
    'update_archive_too_large',
    'update_archive_unsafe',
    'update_busy',
    'update_cancelled',
    'update_changed',
    'update_download_empty',
    'update_download_http_error',
    'update_download_network_error',
    'update_download_redirect_rejected',
    'update_download_timeout',
    'update_download_too_large',
    'update_download_url_invalid',
    'update_hash_mismatch',
    'update_installer_manual',
    'update_network_timeout',
    'update_package_architecture_mismatch',
    'update_package_mode_mismatch',
    'update_package_version_mismatch',
    'update_portable_manifest_invalid',
    'update_portable_manual',
    'update_portable_replace_failed',
    'update_portable_target_invalid',
    'update_prepare_failed',
    'update_publisher_mismatch',
    'update_signature_invalid',
    'update_uac_cancelled',
    'update_untrusted_publisher',
    'update_version_mismatch',
  });
}
