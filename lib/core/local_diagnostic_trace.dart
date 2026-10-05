// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'diagnostic_log.dart';
import 'diagnostics_models.dart';
import 'windows_update_models.dart';

/// Reads the two fixed application trace files for a local diagnostic export.
/// File contents are untrusted: only the application's closed trace vocabulary
/// and bounded numbers become structured events. Paths and raw text never do.
/// The caller supplies the collection deadline; this reader never writes files.
class LocalDiagnosticTrace {
  LocalDiagnosticTrace._();

  static const maximumBytes = 256 * 1024;
  static const maximumEvents = 1024;

  static Future<Map<String, Object?>> collect({
    String? path,
    Iterable<String> currentLines = const [],
  }) async {
    final events = <Map<String, Object?>>[];
    var status = 'absent';
    var truncated = false;
    var discarded = 0;
    var remainingBytes = maximumBytes;
    final sourcePath = path ?? DiagnosticLog.filePath;

    void acceptLine(String line) {
      if (line.isEmpty) return;
      final event = _parse(line);
      if (event == null) {
        discarded++;
        status = 'rejected';
      } else {
        events.add(event);
      }
    }

    if (sourcePath != null) {
      // The newest file gets the byte budget first; a rotation can still supply
      // the previous incident when the current file is short or absent.
      for (final candidate in [sourcePath, '$sourcePath.previous']) {
        try {
          final type = await FileSystemEntity.type(
            candidate,
            followLinks: false,
          );
          if (type == FileSystemEntityType.notFound) continue;
          if (type != FileSystemEntityType.file ||
              !await _plainParents(File(candidate).absolute.parent)) {
            status = 'rejected';
            continue;
          }
          if (remainingBytes == 0) {
            truncated = true;
            continue;
          }
          final file = await File(candidate).open();
          try {
            final length = await file.length();
            final offset = math.max(0, length - remainingBytes);
            await file.setPosition(offset);
            final requestedBytes = math.min(length, remainingBytes);
            final bytes = await file.read(requestedBytes);
            remainingBytes -= bytes.length;
            truncated = truncated || offset != 0;
            // A file shrinking during collection is explicit, not silently a
            // complete observation. Never retain a partial UTF-8 sequence.
            if (bytes.length != requestedBytes) {
              truncated = true;
            }
            var text = utf8.decode(bytes);
            if (offset != 0) {
              final newline = text.indexOf('\n');
              text = newline < 0 ? '' : text.substring(newline + 1);
              discarded++;
            }
            if (status == 'absent') status = 'ok';
            for (final line in const LineSplitter().convert(text)) {
              acceptLine(line);
            }
          } finally {
            await file.close();
          }
        } on FormatException {
          status = 'rejected';
          discarded++;
        } on FileSystemException {
          if (status != 'rejected') status = 'read_failed';
        }
      }
    }

    // This queue is bounded independently of the injected iterable. Preserve
    // only its latest lines without constructing an unbounded intermediate list.
    final recent = <String>[];
    for (final line in currentLines) {
      recent.add(line);
      if (recent.length > maximumEvents) {
        recent.removeAt(0);
        truncated = true;
        discarded++;
      }
    }
    for (final line in recent) {
      acceptLine(line);
    }

    final unique = <String, Map<String, Object?>>{};
    for (final event in events) {
      unique[jsonEncode(event)] = event;
    }
    final ordered = unique.values.toList()
      ..sort((a, b) {
        final timestamp = (a['timestamp'] as String).compareTo(
          b['timestamp'] as String,
        );
        return timestamp != 0
            ? timestamp
            : jsonEncode(a).compareTo(jsonEncode(b));
      });
    if (ordered.length > maximumEvents) {
      final dropped = ordered.length - maximumEvents;
      ordered.removeRange(0, dropped);
      discarded += dropped;
      truncated = true;
    }
    return {
      'status': status,
      'truncated': truncated,
      'discarded_lines': discarded,
      'events': ordered,
    };
  }

  static Future<bool> _plainParents(Directory directory) async {
    for (var depth = 0; depth < 64; depth++) {
      if (await FileSystemEntity.type(directory.path, followLinks: false) !=
          FileSystemEntityType.directory) {
        return false;
      }
      final parent = directory.parent;
      if (parent.path == directory.path) return true;
      directory = parent;
    }
    return false;
  }

  static final _timestamp = RegExp(
    r'^20[0-9]{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$',
  );

  static Map<String, Object?>? _parse(String line) {
    if (line.length > 2048) return null;
    final parts = line.split(' ');
    if (parts.length < 3 || !_timestamp.hasMatch(parts.first)) return null;
    final values = <String, Object?>{'timestamp': parts.first};
    for (final part in parts.skip(1)) {
      final separator = part.indexOf('=');
      if (separator <= 0 || separator != part.lastIndexOf('=')) return null;
      final key = part.substring(0, separator);
      final value = part.substring(separator + 1);
      if (values.containsKey(key)) return null;
      final allowed = _identifiers[key];
      if (allowed != null) {
        if (!allowed.contains(value)) return null;
        values[key] = value;
      } else {
        final range = _numbers[key];
        if (range == null || !RegExp(r'^-?\d{1,11}$').hasMatch(value)) {
          return null;
        }
        final number = int.tryParse(value);
        if (number == null || number < range.$1 || number > range.$2) {
          return null;
        }
        values[key] = number;
      }
    }
    return sanitizeEvent(values);
  }

  /// Revalidates serialized support events, including queued reports read from
  /// disk. A schema already checked during collection is not implicitly trusted.
  static Map<String, Object?>? sanitizeEvent(Map<Object?, Object?> input) {
    final rawTimestamp = input['timestamp'];
    if (rawTimestamp is! String || !_timestamp.hasMatch(rawTimestamp)) {
      return null;
    }
    final timestamp = DateTime.tryParse(rawTimestamp);
    if (timestamp == null ||
        !timestamp.isUtc ||
        timestamp.toIso8601String().substring(0, 19) !=
            rawTimestamp.substring(0, 19)) {
      return null;
    }
    if (input['area'] == null || input['event'] == null) return null;
    for (final entry in input.entries) {
      final key = entry.key;
      final value = entry.value;
      if (key == 'timestamp') continue;
      final identifiers = _identifiers[key];
      if (identifiers != null) {
        if (value is! String || !identifiers.contains(value)) return null;
      } else {
        final range = _numbers[key];
        if (range == null ||
            value is! int ||
            value < range.$1 ||
            value > range.$2) {
          return null;
        }
      }
    }
    // Fixed insertion order deduplicates the same event even when an injected
    // file has reordered its fields.
    return {
      'timestamp': timestamp.toIso8601String(),
      for (final key in [..._identifiers.keys, ..._numbers.keys])
        if (input.containsKey(key)) key: input[key],
    };
  }

  static const _numbers = <String, (int, int)>{
    'duration_ms': (0, 86400000),
    'windows_error': (-0x80000000, 0xffffffff),
    'tls_error': (-0x80000000, 0x7fffffff),
    'trust_status': (0, 0xffffffff),
    'http_status': (100, 599),
    'request_id': (1, 0x7fffffff),
    'connection_id': (1, 0x7fffffff),
    'attempt': (1, 32),
    'count': (0, 1000000),
    'bytes': (0, 0x7fffffff),
  };

  // Inventory of literal identifiers emitted by DiagnosticLog.record,
  // AppController's phase helpers and WindowsUpdateController's phase helpers.
  // Do not replace these sets with a character-pattern check: even a
  // syntactically valid identifier can contain a credential or account name.
  static final _identifiers = <String, Set<String>>{
    'area': {
      'account',
      'api_request',
      'api_transport',
      'devices',
      'locations',
      'network',
      'openvpn',
      'runtime_state',
      'startup',
      'storage',
      'tls_trust',
      'update',
      'wireguard',
    },
    'event': {
      'manual_installation_required',
      'api_activation_received',
      'api_configuration_received',
      'api_enrollment_failed',
      'attempt_failed',
      'begin',
      'body_completed',
      'body_failed',
      'body_started',
      'cancelled',
      'certificate_renewal_failed',
      'check_succeeded',
      'completed',
      'connection_failed',
      'connection_started',
      'deferred',
      'device_enrollment_started',
      'disconnect_acknowledged',
      'disconnect_failed',
      'disconnect_started',
      'disconnect_state_recovered',
      'error',
      'failed',
      'fallback',
      'headers_completed',
      'identity_reset_completed',
      'identity_reset_failed',
      'identity_reset_started',
      'ipv6_enrollment_fallback',
      'ipv6_profile_fallback',
      'json_completed',
      'json_failed',
      'json_started',
      'local_identity_ready',
      'migration_tunnel_suspend_started',
      'migration_tunnel_suspend_succeeded',
      'native_connect_acknowledged',
      'native_connect_failed',
      'native_connect_started',
      'native_resolution_completed',
      'native_resolution_failed',
      'native_resolution_started',
      'native_state_recovered',
      'network_protection_prepare_failed',
      'network_protection_prepare_started',
      'network_protection_prepare_succeeded',
      'open_completed',
      'open_started',
      'profile_enrollment_started',
      'rejected',
      'resolution_completed',
      'resolver_cache_hit',
      'response_received',
      'send_started',
      'skipped',
      'socket_failed',
      'started',
      'tcp_completed',
      'tcp_started',
      'tls_completed',
      'tls_retry_started',
      'tls_started',
      'trusted',
      'windows_trust_completed',
      'windows_trust_failed',
      'windows_trust_rejected',
      'windows_trust_started',
      'artifact_comparison_completed',
      'artifact_comparison_started',
      'compatibility_completed',
      'compatibility_started',
      'discard_skipped',
      'distribution_completed',
      'distribution_failed',
      'distribution_started',
      'environment_architecture',
      'environment_cached',
      'environment_distribution',
      'operation_coalesced',
      'operation_completed',
      'operation_failed',
      'operation_skipped',
      'operation_started',
      'package_comparison_completed',
      'package_comparison_failed',
      'package_comparison_started',
      'package_support_completed',
      'package_support_started',
      'preinstall_skipped',
      'prepared_environment_completed',
      'prepared_environment_started',
      'saved_session_storage_unavailable',
      'saved_session_verification_pending',
      'saved_session_verification_rejected',
      'saved_session_verification_succeeded',
      'version_comparison_completed',
      'version_comparison_started',
      for (final phase in _updatePhases)
        for (final suffix in ['started', 'completed', 'failed'])
          '${phase}_$suffix',
      ..._runtimeStages,
      for (final stage in _runtimeStages) '${stage}_failed',
    },
    'stage': {
      'location_migration',
      'resolution',
      'tcp_connect',
      'system_dns_and_tcp',
      'account_authentication',
      'local_identity',
      'device_catalogue',
      'native_snapshot',
      'diagnostic_environment',
      ...diagnosticStages,
      ...WindowsUpdateFailure.diagnosticStages,
      'certificate_renewal',
      'catalogue_refresh',
      'connectivity_listener',
      'decode_response',
      'device_catalogue_refresh',
      'device_catalogue_session_storage',
      'enrollment',
      'initial_remote_data',
      'initialize',
      'native_preferences',
      'native_resolution',
      'network_check',
      'network_protection_prepare',
      'open_connection',
      'openvpn_availability',
      'preferences_auto_connect',
      'preferences_favorites',
      'preferences_language',
      'preferences_notifications',
      'preferences_protocol',
      'preferences_recent_locations',
      'preferences_security',
      'preferences_selected_location',
      'preferences_theme',
      'read_response',
      'request',
      'response_headers',
      'runtime_observation',
      'saved_session_recovery',
      'saved_session_storage',
      'send_request',
      'session_validation',
      'socket_read',
      'socket_write',
      'stored_device_binding',
      'subscription_preflight',
      'subscription_refresh',
      'tls_handshake',
      'windows_certificate_verification',
      'windows_startup_preference',
      'broker_connection',
      'broker_write',
      'broker_response',
      ..._runtimeStages,
    },
    'code': {
      ...diagnosticCodes,
      'operation_cancelled',
      ..._localUpdateCodes,
      'manual_installation',
      'ready',
      'api_resolver_invalid_response',
      'runtime_detection_failed',
      'runtime_owned_by_another_user',
      'maintenance_in_progress',
      'invalid_argument',
      'unexpected_error',
      'absent',
      'access_allowed',
      'access_denied',
      'access_unknown',
      'account',
      'already_launched',
      'arm64',
      'automatic',
      'automatic_revocation_recovery',
      'available',
      'cancelled',
      'ca_chain',
      'changed',
      'checked',
      'current_session',
      'devices',
      'device_operation',
      'diagnostic_report',
      'discarded',
      'disposed',
      'false',
      'finished',
      'initialized',
      'ipv6_unavailable',
      'locations',
      'login',
      'matched',
      'newer',
      'no_callback',
      'no_release',
      'no_saved_session',
      'no_update',
      'not_newer',
      'not_prepared',
      'observed',
      'operation_in_progress',
      'other',
      'present',
      'retained_protection',
      'revalidated',
      'runtime_not_ready',
      'runtime_verification_pending',
      'secure_defaults',
      'server_certificate',
      'session_unavailable',
      'settled',
      'subscription',
      'superseded',
      'supported',
      'true',
      'unavailable',
      'unknown',
      'unsupported',
      'update_available',
      'update_manifest',
      'verification_pending',
      'x64',
    },
    'family': {'ipv4', 'ipv6', 'system'},
    'error_kind': {
      'unexpected',
      'structured',
      'tls',
      'socket',
      'timeout',
      'http_transport',
      'native_bridge',
      'format',
      'storage',
    },
    'reason': DiagnosticLog.tlsFailureReasons,
  };

  static const _updatePhases = {
    'environment',
    'manifest',
    'discard',
    'download_prepare',
    'preinstall',
    'install_launch',
  };
  static const _localUpdateCodes = {
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
  };
  static const _runtimeStages = {
    'startup_wireguard_connected',
    'startup_openvpn_connected',
    'startup_duplicate_openvpn_disconnect',
    'startup_protection_owner',
    'startup_state_commit',
    'startup_wireguard_protection_snapshot',
    'startup_openvpn_protection_snapshot',
    'startup_wireguard_protection_fallback',
    'startup_openvpn_protection_fallback',
    'recovery_wireguard_connected',
    'recovery_openvpn_connected',
    'recovery_wireguard_protection_snapshot',
    'recovery_openvpn_protection_snapshot',
    'recovery_wireguard_protection_fallback',
    'recovery_openvpn_protection_fallback',
  };
}
