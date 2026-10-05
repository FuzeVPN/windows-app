// SPDX-License-Identifier: MPL-2.0
import 'diagnostics_models.dart';
import 'local_diagnostic_trace.dart';

// A closed, structured extension shared by the complete report and its queue.
// No exception messages, raw log lines, paths or account data are accepted.
class DiagnosticSupport {
  static const maxEvents = 1152;
  static const _states = {
    'absent',
    'unknown',
    'stopped',
    'start_pending',
    'stop_pending',
    'running',
    'continue_pending',
    'pause_pending',
    'paused',
  };
  static const _logStates = {
    'ok',
    'absent',
    'read_failed',
    'rejected',
    'timeout',
    'unavailable',
  };

  static Map<String, Object?> nativeObservation(Object? value) {
    final raw = _map(value);
    if (raw['schema_version'] != 1 || raw['collection_pending'] == true) {
      _invalid();
    }
    final result = <String, Object?>{'schema_version': 1};
    if (raw['environment'] != null) {
      result['environment'] = _environment(raw['environment']);
    }
    if (raw['service'] != null) result['service'] = _service(raw['service']);
    if (raw['runtime'] != null) result['runtime'] = _runtime(raw['runtime']);
    final log = _map(raw['native_log']);
    final events = log['events'];
    if (events is! List || events.length > 128) _invalid();
    final normalized = <Map<String, Object?>>[];
    var discarded = 0;
    for (final event in events) {
      final safe = sanitizeNativeEvent(event);
      if (safe == null) {
        discarded++;
      } else {
        normalized.add(safe);
      }
    }
    final metadata = _log(log, allowEvents: true);
    result['native_log'] = {
      ...metadata,
      'discarded_lines': ((metadata['discarded_lines'] as int) + discarded)
          .clamp(0, 1000000),
      'events': normalized,
    };
    return result;
  }

  static Map<String, Object?> validate(Object? value) {
    final raw = _map(value);
    _keys(raw, {
      'schema_version',
      'collected_at',
      'collection',
      'environment',
      'service',
      'runtime',
      'timeline',
    });
    if (raw['schema_version'] != 1 || !_timestamp(raw['collected_at'])) {
      _invalid();
    }
    final collection = _map(raw['collection']);
    _keys(collection, {'application_log', 'native', 'native_log', 'report'});
    final result = <String, Object?>{
      'schema_version': 1,
      'collected_at': raw['collected_at'],
      'collection': {
        if (collection['report'] != null)
          'report': _enum(collection['report'], {
            'ok',
            'failed',
            'not_run',
            'cancelled',
            'busy',
          }),
        'application_log': _log(collection['application_log']),
        'native': _log(collection['native']),
        'native_log': _log(collection['native_log']),
      },
      if (raw['environment'] != null)
        'environment': _environment(raw['environment']),
      if (raw['service'] != null) 'service': _service(raw['service']),
      if (raw['runtime'] != null) 'runtime': _runtime(raw['runtime']),
    };
    final timeline = raw['timeline'];
    if (timeline is! List || timeline.length > maxEvents) _invalid();
    final normalized = <Map<String, Object?>>[];
    for (final item in timeline) {
      final entry = _map(item);
      if (!_timestamp(entry['timestamp'])) _invalid();
      final source = entry.remove('source');
      final safe = source == 'application'
          ? LocalDiagnosticTrace.sanitizeEvent(entry)
          : source == 'native'
          ? sanitizeNativeEvent(entry)
          : null;
      if (safe == null || safe.length != entry.length) _invalid();
      normalized.add({'source': source, ...safe});
    }
    result['timeline'] = normalized;
    return result;
  }

  static Map<String, Object?>? sanitizeNativeEvent(Object? value) {
    if (value is! Map || value.length > 40) return null;
    final raw = Map<Object?, Object?>.from(value);
    final area = raw['area'], event = raw['event'];
    if (!_timestamp(raw['timestamp']) || !_nativeEvent(area, event)) {
      return null;
    }
    final result = <String, Object?>{
      'timestamp': raw['timestamp'],
      'area': area,
      'event': event,
    };
    for (final entry in raw.entries) {
      final key = entry.key, value = entry.value;
      if (const {'timestamp', 'area', 'event'}.contains(key)) continue;
      if (key == 'code') {
        if (value is int && value >= 0 && value <= 0xffffffff ||
            _nativeCode(value)) {
          result['code'] = value;
        }
      } else if (const {
        'peer_ready',
        'send_attempts',
        'send_ok',
        'send_failed',
        'received',
        'reconnects',
        'command_failed',
        'success',
        'engine_connect_ms',
        'setup_commands_ms',
        'setup_validation_ms',
        'first_failed_code',
        'postcondition_failures',
        'address_expected',
        'address_matched',
        'address_tentative',
        'address_duplicate',
        'complete',
        'last_code',
        'failure_count',
        'pending_groups',
        'elapsed_ms',
        'budget_ms',
      }.contains(key)) {
        if (value is int && value >= 0 && value <= 0xffffffff) {
          result[key as String] = value;
        }
      } else if (key == 'stage' &&
          const {
            'starting',
            'adapter_open',
            'peer_ready',
            'packet_received',
            'tls_active',
            'assign_ip',
            'add_routes',
            'connected',
          }.contains(value)) {
        result['stage'] = value;
      } else if (const {
            'first_error',
            'last_error',
            'failure_before_stop',
          }.contains(key) &&
          _nativeCode(value)) {
        result[key as String] = value;
      } else if (const {'first_failed_action', 'last_action'}.contains(key) &&
          const {
            'none',
            'unknown',
            'command_other',
            'command_route_add',
            'command_route_delete',
            'command_address_set',
            'command_address_delete',
            'command_interface',
            'command_dns_set',
            'command_dns_add',
            'command_dns_delete',
            'command_dns_flush',
            'route_lookup',
            'route_create',
            'route_remove',
            'setup_actions',
            'postcondition_adapter',
            'postcondition_address',
            'postcondition_route',
            'postcondition_dns',
            'postcondition_read_adapter',
            'postcondition_read_routes',
            'postcondition_read_nrpt',
            'dns_manager_open',
            'dns_service_open',
            'dns_notify',
            'dns_gpo_notify',
          }.contains(value)) {
        result[key as String] = value;
      } else if (key == 'last_event' &&
          const {
            'none',
            'unknown',
            'RESOLVE',
            'WAIT',
            'WAIT_PROXY',
            'CONNECTING',
            'GET_CONFIG',
            'ASSIGN_IP',
            'ADD_ROUTES',
            'CONNECTED',
            'RECONNECTING',
            'AUTH_PENDING',
            'DISCONNECTED',
            'PAUSE',
            'RESUME',
            'TRANSPORT_ERROR',
            'TUN_ERROR',
            'AUTH_FAILED',
            'CERT_VERIFY_FAIL',
            'TLS_ALERT_HANDSHAKE_FAILURE',
            'TUN_SETUP_FAILED',
            'CONNECTION_TIMEOUT',
            'CLIENT_SETUP',
          }.contains(value)) {
        result['last_event'] = value;
      }
    }
    return result;
  }

  static bool _nativeCode(Object? value) =>
      diagnosticCodes.contains(value) ||
      const {
        'none',
        'other',
        'tunnel_failure',
        'tunnel_handshake_timeout',
        'runtime_detection_failed',
        'runtime_owned_by_another_user',
        'maintenance_in_progress',
        'network_protection_release_failed',
        'openvpn_transport_started',
        'openvpn_adapter_opened',
      }.contains(value);

  static bool _nativeEvent(Object? area, Object? event) {
    if (area == 'broker') {
      return const {
        'broker_ready',
        'client_connected',
        'request_read',
        'client_authenticated',
        'request_decoded',
        'wireguard_dispatch',
        'wireguard_complete',
        'openvpn_dispatch',
        'openvpn_complete',
        'response_acknowledged',
        'shutdown_pending',
        'shutdown_unconfirmed',
        'shutdown_complete',
        'service_install_failed',
        'connection_failed',
        'request_write_failed',
        'response_unavailable',
        'response_ack_failed',
      }.contains(event);
    }
    if (area == 'runtime') {
      return const {
        'runtime_detection_failed',
        'runtime_status_unavailable',
      }.contains(event);
    }
    if (area != 'wireguard' && area != 'openvpn') return false;
    if (event == 'native_error' ||
        area == 'openvpn' &&
            const {
              'connection_attempt_snapshot',
              'cleanup_snapshot',
            }.contains(event)) {
      return true;
    }
    for (final operation in const {
      'connect',
      'prepareConnection',
      'disconnect',
      'prepareIdentityForAccount',
      'recreateIdentityForAccount',
      'resetIdentity',
      'importAndConnect',
      'suspendForMigration',
    }) {
      for (final state in const {'started', 'succeeded', 'failed'}) {
        if (event == '${operation}_$state') return true;
      }
    }
    return false;
  }

  static Map<String, Object?> _environment(Object? value) {
    final raw = _map(value);
    _keys(raw, {
      'installation_mode',
      'service_executable_present',
      'runtime_executable_present',
      'binary_version',
      'win32_error',
    });
    return {
      if (raw['installation_mode'] != null)
        'installation_mode': _enum(raw['installation_mode'], {
          'installed',
          'portable',
          'unavailable',
        }),
      ..._boolFields(raw, {
        'service_executable_present',
        'runtime_executable_present',
      }),
      ..._intFields(raw, {'win32_error'}),
      ..._version(raw),
    };
  }

  static Map<String, Object?> _service(Object? value) {
    final raw = _map(value);
    _keys(raw, {
      'name',
      'state',
      'query_stage',
      'win32_error',
      'win32_exit_code',
      'service_exit_code',
      'configuration_win32_error',
      'process_present',
      'binary_version',
      'service_binary_matches_application',
    });
    if (raw['name'] != 'FuzeVPNService') _invalid();
    return {
      'name': 'FuzeVPNService',
      'state': _enum(raw['state'], _states),
      'query_stage': _enum(raw['query_stage'], {
        'scm_open',
        'service_open',
        'service_status',
        'completed',
      }),
      ..._intFields(raw, {
        'win32_error',
        'win32_exit_code',
        'service_exit_code',
        'configuration_win32_error',
      }),
      ..._boolFields(raw, {
        'process_present',
        'service_binary_matches_application',
      }),
      ..._version(raw),
    };
  }

  static Map<String, Object?> _runtime(Object? value) {
    final raw = _map(value);
    _keys(raw, {'presence', 'detection_failed', 'win32_error'});
    return {
      'presence': _enum(raw['presence'], {'present', 'absent', 'unknown'}),
      ..._boolFields(raw, {'detection_failed'}),
      ..._intFields(raw, {'win32_error'}),
    };
  }

  static Map<String, Object?> _log(Object? value, {bool allowEvents = false}) {
    final raw = _map(value);
    // nativeObservation separately validates and extracts events.
    _keys(raw, {
      'status',
      'truncated',
      'discarded_lines',
      'win32_error',
      if (allowEvents) 'events',
    });
    if (raw['truncated'] is! bool || raw['discarded_lines'] is! int) {
      _invalid();
    }
    return {
      'status': _enum(raw['status'], _logStates),
      ..._boolFields(raw, {'truncated'}),
      ..._intFields(raw, {'discarded_lines'}, maximum: 1000000),
      ..._intFields(raw, {'win32_error'}),
    };
  }

  static Map<String, Object?> _version(Map<String, Object?> value) {
    final version = value['binary_version'];
    if (version == null) return {};
    if (version is! String ||
        !RegExp(r'^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$').hasMatch(version)) {
      _invalid();
    }
    return {'binary_version': version};
  }

  static Map<String, Object?> _boolFields(
    Map<String, Object?> raw,
    Set<String> keys,
  ) => {
    for (final key in keys)
      if (raw[key] != null) key: raw[key] is bool ? raw[key] : _invalid(),
  };
  static Map<String, Object?> _intFields(
    Map<String, Object?> raw,
    Set<String> keys, {
    int maximum = 0xffffffff,
  }) => {
    for (final key in keys)
      if (raw[key] != null)
        key:
            raw[key] is int &&
                (raw[key]! as int) >= 0 &&
                (raw[key]! as int) <= maximum
            ? raw[key]
            : _invalid(),
  };
  static bool _timestamp(Object? value) {
    if (value is! String ||
        value.length > 32 ||
        !RegExp(
          r'^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?Z$',
        ).hasMatch(value)) {
      return false;
    }
    final parsed = DateTime.tryParse(value);
    return parsed != null &&
        parsed.isUtc &&
        parsed.toIso8601String().substring(0, 19) == value.substring(0, 19);
  }

  static String _enum(Object? value, Set<String> allowed) =>
      value is String && allowed.contains(value) ? value : _invalid();
  static Map<String, Object?> _map(Object? value) {
    if (value is! Map ||
        value.length > 40 ||
        value.keys.any((key) => key is! String)) {
      _invalid();
    }
    return Map<String, Object?>.from(value);
  }

  static void _keys(Map<String, Object?> value, Set<String> allowed) {
    if (value.keys.any((key) => !allowed.contains(key))) _invalid();
  }

  static Never _invalid() =>
      throw const FormatException('Invalid complete diagnostic evidence.');
}
