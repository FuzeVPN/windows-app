// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

/// Version 1 of client-diagnostics-20260916. Never expand this from error text.
const diagnosticCodes = <String>{
  'api_bootstrap_unavailable',
  'api_error',
  'api_resolution_unavailable',
  'api_token_expired',
  'api_transport_unsupported',
  'broker_busy',
  'broker_protocol_error',
  'broker_response_timeout',
  'broker_unavailable',
  'broker_write_failed',
  'certificate_expired',
  'certificate_invalid',
  'certificate_validation_failed',
  'cleanup_failed',
  'csr_generation_failed',
  'device_exists',
  'device_identity_revoked',
  'device_limit',
  'device_proof_invalid',
  'device_proof_replayed',
  'driver_unavailable',
  'email_delivery_unavailable',
  'email_verification_required',
  'endpoint_resolution_failed',
  'flutter_disconnect_timeout',
  'flutter_disconnect_unexpected',
  'handshake_timeout',
  'identity_renewal_unexpected',
  'installation_required',
  'invalid_activation_response',
  'invalid_api_response',
  'invalid_configuration',
  'invalid_credentials',
  'invalid_device',
  'invalid_device_configuration',
  'invalid_location',
  'invalid_migration_response',
  'invalid_response',
  'ipv6_unavailable',
  'key_generation_failed',
  'key_unavailable',
  'location_migration_conflict',
  'location_migration_device_changed',
  'location_migration_verification_failed',
  'login_requires_disconnect',
  'native_bridge_unavailable',
  'native_operation_failed',
  'network_error',
  'network_protection_failed',
  'network_timeout',
  'network_unavailable',
  'node_unavailable',
  'not_found',
  'openvpn_activation_invalid',
  'openvpn_adapter_failed',
  'openvpn_auth_failed',
  'openvpn_certificate_expired',
  'openvpn_certificate_expiry_mismatch',
  'openvpn_certificate_identity_mismatch',
  'openvpn_certificate_validation_failed',
  'openvpn_cleanup_failed',
  'openvpn_client_config_failed',
  'openvpn_client_halted',
  'openvpn_client_setup_failed',
  'openvpn_connection_failed',
  'openvpn_connection_timeout',
  'openvpn_core_stalled',
  'openvpn_core_status_error',
  'openvpn_core_unavailable',
  'openvpn_csr_generation_failed',
  'openvpn_dco_peer_failed',
  'openvpn_dco_profile_incompatible',
  'openvpn_dns_configuration_failed',
  'openvpn_driver_restart_required',
  'openvpn_external_pki_failed',
  'openvpn_identity_cleanup_pending',
  'openvpn_identity_clear_failed',
  'openvpn_identity_store_failed',
  'openvpn_identity_unavailable',
  'openvpn_key_generation_failed',
  'openvpn_local_identity_failed',
  'openvpn_local_identity_mismatch',
  'openvpn_migration_certificate_mismatch',
  'openvpn_native_failed',
  'openvpn_network_configuration_failed',
  'openvpn_network_metadata_invalid',
  'openvpn_no_server_response',
  'openvpn_operation_pending',
  'openvpn_operation_timeout',
  'openvpn_profile_crypto_failed',
  'openvpn_profile_rejected',
  'openvpn_profile_unavailable',
  'openvpn_recovery_exhausted',
  'openvpn_renewal_not_prepared',
  'openvpn_renewal_state_invalid',
  'openvpn_service_start_failed',
  'openvpn_signer_unavailable',
  'openvpn_start_failed',
  'openvpn_stop_timeout',
  'openvpn_tls_handshake_failed',
  'openvpn_transport_failed',
  'permission_denied',
  'profile_forbidden_directive',
  'profile_invalid_ca',
  'profile_invalid_cipher',
  'profile_invalid_remote',
  'profile_invalid_tls_crypt_v2',
  'profile_invalid_verification_name',
  'profile_missing_required_directive',
  'profile_rejected',
  'proxy_authentication_failed',
  'proxy_certificate_invalid',
  'proxy_controlled_by_extension',
  'proxy_controlled_by_policy',
  'proxy_creation_uncertain',
  'proxy_unavailable',
  'rate_limited',
  'renewal_unexpected',
  'request_timeout',
  'response_too_large',
  'revoke_unexpected',
  'runtime_status_unavailable',
  'runtime_unavailable',
  'secure_storage_corrupt',
  'secure_storage_read_failed',
  'secure_storage_write_failed',
  'server_error',
  'service_configuration_mismatch',
  'service_install_failed',
  'service_unavailable',
  'session_expired',
  'storage_access_denied',
  'storage_corrupt',
  'storage_decryption_failed',
  'storage_error',
  'storage_failure',
  'storage_io_error',
  'storage_unavailable',
  'subscription_required',
  'system_vpn_resume_corrupt',
  'system_vpn_resume_failed',
  'system_vpn_resume_identity_changed',
  'system_vpn_resume_identity_invalid',
  'system_vpn_resume_network_timeout',
  'system_vpn_resume_session_invalid',
  'system_vpn_resume_storage_failed',
  'target_unavailable',
  'tls_alert_bad_certificate',
  'tls_alert_misc',
  'tls_alert_unknown_ca',
  'tls_alert_unsupported_certificate',
  'tls_certificate_expired',
  'tls_certificate_revoked',
  'tls_client_certificate_required',
  'tls_handshake_failed',
  'tls_handshake_rejected',
  'tls_signature_algorithm_rejected',
  'tls_version_rejected',
  'traffic_guard_failed',
  'tun_establish_exception',
  'tun_establish_returned_null',
  'tun_failed',
  'tun_halted',
  'tun_interface_create_failed',
  'tun_interface_disabled',
  'tun_network_mismatch',
  'tun_setup_failed',
  'tunnel_failure',
  'tunnel_handshake_timeout',
  'tunnel_start_failed',
  'tunnel_start_unexpected',
  'tunnel_stop_failed',
  'tunnel_stop_timeout',
  'unauthorized',
  'unexpected_error',
  'unknown_error',
  'update_download_failed',
  'update_environment_invalid',
  'update_environment_unavailable',
  'update_install_failed',
  'update_installation_unprotected',
  'update_manifest_invalid',
  'update_network_failed',
  'update_not_prepared',
  'update_preinstall_failed',
  'update_request_failed',
  'update_storage_failed',
  'update_unavailable',
  'update_unsigned_application',
  'update_unsupported',
  'update_verification_failed',
  'update_version_invalid',
  'update_vpn_cleanup_failed',
  'verification_email_cooldown',
  'vpn_host_destroyed',
  'vpn_host_unavailable',
  'vpn_permission_request_failed',
  'webrtc_control_unavailable',
  'wireguard_configuration_invalid',
  'wireguard_foreground_service_unavailable',
  'wireguard_handshake_timeout',
  'wireguard_identity_invalid',
  'wireguard_identity_store_failed',
  'wireguard_identity_unavailable',
  'wireguard_start_failed',
  'wireguard_stop_timeout',
};

String diagnosticCode(String value) =>
    diagnosticCodes.contains(value) ? value : 'unknown_error';

const diagnosticStages = <String>{
  'unknown',
  'startup',
  'storage',
  'authentication',
  'api_request',
  'api_response',
  'enrollment',
  'profile_create',
  'profile_revoke',
  'certificate',
  'certificate_renewal',
  'driver_check',
  'service_start',
  'tunnel_start',
  'handshake',
  'adapter_create',
  'addresses_apply',
  'routes_apply',
  'dns_apply',
  'mtu_apply',
  'postconditions',
  'proxy_configuration',
  'guard_verify',
  'webrtc_check',
  'network_check',
  'disconnect',
  'cleanup',
  'recovery',
  'repair',
  'completed',
};
const diagnosticStates = <String>{
  'unknown',
  'disconnected',
  'connecting',
  'connected',
  'disconnecting',
  'error',
  'degraded',
  'recovering',
};
const _results = {'passed', 'failed', 'skipped', 'unknown'};
const _maxDuration = 604800000;

class DiagnosticsFailure implements Exception {
  const DiagnosticsFailure(this.code);
  final String code;
  @override
  String toString() => 'DiagnosticsFailure($code)';
}

class DiagnosticError {
  DiagnosticError({
    required String code,
    this.domain = 'unknown',
    this.operation = 'unknown',
    this.stage = 'unknown',
    this.httpStatus,
    this.nativeDomain,
    this.nativeCode,
  }) : code = diagnosticCode(code) {
    _validateError(toJson());
  }
  final String code;
  final String domain;
  final String operation;
  final String stage;
  final int? httpStatus;
  final String? nativeDomain;
  final int? nativeCode;
  Map<String, Object?> toJson() => {
    'domain': domain,
    'code': code,
    'operation': operation,
    'stage': stage,
    if (httpStatus != null) 'http_status': httpStatus,
    if (nativeDomain != null || nativeCode != null)
      'native': {'domain': nativeDomain, 'code': nativeCode},
  };
}

class DiagnosticEvent {
  DiagnosticEvent({
    this.source = 'controller',
    required this.stage,
    required this.event,
    String? code,
    this.durationMs,
    this.httpStatus,
    this.spanId,
    this.parentSpanId,
  }) : code = code == null ? null : diagnosticCode(code) {
    _validateEvent(toJson(offsetMs: 0));
  }
  final String source;
  final String stage;
  final String event;
  final String? code;
  final int? durationMs;
  final int? httpStatus;
  final int? spanId;
  final int? parentSpanId;
  Map<String, Object?> toJson({required int offsetMs}) => {
    'source': source,
    'stage': stage,
    'event': event,
    'offset_ms': offsetMs,
    if (code != null) 'code': code,
    if (durationMs != null) 'duration_ms': durationMs,
    if (httpStatus != null) 'http_status': httpStatus,
    if (spanId != null) 'span_id': spanId,
    if (parentSpanId != null) 'parent_span_id': parentSpanId,
  };
}

class DiagnosticCheck {
  DiagnosticCheck({
    required this.id,
    required this.result,
    String? code,
    this.durationMs,
    this.ageMs,
  }) : code = code == null ? null : diagnosticCode(code) {
    _validateFragments({
      'checks': [toJson()],
    });
  }
  factory DiagnosticCheck.fromMap(Map<String, Object?> value) {
    final validated = DiagnosticSnapshot.fromMap({
      'checks': [value],
    });
    final check = (validated.reportFragments['checks'] as List).single as Map;
    return DiagnosticCheck(
      id: check['id'] as String,
      result: check['result'] as String,
      code: check['code'] as String?,
      durationMs: check['duration_ms'] as int?,
      ageMs: check['age_ms'] as int?,
    );
  }
  final String id;
  final String result;
  final String? code;
  final int? durationMs;
  final int? ageMs;
  Map<String, Object?> toJson() => {
    'id': id,
    'result': result,
    if (code != null) 'code': code,
    if (durationMs != null) 'duration_ms': durationMs,
    if (ageMs != null) 'age_ms': ageMs,
  };
}

class DiagnosticRepair {
  DiagnosticRepair({
    required this.id,
    required this.before,
    required this.after,
    required this.result,
    String? code,
    this.durationMs,
  }) : code = code == null ? null : diagnosticCode(code) {
    _validateFragments({
      'repairs': [toJson()],
    });
  }
  final String id;
  final String before;
  final String after;
  final String result;
  final String? code;
  final int? durationMs;
  Map<String, Object?> toJson() => {
    'id': id,
    'before': before,
    'after': after,
    'result': result,
    if (code != null) 'code': code,
    if (durationMs != null) 'duration_ms': durationMs,
  };
}

/// Native local runtime information deliberately never enters reportFragments.
class DiagnosticSnapshot {
  DiagnosticSnapshot.fromMap(Map<String, Object?> value) {
    final copy = _jsonCopy(value);
    _keys(copy, {
      'environment',
      'snapshot',
      'checks',
      'windows',
      'repairs',
      'runtime',
    });
    final runtimeValue = copy.remove('runtime');
    if (runtimeValue != null) {
      final local = _object(runtimeValue);
      _keys(local, {
        'presence',
        'cleanup_eligible',
        'owned_by_another_user',
        'protocol',
        'collection_pending',
      });
      _enum(local, 'presence', {
        'present',
        'absent',
        'unknown',
      }, required: true);
      _bool(local, 'cleanup_eligible');
      _bool(local, 'owned_by_another_user');
      _bool(local, 'collection_pending');
      _enum(local, 'protocol', {'unknown', 'wireguard', 'openvpn'});
      runtime = Map.unmodifiable(local);
    } else {
      runtime = const {};
    }
    _mapFragmentCodes(copy);
    _validateFragments(copy);
    _fragments = _freezeMap(copy);
  }
  late final Map<String, Object?> _fragments;
  late final Map<String, Object?> runtime;
  Map<String, Object?> get reportFragments => _fragments;
}

class FrozenDiagnosticReport {
  FrozenDiagnosticReport._(this._json, this.bytes);

  factory FrozenDiagnosticReport.create({
    required String appVersion,
    required DateTime createdAt,
    required bool manual,
    required bool full,
    required String state,
    String protocol = 'unknown',
    int? appBuild,
    DiagnosticError? error,
    Map<String, Object?> fragments = const {},
    List<Map<String, Object?>> events = const [],
    int occurrences = 1,
    int droppedEvents = 0,
    bool truncated = false,
    String? reportId,
  }) {
    final value = <String, Object?>{
      'schema_version': 1,
      'report_id': reportId ?? newDiagnosticId(),
      'report_type': full ? 'full' : 'simple',
      'platform': 'windows',
      'app_version': appVersion,
      if (appBuild != null) 'app_build': appBuild,
      'created_at': createdAt.toUtc().toIso8601String(),
      'consent': {
        'mode': manual ? 'manual' : 'automatic_opt_in',
        'notice_version': 1,
      },
      'protocol': protocol,
      'state': state,
      'occurrences': occurrences,
      if (error != null) 'error': error.toJson(),
      ..._jsonCopy(fragments),
      if (full && events.isNotEmpty) 'events': _jsonCopyList(events),
      'truncated': truncated,
      'dropped_events': droppedEvents,
    };
    // Fragments cannot replace an envelope field.
    _keys(fragments, {
      'environment',
      'snapshot',
      'checks',
      'windows',
      'repairs',
    });
    validateDiagnosticReport(value);
    final encoded = Uint8List.fromList(utf8.encode(jsonEncode(value)));
    final limit = full ? 2 * 1024 * 1024 : 8192;
    if (encoded.length > limit) {
      throw const DiagnosticsFailure('diagnostic_too_large');
    }
    return FrozenDiagnosticReport._(
      _freezeMap(value),
      encoded.asUnmodifiableView(),
    );
  }

  /// Our own queue stores canonical bytes. Requiring the exact encoding also
  /// rejects duplicate JSON keys rather than silently accepting jsonDecode's
  /// last value. A loaded report is never normalized/re-created for retry.
  factory FrozenDiagnosticReport.fromBytes(Uint8List bytes) {
    if (bytes.length > 2 * 1024 * 1024) _invalid();
    final text = utf8.decode(bytes);
    final value = _object(jsonDecode(text));
    validateDiagnosticReport(value);
    if (jsonEncode(value) != text ||
        (value['report_type'] == 'simple' && bytes.length > 8192)) {
      _invalid();
    }
    return FrozenDiagnosticReport._(
      _freezeMap(value),
      Uint8List.fromList(bytes).asUnmodifiableView(),
    );
  }
  final Map<String, Object?> _json;
  final Uint8List bytes;
  Map<String, Object?> get json => _json;
  Map<String, Object?> toJson() => _json;
  String get reportId => _json['report_id']! as String;
  bool get manual => (_json['consent']! as Map)['mode'] == 'manual';
  bool get full => _json['report_type'] == 'full';
  DateTime get createdAt => DateTime.parse(_json['created_at']! as String);
}

String newDiagnosticId() {
  final random = Random.secure();
  final bytes = List<int>.generate(16, (_) => random.nextInt(256));
  bytes[6] = (bytes[6] & 15) | 64;
  bytes[8] = (bytes[8] & 63) | 128;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return '${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}';
}

bool isDiagnosticId(Object? value) =>
    value is String &&
    RegExp(
      r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    ).hasMatch(value) &&
    value != '00000000-0000-0000-0000-000000000000';

class DiagnosticReceipt {
  DiagnosticReceipt.fromJson(
    Map<String, dynamic> json, {
    required String expectedClientId,
    required int httpStatus,
  }) {
    _keys(json, {
      'report_id',
      'client_report_id',
      'received_at',
      'expires_at',
      'status',
      'duplicate',
    });
    if (!isDiagnosticId(json['report_id']) ||
        json['client_report_id'] != expectedClientId ||
        json['report_id'] == expectedClientId ||
        json['status'] != 'received' ||
        (httpStatus != 200 && httpStatus != 201) ||
        json['duplicate'] != (httpStatus == 200)) {
      _invalid();
    }
    reportId = json['report_id'] as String;
    clientReportId = expectedClientId;
    duplicate = json['duplicate'] as bool;
    receivedAt = _date(json['received_at']);
    expiresAt = _date(json['expires_at']);
    if (!expiresAt.isAfter(receivedAt)) _invalid();
  }
  late final String reportId;
  late final String clientReportId;
  late final bool duplicate;
  late final DateTime receivedAt;
  late final DateTime expiresAt;
}

void validateDiagnosticReport(Map<String, Object?> value) {
  _walk(value, 0);
  _keys(value, {
    'schema_version',
    'report_id',
    'report_type',
    'platform',
    'app_version',
    'app_build',
    'created_at',
    'consent',
    'protocol',
    'state',
    'occurrences',
    'error',
    'duration_ms',
    'environment',
    'snapshot',
    'checks',
    'events',
    'repairs',
    'windows',
    'truncated',
    'dropped_events',
  });
  if (value['schema_version'] != 1 ||
      !isDiagnosticId(value['report_id']) ||
      value['platform'] != 'windows') {
    _invalid();
  }
  _enum(value, 'report_type', {'simple', 'full'}, required: true);
  final full = value['report_type'] == 'full';
  final version = value['app_version'];
  if (version is! String ||
      !RegExp(
        r'^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,4})$',
      ).hasMatch(version)) {
    _invalid();
  }
  final parts = (version).split('.').map(int.parse).toList();
  if (parts[0] > 255 || parts[1] > 255 || parts[2] > 65535) _invalid();
  _int(value, 'app_build', 0, 0x7fffffff);
  _date(value['created_at']);
  final consent = _object(value['consent']);
  _keys(consent, {'mode', 'notice_version'});
  _enum(
    consent,
    'mode',
    full ? {'manual'} : {'manual', 'automatic_opt_in'},
    required: true,
  );
  if (consent['notice_version'] != 1) _invalid();
  _enum(value, 'protocol', {'unknown', 'wireguard', 'openvpn'});
  _enum(value, 'state', diagnosticStates, required: true);
  _int(value, 'occurrences', 1, 1000000, required: true);
  if (!full && value['error'] == null) _invalid();
  if (value['error'] != null) _validateError(_object(value['error']));
  _int(value, 'duration_ms', 0, _maxDuration);
  _bool(value, 'truncated', required: true);
  _int(value, 'dropped_events', 0, 1000000, required: true);
  if ((value['dropped_events']! as int) > 0 && value['truncated'] != true) {
    _invalid();
  }
  if (!full &&
      (value['truncated'] != false ||
          value['dropped_events'] != 0 ||
          [
            'snapshot',
            'checks',
            'events',
            'repairs',
            'windows',
          ].any(value.containsKey))) {
    _invalid();
  }
  _validateFragments(value);
  _list(value, 'events', 2000, _validateEvent);
}

void _validateFragments(Map<String, Object?> value) {
  if (value['environment'] != null) {
    final env = _object(value['environment']);
    _keys(env, {
      'architecture',
      'os_family',
      'os_major',
      'network_type',
      'windows_build',
      'installation_mode',
      'engine_version',
      'driver_version',
    });
    _enum(env, 'architecture', {'x64', 'x86', 'arm64', 'armv7', 'unknown'});
    _enum(env, 'os_family', {
      'windows',
      'android',
      'macos',
      'linux',
      'chromeos',
      'unknown',
    });
    _int(env, 'os_major', 1, 100);
    _enum(env, 'network_type', {
      'wifi',
      'cellular',
      'ethernet',
      'none',
      'unknown',
    });
    _int(env, 'windows_build', 1, 10000000);
    _enum(env, 'installation_mode', {'installed', 'portable', 'unavailable'});
    for (final key in ['engine_version', 'driver_version']) {
      final version = env[key];
      if (version != null &&
          (version is! String ||
              !RegExp(r'^[0-9]{1,5}(\.[0-9]{1,5}){0,3}$').hasMatch(version))) {
        _invalid();
      }
    }
  }
  if (value['snapshot'] != null) {
    final s = _object(value['snapshot']);
    _keys(s, {
      'phase',
      'ip_families',
      'kill_switch_requested',
      'kill_switch_verified',
      'traffic_blocked',
      'owned_by_another_user',
      'handshake_age_ms',
      'connection_duration_ms',
      'freshness_ms',
      'bytes_sent',
      'bytes_received',
      'reconnect_count',
      'recovery_state',
      'certificate_state',
      'cleanup_state',
    });
    _enum(s, 'phase', diagnosticStages);
    final families = s['ip_families'];
    if (families != null &&
        (families is! List ||
            families.length > 2 ||
            families.toSet().length != families.length ||
            families.any((v) => v != 'ipv4' && v != 'ipv6'))) {
      _invalid();
    }
    for (final key in [
      'kill_switch_requested',
      'kill_switch_verified',
      'traffic_blocked',
      'owned_by_another_user',
    ]) {
      _bool(s, key);
    }
    for (final key in [
      'handshake_age_ms',
      'connection_duration_ms',
      'freshness_ms',
    ]) {
      _int(s, key, 0, _maxDuration);
    }
    for (final key in ['bytes_sent', 'bytes_received']) {
      _int(s, key, 0, 9007199254740991);
    }
    _int(s, 'reconnect_count', 0, 1000000);
    _enum(s, 'recovery_state', {
      'none',
      'pending',
      'retrying',
      'succeeded',
      'failed',
      'unknown',
    });
    _enum(s, 'certificate_state', {
      'missing',
      'valid',
      'expiring',
      'renewing',
      'expired',
      'revoked',
      'unknown',
    });
    _enum(s, 'cleanup_state', {
      'not_requested',
      'pending',
      'completed',
      'failed',
      'unknown',
    });
  }
  _list(value, 'checks', 64, (c) {
    _keys(c, {'id', 'result', 'code', 'duration_ms', 'age_ms'});
    _enum(c, 'id', {
      'unknown',
      'api_reachability',
      'service_availability',
      'driver_availability',
      'secure_storage',
      'tunnel_configuration',
      'tunnel_connection',
      'handshake',
      'routing',
      'dns',
      'ipv4',
      'ipv6',
      'kill_switch',
      'webrtc',
      'proxy_settings',
      'certificate',
      'cleanup',
      'connectivity',
      'permissions',
    }, required: true);
    _enum(c, 'result', _results, required: true);
    _enum(c, 'code', diagnosticCodes);
    _int(c, 'duration_ms', 0, _maxDuration);
    _int(c, 'age_ms', 0, _maxDuration);
  });
  _list(value, 'repairs', 32, (r) {
    _keys(r, {'id', 'before', 'after', 'result', 'code', 'duration_ms'});
    _enum(r, 'id', {
      'restart_service',
      'reset_adapter',
      'reapply_routes',
      'reapply_dns',
      'restore_protection',
      'cleanup',
      'refresh_profile',
      'unknown',
    }, required: true);
    for (final key in ['before', 'after', 'result']) {
      _enum(r, key, _results, required: true);
    }
    if (r['result'] == 'passed' && r['after'] != 'passed') _invalid();
    _enum(r, 'code', diagnosticCodes);
    _int(r, 'duration_ms', 0, _maxDuration);
  });
  if (value['windows'] != null) {
    final w = _object(value['windows']);
    _keys(w, {
      'engine_connect_ms',
      'configuration_ms',
      'validation_ms',
      'dco_enabled',
      'dco_failures',
      'postconditions_mask',
      'configured_ipv4_count',
      'configured_ipv6_count',
      'first_error',
      'last_error',
    });
    for (final key in [
      'engine_connect_ms',
      'configuration_ms',
      'validation_ms',
    ]) {
      _int(w, key, 0, _maxDuration);
    }
    _bool(w, 'dco_enabled');
    _int(w, 'dco_failures', 0, 1000000);
    _int(w, 'postconditions_mask', 0, 0xffffffff);
    _int(w, 'configured_ipv4_count', 0, 1000);
    _int(w, 'configured_ipv6_count', 0, 1000);
    _enum(w, 'first_error', diagnosticCodes);
    _enum(w, 'last_error', diagnosticCodes);
  }
}

void _validateError(Map<String, Object?> e) {
  _keys(e, {'domain', 'code', 'operation', 'stage', 'http_status', 'native'});
  _enum(e, 'domain', {
    'api',
    'system',
    'tunnel',
    'storage',
    'protection',
    'proxy',
    'client',
    'unknown',
  }, required: true);
  _enum(e, 'code', diagnosticCodes, required: true);
  _enum(e, 'operation', {
    'unknown',
    'startup',
    'authenticate',
    'register',
    'connect',
    'disconnect',
    'refresh',
    'probe',
    'restore',
    'renew',
    'update',
    'repair',
  }, required: true);
  _enum(e, 'stage', diagnosticStages, required: true);
  _int(e, 'http_status', 100, 599);
  if (e['native'] != null) {
    final n = _object(e['native']);
    _keys(n, {'domain', 'code'});
    _enum(n, 'domain', {
      'win32',
      'hresult',
      'winsock',
      'errno',
      'unknown',
    }, required: true);
    _int(n, 'code', -2147483648, 4294967295, required: true);
  }
}

void _validateEvent(Map<String, Object?> e) {
  _keys(e, {
    'source',
    'stage',
    'event',
    'offset_ms',
    'duration_ms',
    'code',
    'http_status',
    'span_id',
    'parent_span_id',
  });
  _enum(e, 'source', {
    'app',
    'native',
    'flutter',
    'controller',
    'api',
    'system',
  }, required: true);
  _enum(e, 'stage', diagnosticStages, required: true);
  _enum(e, 'event', {
    'begin',
    'end',
    'error',
    'waiting',
    'retry',
    'cancelled',
    'info',
  }, required: true);
  _int(e, 'offset_ms', 0, 600000, required: true);
  _int(e, 'duration_ms', 0, _maxDuration);
  _enum(e, 'code', diagnosticCodes);
  _int(e, 'http_status', 100, 599);
  _int(e, 'span_id', 0, 2000);
  _int(e, 'parent_span_id', 0, 2000);
}

Never _invalid() =>
    throw const FormatException('Invalid structured diagnostic.');
Map<String, Object?> _object(Object? value) {
  if (value is! Map || value.keys.any((key) => key is! String)) _invalid();
  return Map<String, Object?>.from(value);
}

void _keys(Map<String, Object?> m, Set<String> allowed) {
  if (m.keys.any((key) => !allowed.contains(key))) _invalid();
}

void _enum(
  Map<String, Object?> m,
  String k,
  Set<String> allowed, {
  bool required = false,
}) {
  final v = m[k];
  if (v == null && !required) return;
  if (v is! String || !allowed.contains(v)) _invalid();
}

void _int(
  Map<String, Object?> m,
  String k,
  int min,
  int max, {
  bool required = false,
}) {
  final v = m[k];
  if (v == null && !required) return;
  if (v is! int || v < min || v > max) _invalid();
}

void _bool(Map<String, Object?> m, String k, {bool required = false}) {
  if (m[k] == null && !required) return;
  if (m[k] is! bool) _invalid();
}

void _list(
  Map<String, Object?> m,
  String k,
  int max,
  void Function(Map<String, Object?>) validate,
) {
  final v = m[k];
  if (v == null) return;
  if (v is! List || v.length > max) _invalid();
  for (final item in v) {
    validate(_object(item));
  }
}

DateTime _date(Object? value) {
  if (value is! String ||
      !RegExp(
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$',
      ).hasMatch(value)) {
    _invalid();
  }
  final fields = RegExp(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})',
  ).firstMatch(value)!;
  final numbers = List.generate(6, (i) => int.parse(fields.group(i + 1)!));
  final calendar = DateTime.utc(numbers[0], numbers[1], numbers[2]);
  if (numbers[1] < 1 ||
      numbers[1] > 12 ||
      numbers[2] < 1 ||
      calendar.year != numbers[0] ||
      calendar.month != numbers[1] ||
      calendar.day != numbers[2] ||
      numbers[3] > 23 ||
      numbers[4] > 59 ||
      numbers[5] > 59) {
    _invalid();
  }
  if (!value.endsWith('Z')) {
    final zone = value
        .substring(value.length - 5)
        .split(':')
        .map(int.parse)
        .toList();
    if (zone[0] > 23 || zone[1] > 59) _invalid();
  }
  final date = DateTime.tryParse(value);
  if (date == null || date.year < 2000 || date.year > 2100) _invalid();
  return date.toUtc();
}

void _mapFragmentCodes(Map<String, Object?> fragments) {
  for (final name in ['checks', 'repairs']) {
    final items = fragments[name];
    if (items is List) {
      for (final item in items) {
        if (item is Map && item['code'] is String) {
          item['code'] = diagnosticCode(item['code'] as String);
        }
      }
    }
  }
  final windows = fragments['windows'];
  if (windows is Map) {
    for (final name in ['first_error', 'last_error']) {
      if (windows[name] is String) {
        windows[name] = diagnosticCode(windows[name] as String);
      }
    }
  }
}

void _walk(Object? value, int depth) {
  if (depth > 12) _invalid();
  if (value is String) {
    if (value.contains('\u0000') || utf8.encode(value).length > 128) _invalid();
  } else if (value is Map) {
    for (final entry in value.entries) {
      if (entry.key is! String ||
          utf8.encode(entry.key as String).length > 64) {
        _invalid();
      }
      _walk(entry.value, depth + 1);
    }
  } else if (value is List) {
    if (value.length > 2000) _invalid();
    for (final item in value) {
      _walk(item, depth + 1);
    }
  } else if (value != null && value is! bool && value is! int) {
    _invalid();
  }
}

Map<String, Object?> _jsonCopy(Map<String, Object?> value) =>
    _object(jsonDecode(jsonEncode(value)));
List<Object?> _jsonCopyList(List<Map<String, Object?>> value) =>
    (jsonDecode(jsonEncode(value)) as List).cast<Object?>();
Object? _freeze(Object? value) => switch (value) {
  Map value => _freezeMap(Map<String, Object?>.from(value)),
  List value => List<Object?>.unmodifiable(value.map(_freeze)),
  _ => value,
};
Map<String, Object?> _freezeMap(Map<String, Object?> value) =>
    Map<String, Object?>.unmodifiable(
      value.map((k, v) => MapEntry(k, _freeze(v))),
    );
