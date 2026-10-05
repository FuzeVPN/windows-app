// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:collection';
import 'dart:io';

import 'package:flutter/services.dart';

import 'diagnostics_models.dart';

/// Structured failure metadata only; implementations must never expose bodies,
/// credentials, addresses or arbitrary exception text through these fields.
abstract interface class DiagnosticFailureDetails {
  String get diagnosticFailureCode;
  int? get diagnosticWindowsError;
  int? get diagnosticHttpStatus;
}

/// Writes a small, local, secret-free execution trace for VPN operations.
///
/// Callers may provide only stable identifiers. Messages, API bodies, tunnel
/// configurations, addresses, keys, tokens and exception details are never
/// accepted by this API.
class DiagnosticLog {
  DiagnosticLog._();

  static const _maxBytes = 1024 * 1024;
  static final RegExp _safeIdentifier = RegExp(r'^[a-z0-9_.-]{1,80}$');
  static const _maxPendingLines = 256;
  static final _pending = Queue<String>();
  static final _recent = Queue<String>();
  static int _nextRequestId = 0;
  static Future<void>? _writer;
  static final _observers = <void Function(String, String, String?)>{};

  static List<String> get recentLines => List.unmodifiable(_recent);

  static const tlsFailureReasons = <String>{
    'certificate_expired',
    'certificate_not_yet_valid',
    'certificate_hostname_mismatch',
    'certificate_issuer_missing',
    'certificate_self_signed',
    'certificate_revoked',
    'certificate_verify_failed',
    'protocol_rejected',
    'handshake_rejected',
    'peer_closed',
  };

  /// Dart puts BoringSSL's verification detail in OSError.message, separate
  /// from the generic HandshakeException.message. Inspect both in memory,
  /// returning only fixed references; neither source message is exported.
  static String? tlsFailureReason(TlsException error) {
    final detail = '${error.message} ${error.osError?.message ?? ''}'
        .toUpperCase();
    if (detail.contains('CERTIFICATE_VERIFY_FAILED')) {
      if (detail.contains('CERTIFICATE HAS EXPIRED')) {
        return 'certificate_expired';
      }
      if (detail.contains('CERTIFICATE IS NOT YET VALID')) {
        return 'certificate_not_yet_valid';
      }
      if (detail.contains('HOSTNAME MISMATCH') ||
          detail.contains('IP ADDRESS MISMATCH')) {
        return 'certificate_hostname_mismatch';
      }
      if (detail.contains('UNABLE TO GET LOCAL ISSUER CERTIFICATE') ||
          detail.contains('UNABLE TO GET ISSUER CERTIFICATE') ||
          detail.contains('UNABLE TO VERIFY THE FIRST CERTIFICATE')) {
        return 'certificate_issuer_missing';
      }
      if (detail.contains('SELF-SIGNED CERTIFICATE') ||
          detail.contains('SELF SIGNED CERTIFICATE')) {
        return 'certificate_self_signed';
      }
      if (detail.contains('CERTIFICATE REVOKED')) {
        return 'certificate_revoked';
      }
      return 'certificate_verify_failed';
    }
    if (detail.contains('WRONG_VERSION_NUMBER') ||
        detail.contains('UNSUPPORTED_PROTOCOL') ||
        detail.contains('ALERT_PROTOCOL_VERSION')) {
      return 'protocol_rejected';
    }
    if (detail.contains('HANDSHAKE_FAILURE')) return 'handshake_rejected';
    if (detail.contains('CONNECTION TERMINATED DURING HANDSHAKE')) {
      return 'peer_closed';
    }
    return null;
  }

  static int nextRequestId() {
    _nextRequestId = (_nextRequestId % 0x7ffffffe) + 1;
    return _nextRequestId;
  }

  /// Observers receive identifiers only. They must not perform synchronous I/O;
  /// a collector failure must never affect a VPN operation.
  static void Function() observe(
    void Function(String area, String event, String? code) observer,
  ) {
    _observers.add(observer);
    return () => _observers.remove(observer);
  }

  static String? get filePath {
    final localAppData = Platform.environment['LOCALAPPDATA'];
    if (localAppData == null || localAppData.isEmpty) return null;
    return '$localAppData${Platform.pathSeparator}FuzeVPN'
        '${Platform.pathSeparator}diagnostic.log';
  }

  static Future<void> record({
    required String area,
    required String event,
    String? code,
    String? stage,
    int? durationMs,
    int? windowsError,
    int? tlsError,
    int? trustStatus,
    int? httpStatus,
    int? requestId,
    int? connectionId,
    int? attempt,
    String? family,
    String? errorKind,
    String? reason,
    int? count,
    int? bytes,
  }) {
    final safeArea = _sanitize(area);
    final safeEvent = _sanitize(event);
    final safeCode = code == null ? null : _sanitize(code);
    for (final observer in _observers.toList(growable: false)) {
      try {
        observer(safeArea, safeEvent, safeCode);
      } catch (_) {
        // Diagnostics are strictly best-effort and outside the VPN lifecycle.
      }
    }
    final line = <String>[
      DateTime.now().toUtc().toIso8601String(),
      'area=$safeArea',
      'event=$safeEvent',
      if (safeCode != null) 'code=$safeCode',
      if (stage != null) 'stage=${_sanitize(stage)}',
      if (_inRange(durationMs, 0, 86400000)) 'duration_ms=$durationMs',
      if (_inRange(windowsError, -0x80000000, 0xffffffff))
        'windows_error=$windowsError',
      if (_inRange(tlsError, -0x80000000, 0x7fffffff)) 'tls_error=$tlsError',
      if (_inRange(trustStatus, 0, 0xffffffff)) 'trust_status=$trustStatus',
      if (_inRange(httpStatus, 100, 599)) 'http_status=$httpStatus',
      if (_inRange(requestId, 1, 0x7fffffff)) 'request_id=$requestId',
      if (_inRange(connectionId, 1, 0x7fffffff)) 'connection_id=$connectionId',
      if (_inRange(attempt, 1, 32)) 'attempt=$attempt',
      if (const {'ipv4', 'ipv6', 'system'}.contains(family)) 'family=$family',
      if (errorKind != null) 'error_kind=${_sanitize(errorKind)}',
      if (reason != null) 'reason=${_sanitize(reason)}',
      if (_inRange(count, 0, 1000000)) 'count=$count',
      if (_inRange(bytes, 0, 0x7fffffff)) 'bytes=$bytes',
    ].join(' ');

    if (_recent.length == 1024) _recent.removeFirst();
    _recent.addLast(line);

    // Bound memory during slow disk/antivirus operations. Keep the most
    // recent diagnostics and serialize rotation with appends.
    if (_pending.length == _maxPendingLines) _pending.removeFirst();
    _pending.addLast(line);
    unawaited(_writer ??= _drain());
    // Existing callers may await record; disk latency must never become a
    // dependency of the VPN command itself.
    return Future<void>.value();
  }

  static Future<void> recordFailure({
    required String area,
    required String event,
    required Object error,
    String? stage,
    int? durationMs,
    int? requestId,
    int? connectionId,
    int? attempt,
    String? family,
  }) {
    String code = 'unexpected_error';
    String kind = 'unexpected';
    String? reason;
    int? windowsError;
    int? tlsError;
    int? httpStatus;
    if (error is DiagnosticFailureDetails) {
      final reference = error.diagnosticFailureCode;
      code = _knownFailureCode(reference) ? reference : 'unexpected_error';
      kind = 'structured';
      windowsError = error.diagnosticWindowsError;
      httpStatus = error.diagnosticHttpStatus;
    } else if (error is HandshakeException || error is TlsException) {
      code = 'tls_handshake_failed';
      kind = 'tls';
      final tls = error as TlsException;
      // This is BoringSSL's status (often -1), not a Windows system code.
      tlsError = tls.osError?.errorCode;
      reason = tlsFailureReason(tls);
    } else if (error is SocketException) {
      code = 'network_error';
      kind = 'socket';
      windowsError = error.osError?.errorCode;
    } else if (error is TimeoutException) {
      code = 'request_timeout';
      kind = 'timeout';
    } else if (error is HttpException) {
      code = 'network_error';
      kind = 'http_transport';
    } else if (error is MissingPluginException) {
      code = 'native_bridge_unavailable';
      kind = 'native_bridge';
    } else if (error is PlatformException) {
      code = _knownFailureCode(error.code)
          ? error.code
          : 'native_operation_failed';
      kind = 'native_bridge';
      final details = error.details;
      final value = details is Map ? details['win32_error'] : null;
      if (value is int) windowsError = value;
      final nativeStage = details is Map ? details['stage'] : null;
      if (const {
            'broker_unavailable',
            'broker_write_failed',
            'broker_response_timeout',
            'installation_required',
          }.contains(error.code) &&
          const {
            'broker_connection',
            'broker_write',
            'broker_response',
          }.contains(nativeStage)) {
        stage = nativeStage as String;
      }
    } else if (error is FormatException || error is TypeError) {
      code = 'invalid_response';
      kind = 'format';
    } else if (error is FileSystemException || error is OSError) {
      code = 'storage_io_error';
      kind = 'storage';
      windowsError = error is FileSystemException
          ? error.osError?.errorCode
          : (error as OSError).errorCode;
    }
    return record(
      area: area,
      event: event,
      code: code,
      stage: stage,
      durationMs: durationMs,
      windowsError: windowsError,
      tlsError: tlsError,
      httpStatus: httpStatus,
      requestId: requestId,
      connectionId: connectionId,
      attempt: attempt,
      family: family,
      errorKind: kind,
      reason: reason,
    );
  }

  static bool _inRange(int? value, int minimum, int maximum) =>
      value != null && value >= minimum && value <= maximum;

  static bool _knownFailureCode(String value) =>
      diagnosticCodes.contains(value) ||
      const {
        'api_resolver_invalid_response',
        'runtime_detection_failed',
        'runtime_owned_by_another_user',
        'maintenance_in_progress',
        'invalid_argument',
      }.contains(value);

  /// Waits for diagnostics when explicitly needed, e.g. a local export/test.
  static Future<void> flush() => _writer ?? Future<void>.value();

  static String _sanitize(String value) =>
      _safeIdentifier.hasMatch(value) ? value : 'redacted';

  static Future<void> _drain() async {
    try {
      while (_pending.isNotEmpty) {
        final batch = <String>[];
        while (_pending.isNotEmpty) {
          batch.add(_pending.removeFirst());
        }
        try {
          await _append(batch.join('\r\n'));
        } on FileSystemException {
          // Logging failure must not change the result of a VPN operation.
        }
      }
    } finally {
      _writer = null;
    }
  }

  static Future<void> _append(String line) async {
    final path = filePath;
    if (path == null) return;
    final file = File(path);
    await file.parent.create(recursive: true);
    if (await file.exists() && await file.length() >= _maxBytes) {
      final previous = File('$path.previous');
      if (await previous.exists()) await previous.delete();
      await file.rename(previous.path);
    }
    await file.writeAsString('$line\r\n', mode: FileMode.append, flush: true);
  }
}
