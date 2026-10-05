// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'diagnostics_support.dart';

/// Bounded, read-only native observations. This method never starts a runtime,
/// elevates, sends probes, reconnects or repairs the VPN.
class DiagnosticsBridge {
  static const _channel = MethodChannel('com.fuzevpn/windows_diagnostics');

  /// Collects service status and the sanitized native trace directly in the
  /// GUI process, including when its privileged broker cannot be contacted.
  Future<Map<String, Object?>> collectLocalDiagnostics() async {
    for (var attempt = 0; attempt < 40; attempt++) {
      final value = await _channel.invokeMapMethod<Object?, Object?>(
        'collectLocalDiagnostics',
      );
      if (value == null) {
        throw const FormatException('Complete native diagnostics unavailable.');
      }
      if (value['collection_pending'] != true) {
        return DiagnosticSupport.nativeObservation(value);
      }
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    throw const FormatException('Complete native diagnostics still pending.');
  }

  /// Only snapshot/checks/windows/environment may become report fragments.
  /// `runtime` is local UI capability information and must never be uploaded.
  Future<Map<String, Object?>> collectSnapshot() async {
    final elapsed = Stopwatch()..start();
    for (var attempt = 0; ; attempt++) {
      final snapshot = await _readSnapshot();
      final runtime = snapshot['runtime'];
      if (runtime is! Map ||
          runtime['collection_pending'] != true ||
          elapsed.elapsed >= const Duration(seconds: 8) ||
          attempt >= 80) {
        return snapshot;
      }
      // Release both native command queues between cache polls. An ongoing
      // passive Windows query cannot hold up a VPN connect/disconnect command.
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }

  Future<Map<String, Object?>> _readSnapshot() async {
    final value = await _channel.invokeMapMethod<Object?, Object?>(
      'collectSnapshot',
    );
    if (value == null) {
      throw const FormatException('Native diagnostic snapshot unavailable.');
    }
    Object? normalize(Object? value, int depth) {
      if (depth > 5) throw const FormatException('Invalid diagnostic depth.');
      if (value == null || value is bool || value is int || value is String) {
        return value;
      }
      if (value is List && value.length <= 64) {
        return value.map((item) => normalize(item, depth + 1)).toList();
      }
      if (value is Map && value.length <= 32) {
        final result = <String, Object?>{};
        for (final entry in value.entries) {
          if (entry.key is! String) {
            throw const FormatException('Invalid diagnostic key.');
          }
          result[entry.key as String] = normalize(entry.value, depth + 1);
        }
        return result;
      }
      throw const FormatException('Invalid diagnostic value.');
    }

    final normalized = normalize(value, 0) as Map<String, Object?>;
    const allowed = {'runtime', 'snapshot', 'checks', 'windows', 'environment'};
    if (normalized.keys.any((key) => !allowed.contains(key))) {
      throw const FormatException('Invalid diagnostic fragment.');
    }
    return normalized;
  }
}
