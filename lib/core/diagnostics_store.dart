// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';

import 'diagnostics_models.dart';

class QueuedDiagnosticReport {
  const QueuedDiagnosticReport({
    required this.report,
    required this.expiresAt,
    this.attempts = 0,
    this.automaticAttempts = 0,
    this.nextAttemptAt,
    this.pausedForAuth = false,
    this.terminalCode,
  });
  final FrozenDiagnosticReport report;
  final DateTime expiresAt;
  final int attempts;
  final int automaticAttempts;
  final DateTime? nextAttemptAt;
  final bool pausedForAuth;
  final String? terminalCode;
  String get reportId => report.reportId;
  bool get manual => report.manual;

  factory QueuedDiagnosticReport.fromMap(Map<Object?, Object?> value) {
    final raw = value['body'];
    if (raw is! Uint8List) {
      throw const FormatException('Invalid diagnostic queue body.');
    }
    final report = FrozenDiagnosticReport.fromBytes(raw);
    if (value['report_id'] != report.reportId ||
        value['manual'] != report.manual ||
        value['created_at'] != report.createdAt.millisecondsSinceEpoch ||
        value['expires_at'] is! int ||
        value['attempts'] is! int ||
        value['automatic_attempts'] is! int ||
        value['paused_for_auth'] is! bool) {
      throw const FormatException('Invalid diagnostic queue metadata.');
    }
    final expires = DateTime.fromMillisecondsSinceEpoch(
      value['expires_at'] as int,
      isUtc: true,
    );
    final attempts = value['attempts'] as int;
    final automatic = value['automatic_attempts'] as int;
    if (attempts < 0 ||
        automatic < 0 ||
        automatic > 5 ||
        automatic > attempts ||
        !expires.isAfter(report.createdAt) ||
        expires.isAfter(report.createdAt.add(const Duration(hours: 24))) ||
        (value['next_attempt_at'] != null &&
            value['next_attempt_at'] is! int) ||
        (value['terminal_code'] != null && value['terminal_code'] is! String)) {
      throw const FormatException('Invalid diagnostic queue limits.');
    }
    return QueuedDiagnosticReport(
      report: report,
      expiresAt: expires,
      attempts: attempts,
      automaticAttempts: automatic,
      nextAttemptAt: value['next_attempt_at'] == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(
              value['next_attempt_at'] as int,
              isUtc: true,
            ),
      pausedForAuth: value['paused_for_auth'] as bool,
      terminalCode: value['terminal_code'] as String?,
    );
  }
}

class DiagnosticRateAttempt {
  const DiagnosticRateAttempt({required this.at, required this.automatic});
  final DateTime at;
  final bool automatic;
}

class DiagnosticsStoreState {
  const DiagnosticsStoreState({
    this.automaticConsent = false,
    this.reports = const [],
    this.rateAttempts = const [],
    this.retryAfterUntil,
  });
  final bool automaticConsent;
  final List<QueuedDiagnosticReport> reports;
  final List<DiagnosticRateAttempt> rateAttempts;
  final DateTime? retryAfterUntil;

  factory DiagnosticsStoreState.fromMap(Map<Object?, Object?> value) {
    if (value['automatic_consent'] is! bool ||
        value['notice_version'] != 1 ||
        value['reports'] is! List ||
        value['rate_attempts'] is! List) {
      throw const FormatException('Invalid diagnostic queue state.');
    }
    final reports = (value['reports'] as List)
        .map(
          (item) => QueuedDiagnosticReport.fromMap(
            Map<Object?, Object?>.from(item as Map),
          ),
        )
        .toList();
    if (reports.length > 10 ||
        reports.map((r) => r.reportId).toSet().length != reports.length ||
        reports.fold<int>(0, (size, r) => size + r.report.bytes.length) >
            20 * 1024 * 1024) {
      throw const FormatException('Invalid diagnostic queue size.');
    }
    final rates = <DiagnosticRateAttempt>[];
    for (final item in value['rate_attempts'] as List) {
      if (item is! Map || item['at'] is! int || item['automatic'] is! bool) {
        throw const FormatException('Invalid diagnostic attempt.');
      }
      rates.add(
        DiagnosticRateAttempt(
          at: DateTime.fromMillisecondsSinceEpoch(
            item['at'] as int,
            isUtc: true,
          ),
          automatic: item['automatic'] as bool,
        ),
      );
    }
    return DiagnosticsStoreState(
      automaticConsent: value['automatic_consent'] as bool,
      reports: List.unmodifiable(reports),
      rateAttempts: List.unmodifiable(rates),
      retryAfterUntil: value['retry_after_until'] == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(
              value['retry_after_until'] as int,
              isUtc: true,
            ),
    );
  }
}

/// Dedicated GUI storage: no broker/UAC, no token, no generic secure-store size change.
/// Every call is bound to a native generation; stale async work cannot write into
/// the next account's queue. UTC timestamps here are local metadata, not payload fields.
class DiagnosticsStore {
  const DiagnosticsStore();
  static const _channel = MethodChannel('fuzevpn/diagnostics_store');
  Future<void> bindSession({
    required String? accountId,
    required int generation,
    bool purgePrevious = false,
  }) => _channel.invokeMethod<void>('bindSession', {
    'account_id': accountId,
    'generation': generation,
    'purge_previous': purgePrevious,
  });
  Future<DiagnosticsStoreState> readState(int generation) async {
    final value = await _channel.invokeMapMethod<Object?, Object?>(
      'readState',
      {'generation': generation},
    );
    if (value == null) {
      throw const DiagnosticsFailure('diagnostics_storage_failed');
    }
    return DiagnosticsStoreState.fromMap(value);
  }

  Future<void> setConsent({required int generation, required bool enabled}) =>
      _channel.invokeMethod<void>('setConsent', {
        'generation': generation,
        'enabled': enabled,
        'notice_version': 1,
      });
  Future<void> enqueue({
    required int generation,
    required FrozenDiagnosticReport report,
  }) => _channel.invokeMethod<void>('enqueue', {
    'generation': generation,
    'report_id': report.reportId,
    'body': report.bytes,
    'created_at': report.createdAt.millisecondsSinceEpoch,
    'expires_at': report.createdAt
        .add(const Duration(hours: 24))
        .millisecondsSinceEpoch,
    'manual': report.manual,
    'attempts': 0,
    'automatic_attempts': 0,
    'next_attempt_at': null,
    'paused_for_auth': false,
    'terminal_code': null,
  });
  Future<void> markAttempt({
    required int generation,
    required String reportId,
    required DateTime at,
    required bool automatic,
  }) => _channel.invokeMethod<void>('markAttempt', {
    'generation': generation,
    'report_id': reportId,
    'at': at.millisecondsSinceEpoch,
    'automatic': automatic,
  });
  Future<void> updateReport({
    required int generation,
    required String reportId,
    DateTime? nextAttemptAt,
    DateTime? accountRetryAfter,
    bool pausedForAuth = false,
    String? terminalCode,
  }) => _channel.invokeMethod<void>('updateReport', {
    'generation': generation,
    'report_id': reportId,
    'next_attempt_at': nextAttemptAt?.millisecondsSinceEpoch,
    'account_retry_after': accountRetryAfter?.millisecondsSinceEpoch,
    'paused_for_auth': pausedForAuth,
    'terminal_code': terminalCode,
  });
  Future<void> remove({required int generation, required String reportId}) =>
      _channel.invokeMethod<void>('remove', {
        'generation': generation,
        'report_id': reportId,
      });
  Future<void> clear({required int generation, bool revokeConsent = true}) =>
      _channel.invokeMethod<void>('clear', {
        'generation': generation,
        'revoke_consent': revokeConsent,
      });
}
