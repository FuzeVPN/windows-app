// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/diagnostics_store.dart';

import 'diagnostics_api_test.dart' show syntheticReceipt;
import 'diagnostics_models_test.dart' show syntheticReport;

void main() {
  test(
    'cancellation while persisting a manual report cannot resurrect delivery',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      final gate = Completer<void>();
      fixture.store.enqueueGate = gate.future;
      final report = fixture.controller.prepareManualReport()!;
      final sending = fixture.controller.sendPreparedReport(report);
      await _settle();
      await fixture.controller.cancel(report.reportId);
      gate.complete();
      expect(await sending, isFalse);
      expect(fixture.store.entries, isEmpty);
      expect(fixture.api.calls, isEmpty);
      await fixture.bind('a');
      expect(fixture.api.calls, isEmpty);
      expect(await fixture.controller.sendPreparedReport(report), isTrue);
      expect(fixture.api.calls.single.reportId, report.reportId);
    },
  );
  test(
    'preview and checks work signed out; neither collect nor prepare sends',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      final result = await fixture.controller.runChecks();
      expect(result?['runtime'], isNotNull);
      final preview = fixture.controller.prepareManualReport();
      expect(preview, isNotNull);
      expect(preview!.json.containsKey('runtime'), false);
      expect(fixture.api.calls, isEmpty);
      expect(fixture.store.entries, isEmpty);
      expect(await fixture.controller.sendPreparedReport(preview), false);
      await fixture.bind('a');
      expect(await fixture.controller.sendPreparedReport(preview), true);
      expect(fixture.api.tokens, ['token-a']);
    },
  );
  test('a report prepared for account A never crosses to account B', () async {
    final fixture = _Fixture();
    addTearDown(fixture.dispose);
    await fixture.bind('a');
    final report = fixture.controller.prepareManualReport()!;
    await fixture.bind('b');
    expect(await fixture.controller.sendPreparedReport(report), false);
    expect(fixture.controller.lastFailure?.code, 'diagnostic_account_changed');
    expect(fixture.api.calls, isEmpty);
  });
  test(
    'unknown delivery retries exactly the same frozen bytes and account',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      fixture.api.failure = const ApiException(
        statusCode: 503,
        observedHttpStatus: 503,
        errorCode: 'diagnostics_unavailable',
        retryAfterSeconds: 60,
      );
      final report = fixture.controller.prepareManualReport()!;
      expect(await fixture.controller.sendPreparedReport(report), false);
      expect(fixture.api.calls.length, 1);
      await fixture.controller.retry(report.reportId);
      expect(
        fixture.api.calls.length,
        1,
        reason: 'manual retry cannot bypass Retry-After',
      );
      fixture.now = fixture.now.add(const Duration(seconds: 61));
      fixture.api.failure = null;
      await fixture.controller.resumePending();
      expect(fixture.api.calls.length, 2);
      expect(fixture.api.calls[0].bytes, fixture.api.calls[1].bytes);
      expect(fixture.api.calls[0].reportId, fixture.api.calls[1].reportId);
      expect(fixture.api.tokens, ['token-a', 'token-a']);
      expect(fixture.controller.pendingReports, isEmpty);
      expect(
        fixture.controller.receipts.single.clientReportId,
        report.reportId,
      );
    },
  );
  test(
    '401 pauses diagnostics only until same-account validated session',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      fixture.api.failure = const ApiException(
        statusCode: 401,
        observedHttpStatus: 401,
        errorCode: 'unauthorized',
      );
      final report = fixture.controller.prepareManualReport()!;
      await fixture.controller.sendPreparedReport(report);
      expect(fixture.controller.isPausedForAuthentication, true);
      expect(fixture.controller.pendingReports.single.pausedForAuth, true);
      expect(fixture.controller.accountId, 'a');
      expect(fixture.store.entries.single.pausedForAuth, true);
      await fixture.controller.resumePending();
      expect(fixture.api.calls.length, 1);
      fixture.api.failure = null;
      await fixture.bind('a');
      expect(fixture.api.calls.length, 2);
      expect(fixture.api.calls.last.bytes, report.bytes);
      expect(fixture.controller.isPausedForAuthentication, false);
    },
  );
  for (final status in [400, 403, 404, 409, 413, 415]) {
    test(
      'HTTP $status is terminal and retry does not silently create a new UUID',
      () async {
        final fixture = _Fixture();
        addTearDown(fixture.dispose);
        await fixture.bind('a');
        fixture.api.failure = ApiException(
          statusCode: status,
          observedHttpStatus: status,
          errorCode: 'invalid_diagnostic',
        );
        final report = fixture.controller.prepareManualReport()!;
        await fixture.controller.sendPreparedReport(report);
        expect(
          fixture.controller.pendingReports.single.terminalCode,
          'invalid_diagnostic',
        );
        fixture.now = fixture.now.add(const Duration(hours: 1));
        expect(await fixture.controller.retry(report.reportId), false);
        await fixture.controller.resumePending();
        expect(fixture.api.calls.length, 1);
      },
    );
  }
  test(
    'cancelling while reading token prevents HTTP and removes queued report',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      final token = Completer<String?>();
      await fixture.controller.sessionChanged(
        accountId: 'a',
        tokenProvider: () => token.future,
      );
      await fixture.controller.resumePending();
      final report = fixture.controller.prepareManualReport()!;
      final sending = fixture.controller.sendPreparedReport(report);
      await _settle();
      expect(fixture.controller.isSending, true);
      await fixture.controller.cancel(report.reportId);
      expect(await sending, false);
      token.complete('token-a');
      await _settle();
      expect(fixture.api.calls, isEmpty);
      expect(fixture.store.entries, isEmpty);
    },
  );
  test(
    'session switch invalidates a delayed token read without blocking new account',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      final token = Completer<String?>();
      await fixture.controller.sessionChanged(
        accountId: 'a',
        tokenProvider: () => token.future,
      );
      final old = fixture.controller.prepareManualReport()!;
      final sending = fixture.controller.sendPreparedReport(old);
      await _settle();
      await fixture.bind('b');
      expect(await sending, false);
      token.complete('old-token');
      expect(
        await fixture.controller.sendPreparedReport(
          fixture.controller.prepareManualReport()!,
        ),
        true,
      );
      expect(fixture.api.tokens, ['token-b']);
      expect(fixture.store.account, 'b');
    },
  );
  test(
    'success arriving after logout cannot add a receipt or restart delivery',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      final delayed = Completer<void>();
      fixture.api.delay = delayed.future;
      final report = fixture.controller.prepareManualReport()!;
      final send = fixture.controller.sendPreparedReport(report);
      await _settle();
      await fixture.controller.suspendSession(purge: true);
      delayed.complete();
      await send;
      expect(fixture.controller.receipts, isEmpty);
      expect(fixture.store.entries, isEmpty);
      expect(fixture.controller.hasSession, false);
    },
  );
  test(
    'attempt reservation failure never sends and does not close injected API',
    () async {
      final fixture = _Fixture();
      await fixture.bind('a');
      fixture.store.failMark = true;
      await fixture.controller.sendPreparedReport(
        fixture.controller.prepareManualReport()!,
      );
      expect(fixture.api.calls, isEmpty);
      fixture.controller.dispose();
      expect(fixture.api.closed, false);
      fixture.api.close();
    },
  );
  test(
    'queue expires at 24h and a stale preview is never re-created',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      final report = fixture.controller.prepareManualReport()!;
      fixture.now = fixture.now.add(const Duration(hours: 24));
      expect(await fixture.controller.sendPreparedReport(report), false);
      expect(fixture.controller.lastFailure?.code, 'diagnostics_expired');
      expect(fixture.api.calls, isEmpty);
    },
  );
  test('20 requests per hour defer even an explicit send', () async {
    final fixture = _Fixture();
    addTearDown(fixture.dispose);
    await fixture.bind('a');
    fixture.store.rates.addAll(
      List.generate(
        20,
        (_) => DiagnosticRateAttempt(at: fixture.now, automatic: false),
      ),
    );
    final report = fixture.controller.prepareManualReport()!;
    await fixture.controller.sendPreparedReport(report);
    expect(fixture.api.calls, isEmpty);
    fixture.now = fixture.now.add(const Duration(hours: 1, seconds: 1));
    await fixture.controller.resumePending();
    expect(fixture.api.calls.single.reportId, report.reportId);
  });
  testWidgets('expiry refreshes the queue while authentication stays paused', (
    tester,
  ) async {
    final fixture = _Fixture();
    addTearDown(fixture.dispose);
    await fixture.bind('a');
    fixture.api.failure = const ApiException(
      statusCode: 401,
      observedHttpStatus: 401,
      errorCode: 'unauthorized',
    );
    await fixture.controller.sendPreparedReport(
      fixture.controller.prepareManualReport()!,
    );
    expect(fixture.controller.pendingReports, hasLength(1));
    final reads = fixture.store.reads;
    fixture.now = fixture.now.add(const Duration(hours: 24));
    await tester.pump(const Duration(hours: 24));
    expect(fixture.store.reads, greaterThan(reads));
    expect(fixture.controller.pendingReports, isEmpty);
    expect(fixture.controller.isPausedForAuthentication, isTrue);
    expect(fixture.api.calls, hasLength(1));
  });
  test(
    '10 automatic attempts per hour and 5 per report are independent budgets',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      fixture.store.consent = true;
      final first = syntheticReport(manual: false, createdAt: fixture.now);
      fixture.store.entries.add(
        QueuedDiagnosticReport(
          report: first,
          expiresAt: fixture.now.add(const Duration(hours: 24)),
          attempts: 5,
          automaticAttempts: 5,
        ),
      );
      await fixture.controller.resumePending();
      expect(fixture.api.calls, isEmpty);
      final second = syntheticReport(manual: false, createdAt: fixture.now);
      fixture.store.entries.add(
        QueuedDiagnosticReport(
          report: second,
          expiresAt: fixture.now.add(const Duration(hours: 24)),
        ),
      );
      fixture.store.rates.addAll(
        List.generate(
          10,
          (_) => DiagnosticRateAttempt(at: fixture.now, automatic: true),
        ),
      );
      await fixture.controller.resumePending();
      expect(fixture.api.calls, isEmpty);
      fixture.now = fixture.now.add(const Duration(hours: 1, seconds: 1));
      await fixture.controller.resumePending();
      expect(fixture.api.calls.single.reportId, second.reportId);
    },
  );
  test('manual reports are drained before automatic reports', () async {
    final fixture = _Fixture();
    addTearDown(fixture.dispose);
    await fixture.bind('a');
    fixture.store.consent = true;
    final automatic = syntheticReport(manual: false, createdAt: fixture.now);
    final manual = syntheticReport(full: true, createdAt: fixture.now);
    for (final report in [automatic, manual]) {
      fixture.store.entries.add(
        QueuedDiagnosticReport(
          report: report,
          expiresAt: fixture.now.add(const Duration(hours: 24)),
        ),
      );
    }
    await fixture.controller.resumePending();
    expect(fixture.api.calls.map((r) => r.reportId), [
      manual.reportId,
      automatic.reportId,
    ]);
  });
  testWidgets(
    'automatic opt-in batches terminal incidents and excludes expected failures',
    (tester) async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      final error = DiagnosticError(
        code: 'openvpn_dns_configuration_failed',
        stage: 'dns_apply',
      );
      fixture.controller.recordTerminalError(error);
      await tester.pump(const Duration(seconds: 3));
      expect(fixture.api.calls, isEmpty);
      await fixture.controller.setAutomaticConsent(true);
      fixture.controller.recordTerminalError(error);
      fixture.controller.recordTerminalError(error);
      fixture.controller.recordTerminalError(
        DiagnosticError(code: 'rate_limited'),
      );
      fixture.controller.recordTerminalError(
        DiagnosticError(code: 'network_timeout'),
        terminal: false,
      );
      await tester.pump(const Duration(seconds: 3));
      await fixture.controller.resumePending();
      expect(fixture.api.calls.length, 1);
      expect(fixture.api.calls.single.json['occurrences'], 2);
      expect(fixture.api.calls.single.full, false);
      expect(fixture.api.calls.single.json.containsKey('events'), false);
    },
  );
  test('opt-out remains effective in memory when persistence fails', () async {
    final fixture = _Fixture();
    addTearDown(fixture.dispose);
    await fixture.bind('a');
    await fixture.controller.setAutomaticConsent(true);
    fixture.store.failConsent = true;
    expect(await fixture.controller.setAutomaticConsent(false), false);
    await fixture.controller.resumePending();
    expect(fixture.controller.automaticConsent, false);
    await fixture.bind('a');
    expect(fixture.controller.automaticConsent, false);
  });
  testWidgets(
    'revoking then renewing opt-in cancels the old batch and allows a new one',
    (tester) async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      final error = DiagnosticError(code: 'openvpn_dns_configuration_failed');
      await fixture.controller.setAutomaticConsent(true);
      fixture.controller.recordTerminalError(error);
      await fixture.controller.setAutomaticConsent(false);
      await tester.pump(const Duration(seconds: 3));
      expect(fixture.api.calls, isEmpty);
      await fixture.controller.setAutomaticConsent(true);
      fixture.controller.recordTerminalError(error);
      await tester.pump(const Duration(seconds: 3));
      await fixture.controller.resumePending();
      expect(fixture.api.calls.length, 1);
      expect(fixture.api.calls.single.json['occurrences'], 1);
    },
  );
  test('a late opt-in acknowledgement cannot undo a newer opt-out', () async {
    final fixture = _Fixture();
    addTearDown(fixture.dispose);
    await fixture.bind('a');
    final ack = Completer<void>();
    fixture.store.consentAck = ack.future;
    final enabling = fixture.controller.setAutomaticConsent(true);
    await _settle();
    expect(await fixture.controller.setAutomaticConsent(false), true);
    ack.complete();
    expect(await enabling, false);
    expect(fixture.controller.automaticConsent, false);
    expect(fixture.store.consent, false);
  });
  test(
    'Retry-After pauses the account including a second manual report',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      fixture.api.failure = const ApiException(
        statusCode: 429,
        observedHttpStatus: 429,
        errorCode: 'rate_limited',
        retryAfterSeconds: 3600,
      );
      await fixture.controller.sendPreparedReport(
        fixture.controller.prepareManualReport()!,
      );
      await fixture.controller.sendPreparedReport(
        fixture.controller.prepareManualReport()!,
      );
      expect(fixture.api.calls.length, 1);
      expect(
        fixture.store.retryAfterUntil,
        fixture.now.add(const Duration(hours: 1)),
      );
    },
  );
  test(
    'failed deletion after cancel cannot restart a cancelled request',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      final delay = Completer<void>();
      fixture.api.delay = delay.future;
      final report = fixture.controller.prepareManualReport()!;
      final send = fixture.controller.sendPreparedReport(report);
      await _settle();
      fixture.store.failRemove = true;
      await fixture.controller.cancel(report.reportId);
      await send;
      await fixture.controller.resumePending();
      expect(fixture.api.calls.length, 1);
      delay.complete();
    },
  );
  test(
    'confirmed receipt is kept even if deleting the local copy fails',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      await fixture.bind('a');
      fixture.store.failRemove = true;
      expect(
        await fixture.controller.sendPreparedReport(
          fixture.controller.prepareManualReport()!,
        ),
        true,
      );
      await fixture.controller.resumePending();
      expect(fixture.api.calls.length, 1);
      expect(fixture.controller.receipts.length, 1);
      expect(
        fixture.controller.lastFailure?.code,
        'diagnostics_storage_failed',
      );
    },
  );
  test(
    'event ring uses monotonic 10-minute window and accounts for dropped events',
    () {
      final fixture = _Fixture();
      addTearDown(fixture.dispose);
      for (var i = 0; i < 2001; i++) {
        fixture.controller.recordEvent(
          DiagnosticEvent(stage: 'handshake', event: 'info'),
        );
      }
      final first = fixture.controller.prepareManualReport()!;
      expect((first.json['events'] as List).length, 2000);
      expect(first.json['dropped_events'], 1);
      fixture.monotonic = const Duration(minutes: 11);
      fixture.now = fixture.now.subtract(const Duration(days: 1));
      fixture.controller.recordEvent(
        DiagnosticEvent(stage: 'cleanup', event: 'end'),
      );
      final later = fixture.controller.prepareManualReport()!;
      expect((later.json['events'] as List).length, 1);
      expect((later.json['events'] as List).single['offset_ms'], 600000);
      expect(later.json['dropped_events'], 2001);
      expect(later.json['truncated'], true);
    },
  );
}

Future<void> _settle() async {
  for (var i = 0; i < 20; i++) {
    await Future<void>.delayed(Duration.zero);
  }
}

class _Fixture {
  _Fixture() {
    controller = DiagnosticsController(
      api: api,
      store: store,
      now: () => now,
      monotonic: () => monotonic,
      random: () => 0,
      collectSnapshot: () async => {
        'protocol': 'openvpn',
        'state': 'error',
        'checks': [
          {
            'id': 'dns',
            'result': 'failed',
            'code': 'openvpn_dns_configuration_failed',
          },
        ],
        'runtime': {
          'presence': 'present',
          'protocol': 'openvpn',
          'cleanup_eligible': true,
        },
      },
    );
  }
  DateTime now = DateTime.utc(2026, 9, 16, 12);
  Duration monotonic = Duration.zero;
  final store = _MemoryStore();
  final api = _Api();
  late final DiagnosticsController controller;
  Future<void> bind(String account) async {
    await controller.sessionChanged(
      accountId: account,
      tokenProvider: () async => 'token-$account',
    );
    await controller.resumePending();
  }

  void dispose() {
    controller.dispose();
    api.close();
  }
}

class _Api extends ApiClient {
  _Api() : super(baseUri: Uri.parse('http://127.0.0.1'));
  final calls = <FrozenDiagnosticReport>[];
  final tokens = <String>[];
  Object? failure;
  Future<void>? delay;
  bool closed = false;
  @override
  Future<DiagnosticReceipt> submitDiagnostic({
    required String token,
    required FrozenDiagnosticReport report,
    DiagnosticRequestCancellation? cancellation,
  }) async {
    cancellation?.check();
    calls.add(report);
    tokens.add(token);
    if (delay != null) await (cancellation?.wait(delay!) ?? delay!);
    if (failure != null) throw failure!;
    return DiagnosticReceipt.fromJson(
      Map<String, dynamic>.from(syntheticReceipt(report.reportId)),
      expectedClientId: report.reportId,
      httpStatus: 201,
    );
  }

  @override
  void close() {
    closed = true;
    super.close();
  }
}

class _MemoryStore extends DiagnosticsStore {
  Future<void>? enqueueGate;
  int reads = 0;
  String? account;
  int generation = 0;
  bool consent = false;
  bool failMark = false;
  bool failConsent = false;
  bool failRemove = false;
  Future<void>? consentAck;
  DateTime? retryAfterUntil;
  final entries = <QueuedDiagnosticReport>[];
  final rates = <DiagnosticRateAttempt>[];
  void guard(int actual) {
    if (actual != generation) {
      throw const DiagnosticsFailure('diagnostics_stale_session');
    }
  }

  @override
  Future<void> bindSession({
    required String? accountId,
    required int generation,
    bool purgePrevious = false,
  }) async {
    this.generation = generation;
    if (purgePrevious ||
        (account != null && accountId != null && account != accountId)) {
      entries.clear();
      rates.clear();
      consent = false;
    }
    if (accountId != null || purgePrevious) account = accountId;
  }

  @override
  Future<DiagnosticsStoreState> readState(int generation) async {
    reads++;
    guard(generation);
    return DiagnosticsStoreState(
      automaticConsent: consent,
      reports: List.of(entries),
      rateAttempts: List.of(rates),
      retryAfterUntil: retryAfterUntil,
    );
  }

  @override
  Future<void> setConsent({
    required int generation,
    required bool enabled,
  }) async {
    guard(generation);
    if (failConsent) {
      throw const DiagnosticsFailure('diagnostics_storage_failed');
    }
    consent = enabled;
    if (enabled && consentAck != null) await consentAck;
  }

  @override
  Future<void> enqueue({
    required int generation,
    required FrozenDiagnosticReport report,
  }) async {
    guard(generation);
    await enqueueGate;
    guard(generation);
    final existing = entries.where((e) => e.reportId == report.reportId);
    if (existing.isNotEmpty) {
      if (utf8.decode(existing.single.report.bytes) !=
          utf8.decode(report.bytes)) {
        throw const DiagnosticsFailure('diagnostics_conflict');
      }
      return;
    }
    entries.add(
      QueuedDiagnosticReport(
        report: report,
        expiresAt: report.createdAt.add(const Duration(hours: 24)),
      ),
    );
  }

  @override
  Future<void> markAttempt({
    required int generation,
    required String reportId,
    required DateTime at,
    required bool automatic,
  }) async {
    guard(generation);
    if (failMark) throw const DiagnosticsFailure('diagnostics_storage_failed');
    final index = entries.indexWhere((e) => e.reportId == reportId);
    final value = entries[index];
    entries[index] = QueuedDiagnosticReport(
      report: value.report,
      expiresAt: value.expiresAt,
      attempts: value.attempts + 1,
      automaticAttempts: value.automaticAttempts + (automatic ? 1 : 0),
      nextAttemptAt: value.nextAttemptAt,
      pausedForAuth: value.pausedForAuth,
      terminalCode: value.terminalCode,
    );
    rates.add(DiagnosticRateAttempt(at: at, automatic: automatic));
  }

  @override
  Future<void> updateReport({
    required int generation,
    required String reportId,
    DateTime? nextAttemptAt,
    DateTime? accountRetryAfter,
    bool pausedForAuth = false,
    String? terminalCode,
  }) async {
    guard(generation);
    if (accountRetryAfter != null &&
        (retryAfterUntil == null ||
            accountRetryAfter.isAfter(retryAfterUntil!))) {
      retryAfterUntil = accountRetryAfter;
    }
    final index = entries.indexWhere((e) => e.reportId == reportId);
    if (index == -1) throw const DiagnosticsFailure('diagnostics_not_found');
    final value = entries[index];
    entries[index] = QueuedDiagnosticReport(
      report: value.report,
      expiresAt: value.expiresAt,
      attempts: value.attempts,
      automaticAttempts: value.automaticAttempts,
      nextAttemptAt: nextAttemptAt,
      pausedForAuth: pausedForAuth,
      terminalCode: terminalCode,
    );
  }

  @override
  Future<void> remove({
    required int generation,
    required String reportId,
  }) async {
    guard(generation);
    if (failRemove) {
      throw const DiagnosticsFailure('diagnostics_storage_failed');
    }
    entries.removeWhere((e) => e.reportId == reportId);
  }

  @override
  Future<void> clear({
    required int generation,
    bool revokeConsent = true,
  }) async {
    guard(generation);
    entries.clear();
    if (revokeConsent) consent = false;
  }
}
