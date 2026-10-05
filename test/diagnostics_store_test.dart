// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/diagnostics_store.dart';

import 'diagnostics_models_test.dart' show syntheticReport;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('fuzevpn/diagnostics_store');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;

  test(
    'native queue receives frozen bytes and metadata but never a bearer',
    () async {
      final calls = <MethodCall>[];
      final report = syntheticReport(full: true);
      final expires = report.createdAt.add(const Duration(hours: 24));
      final retryAt = report.createdAt.add(const Duration(hours: 1));
      messenger.setMockMethodCallHandler(channel, (call) async {
        calls.add(call);
        if (call.method == 'readState') {
          return <String, Object?>{
            'notice_version': 1,
            'automatic_consent': false,
            'retry_after_until': retryAt.millisecondsSinceEpoch,
            'reports': [
              {
                'report_id': report.reportId,
                'body': report.bytes,
                'created_at': report.createdAt.millisecondsSinceEpoch,
                'expires_at': expires.millisecondsSinceEpoch,
                'manual': true,
                'attempts': 1,
                'automatic_attempts': 0,
                'next_attempt_at': null,
                'paused_for_auth': true,
                'terminal_code': null,
              },
            ],
            'rate_attempts': [
              {
                'at': report.createdAt.millisecondsSinceEpoch,
                'automatic': false,
              },
            ],
          };
        }
        return null;
      });
      addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
      const store = DiagnosticsStore();
      await store.bindSession(accountId: 'local-owner-only', generation: 7);
      await store.enqueue(generation: 7, report: report);
      await store.markAttempt(
        generation: 7,
        reportId: report.reportId,
        at: report.createdAt,
        automatic: false,
      );
      await store.updateReport(
        generation: 7,
        reportId: report.reportId,
        accountRetryAfter: retryAt,
        pausedForAuth: true,
      );
      final state = await store.readState(7);
      expect(state.reports.single.report.bytes, report.bytes);
      expect(state.reports.single.pausedForAuth, true);
      expect(state.retryAfterUntil, retryAt);
      expect(calls.map((c) => c.method), [
        'bindSession',
        'enqueue',
        'markAttempt',
        'updateReport',
        'readState',
      ]);
      for (final call in calls) {
        final args = call.arguments as Map;
        expect(args['generation'], 7);
        expect(args.keys, isNot(contains('token')));
        if (call.method != 'bindSession') {
          expect(args.keys, isNot(contains('account_id')));
        }
      }
      final enqueue = calls[1].arguments as Map;
      expect(enqueue['body'], report.bytes);
      expect(enqueue['expires_at'], expires.millisecondsSinceEpoch);
    },
  );

  test(
    'queue parser rejects mismatched identity, impossible attempts and extended retention',
    () {
      final report = syntheticReport();
      Map<Object?, Object?> metadata() => {
        'report_id': report.reportId,
        'body': report.bytes,
        'created_at': report.createdAt.millisecondsSinceEpoch,
        'expires_at': report.createdAt
            .add(const Duration(hours: 24))
            .millisecondsSinceEpoch,
        'manual': true,
        'attempts': 1,
        'automatic_attempts': 0,
        'next_attempt_at': null,
        'paused_for_auth': false,
        'terminal_code': null,
      };
      for (final changed in [
        {'report_id': 'wrong'},
        {'manual': false},
        {'automatic_attempts': 6},
        {'created_at': 0},
        {
          'expires_at': report.createdAt
              .add(const Duration(hours: 25))
              .millisecondsSinceEpoch,
        },
      ]) {
        expect(
          () => QueuedDiagnosticReport.fromMap({...metadata(), ...changed}),
          throwsFormatException,
        );
      }
    },
  );
}
