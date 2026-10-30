// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/diagnostics_support.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('com.fuzevpn/windows_diagnostics');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  test(
    'one rejected native section does not erase independently valid evidence',
    () {
      final value = DiagnosticSupport.nativeObservation({
        'schema_version': 1,
        'environment': {
          'installation_mode': 'installed',
          'private_path': 'secret',
        },
        'service': {
          'name': 'FuzeVPNService',
          'state': 'stopped',
          'query_stage': 'completed',
          'win32_exit_code': 50,
        },
        'runtime': {'presence': 'present'},
        'native_log': {
          'status': 'absent',
          'truncated': false,
          'discarded_lines': 0,
          'events': [],
        },
      });
      expect(value['environment'], isNull);
      expect((value['service'] as Map)['win32_exit_code'], 50);
      expect((value['collection'] as Map)['status'], 'rejected');
      expect((value['collection'] as Map)['discarded_lines'], 1);
    },
  );

  test(
    'native reader exception retains other sections and collection error',
    () {
      final value = DiagnosticSupport.nativeObservation({
        'schema_version': 1,
        'collection_error': 574,
        'environment': {'installation_mode': 'installed'},
        'runtime': {'presence': 'present'},
        'native_log': {
          'status': 'absent',
          'truncated': false,
          'discarded_lines': 0,
          'events': [],
        },
      });
      expect(value['service'], isNull);
      expect((value['environment'] as Map)['installation_mode'], 'installed');
      expect((value['collection'] as Map)['status'], 'read_failed');
      expect((value['collection'] as Map)['win32_error'], 574);
    },
  );

  testWidgets('local collection pending deadline is a timeout', (tester) async {
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {'schema_version': 1, 'collection_pending': true},
    );
    final pending = expectLater(
      DiagnosticsBridge().collectLocalDiagnostics(),
      throwsA(isA<TimeoutException>()),
    );
    await tester.pump();
    for (var poll = 0; poll < 40; poll++) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    await pending;
  });

  test('collects only a passive no-argument snapshot', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'collectSnapshot');
      expect(call.arguments, isNull);
      return {
        'runtime': {'presence': 'absent', 'cleanup_eligible': false},
        'snapshot': <String, Object?>{},
        'checks': [
          {'id': 'tunnel_connection', 'result': 'skipped'},
        ],
        'windows': <String, Object?>{},
      };
    });
    final snapshot = await DiagnosticsBridge().collectSnapshot();
    expect((snapshot['runtime'] as Map)['cleanup_eligible'], false);
    expect((snapshot['checks'] as List).single, {
      'id': 'tunnel_connection',
      'result': 'skipped',
    });
  });

  test('does not accept an unbounded or arbitrary native fragment', () async {
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {'raw_log': 'private'},
    );
    await expectLater(
      DiagnosticsBridge().collectSnapshot(),
      throwsFormatException,
    );
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {
        'checks': List.generate(65, (_) => {'id': 'dns', 'result': 'unknown'}),
      },
    );
    await expectLater(
      DiagnosticsBridge().collectSnapshot(),
      throwsFormatException,
    );
  });

  test('an unavailable native observation remains an error', () async {
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(code: 'runtime_status_unavailable');
    });
    await expectLater(
      DiagnosticsBridge().collectSnapshot(),
      throwsA(isA<PlatformException>()),
    );
  });

  test(
    'polling releases native requests while a passive collection runs',
    () async {
      var polls = 0;
      var outstanding = 0;
      messenger.setMockMethodCallHandler(channel, (call) async {
        expect(call.arguments, isNull);
        expect(++outstanding, 1);
        final pending = ++polls < 3;
        outstanding--;
        return {
          'runtime': {
            'presence': 'present',
            'cleanup_eligible': false,
            if (pending) 'collection_pending': true,
          },
          'checks': [
            {'id': 'routing', 'result': pending ? 'unknown' : 'passed'},
          ],
        };
      });
      final snapshot = await DiagnosticsBridge().collectSnapshot();
      expect(polls, 3);
      expect((snapshot['checks'] as List).single['result'], 'passed');
      expect((snapshot['runtime'] as Map)['collection_pending'], isNull);
    },
  );

  testWidgets('passive collection timeout retains unknown instead of success', (
    tester,
  ) async {
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {
        'runtime': {
          'presence': 'present',
          'cleanup_eligible': false,
          'collection_pending': true,
        },
        'checks': [
          {'id': 'routing', 'result': 'unknown'},
        ],
      },
    );
    Map<String, Object?>? result;
    final pending = DiagnosticsBridge().collectSnapshot().then(
      (value) => result = value,
    );
    await tester.pump();
    for (var poll = 0; poll < 80; poll++) {
      await tester.pump(const Duration(milliseconds: 100));
    }
    await pending;
    expect((result!['checks'] as List).single['result'], 'unknown');
    expect((result!['runtime'] as Map)['collection_pending'], isTrue);
  });
}
