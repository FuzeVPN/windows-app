// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('com.fuzevpn/windows_diagnostics');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

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
