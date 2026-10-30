// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/diagnostics_support.dart';

/// Mirrors diagnostics_local.cpp for a well-formed line: the timestamp, then
/// key=value tokens whose decimal values become integers.
Map<String, Object?> _nativeLine(String line) {
  final tokens = line.split(' ');
  return {
    'timestamp': tokens.first,
    for (final token in tokens.skip(1))
      token.substring(0, token.indexOf('=')): switch (token.substring(
        token.indexOf('=') + 1,
      )) {
        final value when RegExp(r'^[0-9]{1,10}$').hasMatch(value) => int.parse(
          value,
        ),
        final value => value,
      },
  };
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('com.fuzevpn/windows_diagnostics');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  test(
    'the WireGuard attempt snapshot reaches the export with every field',
    () async {
      const line =
          '2026-10-28T00:22:36.395Z area=wireguard '
          'event=connection_attempt_snapshot candidates=1 candidate_index=0 '
          'stage=peer_ready handshake=0 success=0 elapsed_ms=14300 '
          'budget_ms=69000 service_start_ms=900 handshake_wait_ms=20000 '
          'stop_ms=1200 tx_bytes=592 rx_bytes=0 stats_reads=190';
      final snapshot = _nativeLine(line);
      expect(snapshot, hasLength(16));
      messenger.setMockMethodCallHandler(channel, (call) async {
        expect(call.method, 'collectLocalDiagnostics');
        return {
          'schema_version': 1,
          'native_log': {
            'status': 'ok',
            'truncated': false,
            'discarded_lines': 0,
            'events': [
              {
                ...snapshot,
                // Never part of the contract: dropped, never exported.
                'endpoint': '198.51.100.7:51820',
                'peer_key': 'private-key-material',
                'retries': 3,
              },
            ],
          },
        };
      });

      final observation = await DiagnosticsBridge().collectLocalDiagnostics();
      final log = observation['native_log'] as Map;
      expect(log['discarded_lines'], 0);
      final event = (log['events'] as List).single as Map<String, Object?>;
      expect(event, snapshot);
      // A complete report validates timeline entries without losing a key.
      expect(DiagnosticSupport.sanitizeNativeEvent(event), snapshot);

      for (final stage in [
        'starting',
        'adapter_open',
        'peer_ready',
        'connected',
      ]) {
        final kept = DiagnosticSupport.sanitizeNativeEvent({
          ...snapshot,
          'stage': stage,
        });
        expect(kept?['stage'], stage);
      }
      expect(
        DiagnosticSupport.sanitizeNativeEvent({
          ...snapshot,
          'tx_bytes': 0x100000000,
        }),
        isNot(contains('tx_bytes')),
      );
      expect(
        DiagnosticSupport.sanitizeNativeEvent({...snapshot, 'area': 'broker'}),
        isNull,
      );
    },
  );

  test('every numeric field the native reader keeps survives in Dart', () {
    final reader = File(
      'windows/runner/diagnostics_local.cpp',
    ).readAsStringSync();
    final start = reader.indexOf('Is(key, {"peer_ready"');
    expect(start, isNot(-1));
    final keys = RegExp(r'"([a-z0-9_]+)"')
        .allMatches(reader.substring(start, reader.indexOf('}))', start)))
        .map((match) => match.group(1)!)
        .toList();
    expect(keys, containsAll(['candidates', 'tx_bytes', 'rx_bytes']));
    for (final key in keys) {
      final event = DiagnosticSupport.sanitizeNativeEvent({
        'timestamp': '2026-10-28T00:22:36.395Z',
        'area': 'wireguard',
        'event': 'connection_attempt_snapshot',
        key: 7,
      });
      expect(event?[key], 7, reason: key);
    }
  });

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
