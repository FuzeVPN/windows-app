// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/local_diagnostic_trace.dart';

String line(int second, {String event = 'started', String fields = ''}) =>
    '2026-10-05T20:34:${second.toString().padLeft(2, '0')}.001Z '
    'area=api_request event=$event${fields.isEmpty ? '' : ' $fields'}';

void main() {
  late Directory directory;
  late String path;
  setUp(() async {
    directory = await Directory.systemTemp.createTemp('fuzevpn-trace-test-');
    path = '${directory.path}${Platform.pathSeparator}diagnostic.log';
  });
  tearDown(() async {
    if (await directory.exists()) await directory.delete(recursive: true);
  });

  test(
    'absent disk files preserve current events with explicit source status',
    () async {
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [line(2, fields: 'code=login request_id=2')],
      );
      expect(result['status'], 'absent');
      expect(result['truncated'], false);
      expect(result['discarded_lines'], 0);
      expect(result['events'], [
        {
          'timestamp': '2026-10-05T20:34:02.001Z',
          'area': 'api_request',
          'event': 'started',
          'code': 'login',
          'request_id': 2,
        },
      ]);
      expect(jsonEncode(result), isNot(contains(directory.path)));
    },
  );

  test(
    'rotation and current memory are ordered and deduplicated by fields',
    () async {
      await File(
        '$path.previous',
      ).writeAsString('${line(1)}\r\n${line(2)}\r\n');
      await File(path).writeAsString('${line(3)}\r\n${line(2)}\r\n');
      final reordered =
          '2026-10-05T20:34:03.001Z event=started area=api_request';
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [reordered, line(4)],
      );
      expect(result['status'], 'ok');
      expect(result['discarded_lines'], 0);
      expect(
        (result['events'] as List).map((event) => (event as Map)['timestamp']),
        [
          '2026-10-05T20:34:01.001Z',
          '2026-10-05T20:34:02.001Z',
          '2026-10-05T20:34:03.001Z',
          '2026-10-05T20:34:04.001Z',
        ],
      );
    },
  );

  test('previous file alone remains available after rotation', () async {
    await File('$path.previous').writeAsString('${line(1)}\n');
    final result = await LocalDiagnosticTrace.collect(path: path);
    expect(result['status'], 'ok');
    expect(result['events'], hasLength(1));
  });

  test(
    'malformed UTF-8 rejects disk source without dropping memory events',
    () async {
      await File(path).writeAsBytes([0xff, 0xfe, 0xc3, 0x28]);
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [line(1)],
      );
      expect(result['status'], 'rejected');
      expect(result['discarded_lines'], 1);
      expect(result['events'], hasLength(1));
      expect(jsonEncode(result), isNot(contains('�')));
    },
  );

  test(
    'untrusted fields and syntactically safe secret identifiers are rejected',
    () async {
      final malicious = [
        line(1, fields: 'token=synthetic-token'),
        line(1, fields: 'code=synthetic-token'),
        line(1, event: 'synthetic-token'),
        line(1, fields: 'stage=synthetic-token'),
        line(1, fields: 'reason=synthetic-token'),
        line(1, fields: 'error_kind=synthetic-token'),
        line(1, fields: 'code=person@example.invalid'),
        line(1, fields: 'code=192.0.2.10'),
        line(1, fields: r'code=C:\Users\Private\secret'),
        line(1, fields: 'code=-----BEGIN-PRIVATE-KEY-----'),
        line(1, fields: 'area=account'),
        line(1, fields: 'http_status=999'),
        line(1, fields: 'request_id=-1'),
        '2026-10-32T20:34:01Z area=api_request event=started',
        '2026-10-05T20:34:01Z area=synthetic-token event=started',
      ];
      await File(path).writeAsString('${malicious.join('\n')}\n${line(2)}\n');
      final result = await LocalDiagnosticTrace.collect(path: path);
      expect(result['status'], 'rejected');
      expect(result['discarded_lines'], malicious.length);
      expect(result['events'], hasLength(1));
      final output = jsonEncode(result);
      for (final secret in [
        'synthetic-token',
        'person@',
        '192.0.2.10',
        'Private',
        'PRIVATE-KEY',
      ]) {
        expect(output, isNot(contains(secret)));
      }
    },
  );

  test('retains exact bounded Windows, TLS and observed HTTP metadata', () async {
    final result = await LocalDiagnosticTrace.collect(
      path: path,
      currentLines: [
        '2026-10-05T20:34:01Z area=wireguard event=network_protection_prepare_failed '
            'code=broker_unavailable stage=broker_connection duration_ms=259 '
            'windows_error=50 request_id=4 connection_id=5 attempt=1 family=system '
            'error_kind=native_bridge count=0 bytes=1024',
        '2026-10-05T20:34:02Z area=api_transport event=attempt_failed '
            'code=tls_handshake_failed stage=tls_handshake tls_error=-1 '
            'trust_status=2148204809 error_kind=tls reason=certificate_issuer_missing',
        line(
          3,
          event: 'response_received',
          fields: 'http_status=403 code=subscription_required',
        ),
      ],
    );
    final events = result['events'] as List;
    expect(events, hasLength(3));
    expect((events[0] as Map)['windows_error'], 50);
    expect((events[1] as Map)['tls_error'], -1);
    expect((events[1] as Map)['trust_status'], 2148204809);
    expect((events[1] as Map)['reason'], 'certificate_issuer_missing');
    expect((events[2] as Map)['http_status'], 403);
  });

  test('large files are bounded and retain the newest complete event', () async {
    final filler = '${line(1)}\n';
    await File(path).writeAsString(
      '${List.filled(5000, filler).join()}${line(59, fields: 'request_id=59')}\n',
    );
    final result = await LocalDiagnosticTrace.collect(path: path);
    expect(result['status'], 'ok');
    expect(result['truncated'], true);
    expect((result['discarded_lines'] as int), greaterThan(0));
    expect((result['events'] as List).last, containsPair('request_id', 59));
    expect((result['events'] as List).length, lessThanOrEqualTo(1024));
  });

  test(
    'combined files and memory enforce the event limit after deduplication',
    () async {
      final lines = List.generate(
        1600,
        (i) => line(1, fields: 'request_id=${i + 1}'),
      );
      await File(path).writeAsString('${lines.take(800).join('\n')}\n');
      await File(
        '$path.previous',
      ).writeAsString('${lines.skip(800).join('\n')}\n');
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: lines.take(500),
      );
      expect(result['status'], 'ok');
      expect(result['truncated'], true);
      expect(result['discarded_lines'], 576);
      expect(result['events'], hasLength(1024));
    },
  );

  test(
    'a directory in place of a trace file is rejected and not traversed',
    () async {
      await Directory(path).create();
      await File(
        '$path${Platform.pathSeparator}private.txt',
      ).writeAsString('synthetic-token');
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [line(1)],
      );
      expect(result['status'], 'rejected');
      expect(result['events'], hasLength(1));
      expect(jsonEncode(result), isNot(contains('synthetic-token')));
    },
  );

  test(
    'symlink files are rejected without exporting their target contents',
    () async {
      final target = File(
        '${directory.path}${Platform.pathSeparator}private.txt',
      );
      await target.writeAsString('${line(1)}\n');
      try {
        await Link(path).create(target.path);
      } on FileSystemException catch (error) {
        if (Platform.isWindows &&
            const {5, 1314}.contains(error.osError?.errorCode)) {
          markTestSkipped(
            'Windows account cannot create a test symbolic link.',
          );
          return;
        }
        rethrow;
      }
      final result = await LocalDiagnosticTrace.collect(path: path);
      expect(result['status'], 'rejected');
      expect(result['events'], isEmpty);
    },
  );

  test(
    'serialized events are revalidated against fields, enums and numeric bounds',
    () {
      final valid = <Object?, Object?>{
        'timestamp': '2026-10-05T20:34:01Z',
        'area': 'api_request',
        'event': 'started',
        'code': 'login',
        'request_id': 1,
      };
      expect(LocalDiagnosticTrace.sanitizeEvent(valid), isNotNull);
      for (final mutation in <Map<Object?, Object?>>[
        {...valid, 'token': 'synthetic-token'},
        {...valid, 'code': 'synthetic-token'},
        {...valid, 'request_id': '1'},
        {...valid, 'request_id': 0},
        {...valid, 'request_id': true},
        {...valid, 'timestamp': '2026-10-32T20:34:01Z'},
        {...valid, 'timestamp': '2026-10-05T20:34:01+02:00'},
        {...valid, null: 'private'},
      ]) {
        expect(LocalDiagnosticTrace.sanitizeEvent(mutation), isNull);
      }
    },
  );

  test(
    'authentication and complete diagnostic collection phases are retained',
    () async {
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [
          for (final stage in [
            'account_authentication',
            'local_identity',
            'saved_session_storage',
            'device_catalogue',
          ])
            '2026-10-05T20:34:01Z area=account event=begin stage=$stage',
          '2026-10-05T20:34:02Z area=runtime_state event=failed '
              'stage=native_snapshot code=runtime_status_unavailable',
          '2026-10-05T20:34:03Z area=startup event=failed '
              'stage=diagnostic_environment code=unexpected_error',
        ],
      );
      expect(result['events'], hasLength(6));
      expect(result['discarded_lines'], 0);
    },
  );

  test(
    'transport, location migration and precise update phases are retained',
    () async {
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [
          for (final stage in [
            'resolution',
            'tcp_connect',
            'system_dns_and_tcp',
          ])
            '2026-10-05T20:34:01Z area=api_transport event=connection_started stage=$stage',
          '2026-10-05T20:34:02Z area=account event=failed '
              'stage=location_migration code=unexpected_error',
          '2026-10-05T20:34:03Z area=update event=manual_installation_required '
              'stage=update_check code=update_installer_manual',
          '2026-10-05T20:34:04Z area=update event=check_succeeded code=manual_installation',
          '2026-10-05T20:34:05Z area=update event=failed '
              'stage=package_hash code=update_hash_mismatch',
        ],
      );
      expect(result['events'], hasLength(7));
      expect(result['discarded_lines'], 0);
    },
  );

  test(
    'expected operation cancellation remains exact without a false failure code',
    () async {
      final result = await LocalDiagnosticTrace.collect(
        path: path,
        currentLines: [
          '2026-10-05T20:34:01Z area=wireguard event=network_protection_prepare_failed '
              'code=operation_cancelled stage=network_protection_prepare error_kind=native_bridge',
          '1999-10-05T20:34:01Z area=api_request event=started code=login',
        ],
      );
      expect(result['events'], hasLength(1));
      expect(
        (result['events'] as List).single,
        containsPair('code', 'operation_cancelled'),
      );
      expect(result['discarded_lines'], 1);
      expect(jsonEncode(result), isNot(contains('native_operation_failed')));
    },
  );
}
