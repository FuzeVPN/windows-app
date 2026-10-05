// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';

FrozenDiagnosticReport syntheticReport({
  bool full = false,
  bool manual = true,
  DateTime? createdAt,
  Map<String, Object?> fragments = const {},
}) => FrozenDiagnosticReport.create(
  appVersion: '1.2.3',
  createdAt: createdAt ?? DateTime.utc(2026, 9, 16),
  manual: manual,
  full: full,
  state: 'error',
  protocol: 'openvpn',
  error: DiagnosticError(
    code: 'openvpn_dns_configuration_failed',
    domain: 'tunnel',
    operation: 'connect',
    stage: 'dns_apply',
  ),
  fragments: fragments,
);

void main() {
  test('collection pending is a typed local value excluded from reports', () {
    final snapshot = DiagnosticSnapshot.fromMap({
      'runtime': {'presence': 'unknown', 'collection_pending': true},
    });
    expect(snapshot.runtime['collection_pending'], isTrue);
    expect(snapshot.reportFragments, isEmpty);
    expect(
      () => DiagnosticSnapshot.fromMap({
        'runtime': {'presence': 'unknown', 'collection_pending': 'true'},
      }),
      throwsFormatException,
    );
  });
  test(
    'typed checks preserve unknown observations and reject unsupported fields',
    () {
      final check = DiagnosticCheck.fromMap({
        'id': 'dns',
        'result': 'unknown',
        'age_ms': 0,
      });
      expect(check.ageMs, 0);
      expect(check.durationMs, isNull);
      expect(check.result, 'unknown');
      expect(
        () => DiagnosticCheck.fromMap({
          'id': 'dns',
          'result': 'unknown',
          'resolver': '192.0.2.1',
        }),
        throwsFormatException,
      );
    },
  );
  test('typed repair cannot claim success without a verified after result', () {
    expect(
      () => DiagnosticRepair(
        id: 'cleanup',
        before: 'failed',
        after: 'unknown',
        result: 'passed',
      ),
      throwsFormatException,
    );
    final repair = DiagnosticRepair(
      id: 'cleanup',
      before: 'failed',
      after: 'unknown',
      result: 'failed',
      code: 'personal@example.invalid',
    );
    expect(repair.code, 'unknown_error');
    expect(repair.durationMs, isNull);
  });
  test(
    'registry is versioned at 206 codes, unknown input cannot become text',
    () {
      expect(diagnosticCodes.length, 206);
      final error = DiagnosticError(code: 'secret/endpoint@example.test');
      expect(error.toJson()['code'], 'unknown_error');
      expect(jsonEncode(error.toJson()), isNot(contains('secret')));
    },
  );
  test('UUIDs are random canonical v4 and frozen body cannot be changed', () {
    final ids = <String>{};
    for (var i = 0; i < 100; i++) {
      final report = syntheticReport();
      expect(
        report.reportId,
        matches(
          RegExp(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
          ),
        ),
      );
      ids.add(report.reportId);
      expect(() => report.bytes[0] = 0, throwsUnsupportedError);
      expect(
        () => (report.json['consent'] as Map)['mode'] = 'automatic_opt_in',
        throwsUnsupportedError,
      );
      expect(
        FrozenDiagnosticReport.fromBytes(report.bytes).bytes,
        report.bytes,
      );
    }
    expect(ids.length, 100);
  });
  for (final version in [
    '01.2.3',
    '1.02.3',
    '256.0.0',
    '0.256.0',
    '0.0.65536',
    '1.2.3.4',
    '1.2.3+1',
  ]) {
    test('MSI diagnostic version rejects $version', () {
      expect(
        () => FrozenDiagnosticReport.create(
          appVersion: version,
          createdAt: DateTime.utc(2026),
          manual: true,
          full: true,
          state: 'unknown',
        ),
        throwsFormatException,
      );
    });
  }
  test(
    'closed schema rejects free fields, wrong types, NUL and invalid evidence',
    () {
      final mutations = <void Function(Map<String, dynamic>)>[
        (r) => r['email'] = 'private@example.test',
        (r) => r['state'] = 'Connected',
        (r) => r['occurrences'] = 1.5,
        (r) => r['created_at'] = 'not-a-date',
        (r) => r['created_at'] = '2026-02-31T12:00:00Z',
        (r) => r['created_at'] = '2026-09-16T24:00:00Z',
        (r) => r['created_at'] = '2026-09-16T12:00:00+30:00',
        (r) => r['consent'] = {'mode': 'automatic_opt_in', 'notice_version': 1},
        (r) => r['snapshot'] = {
          'ip_families': ['ipv4', 'ipv4'],
        },
        (r) => r['snapshot'] = {'kill_switch_verified': 'true'},
        (r) => r['snapshot'] = {'bytes_received': -1},
        (r) => r['environment'] = {'driver_version': '1.0\u0000'},
        (r) => r['checks'] = [
          {'id': 'dns', 'result': 'success'},
        ],
        (r) => r['repairs'] = [
          {
            'id': 'cleanup',
            'before': 'failed',
            'after': 'unknown',
            'result': 'passed',
          },
        ],
        (r) => r['events'] = [
          {
            'source': 'app',
            'stage': 'dns_apply',
            'event': 'error',
            'offset_ms': 600001,
          },
        ],
        (r) => r['windows'] = {'engine_connect_ms': 604800001},
        (r) => r['error'] = {
          'domain': 'tunnel',
          'code': 'unregistered_error',
          'operation': 'connect',
          'stage': 'handshake',
        },
        (r) => r['dropped_events'] = 1,
      ];
      for (final mutate in mutations) {
        final json =
            jsonDecode(utf8.decode(syntheticReport(full: true).bytes))
                as Map<String, dynamic>;
        mutate(json);
        expect(
          () => FrozenDiagnosticReport.fromBytes(
            Uint8List.fromList(utf8.encode(jsonEncode(json))),
          ),
          throwsFormatException,
        );
      }
    },
  );
  test(
    'simple excludes even empty full-only fields and full forbids automatic consent',
    () {
      expect(
        () => syntheticReport(fragments: {'snapshot': <String, Object?>{}}),
        throwsFormatException,
      );
      expect(
        () => syntheticReport(full: true, manual: false),
        throwsFormatException,
      );
    },
  );
  test(
    'duplicate keys and non-canonical queued data cannot silently change retry content',
    () {
      final body = utf8.decode(syntheticReport().bytes);
      for (final changed in [
        ' $body',
        body.replaceFirst('{', '{"state":"connected",'),
      ]) {
        expect(
          () => FrozenDiagnosticReport.fromBytes(
            Uint8List.fromList(utf8.encode(changed)),
          ),
          throwsFormatException,
        );
      }
      expect(
        () => FrozenDiagnosticReport.fromBytes(Uint8List(2 * 1024 * 1024 + 1)),
        throwsFormatException,
      );
    },
  );
  test('full keeps false and zero observations separate from absent/null', () {
    final report = syntheticReport(
      full: true,
      fragments: {
        'snapshot': {
          'kill_switch_requested': true,
          'kill_switch_verified': false,
          'traffic_blocked': null,
          'bytes_sent': 0,
        },
      },
    );
    final snapshot = report.json['snapshot'] as Map;
    expect(snapshot['kill_switch_verified'], false);
    expect(snapshot['bytes_sent'], 0);
    expect(snapshot['traffic_blocked'], isNull);
    expect(snapshot.containsKey('handshake_age_ms'), false);
  });
  test('native local runtime is never included in API fragments', () {
    final snapshot = DiagnosticSnapshot.fromMap({
      'snapshot': {'owned_by_another_user': false},
      'runtime': {
        'presence': 'present',
        'protocol': 'openvpn',
        'cleanup_eligible': true,
      },
    });
    expect(snapshot.runtime['cleanup_eligible'], true);
    final report = syntheticReport(
      full: true,
      fragments: snapshot.reportFragments,
    );
    expect(utf8.decode(report.bytes), isNot(contains('cleanup_eligible')));
    expect(report.json.containsKey('runtime'), false);
  });
  test('new native codes are mapped to unknown before forming a report', () {
    final snapshot = DiagnosticSnapshot.fromMap({
      'checks': [
        {'id': 'dns', 'result': 'failed', 'code': 'not_in_registry'},
      ],
      'windows': {
        'first_error': 'not_in_registry',
        'last_error': 'cleanup_failed',
      },
    });
    final report = syntheticReport(
      full: true,
      fragments: snapshot.reportFragments,
    );
    expect((report.json['checks'] as List).single['code'], 'unknown_error');
    expect((report.json['windows'] as Map)['first_error'], 'unknown_error');
    expect((report.json['windows'] as Map)['last_error'], 'cleanup_failed');
  });
  test(
    'limits reject too many checks/events; 2000 bounded events fit full',
    () {
      expect(
        () => syntheticReport(
          full: true,
          fragments: {
            'checks': List.generate(
              65,
              (_) => {'id': 'dns', 'result': 'unknown'},
            ),
          },
        ),
        throwsFormatException,
      );
      final event = DiagnosticEvent(
        stage: 'handshake',
        event: 'begin',
      ).toJson(offsetMs: 0);
      final report = FrozenDiagnosticReport.create(
        appVersion: '1.0.0',
        createdAt: DateTime.utc(2026),
        manual: true,
        full: true,
        state: 'connecting',
        events: List.generate(2000, (_) => event),
      );
      expect(report.bytes.length, lessThan(2 * 1024 * 1024));
      expect(
        () => FrozenDiagnosticReport.create(
          appVersion: '1.0.0',
          createdAt: DateTime.utc(2026),
          manual: true,
          full: true,
          state: 'connecting',
          events: List.generate(2001, (_) => event),
        ),
        throwsFormatException,
      );
    },
  );
}
