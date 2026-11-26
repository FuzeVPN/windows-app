// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/diagnostics_support.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/runtime_storage_diagnostics.dart';

import 'support/audit_fixtures.dart' as fixtures;

Map<String, Object?> nativeEvidence() => {
  'schema_version': 1,
  'environment': {
    'installation_mode': 'installed',
    'binary_version': '1.0.7.1',
  },
  'service': {
    'name': 'FuzeVPNService',
    'state': 'stopped',
    'query_stage': 'completed',
    'win32_exit_code': 50,
    'service_exit_code': 123,
    'process_present': false,
    'binary_version': '1.0.6.1',
    'service_binary_matches_application': false,
  },
  'runtime': {'presence': 'absent', 'detection_failed': false},
  'native_log': {
    'status': 'ok',
    'truncated': false,
    'discarded_lines': 0,
    'events': [
      {
        'timestamp': '2026-10-05T20:12:11.932Z',
        'area': 'broker',
        'event': 'connection_failed',
        'code': 50,
      },
    ],
  },
};

class _Bridge extends DiagnosticsBridge {
  int nativeCalls = 0;
  bool fail = false;
  Object? failure;
  Map<String, Object?>? evidence;
  Completer<void>? gate;
  @override
  Future<Map<String, Object?>> collectSnapshot() async => {
    'runtime': {'presence': 'absent'},
    'checks': [
      {'id': 'service_availability', 'result': 'unknown'},
    ],
  };
  @override
  Future<Map<String, Object?>> collectLocalDiagnostics() async {
    nativeCalls++;
    await gate?.future;
    if (fail) throw PlatformException(code: 'native_bridge_unavailable');
    if (failure != null) throw failure!;
    return evidence ?? nativeEvidence();
  }
}

class _Delivery extends DiagnosticsController {
  _Delivery({this.consent = true});
  final sent = <FrozenDiagnosticReport>[];
  bool consent;
  bool receive = true;
  @override
  bool get automaticConsent => consent;
  @override
  Future<Map<String, Object?>?> runChecks() async => {
    'protocol': 'wireguard',
    'state': 'disconnected',
    'checks': [
      {'id': 'api_reachability', 'result': 'passed'},
    ],
  };
  @override
  Future<bool> sendPreparedReport(FrozenDiagnosticReport report) async {
    sent.add(FrozenDiagnosticReport.fromBytes(report.bytes));
    return receive;
  }
}

const _localOnlyMessage =
    'Diagnostic complet collecté sur cet appareil. Vous pouvez le copier ou l’envoyer à l’assistance.';

class _BusyController extends AppController {
  _BusyController(_Bridge bridge, _Delivery delivery)
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        window: fixtures.ProbeWindow(),
        diagnosticsBridge: bridge,
        diagnostics: delivery,
        now: () => DateTime.utc(2026, 10, 5, 22),
      );
  @override
  bool get isConnectionBusy => true;
}

Map<String, Object?> supportOf(FrozenDiagnosticReport report) =>
    Map<String, Object?>.from(
      (report.json['windows'] as Map)['support'] as Map,
    );

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  AppController app(
    _Bridge bridge, {
    _Delivery? delivery,
    bool signedIn = false,
  }) {
    final result = AppController(
      api: fixtures.ProbeApi(),
      store: fixtures.ProbeStore(),
      wireguard: fixtures.ProbeWireGuard(),
      openVpn: fixtures.ProbeOpenVpn(),
      window: fixtures.ProbeWindow(),
      diagnosticsBridge: bridge,
      diagnostics: delivery,
      now: () => DateTime.utc(2026, 10, 5, 22),
    );
    if (signedIn) result.profile = fixtures.account;
    addTearDown(result.dispose);
    return result;
  }

  test(
    'precise storage steps and Windows errors survive the complete report',
    () async {
      for (final stage in runtimeStorageStages) {
        await DiagnosticLog.recordFailure(
          area: 'wireguard',
          event: 'native_connect_failed',
          error: PlatformException(
            code: 'storage_failure',
            message: 'private message',
            details: {
              'stage': stage,
              'win32_error': 32,
              'path': r'C:\private\FuzeVPN.conf',
              'private_key': 'private-key-test',
            },
          ),
        );
      }
      await DiagnosticLog.recordFailure(
        area: 'wireguard',
        event: 'native_connect_failed',
        error: PlatformException(
          code: 'storage_failure',
          details: {'stage': r'C:\private\FuzeVPN.conf', 'win32_error': 5},
        ),
      );
      final controller = app(_Bridge());
      await controller.runCompleteDiagnostic();
      final report = controller.preparedDiagnosticReport!;
      final timeline = supportOf(report)['timeline'] as List;
      for (final stage in runtimeStorageStages) {
        expect(timeline, contains(containsPair('stage', stage)));
      }
      expect(
        timeline,
        contains(
          allOf(
            containsPair('code', 'storage_failure'),
            containsPair('windows_error', 32),
          ),
        ),
      );
      final encoded = jsonEncode(report.json);
      for (final secret in [
        'private message',
        r'C:\private',
        'private-key-test',
        'private_key',
      ]) {
        expect(encoded, isNot(contains(secret)));
      }
    },
  );

  test(
    'bad native log preserves service evidence and reports partial rejection',
    () async {
      final observation = DiagnosticSupport.nativeObservation({
        ...nativeEvidence(),
        'native_log': {'events': 'private malformed log'},
      });
      final controller = app(_Bridge()..evidence = observation);
      await controller.runCompleteDiagnostic();
      final support = supportOf(controller.preparedDiagnosticReport!);
      expect((support['service'] as Map)['win32_exit_code'], 50);
      expect((support['environment'] as Map)['installation_mode'], 'installed');
      final collection = support['collection'] as Map;
      expect((collection['native'] as Map)['status'], 'rejected');
      expect((collection['native_log'] as Map)['status'], 'rejected');
      expect(jsonEncode(support), isNot(contains('private malformed log')));
    },
  );

  test(
    'invalid native envelope is distinguished from unavailable bridge',
    () async {
      final controller = app(
        _Bridge()..failure = const FormatException('private'),
      );
      await controller.runCompleteDiagnostic();
      final collection =
          supportOf(controller.preparedDiagnosticReport!)['collection'] as Map;
      expect((collection['native'] as Map)['status'], 'rejected');
    },
  );

  test(
    'one action sends checks, app stages, native Windows50 and SCM state together',
    () async {
      final bridge = _Bridge(), delivery = _Delivery();
      final controller = app(bridge, delivery: delivery, signedIn: true);
      await DiagnosticLog.record(
        area: 'startup',
        event: 'begin',
        stage: 'initialize',
      );
      await controller.runCompleteDiagnostic();
      expect(delivery.sent, hasLength(1));
      final report = delivery.sent.single;
      expect(report.json['app_version'], '1.3.1');
      expect((report.json['checks'] as List).single['result'], 'passed');
      final support = supportOf(report);
      expect((support['service'] as Map)['state'], 'stopped');
      expect((support['service'] as Map)['win32_exit_code'], 50);
      expect((support['service'] as Map)['service_exit_code'], 123);
      expect(
        (support['service'] as Map)['service_binary_matches_application'],
        false,
      );
      final timeline = support['timeline'] as List;
      expect(
        timeline.any(
          (e) => e['source'] == 'application' && e['stage'] == 'initialize',
        ),
        true,
      );
      expect(
        timeline.any((e) => e['source'] == 'native' && e['code'] == 50),
        true,
      );
      expect(jsonDecode(controller.diagnosticLocalExport), report.json);
      expect(
        controller.diagnosticMessage,
        'Diagnostic complet transmis à l’assistance.',
      );
      expect(bridge.nativeCalls, 1);
      // Automatic consent already sent this report: no explicit send remains.
      expect(controller.hasUnsentCompleteDiagnostic, isFalse);
      await controller.sendCompleteDiagnostic();
      expect(delivery.sent, hasLength(1));
    },
  );

  test(
    'without automatic consent the complete diagnostic stays local until one explicit send',
    () async {
      final delivery = _Delivery(consent: false);
      final controller = app(_Bridge(), delivery: delivery, signedIn: true);
      await controller.runCompleteDiagnostic();
      final first = controller.preparedDiagnosticReport!;
      expect(delivery.sent, isEmpty);
      expect(controller.diagnostics.pendingReports, isEmpty);
      expect(controller.diagnosticMessage, _localOnlyMessage);
      expect(controller.hasUnsentCompleteDiagnostic, isTrue);
      expect(controller.canSendCompleteDiagnostic, isTrue);
      expect(jsonDecode(controller.diagnosticLocalExport), first.json);

      await controller.sendCompleteDiagnostic();
      expect(delivery.sent.single.reportId, first.reportId);
      expect(delivery.sent.single.json, first.json);
      expect(
        controller.diagnosticMessage,
        'Diagnostic complet transmis à l’assistance.',
      );
      expect(controller.diagnosticSendRunning, isFalse);
      expect(controller.hasUnsentCompleteDiagnostic, isFalse);
      await controller.sendCompleteDiagnostic();
      expect(delivery.sent, hasLength(1));

      await controller.runCompleteDiagnostic();
      final second = controller.preparedDiagnosticReport!;
      expect(second.reportId, isNot(first.reportId));
      expect(delivery.sent, hasLength(1));
      expect(controller.diagnosticMessage, _localOnlyMessage);
      expect(controller.hasUnsentCompleteDiagnostic, isTrue);
      await controller.sendCompleteDiagnostic();
      expect(delivery.sent.map((report) => report.reportId), [
        first.reportId,
        second.reportId,
      ]);
    },
  );

  test(
    'an explicit send keeps the delivery outcome messages and is not offered again',
    () async {
      final delivery = _Delivery(consent: false)..receive = false;
      final controller = app(_Bridge(), delivery: delivery, signedIn: true);
      await controller.runCompleteDiagnostic();
      await controller.sendCompleteDiagnostic();
      expect(delivery.sent, hasLength(1));
      expect(
        controller.diagnosticMessage,
        'Le diagnostic complet n’a pas pu être transmis. Consultez le code d’erreur.',
      );
      expect(controller.hasUnsentCompleteDiagnostic, isFalse);
      await controller.sendCompleteDiagnostic();
      expect(delivery.sent, hasLength(1));
    },
  );

  test(
    'signed-out collection and account changes never offer an explicit send',
    () async {
      final delivery = _Delivery();
      final signedOut = app(_Bridge(), delivery: delivery);
      await signedOut.runCompleteDiagnostic();
      expect(signedOut.preparedDiagnosticReport, isNotNull);
      expect(
        signedOut.diagnosticMessage,
        'Diagnostic complet collecté. Connectez-vous à votre compte pour l’envoyer.',
      );
      expect(signedOut.hasUnsentCompleteDiagnostic, isFalse);
      await signedOut.sendCompleteDiagnostic();
      expect(delivery.sent, isEmpty);

      final local = _Delivery(consent: false);
      final switched = app(_Bridge(), delivery: local, signedIn: true);
      await switched.runCompleteDiagnostic();
      expect(switched.hasUnsentCompleteDiagnostic, isTrue);
      switched.profile = const UserProfile(
        userId: 'second-synthetic-account',
        email: 'second@example.invalid',
        firstName: 'Second',
        emailVerified: true,
      );
      expect(switched.hasUnsentCompleteDiagnostic, isFalse);
      await switched.sendCompleteDiagnostic();
      expect(local.sent, isEmpty);
    },
  );

  test(
    'broker-independent collection remains available during a stuck VPN operation',
    () async {
      final bridge = _Bridge(), delivery = _Delivery();
      final controller = _BusyController(bridge, delivery)
        ..profile = fixtures.account
        ..vpnStatus = VpnStatus.connecting;
      addTearDown(controller.dispose);
      expect(controller.canRunDiagnostic, false);
      expect(controller.canRunCompleteDiagnostic, true);
      await controller.runCompleteDiagnostic();
      final support = supportOf(delivery.sent.single);
      expect((support['collection'] as Map)['report'], 'busy');
      expect((support['service'] as Map)['win32_exit_code'], 50);
      expect(controller.vpnStatus, VpnStatus.connecting);
    },
  );

  test(
    'native collection failure preserves checks and app chronology explicitly',
    () async {
      final controller = app(_Bridge()..fail = true);
      await controller.runCompleteDiagnostic();
      final support = supportOf(controller.preparedDiagnosticReport!);
      expect(
        ((support['collection'] as Map)['native'] as Map)['status'],
        'unavailable',
      );
      expect(controller.preparedDiagnosticReport!.json['checks'], isNotEmpty);
      expect(
        controller.diagnosticMessage,
        'Diagnostic complet collecté. Connectez-vous à votre compte pour l’envoyer.',
      );
      expect(controller.diagnostics.pendingReports, isEmpty);
    },
  );

  test(
    'overlapping complete actions coalesce and do not send two reports',
    () async {
      final bridge = _Bridge()..gate = Completer<void>();
      final delivery = _Delivery();
      final controller = app(bridge, delivery: delivery, signedIn: true);
      final first = controller.runCompleteDiagnostic();
      await Future<void>.delayed(Duration.zero);
      await controller.runCompleteDiagnostic();
      bridge.gate!.complete();
      await first;
      expect(bridge.nativeCalls, 1);
      expect(delivery.sent, hasLength(1));
    },
  );

  test(
    'complete report validator rejects secret fields and unknown native values after serialization',
    () async {
      final controller = app(_Bridge());
      await controller.runCompleteDiagnostic();
      final report = controller.preparedDiagnosticReport!;
      final support = supportOf(report);
      for (final mutation in <Map<String, Object?>>[
        {...support, 'collected_at': '2026-10-32T20:12:11.932Z'},
        {...support, 'path': r'C:\Users\private\secret'},
        {
          ...support,
          'service': {...support['service'] as Map, 'bin_path': 'private'},
        },
        {
          ...support,
          'collection': {
            ...support['collection'] as Map,
            'application_log': {
              'status': 'ok',
              'truncated': false,
              'discarded_lines': 0,
              'events': ['private-token'],
            },
          },
        },
        {
          ...support,
          'timeline': [
            {
              'source': 'native',
              'timestamp': '2026-10-05T20:12:11.932Z',
              'area': 'broker',
              'event': 'connection_failed',
              'code': 'private-token',
            },
          ],
        },
      ]) {
        expect(
          () => DiagnosticSupport.validate(mutation),
          throwsFormatException,
        );
        expect(
          () => FrozenDiagnosticReport.create(
            appVersion: '1.0.7',
            createdAt: DateTime.utc(2026, 10, 5),
            manual: true,
            full: true,
            state: 'disconnected',
            fragments: {
              'windows': {'support': mutation},
            },
          ),
          throwsFormatException,
        );
      }
    },
  );

  test(
    'bridge polls pending observations without invoking VPN or maintenance channels',
    () async {
      const channel = MethodChannel('com.fuzevpn/windows_diagnostics');
      final messenger =
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      var calls = 0;
      messenger.setMockMethodCallHandler(channel, (call) async {
        expect(call.method, 'collectLocalDiagnostics');
        expect(call.arguments, isNull);
        return ++calls == 1
            ? {'schema_version': 1, 'collection_pending': true}
            : nativeEvidence();
      });
      addTearDown(() => messenger.setMockMethodCallHandler(channel, null));
      final result = await DiagnosticsBridge().collectLocalDiagnostics();
      expect(calls, 2);
      expect((result['service'] as Map)['win32_exit_code'], 50);
    },
  );
}
