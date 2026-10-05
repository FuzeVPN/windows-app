// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _FailingApi extends fixtures.ProbeApi {
  _FailingApi(this.failure);
  final Object? failure;
  @override
  Future<List<Location>> locations() async {
    if (failure case final value?) throw value;
    return [fixtures.source];
  }
}

class _IdleSnapshot extends DiagnosticsBridge {
  @override
  Future<Map<String, Object?>> collectSnapshot() async => {
    'runtime': {'presence': 'absent'},
    'checks': [
      {'id': 'service_availability', 'result': 'passed'},
    ],
  };
}

class _UiController extends AppController {
  _UiController(Object? failure)
    : super(
        api: _FailingApi(failure),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        diagnosticsBridge: _IdleSnapshot(),
      ) {
    language = AppLanguage.french;
    profile = fixtures.account;
    section = AppSection.help;
  }

  @override
  Future<void> initialize() async {}
}

Future<void> _mount(WidgetTester tester, _UiController app) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(1280, 1200);
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(app.dispose);
  await tester.pumpWidget(FuzeVpnApp(controller: app));
  await tester.pumpAndSettle();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('local TLS view admits canonical reasons only', () {
    const known = DiagnosticCheckView(
      'Connexion de l’application',
      'failed',
      0,
      tlsReason: 'certificate_issuer_missing',
    );
    const untrusted = DiagnosticCheckView(
      'Connexion de l’application',
      'failed',
      0,
      tlsReason: 'secret-should-not-appear',
    );
    expect(known.tlsReason, 'certificate_issuer_missing');
    expect(untrusted.tlsReason, isNull);
  });
  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('fuzevpn/update'),
          (_) async => {
            'version': '1.0.6',
            'windows_build': 26200,
            'arch': 'x64',
            'installation_mode': 'installed',
          },
        );
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('fuzevpn/update'), null);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null);
  });

  const localCases = <({String code, String label})>[
    (code: 'broker_protocol_error', label: 'Moteur VPN'),
    (code: 'native_bridge_unavailable', label: 'Moteur VPN'),
    (code: 'native_operation_failed', label: 'Moteur VPN'),
    (code: 'api_resolution_unavailable', label: 'Résolution réseau'),
    (code: 'api_resolver_invalid_response', label: 'Résolution réseau'),
    (code: 'secure_storage_read_failed', label: 'Stockage protégé'),
  ];
  for (final item in localCases) {
    testWidgets('local ${item.code} identifies its component and exact code', (
      tester,
    ) async {
      final app = _UiController(
        ApiException(
          statusCode: 503,
          errorCode: 'api_resolution_unavailable',
          localErrorCode: item.code,
        ),
      );
      await app.runUserDiagnostic();
      final check = app.diagnosticChecks.singleWhere(
        (value) => value.id == 'api_reachability',
      );
      expect(check.label, item.label);
      expect(check.result, 'unknown');
      await _mount(tester, app);
      expect(find.text(item.label), findsOneWidget);
      expect(find.text('Code d’erreur : ${item.code}'), findsOneWidget);
      expect(find.text('Accès aux services FuzeVPN'), findsNothing);
      expect(find.textContaining('momentanément indisponible'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  for (final failure in [
    StateError('private exception / secret-should-not-appear'),
    const ApiException(
      statusCode: 503,
      errorCode: 'api_resolution_unavailable',
      localErrorCode: 'secret-should-not-appear',
      windowsError: -0x80000001,
    ),
  ]) {
    testWidgets('unclassified failure stays neutral (${failure.runtimeType})', (
      tester,
    ) async {
      final app = _UiController(failure);
      await app.runUserDiagnostic();
      final check = app.diagnosticChecks.singleWhere(
        (value) => value.id == 'api_reachability',
      );
      expect(check.result, 'unknown');
      expect(check.label, 'Vérification technique');
      expect(
        check.code,
        failure is ApiException ? 'unknown_error' : 'unexpected_error',
      );
      expect(check.windowsError, isNull);
      await _mount(tester, app);
      expect(
        find.text(
          'La vérification n’a pas abouti. La cause n’est pas encore identifiée.',
        ),
        findsOneWidget,
      );
      expect(find.text('Code d’erreur : ${check.code}'), findsOneWidget);
      expect(find.textContaining('secret-should-not-appear'), findsNothing);
      expect(find.text('Accès aux services FuzeVPN'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  for (final item
      in <
        ({
          Object failure,
          String code,
          String message,
          int? windowsError,
          String? tlsReason,
        })
      >[
        (
          failure: const SocketException(
            'secret-should-not-appear',
            osError: OSError('private_os_error', 10061),
          ),
          code: 'network_unreachable',
          windowsError: 10061,
          tlsReason: null,
          message:
              'La tentative de connexion réseau a échoué. Cela ne permet pas de déterminer si le service est indisponible.',
        ),
        (
          failure: const HandshakeException(
            'secret-should-not-appear',
            OSError(
              'CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate / secret-should-not-appear',
              -1,
            ),
          ),
          code: 'tls_handshake_failed',
          windowsError: null,
          tlsReason: 'certificate_issuer_missing',
          message:
              'La connexion sécurisée au service n’a pas pu être vérifiée.',
        ),
      ]) {
    testWidgets('${item.code} describes only the failed connection attempt', (
      tester,
    ) async {
      final app = _UiController(item.failure);
      await app.runUserDiagnostic();
      final check = app.diagnosticChecks.singleWhere(
        (value) => value.id == 'api_reachability',
      );
      expect(check.code, item.code);
      expect(check.result, 'failed');
      expect(check.label, 'Connexion de l’application');
      expect(check.httpStatus, isNull);
      expect(check.windowsError, item.windowsError);
      expect(check.tlsReason, item.tlsReason);
      await _mount(tester, app);
      expect(find.text(item.message), findsOneWidget);
      expect(find.text('Connexion de l’application'), findsOneWidget);
      expect(find.text('Accès aux services FuzeVPN'), findsNothing);
      expect(find.text('Code d’erreur : ${item.code}'), findsOneWidget);
      if (item.windowsError != null) {
        expect(
          find.text('Code Windows : ${item.windowsError}'),
          findsOneWidget,
        );
      } else {
        expect(find.textContaining('Code Windows :'), findsNothing);
      }
      if (item.tlsReason != null) {
        expect(find.text('TLS : ${item.tlsReason}'), findsOneWidget);
      } else {
        expect(find.textContaining('TLS :'), findsNothing);
      }
      expect(find.textContaining('private_os_error'), findsNothing);
      expect(find.textContaining('secret-should-not-appear'), findsNothing);
      expect(find.textContaining('momentanément indisponible'), findsNothing);
      expect(find.textContaining('HTTP :'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  testWidgets('unknown measurements always display a stable code reference', (
    tester,
  ) async {
    final app = _UiController(null)
      ..diagnosticResults = {
        'checks': [
          {
            'id': 'api_reachability',
            'result': 'failed',
            'code': 'unknown_error',
          },
          {'id': 'driver_availability', 'result': 'unknown'},
        ],
      };
    await _mount(tester, app);
    expect(find.text('Vérification technique'), findsOneWidget);
    expect(find.text('Code d’erreur : unknown_error'), findsNWidgets(2));
    expect(find.text('Accès aux services FuzeVPN'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'signed-out users can inspect and copy local trace without sending',
    (tester) async {
      final app = _UiController(null)
        ..profile = null
        ..isInitialized = true;
      String? copied;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(SystemChannels.platform, (call) async {
            if (call.method == 'Clipboard.setData') {
              copied = (call.arguments as Map)['text'] as String;
            }
            return null;
          });
      await DiagnosticLog.record(
        area: 'api_transport',
        event: 'ui_export_fixture',
        code: 'network_error',
      );
      await _mount(tester, app);
      await tester.tap(find.widgetWithText(TextButton, 'Diagnostic local'));
      await tester.pumpAndSettle();
      await tester.tap(
        find.descendant(
          of: find.byType(AlertDialog).last,
          matching: find.widgetWithText(OutlinedButton, 'Chronologie locale'),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.textContaining('event=ui_export_fixture'), findsOneWidget);
      await tester.tap(
        find.descendant(
          of: find.byType(AlertDialog).last,
          matching: find.widgetWithText(
            TextButton,
            'Copier le diagnostic local',
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(copied, contains('--- report ---\n{}'));
      expect(copied, contains('--- local_trace ---'));
      expect(copied, contains('event=ui_export_fixture code=network_error'));
      expect(app.diagnostics.pendingReports, isEmpty);
      expect(app.diagnostics.receipts, isEmpty);
      expect(app.profile, isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
