// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _SessionStore extends fixtures.ProbeStore {
  String? savedToken = 'synthetic-saved-session';
  bool unreadable = false;
  int clearCalls = 0;
  @override
  Future<String?> token() async {
    if (unreadable) throw PlatformException(code: 'storage_access_denied');
    return savedToken;
  }

  @override
  Future<void> clearToken() async {
    clearCalls++;
    savedToken = null;
  }
}

class _SessionApi extends fixtures.ProbeApi {
  Object? profileFailure;
  Object? locationsFailure;
  Completer<void>? profileGate;
  int loginCalls = 0;
  @override
  Future<UserProfile> me(String token) async {
    meCalls++;
    await profileGate?.future;
    if (profileFailure case final failure?) throw failure;
    return fixtures.account;
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    loginCalls++;
    throw StateError('A saved-session retry must never log in');
  }

  @override
  Future<List<Location>> locations() async {
    if (locationsFailure case final failure?) throw failure;
    return [fixtures.source];
  }
}

class _IdleSnapshot extends DiagnosticsBridge {
  @override
  Future<Map<String, Object?>> collectSnapshot() async => {
    'runtime': {'presence': 'absent'},
    'checks': <Object?>[],
  };
}

class _UiController extends AppController {
  _UiController(
    _SessionApi api,
    _SessionStore store,
    fixtures.ProbeWireGuard wireguard,
    fixtures.ProbeOpenVpn openVpn,
  ) : super(
        api: api,
        store: store,
        wireguard: wireguard,
        openVpn: openVpn,
        window: fixtures.ProbeWindow(),
        diagnosticsBridge: _IdleSnapshot(),
      ) {
    language = AppLanguage.french;
  }
  Future<void> bootstrap() => super.initialize();
  @override
  Future<void> initialize() async {}
}

Future<void> _pump(WidgetTester tester, _UiController controller) async {
  tester.view.physicalSize = const Size(1280, 1000);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
}

Future<void> _close(WidgetTester tester, _UiController controller) async {
  await tester.pumpWidget(const SizedBox.shrink());
  controller.dispose();
  await tester.pumpAndSettle();
  expect(tester.takeException(), isNull);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('fuzevpn/update'),
          (_) async => {
            'version': '1.0.3',
            'windows_build': 22631,
            'arch': 'x64',
            'installation_mode': 'installed',
          },
        );
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('fuzevpn/update'), null);
  });

  testWidgets(
    'saved session survives local DNS failure without a forced login',
    (tester) async {
      final api = _SessionApi()
        ..profileFailure = const ApiException(
          statusCode: 503,
          errorCode: 'api_resolution_unavailable',
          localErrorCode: 'api_bootstrap_unavailable',
        );
      final store = _SessionStore();
      final wg = fixtures.ProbeWireGuard();
      final ov = fixtures.ProbeOpenVpn();
      final controller = _UiController(api, store, wg, ov);
      await controller.bootstrap();
      await _pump(tester, controller);
      expect(find.byType(AlertDialog), findsNothing);
      expect(controller.savedSessionVerificationPending, isTrue);
      expect(
        find.byKey(const ValueKey('saved-session-verification-notice')),
        findsOneWidget,
      );
      expect(
        find.textContaining('Votre session est conservée.'),
        findsOneWidget,
      );
      expect(
        find.textContaining('FuzeVPN ne peut pas résoudre l’adresse'),
        findsOneWidget,
      );
      expect(store.savedToken, 'synthetic-saved-session');
      expect(store.clearCalls, 0);
      expect(api.loginCalls, 0);

      api.profileFailure = null;
      final retry = find.descendant(
        of: find.byKey(const ValueKey('saved-session-verification-notice')),
        matching: find.widgetWithText(OutlinedButton, 'Réessayer'),
      );
      await tester.tap(retry);
      await tester.pumpAndSettle();
      expect(controller.profile, fixtures.account);
      expect(controller.savedSessionVerificationPending, isFalse);
      expect(find.byType(AlertDialog), findsNothing);
      expect(api.loginCalls, 0);
      expect(wg.connectCalls, 0);
      expect(wg.prepareCalls, 0);
      expect(wg.disconnectCalls, 0);
      expect(ov.importCalls, 0);
      expect(ov.disconnectCalls, 0);
      await _close(tester, controller);
    },
  );

  testWidgets(
    'unreadable saved session offers verification rather than credentials',
    (tester) async {
      final api = _SessionApi();
      final store = _SessionStore()..unreadable = true;
      final controller = _UiController(
        api,
        store,
        fixtures.ProbeWireGuard(),
        fixtures.ProbeOpenVpn(),
      );
      await controller.bootstrap();
      await _pump(tester, controller);
      expect(find.byType(AlertDialog), findsNothing);
      expect(
        find.textContaining('Votre session enregistrée ne peut pas être lue.'),
        findsOneWidget,
      );
      expect(store.clearCalls, 0);
      expect(api.meCalls, 0);
      await _close(tester, controller);
    },
  );

  testWidgets(
    'account and connection actions retry saved verification without login',
    (tester) async {
      final api = _SessionApi()
        ..profileFailure = const ApiException(
          statusCode: 503,
          errorCode: 'server_error',
          observedHttpStatus: 503,
        );
      final controller = _UiController(
        api,
        _SessionStore(),
        fixtures.ProbeWireGuard(),
        fixtures.ProbeOpenVpn(),
      );
      await controller.bootstrap();
      await _pump(tester, controller);
      final before = api.meCalls;
      final account = tester.widget<InkWell>(
        find.descendant(
          of: find.byTooltip('Mon compte'),
          matching: find.byType(InkWell),
        ),
      );
      account.onTap!();
      await tester.pumpAndSettle();
      expect(api.meCalls, before + 1);
      final connect = tester.widget<FilledButton>(
        find.byKey(const ValueKey('connection-primary-action')),
      );
      connect.onPressed!();
      await tester.pumpAndSettle();
      expect(api.meCalls, before + 2);
      expect(find.byType(AlertDialog), findsNothing);
      expect(api.loginCalls, 0);
      await _close(tester, controller);
    },
  );

  testWidgets('a confirmed unauthorized response still requires sign in', (
    tester,
  ) async {
    final api = _SessionApi()
      ..profileFailure = const ApiException(
        statusCode: 401,
        errorCode: 'unauthorized',
        observedHttpStatus: 401,
      );
    final store = _SessionStore();
    final controller = _UiController(
      api,
      store,
      fixtures.ProbeWireGuard(),
      fixtures.ProbeOpenVpn(),
    );
    await controller.bootstrap();
    await _pump(tester, controller);
    expect(store.clearCalls, 1);
    expect(controller.savedSessionVerificationPending, isFalse);
    expect(find.byType(AlertDialog), findsOneWidget);
    expect(
      find.byKey(const ValueKey('saved-session-verification-notice')),
      findsNothing,
    );
    await _close(tester, controller);
  });

  final localCases = <({String code, String message})>[
    (
      code: 'api_bootstrap_unavailable',
      message:
          'FuzeVPN ne peut pas résoudre l’adresse du service de connexion.',
    ),
    (
      code: 'broker_unavailable',
      message:
          'Le service VPN local est indisponible. Fermez puis rouvrez FuzeVPN.',
    ),
    (
      code: 'runtime_status_unavailable',
      message:
          'FuzeVPN ne peut pas vérifier l’état du VPN. Réessayez la vérification.',
    ),
  ];
  for (final item in localCases) {
    testWidgets(
      'diagnostic retains local ${item.code} without claiming server failure',
      (tester) async {
        final api = _SessionApi()
          ..locationsFailure = ApiException(
            statusCode: 503,
            errorCode: 'api_resolution_unavailable',
            localErrorCode: item.code,
            windowsError: 5,
          );
        final wg = fixtures.ProbeWireGuard();
        final ov = fixtures.ProbeOpenVpn();
        final controller = _UiController(api, _SessionStore(), wg, ov)
          ..section = AppSection.help;
        await controller.runUserDiagnostic();
        final check = controller.diagnosticChecks.firstWhere(
          (c) => c.id == 'api_reachability',
        );
        expect(check.result, 'unknown');
        expect(check.code, item.code);
        expect(
          check.label,
          item.code == 'api_bootstrap_unavailable'
              ? 'Résolution réseau'
              : 'Moteur VPN',
        );
        expect(check.windowsError, 5);
        expect(
          controller.preparedDiagnosticReport!.json.toString(),
          isNot(contains('win32_error')),
        );
        await _pump(tester, controller);
        expect(find.text('Accès à l’API'), findsNothing);
        expect(find.text(item.message), findsOneWidget);
        expect(find.text('Code Windows : 5'), findsOneWidget);
        expect(find.text('Code d’erreur : ${item.code}'), findsOneWidget);
        expect(find.text('Accès aux services FuzeVPN'), findsNothing);
        expect(find.text('Ancienneté de la mesure : 0 s'), findsOneWidget);
        expect(wg.connectCalls, 0);
        expect(wg.disconnectCalls, 0);
        expect(ov.disconnectCalls, 0);
        await _close(tester, controller);
      },
    );
  }

  testWidgets(
    'diagnostic presents actual HTTP failure separately from local DNS',
    (tester) async {
      final api = _SessionApi()
        ..locationsFailure = const ApiException(
          statusCode: 503,
          errorCode: 'server_error',
          observedHttpStatus: 503,
        );
      final controller = _UiController(
        api,
        _SessionStore(),
        fixtures.ProbeWireGuard(),
        fixtures.ProbeOpenVpn(),
      )..section = AppSection.help;
      await controller.runUserDiagnostic();
      final check = controller.diagnosticChecks.firstWhere(
        (c) => c.id == 'api_reachability',
      );
      expect(check.result, 'failed');
      await _pump(tester, controller);
      expect(
        find.text(
          'Le service a renvoyé une réponse HTTP en erreur. Consultez le code d’erreur.',
        ),
        findsOneWidget,
      );
      expect(find.textContaining('ne peut pas résoudre'), findsNothing);
      expect(find.text('HTTP : 503'), findsOneWidget);
      expect(find.text('Code d’erreur : server_error'), findsOneWidget);
      await _close(tester, controller);
    },
  );
}
