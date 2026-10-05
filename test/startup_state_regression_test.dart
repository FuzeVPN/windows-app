// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/generated_catalogs.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixture;

const _unknownProtectionMessage =
    'FuzeVPN ne peut pas vérifier l’état du VPN. Réessayez la vérification.';
const _interruptedMessage =
    'La connexion VPN s’est interrompue. Le kill switch bloque toujours le trafic réseau.';
const _failedDisconnectMessage =
    'La déconnexion VPN n’a pas pu être confirmée. Réessayez la déconnexion.';
const _invalidCredentialsMessage =
    'La connexion au compte a échoué. Vérifiez votre adresse e-mail et votre mot de passe.';

class _StartupWireGuard extends fixture.ProbeWireGuard {
  bool statusUnavailable = false;
  bool snapshotUnavailable = false;
  bool protectionUnavailable = false;
  bool failFirstStatus = false;
  bool failAfterFirstStatus = false;
  Completer<bool>? statusGate;
  int statusCalls = 0;
  String statusErrorCode = 'runtime_status_unavailable';
  Map<String, Object>? statusErrorDetails;

  @override
  Future<bool> isConnected() async {
    statusCalls++;
    if (statusGate != null) return statusGate!.future;
    if (statusUnavailable ||
        (failFirstStatus && statusCalls == 1) ||
        (failAfterFirstStatus && statusCalls > 1)) {
      throw PlatformException(
        code: statusErrorCode,
        details: statusErrorDetails,
      );
    }
    return super.isConnected();
  }

  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    if (snapshotUnavailable || protectionUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return super.networkProtectionStatus();
  }

  @override
  Future<bool> isNetworkProtectionActive() async {
    if (protectionUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return super.isNetworkProtectionActive();
  }
}

class _StartupOpenVpn extends fixture.ProbeOpenVpn {
  bool statusUnavailable = false;
  bool snapshotUnavailable = false;
  bool protectionUnavailable = false;

  @override
  Future<bool> isConnected() async {
    if (statusUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return super.isConnected();
  }

  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    if (snapshotUnavailable || protectionUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return super.networkProtectionStatus();
  }

  @override
  Future<bool> isNetworkProtectionActive() async {
    if (protectionUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return super.isNetworkProtectionActive();
  }
}

class _StartupApi extends fixture.ProbeApi {
  int locationsCalls = 0;
  int loginCalls = 0;

  @override
  Future<List<Location>> locations() async {
    locationsCalls++;
    return super.locations();
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    loginCalls++;
    throw const ApiException(statusCode: 401, errorCode: 'invalid_credentials');
  }
}

class _StartupStore extends fixture.ProbeStore {
  @override
  Future<SecuritySettings> securitySettings() async => const SecuritySettings(
    killSwitch: true,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: false,
  );
}

class _NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

class _NoSessionStore extends _StartupStore {
  @override
  Future<String?> token() async => null;
}

AppController _makeController({
  required _StartupApi api,
  _StartupStore? store,
  _StartupWireGuard? wireguard,
  _StartupOpenVpn? openVpn,
}) => AppController(
  api: api,
  store: store ?? _StartupStore(),
  wireguard: wireguard ?? _StartupWireGuard(),
  openVpn: openVpn ?? _StartupOpenVpn(),
  window: fixture.ProbeWindow(),
  updates: _NoUpdates(),
);

class _SignInController extends AppController {
  _SignInController(_StartupApi api)
    : super(
        api: api,
        store: _StartupStore(),
        wireguard: _StartupWireGuard(),
        openVpn: _StartupOpenVpn(),
        window: fixture.ProbeWindow(),
        updates: _NoUpdates(),
      ) {
    language = AppLanguage.french;
    isLoadingLocations = false;
    errorMessage = _failedDisconnectMessage;
  }

  @override
  Future<void> initialize() async {}
}

Future<void> _pumpApp(WidgetTester tester, AppController controller) async {
  tester.view.physicalSize = const Size(1280, 900);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
}

Future<void> _openSignIn(WidgetTester tester) async {
  await tester.tap(find.byTooltip('Mon compte'));
  await tester.pumpAndSettle();
  expect(find.byType(AlertDialog), findsOneWidget);
}

Future<void> _closeApp(WidgetTester tester, AppController controller) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pumpAndSettle();
  expect(tester.takeException(), isNull);
  controller.dispose();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final protocol in VpnProtocol.values) {
    for (final unavailableTunnel in [false, true]) {
      test('startup ${protocol.name} unknown filters waits for verification '
          '(tunnel unavailable $unavailableTunnel)', () async {
        final api = _StartupApi();
        final wg = _StartupWireGuard()
          ..statusUnavailable =
              protocol == VpnProtocol.wireGuard && unavailableTunnel
          ..protectionUnavailable = protocol == VpnProtocol.wireGuard;
        final ov = _StartupOpenVpn()
          ..statusUnavailable =
              protocol == VpnProtocol.openVpn && unavailableTunnel
          ..protectionUnavailable = protocol == VpnProtocol.openVpn;
        final controller = _makeController(
          api: api,
          wireguard: wg,
          openVpn: ov,
        );
        addTearDown(controller.dispose);
        await controller.initialize();
        expect(controller.vpnStatus, VpnStatus.error);
        expect(controller.requiresExplicitDisconnect, isFalse);
        expect(controller.runtimeVerificationPending, isTrue);
        expect(controller.errorMessage, _unknownProtectionMessage);
        expect(controller.profile, isNull);
        expect(api.meCalls, 0);
        expect(api.locationsCalls, 0);
        expect(wg.disconnectCalls, 0);
        expect(ov.disconnectCalls, 0);
        expect(wg.reconnectCalls, 0);
      });
    }

    test(
      'startup ${protocol.name} legacy false confirms filter absence',
      () async {
        final api = _StartupApi();
        final controller = _makeController(
          api: api,
          wireguard: _StartupWireGuard()
            ..snapshotUnavailable = protocol == VpnProtocol.wireGuard,
          openVpn: _StartupOpenVpn()
            ..snapshotUnavailable = protocol == VpnProtocol.openVpn,
        );
        addTearDown(controller.dispose);
        await controller.initialize();
        expect(controller.vpnStatus, VpnStatus.disconnected);
        expect(controller.requiresExplicitDisconnect, isFalse);
        expect(controller.errorMessage, isNull);
        expect(api.meCalls, 1);
        expect(api.locationsCalls, 1);
      },
    );

    test(
      'startup ${protocol.name} retained lock has no failed-operation claim',
      () async {
        final api = _StartupApi();
        final wg = _StartupWireGuard()
          ..protectionActive = protocol == VpnProtocol.wireGuard;
        final ov = _StartupOpenVpn()
          ..protectionActive = protocol == VpnProtocol.openVpn;
        final controller = _makeController(
          api: api,
          wireguard: wg,
          openVpn: ov,
        );
        addTearDown(controller.dispose);
        await controller.initialize();
        expect(controller.vpnStatus, VpnStatus.blocked);
        expect(controller.runtimeVerificationPending, isFalse);
        expect(controller.requiresExplicitDisconnect, isTrue);
        expect(controller.errorMessage, _interruptedMessage);
        expect(api.meCalls, 0);
        expect(api.locationsCalls, 0);
        expect(wg.disconnectCalls, 0);
        expect(ov.disconnectCalls, 0);
      },
    );
  }

  test(
    'startup recovered live tunnel has no failed-disconnect warning',
    () async {
      final api = _StartupApi();
      final wg = _StartupWireGuard()
        ..failFirstStatus = true
        ..connected = true;
      final controller = _makeController(api: api, wireguard: wg);
      addTearDown(controller.dispose);
      await controller.initialize();
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
      expect(controller.errorMessage, isNull);
      expect(wg.disconnectCalls, 0);
    },
  );

  test('an actual failed disconnect retains its retry warning', () async {
    final api = _StartupApi();
    final wg = _StartupWireGuard()
      ..protectionActive = true
      ..failDisconnect = true;
    final controller = _makeController(api: api, wireguard: wg);
    addTearDown(controller.dispose);
    await controller.initialize();
    expect(controller.vpnStatus, VpnStatus.blocked);
    wg.protectionActive = false;
    wg.protectionUnavailable = true;
    await controller.toggleConnection();
    expect(controller.vpnStatus, VpnStatus.error);
    expect(controller.requiresExplicitDisconnect, isTrue);
    expect(controller.runtimeVerificationPending, isFalse);
    expect(controller.errorMessage, _failedDisconnectMessage);
    expect(wg.disconnectCalls, greaterThan(0));
    expect(api.meCalls, 0);
    expect(api.locationsCalls, 0);
  });

  test('startup messages already exist in all 30 translation catalogs', () {
    for (final message in [
      _unknownProtectionMessage,
      _interruptedMessage,
      'État VPN inconnu',
      'Windows n’a pas permis de vérifier l’installation de FuzeVPN.',
    ]) {
      expect(sourceCatalog, contains(message));
      for (final catalog in translationCatalogs.values) {
        expect(catalog[message]?.trim(), isNotEmpty);
      }
    }
    expect(translationCatalogs, hasLength(30));
  });

  testWidgets('sign-in excludes startup warning until an account attempt', (
    tester,
  ) async {
    final api = _StartupApi();
    final controller = _makeController(
      api: api,
      store: _NoSessionStore(),
      wireguard: _StartupWireGuard()..protectionUnavailable = true,
    );
    await _pumpApp(tester, controller);
    expect(controller.errorMessage, _unknownProtectionMessage);
    expect(controller.savedSessionVerificationPending, isFalse);
    await _openSignIn(tester);
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(_unknownProtectionMessage),
      ),
      findsNothing,
    );
    await tester.tap(find.widgetWithText(FilledButton, 'Se connecter'));
    await tester.pumpAndSettle();
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(_unknownProtectionMessage),
      ),
      findsOneWidget,
    );
    expect(api.loginCalls, 0);
    await _closeApp(tester, controller);
  });

  test(
    'explicit retry recovers passive state without any VPN mutation',
    () async {
      final api = _StartupApi();
      final wg = _StartupWireGuard()..statusUnavailable = true;
      final app = _makeController(api: api, wireguard: wg);
      addTearDown(app.dispose);
      await app.initialize();
      expect(app.runtimeVerificationPending, isTrue);
      await app.quickConnect();
      expect(app.runtimeVerificationPending, isTrue);
      expect(wg.prepareCalls + wg.disconnectCalls + wg.reconnectCalls, 0);
      expect(api.meCalls + api.locationsCalls, 0);
      wg.statusUnavailable = false;
      app.autoConnectOnLaunch = true;
      await app.retryRuntimeVerification();
      expect(app.runtimeVerificationPending, isFalse);
      expect(app.vpnStatus, VpnStatus.disconnected);
      expect(app.errorMessage, isNull);
      expect(api.meCalls, 1);
      expect(api.locationsCalls, 1);
      expect(wg.prepareCalls + wg.disconnectCalls + wg.reconnectCalls, 0);
    },
  );

  test('passive retry never stops either of two confirmed tunnels', () async {
    final api = _StartupApi();
    final wg = _StartupWireGuard()..statusUnavailable = true;
    final ov = _StartupOpenVpn();
    final app = _makeController(api: api, wireguard: wg, openVpn: ov);
    addTearDown(app.dispose);
    await app.initialize();
    wg.statusUnavailable = false;
    wg.connected = true;
    ov.connected = true;
    await app.retryRuntimeVerification();
    expect(app.vpnStatus, VpnStatus.connected);
    expect(app.runtimeVerificationPending, isFalse);
    expect(app.requiresExplicitDisconnect, isTrue);
    expect(wg.disconnectCalls + ov.disconnectCalls, 0);
    expect(wg.prepareCalls + wg.reconnectCalls, 0);
    await app.toggleConnection();
    expect(wg.disconnectCalls, 1);
    expect(ov.disconnectCalls, 1);
    expect(app.vpnStatus, VpnStatus.disconnected);
  });

  test(
    'a confirmed WireGuard tunnel survives a later status query failure',
    () async {
      final wg = _StartupWireGuard()
        ..connected = true
        ..failAfterFirstStatus = true
        ..protectionUnavailable = true;
      final ov = _StartupOpenVpn()..statusUnavailable = true;
      final app = _makeController(
        api: _StartupApi(),
        wireguard: wg,
        openVpn: ov,
      );
      addTearDown(app.dispose);
      await app.initialize();
      expect(app.runtimeVerificationPending, isFalse);
      expect(app.requiresExplicitDisconnect, isTrue);
      expect(app.activeProtocol, VpnProtocol.wireGuard);
      expect(app.vpnStatus, VpnStatus.error);
      expect(wg.disconnectCalls + ov.disconnectCalls, 0);
    },
  );

  test(
    'an in-flight passive result is discarded after account sign-out',
    () async {
      final api = _StartupApi();
      final wg = _StartupWireGuard()..statusUnavailable = true;
      final app = _makeController(api: api, wireguard: wg);
      addTearDown(app.dispose);
      await app.initialize();
      wg.statusGate = Completer<bool>();
      final retry = app.retryRuntimeVerification();
      await app.signOut();
      wg.statusGate!.complete(true);
      await retry;
      expect(app.vpnStatus, VpnStatus.error);
      expect(app.activeProtocol, isNull);
      expect(app.runtimeVerificationPending, isTrue);
      expect(app.profile, isNull);
      expect(wg.prepareCalls + wg.disconnectCalls + wg.reconnectCalls, 0);
      expect(api.meCalls + api.locationsCalls, 0);
    },
  );

  test(
    'native detection cause is safe and does not become a disconnect request',
    () async {
      final api = _StartupApi();
      final wg = _StartupWireGuard()
        ..statusUnavailable = true
        ..statusErrorCode = 'runtime_detection_failed'
        ..statusErrorDetails = {
          'win32_error': 5,
          'private': 'ignored-private-value',
        };
      final app = _makeController(api: api, wireguard: wg);
      addTearDown(app.dispose);
      await app.initialize();
      expect(app.vpnStatus, VpnStatus.error);
      expect(app.runtimeVerificationPending, isTrue);
      expect(app.requiresExplicitDisconnect, isFalse);
      expect(app.runtimeVerificationErrorCode, 'runtime_detection_failed');
      expect(app.runtimeVerificationWindowsError, 5);
      expect(
        app.errorMessage,
        'Windows n’a pas permis de vérifier l’installation de FuzeVPN.',
      );
      expect(
        await app.signIn(email: 'test@example.invalid', password: 'synthetic'),
        isFalse,
      );
      expect(api.loginCalls, 0);
      expect(app.errorMessage, isNot(contains('déconnexion')));
      expect(app.errorMessage, isNot(contains('private')));
    },
  );

  testWidgets('startup retries are bounded to three passive observations', (
    tester,
  ) async {
    final api = _StartupApi();
    final wg = _StartupWireGuard()..statusUnavailable = true;
    final ov = _StartupOpenVpn();
    final app = _makeController(api: api, wireguard: wg, openVpn: ov);
    await app.initialize();
    final initial = wg.statusCalls;
    for (final delay in [250, 1000, 2000]) {
      await tester.pump(Duration(milliseconds: delay));
      await tester.pump();
    }
    expect(wg.statusCalls, initial + 6);
    final afterRetries = wg.statusCalls;
    await tester.pump(const Duration(seconds: 10));
    expect(wg.statusCalls, afterRetries);
    expect(app.vpnStatus, VpnStatus.error);
    expect(app.runtimeVerificationPending, isTrue);
    expect(app.requiresExplicitDisconnect, isFalse);
    expect(
      wg.prepareCalls +
          wg.disconnectCalls +
          wg.reconnectCalls +
          ov.disconnectCalls,
      0,
    );
    expect(api.meCalls + api.locationsCalls, 0);
    app.dispose();
  });

  testWidgets('dispose cancels passive startup retries', (tester) async {
    final wg = _StartupWireGuard()..statusUnavailable = true;
    final app = _makeController(api: _StartupApi(), wireguard: wg);
    await app.initialize();
    final before = wg.statusCalls;
    app.dispose();
    await tester.pump(const Duration(seconds: 10));
    expect(wg.statusCalls, before);
  });

  testWidgets(
    'account sign-out invalidates pending retry without claiming disconnected',
    (tester) async {
      final wg = _StartupWireGuard()..statusUnavailable = true;
      final app = _makeController(api: _StartupApi(), wireguard: wg);
      await app.initialize();
      await app.signOut();
      final before = wg.statusCalls;
      await tester.pump(const Duration(seconds: 10));
      expect(wg.statusCalls, before);
      expect(wg.disconnectCalls, 0);
      expect(app.vpnStatus, VpnStatus.error);
      expect(app.runtimeVerificationPending, isTrue);
      app.dispose();
    },
  );

  testWidgets('sign-in shows actual credential failure and keeps it scoped', (
    tester,
  ) async {
    final api = _StartupApi();
    final controller = _SignInController(api);
    await _pumpApp(tester, controller);
    await _openSignIn(tester);
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(_failedDisconnectMessage),
      ),
      findsNothing,
    );
    await tester.enterText(
      find.byType(TextField).first,
      'audit@example.invalid',
    );
    await tester.enterText(find.byType(TextField).last, 'synthetic-password');
    await tester.tap(find.widgetWithText(FilledButton, 'Se connecter'));
    await tester.pumpAndSettle();
    expect(api.loginCalls, 1);
    final credentialError = find.descendant(
      of: find.byType(AlertDialog),
      matching: find.text(_invalidCredentialsMessage),
    );
    expect(credentialError, findsOneWidget);
    controller.errorMessage = _unknownProtectionMessage;
    controller.notifyListeners();
    await tester.pumpAndSettle();
    expect(credentialError, findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(_unknownProtectionMessage),
      ),
      findsNothing,
    );
    await _closeApp(tester, controller);
  });
}
