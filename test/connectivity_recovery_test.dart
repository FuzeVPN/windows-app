// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';

import 'native_protection_status_fixture.dart';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/split_tunnel.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

const location = Location(
  id: 'frankfurt-01',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const profile = UserProfile(
  userId: 'user-1',
  email: 'test@example.invalid',
  firstName: 'Test',
  emailVerified: true,
);
// Another node, which only a location migration moves the device to.
const otherLocation = Location(
  id: 'paris-01',
  city: 'Paris',
  countryCode: 'FR',
  displayName: 'Paris 1',
  supportedProtocols: {VpnProtocol.openVpn},
);
const device = VpnDevice(
  deviceId: 'device-1',
  name: 'FuzeVPN — Windows',
  location: location,
  createdAt: null,
);

Future<void> pumpNativeRecovery(WidgetTester tester) async {
  for (var attempt = 0; attempt < 10; attempt++) {
    await tester.pump(const Duration(milliseconds: 200));
  }
}

// The fingerprint the client keeps of a CSR: never the CSR itself.
String _sha256(String csrPem) => sha256.convert(utf8.encode(csrPem)).toString();

// Runs a command while fake time passes, so that a regression waiting on a
// native recovery fails the expectations that follow instead of hanging.
Future<void> runCommand(WidgetTester tester, Future<void> command) async {
  var done = false;
  unawaited(command.whenComplete(() => done = true));
  for (var tick = 0; tick < 60 && !done; tick++) {
    await tester.pump(const Duration(milliseconds: 500));
  }
}

/// Every command and automatic attempt ends in a state the next command can
/// begin from, with no uncaught error: checked at every notification that
/// finds no command running, so that a wedge fails the test that produced
/// it rather than a later one.
class _RestingGuard {
  _RestingGuard(this.controller) {
    controller.addListener(_check);
  }

  final AppController controller;
  final violations = <VpnStatus>[];
  static const _resting = {
    VpnStatus.disconnected,
    VpnStatus.connected,
    VpnStatus.blocked,
    VpnStatus.error,
  };

  void _check() {
    if (!controller.isConnectionBusy &&
        !_resting.contains(controller.vpnStatus)) {
      violations.add(controller.vpnStatus);
    }
  }

  /// Nothing runs, the state rests and nothing was thrown: Connect,
  /// Disconnect and Retry can all begin from here.
  void expectResting(WidgetTester tester) {
    expect(tester.takeException(), isNull);
    expect(violations, isEmpty);
    expect(controller.isConnectionBusy, isFalse);
    expect(_resting, contains(controller.vpnStatus));
  }
}

void main() {
  testWidgets(
    'regroupe les événements réseau et reconnecte WireGuard une fois',
    (tester) async {
      final clock = _Clock();
      final window = _ConnectivityWindow();
      final wireGuard = _RecoveryWireGuard()..connected = true;
      final openVpn = _RecoveryOpenVpn();
      final controller = AppController(
        api: _RecoveryApi(),
        store: _RecoveryStore(protocol: 'wireguard'),
        wireguard: wireGuard,
        openVpn: openVpn,
        window: window,
        now: clock.call,
      );
      await controller.initialize();
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
      clock.advance(const Duration(seconds: 11));

      await window.emit(WindowsConnectivityEvent.networkAvailable);
      await window.emit(WindowsConnectivityEvent.networkAvailable);
      await window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 3));
      await tester.pump();

      expect(wireGuard.connectCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
      controller.dispose();
    },
  );

  testWidgets(
    'reprend OpenVPN après la sortie de veille sans changer de protocole',
    (tester) async {
      final clock = _Clock();
      final window = _ConnectivityWindow();
      final wireGuard = _RecoveryWireGuard();
      final openVpn = _RecoveryOpenVpn()
        ..available = true
        ..connected = true;
      final controller = AppController(
        api: _RecoveryApi(),
        store: _RecoveryStore(protocol: 'openvpn'),
        wireguard: wireGuard,
        openVpn: openVpn,
        window: window,
        now: clock.call,
      );
      await controller.initialize();
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      clock.advance(const Duration(seconds: 11));

      await window.emit(WindowsConnectivityEvent.systemResumed);
      await tester.pump(const Duration(seconds: 2));
      await tester.pump();

      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      controller.dispose();
    },
  );

  testWidgets('ne reconnecte pas lorsque la préférence est désactivée', (
    tester,
  ) async {
    final clock = _Clock();
    final window = _ConnectivityWindow();
    final wireGuard = _RecoveryWireGuard()..connected = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard', automaticReconnect: false),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(),
      window: window,
      now: clock.call,
    );
    await controller.initialize();
    clock.advance(const Duration(seconds: 11));
    await window.emit(WindowsConnectivityEvent.networkAvailable);
    await tester.pump(const Duration(seconds: 4));

    expect(wireGuard.connectCalls, 0);
    controller.dispose();
  });

  testWidgets('conserve le kill switch après une reconnexion WireGuard ratée', (
    tester,
  ) async {
    final clock = _Clock();
    final window = _ConnectivityWindow();
    final wireGuard = _RecoveryWireGuard()
      ..connected = true
      ..protectionActive = true
      ..failConnect = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(),
      window: window,
      now: clock.call,
    );
    await controller.initialize();
    clock.advance(const Duration(seconds: 11));

    await window.emit(WindowsConnectivityEvent.networkAvailable);
    await tester.pump(const Duration(seconds: 3));
    await pumpNativeRecovery(tester);

    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.activeProtocol, isNull);
    expect(controller.requiresExplicitDisconnect, isTrue);
    expect(wireGuard.protectionActive, isTrue);
    expect(wireGuard.disconnectCalls, 0);

    wireGuard.failConnect = false;
    await window.emit(WindowsConnectivityEvent.networkAvailable);
    await tester.pump(const Duration(seconds: 3));
    await tester.pump();
    expect(controller.vpnStatus, VpnStatus.connected);
    expect(controller.activeProtocol, VpnProtocol.wireGuard);
    expect(wireGuard.disconnectCalls, 0);

    await controller.toggleConnection();
    expect(controller.vpnStatus, VpnStatus.disconnected);
    expect(wireGuard.protectionActive, isFalse);
    expect(wireGuard.disconnectCalls, 1);
    controller.dispose();
  });

  testWidgets('conserve le kill switch après une reconnexion OpenVPN ratée', (
    tester,
  ) async {
    final clock = _Clock();
    final window = _ConnectivityWindow();
    final openVpn = _RecoveryOpenVpn()
      ..available = true
      ..connected = true
      ..protectionActive = true
      ..failConnect = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'openvpn'),
      wireguard: _RecoveryWireGuard(),
      openVpn: openVpn,
      window: window,
      now: clock.call,
    );
    await controller.initialize();
    clock.advance(const Duration(seconds: 11));

    await window.emit(WindowsConnectivityEvent.systemResumed);
    await tester.pump(const Duration(seconds: 2));
    await pumpNativeRecovery(tester);

    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.activeProtocol, isNull);
    expect(openVpn.protectionActive, isTrue);
    expect(openVpn.disconnectCalls, 0);
    controller.dispose();
  });

  testWidgets('restaure au démarrage un kill switch sans tunnel', (
    tester,
  ) async {
    final openVpn = _RecoveryOpenVpn()
      ..available = true
      ..cacheAvailable = false
      ..protectionActive = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'openvpn'),
      wireguard: _RecoveryWireGuard(),
      openVpn: openVpn,
      window: _ConnectivityWindow(),
    );

    await controller.initialize();

    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.requiresExplicitDisconnect, isTrue);
    await controller.toggleConnection();
    expect(openVpn.disconnectCalls, 1);
    expect(controller.vpnStatus, VpnStatus.disconnected);
    controller.dispose();
  });

  testWidgets('un échec initial conserve le pré-blocage WFP', (tester) async {
    final wireGuard = _RecoveryWireGuard()..failConnect = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(),
      window: _ConnectivityWindow(),
    );
    await controller.initialize();

    final connection = controller.quickConnect();
    await pumpNativeRecovery(tester);
    await connection;

    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.requiresExplicitDisconnect, isTrue);
    expect(wireGuard.protectionActive, isTrue);
    controller.dispose();
  });

  testWidgets('prépare WFP avant le premier appel API de connexion', (
    tester,
  ) async {
    final trace = <String>[];
    final wireGuard = _RecoveryWireGuard(trace: trace);
    final api = _RecoveryApi(trace: trace);
    final controller = AppController(
      api: api,
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(trace: trace),
      window: _ConnectivityWindow(),
    );
    await controller.initialize();
    trace.clear();

    await controller.quickConnect();

    expect(trace.indexOf('wireguard.prepare'), 0);
    expect(
      trace.indexOf('api.register'),
      greaterThan(trace.indexOf('wireguard.prepare')),
    );
    expect(
      trace.indexOf('wireguard.connect'),
      greaterThan(trace.indexOf('api.register')),
    );
    expect(controller.vpnStatus, VpnStatus.connected);
    controller.dispose();
  });

  testWidgets('un échec de préparation empêche API et moteur natif', (
    tester,
  ) async {
    final trace = <String>[];
    final wireGuard = _RecoveryWireGuard(trace: trace)..failPrepare = true;
    final api = _RecoveryApi(trace: trace);
    final controller = AppController(
      api: api,
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(trace: trace),
      window: _ConnectivityWindow(),
    );
    await controller.initialize();
    trace.clear();

    await controller.quickConnect();

    expect(trace, ['wireguard.prepare']);
    expect(api.registerCalls, 0);
    expect(wireGuard.connectCalls, 0);
    expect(controller.vpnStatus, VpnStatus.error);
    expect(controller.requiresExplicitDisconnect, isFalse);
    controller.dispose();
  });

  testWidgets('prépare OpenVPN avant tout appel API de connexion', (
    tester,
  ) async {
    final trace = <String>[];
    final openVpn = _RecoveryOpenVpn(trace: trace)..available = true;
    final controller = AppController(
      api: _RecoveryApi(trace: trace),
      store: _RecoveryStore(protocol: 'openvpn'),
      wireguard: _RecoveryWireGuard(trace: trace),
      openVpn: openVpn,
      window: _ConnectivityWindow(),
    );
    await controller.initialize();
    trace.clear();

    await controller.quickConnect();

    expect(trace.first, 'openvpn.prepare');
    expect(
      trace.indexOf('api.devices'),
      greaterThan(trace.indexOf('openvpn.prepare')),
    );
    expect(
      trace.indexOf('openvpn.csr'),
      greaterThan(trace.indexOf('api.devices')),
    );
    expect(
      trace.indexOf('api.openvpn_profile'),
      greaterThan(trace.indexOf('openvpn.csr')),
    );
    expect(
      trace.indexOf('openvpn.connect'),
      greaterThan(trace.indexOf('api.openvpn_profile')),
    );
    expect(controller.vpnStatus, VpnStatus.connected);
    controller.dispose();
  });

  testWidgets('un échec OpenVPN initial conserve le pré-blocage WFP', (
    tester,
  ) async {
    final openVpn = _RecoveryOpenVpn()
      ..available = true
      ..failConnect = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'openvpn'),
      wireguard: _RecoveryWireGuard(),
      openVpn: openVpn,
      window: _ConnectivityWindow(),
    );
    await controller.initialize();

    final connection = controller.quickConnect();
    await pumpNativeRecovery(tester);
    await connection;

    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.requiresExplicitDisconnect, isTrue);
    expect(openVpn.protectionActive, isTrue);
    controller.dispose();
  });

  testWidgets('sans kill switch le contrôleur ne pose aucun pré-blocage', (
    tester,
  ) async {
    final wireGuard = _RecoveryWireGuard();
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard', killSwitch: false),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(),
      window: _ConnectivityWindow(),
    );
    await controller.initialize();

    await controller.quickConnect();

    expect(wireGuard.prepareCalls, 0);
    expect(wireGuard.connectCalls, 1);
    expect(controller.vpnStatus, VpnStatus.connected);
    controller.dispose();
  });

  testWidgets('reste bloqué si la déconnexion explicite échoue', (
    tester,
  ) async {
    final wireGuard = _RecoveryWireGuard()
      ..cacheAvailable = false
      ..protectionActive = true
      ..failDisconnect = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(),
      window: _ConnectivityWindow(),
    );
    await controller.initialize();
    expect(controller.vpnStatus, VpnStatus.blocked);

    final disconnect = controller.toggleConnection();
    await pumpNativeRecovery(tester);
    await disconnect;

    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(wireGuard.protectionActive, isTrue);
    expect(controller.errorMessage, contains('kill switch bloque toujours'));
    expect(controller.requiresExplicitDisconnect, isTrue);
    controller.dispose();
  });

  testWidgets(
    'libère le propriétaire WFP natif si le protocole UI est obsolète',
    (tester) async {
      final wireGuard = _RecoveryWireGuard()
        ..connected = true
        ..protectionActive = true;
      final openVpn = _RecoveryOpenVpn()..available = true;
      final controller = AppController(
        api: _RecoveryApi(),
        store: _RecoveryStore(protocol: 'wireguard'),
        wireguard: wireGuard,
        openVpn: openVpn,
        window: _ConnectivityWindow(),
      );
      await controller.initialize();
      expect(controller.activeProtocol, VpnProtocol.wireGuard);

      // Reproduce an interrupted cross-protocol preparation: native WFP has
      // already moved to OpenVPN while the UI still remembers WireGuard.
      wireGuard.protectionActive = false;
      openVpn.protectionActive = true;

      await controller.toggleConnection();

      expect(wireGuard.disconnectCalls, 1);
      expect(openVpn.disconnectCalls, 1);
      expect(wireGuard.protectionActive, isFalse);
      expect(openVpn.protectionActive, isFalse);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.requiresExplicitDisconnect, isFalse);
      controller.dispose();
    },
  );

  testWidgets('tente l’autre propriétaire WFP si son statut est indisponible', (
    tester,
  ) async {
    final wireGuard = _RecoveryWireGuard()
      ..connected = true
      ..protectionActive = true;
    final openVpn = _RecoveryOpenVpn()
      ..available = true
      ..protectionActive = true
      ..failProtectionReads = 1;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: openVpn,
      window: _ConnectivityWindow(),
    );
    await controller.initialize();

    await controller.toggleConnection();

    expect(wireGuard.disconnectCalls, 1);
    expect(openVpn.disconnectCalls, 1);
    expect(openVpn.protectionActive, isFalse);
    expect(controller.vpnStatus, VpnStatus.disconnected);
    controller.dispose();
  });

  testWidgets(
    'bascule automatiquement vers OpenVPN sans déconnecter WireGuard',
    (tester) async {
      final wireGuard = _RecoveryWireGuard()..failConnect = true;
      final openVpn = _RecoveryOpenVpn()..available = true;
      final controller = AppController(
        api: _RecoveryApi(),
        store: _RecoveryStore(protocol: 'auto'),
        wireguard: wireGuard,
        openVpn: openVpn,
        window: _ConnectivityWindow(),
      );
      await controller.initialize();

      final connection = controller.quickConnect();
      await pumpNativeRecovery(tester);
      await connection;

      expect(wireGuard.disconnectCalls, 0);
      expect(wireGuard.prepareCalls, 1);
      expect(openVpn.prepareCalls, 1);
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      controller.dispose();
    },
  );

  test('renouvelle OpenVPN sous pré-blocage avant le CSR et l’API', () async {
    final trace = <String>[];
    final api = _RecoveryApi(trace: trace);
    final openVpn = _RecoveryOpenVpn(trace: trace)
      ..available = true
      ..connected = true
      ..protectionActive = true;
    final controller = AppController(
      api: api,
      store: _RecoveryStore(protocol: 'openvpn'),
      wireguard: _RecoveryWireGuard(trace: trace),
      openVpn: openVpn,
      window: _ConnectivityWindow(),
    );
    addTearDown(controller.dispose);
    await controller.initialize();
    trace.clear();

    await controller.renewOpenVpnProfile();

    expect(trace, [
      'openvpn.prepare',
      'openvpn.suspend',
      'openvpn.renew_csr',
      'api.openvpn_renew',
      'openvpn.connect',
    ]);
    expect(openVpn.disconnectCalls, 0);
    expect(openVpn.suspendCalls, 1);
    expect(controller.vpnStatus, VpnStatus.connected);
    expect(controller.activeProtocol, VpnProtocol.openVpn);
  });

  test('garde le pré-blocage si le renouvellement OpenVPN échoue', () async {
    final trace = <String>[];
    final api = _RecoveryApi(trace: trace)..failRenew = true;
    final openVpn = _RecoveryOpenVpn(trace: trace)
      ..available = true
      ..connected = true
      ..protectionActive = true;
    final controller = AppController(
      api: api,
      store: _RecoveryStore(protocol: 'openvpn'),
      wireguard: _RecoveryWireGuard(trace: trace),
      openVpn: openVpn,
      window: _ConnectivityWindow(),
    );
    addTearDown(controller.dispose);
    await controller.initialize();
    trace.clear();

    await controller.renewOpenVpnProfile();

    expect(
      trace,
      containsAllInOrder([
        'openvpn.prepare',
        'openvpn.suspend',
        'openvpn.renew_csr',
        'api.openvpn_renew',
      ]),
    );
    expect(openVpn.importCalls, 0);
    expect(openVpn.protectionActive, isTrue);
    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.requiresExplicitDisconnect, isTrue);
  });

  testWidgets(
    'reporte l’actualisation des adresses API jusqu’à la fin de la connexion',
    (tester) async {
      final clock = _Clock();
      final window = _ConnectivityWindow();
      final api = _RecoveryApi();
      final gate = Completer<void>();
      final wireGuard = _RecoveryWireGuard()..connectGate = gate;
      final controller = AppController(
        api: api,
        store: _RecoveryStore(protocol: 'wireguard'),
        wireguard: wireGuard,
        openVpn: _RecoveryOpenVpn(),
        window: window,
        now: clock.call,
      );
      await controller.initialize();
      expect(controller.isConnectionBusy, isFalse);

      // Idle: a connectivity hint still refreshes the cache at once.
      var expected = api.bootstrapInvalidations + 1;
      await window.emit(WindowsConnectivityEvent.networkAvailable);
      expect(api.bootstrapInvalidations, expected);

      final connecting = controller.toggleConnection();
      for (var turn = 0; turn < 20 && wireGuard.connectCalls == 0; turn++) {
        await tester.pump();
      }
      expect(wireGuard.connectCalls, 1);
      expect(controller.isConnectionBusy, isTrue);

      // The adapter coming up fires hints while the native connect still
      // holds the privileged worker: a forced resolution would queue there.
      await window.emit(WindowsConnectivityEvent.networkAvailable);
      await window.emit(WindowsConnectivityEvent.networkAvailable);
      expect(api.bootstrapInvalidations, expected);

      gate.complete();
      await connecting;
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.isConnectionBusy, isFalse);
      expect(api.bootstrapInvalidations, ++expected);
      controller.dispose();
    },
  );

  testWidgets('confirme deux fois une interruption avant de changer l’état', (
    tester,
  ) async {
    final window = _ConnectivityWindow();
    final wireGuard = _RecoveryWireGuard()..connected = true;
    final controller = AppController(
      api: _RecoveryApi(),
      store: _RecoveryStore(protocol: 'wireguard'),
      wireguard: wireGuard,
      openVpn: _RecoveryOpenVpn(),
      window: window,
    );
    await controller.initialize();
    expect(controller.vpnStatus, VpnStatus.connected);

    wireGuard.connected = false;
    await tester.pump(const Duration(seconds: 4));
    expect(controller.vpnStatus, VpnStatus.connected);
    await tester.pump(const Duration(seconds: 4));
    await tester.pump();

    expect(controller.vpnStatus, VpnStatus.disconnected);
    expect(controller.activeProtocol, isNull);
    expect(controller.errorMessage, contains('interrompue'));
    controller.dispose();
  });

  group('certificat OpenVPN à renouveler', () {
    Future<AppController> connectOpenVpn(
      _Clock clock,
      _RecoveryApi api,
      _RecoveryOpenVpn openVpn, {
      required bool killSwitch,
      _ConnectivityWindow? window,
      _RecoveryStore? store,
    }) async {
      openVpn.server = api;
      final controller = AppController(
        api: api,
        store:
            store ??
            _RecoveryStore(protocol: 'openvpn', killSwitch: killSwitch),
        wireguard: _RecoveryWireGuard(),
        openVpn: openVpn..available = true,
        window: window ?? _ConnectivityWindow(),
        now: clock.call,
      );
      await controller.initialize();
      await controller.toggleConnection();
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      return controller;
    }

    List<String> openVpnTrace(String event) => DiagnosticLog.recentLines
        .where((line) => line.contains(' area=openvpn event=$event '))
        .toList();

    String mode(bool killSwitch) =>
        'kill switch ${killSwitch ? 'actif' : 'inactif'}';

    for (final killSwitch in [true, false]) {
      testWidgets('après une coupure, la reconnexion automatique renouvelle un '
          'certificat expiré sans création ni rejeu du cache natif '
          '(${mode(killSwitch)})', (tester) async {
        final clock = _Clock();
        final trace = <String>[];
        final api = _RecoveryApi(trace: trace, clock: clock)
          ..storedNotAfter = clock.value.add(const Duration(days: 20));
        final openVpn = _RecoveryOpenVpn(trace: trace);
        final controller = await connectOpenVpn(
          clock,
          api,
          openVpn,
          killSwitch: killSwitch,
        );
        final guard = _RestingGuard(controller);
        final creates = api.createCalls;
        final statuses = <VpnStatus>[];
        controller.addListener(() => statuses.add(controller.vpnStatus));

        // The PC slept past the expiry; the server then dropped the tunnel.
        clock.advance(const Duration(days: 21));
        openVpn.connected = false;
        trace.clear();
        for (var second = 0; second < 20; second++) {
          await tester.pump(const Duration(seconds: 1));
        }
        await pumpNativeRecovery(tester);

        // Neither the broker's expired copy nor a creation the server would
        // count and refuse: the known expiry renews directly.
        guard.expectResting(tester);
        expect(openVpn.reconnectCalls, 0);
        expect(api.createCalls, creates);
        expect(
          trace,
          containsAllInOrder([
            'openvpn.renew_csr',
            'api.openvpn_renew',
            'openvpn.connect',
          ]),
        );
        expect(api.countedRenewals, 1);
        expect(openVpn.importedNotAfter.last, api.renewedNotAfter);
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.errorMessage, isNull);
        expect(openVpn.disconnectCalls, 0);
        if (killSwitch) {
          // The protection was never released meanwhile.
          expect(statuses, contains(VpnStatus.blocked));
          expect(statuses, isNot(contains(VpnStatus.disconnected)));
          expect(openVpn.protectionActive, isTrue);
        }
        expect(
          openVpnTrace('started').last,
          contains('code=certificate_expired stage=certificate_renewal'),
        );
        controller.dispose();
      });

      testWidgets(
        'un événement réseau reconnecte par un renouvellement un certificat '
        'qui expire dans les 14 jours (${mode(killSwitch)})',
        (tester) async {
          final clock = _Clock();
          final window = _ConnectivityWindow();
          final api = _RecoveryApi(clock: clock)
            ..storedNotAfter = clock.value.add(const Duration(days: 30));
          final openVpn = _RecoveryOpenVpn();
          final controller = await connectOpenVpn(
            clock,
            api,
            openVpn,
            killSwitch: killSwitch,
            window: window,
          );
          final guard = _RestingGuard(controller);
          final creates = api.createCalls;
          clock.advance(const Duration(days: 20));
          openVpn.connected = false;

          await window.emit(WindowsConnectivityEvent.systemResumed);
          for (var second = 0; second < 10; second++) {
            await tester.pump(const Duration(seconds: 1));
          }
          await pumpNativeRecovery(tester);

          guard.expectResting(tester);
          expect(openVpn.reconnectCalls, 0);
          expect(api.createCalls, creates);
          expect(api.countedRenewals, 1);
          expect(openVpn.importedNotAfter.last, api.renewedNotAfter);
          expect(controller.vpnStatus, VpnStatus.connected);
          expect(openVpn.disconnectCalls, 0);
          controller.dispose();
        },
      );

      testWidgets(
        'un certificat valide plus de 14 jours reprend par le cache natif '
        'sans aucune requête (${mode(killSwitch)})',
        (tester) async {
          final clock = _Clock();
          final window = _ConnectivityWindow();
          final api = _RecoveryApi(clock: clock)
            ..storedNotAfter = clock.value.add(const Duration(days: 60));
          final openVpn = _RecoveryOpenVpn();
          final controller = await connectOpenVpn(
            clock,
            api,
            openVpn,
            killSwitch: killSwitch,
            window: window,
          );
          final guard = _RestingGuard(controller);
          final creates = api.createCalls;
          clock.advance(const Duration(days: 1));
          openVpn.connected = false;

          await window.emit(WindowsConnectivityEvent.systemResumed);
          for (var second = 0; second < 10; second++) {
            await tester.pump(const Duration(seconds: 1));
          }
          await pumpNativeRecovery(tester);

          guard.expectResting(tester);
          expect(api.renewCalls, 0);
          expect(openVpn.renewCsrCalls, 0);
          // Without the kill switch nothing is retained, so the cache cannot
          // be replayed and the free creation reconnects it.
          if (killSwitch) {
            expect(openVpn.reconnectCalls, 1);
            expect(api.createCalls, creates);
          } else {
            expect(api.createCalls, creates + 1);
            expect(api.countedCreates, 1);
          }
          expect(controller.vpnStatus, VpnStatus.connected);
          controller.dispose();
        },
      );

      testWidgets(
        'un tunnel rattaché que le serveur refuse comme expiré est renouvelé '
        'par la tentative automatique suivante (${mode(killSwitch)})',
        (tester) async {
          // The window opened while the service kept the tunnel up: nothing
          // tells it the certificate's date.
          final clock = _Clock();
          final window = _ConnectivityWindow();
          final store = _RecoveryStore(
            protocol: 'openvpn',
            killSwitch: killSwitch,
          );
          final api = _RecoveryApi(clock: clock)
            ..storedCsr = 'csr-not-logged'
            ..storedNotAfter = clock.value.add(const Duration(hours: 1));
          final openVpn = _RecoveryOpenVpn()
            ..server = api
            ..available = true
            ..connected = true
            ..protectionActive = killSwitch;
          final controller = AppController(
            api: api,
            store: store,
            wireguard: _RecoveryWireGuard(),
            openVpn: openVpn,
            window: window,
            now: clock.call,
          );
          await controller.initialize();
          expect(controller.vpnStatus, VpnStatus.connected);
          final guard = _RestingGuard(controller);

          clock.advance(const Duration(hours: 2));
          openVpn
            ..connected = false
            ..reconnectFailureCode = 'openvpn_certificate_expired';
          await window.emit(WindowsConnectivityEvent.systemResumed);
          for (var second = 0; second < 30; second++) {
            await tester.pump(const Duration(seconds: 1));
          }
          await pumpNativeRecovery(tester);

          guard.expectResting(tester);
          if (killSwitch) {
            // The broker replayed its copy once, which the server refused:
            // the next attempt renews without creating the profile.
            expect(openVpn.reconnectCalls, 1);
            expect(api.createCalls, 0);
          } else {
            // Nothing retained, no copy to replay: the creation the server
            // refuses for the expired certificate leads to the renewal.
            expect(api.countedCreates, 1);
          }
          expect(api.countedRenewals, 1);
          expect(openVpn.importedNotAfter.last, api.renewedNotAfter);
          expect(controller.vpnStatus, VpnStatus.connected);
          expect(openVpn.disconnectCalls, 0);
          controller.dispose();
        },
      );

      testWidgets(
        'une réponse perdue pendant la reconnexion automatique est rejouée '
        'avec le même CSR par la tentative suivante, sans renouvellement '
        'compté (${mode(killSwitch)})',
        (tester) async {
          final clock = _Clock();
          final store = _RecoveryStore(
            protocol: 'openvpn',
            killSwitch: killSwitch,
          );
          final api = _RecoveryApi(clock: clock)
            ..storedNotAfter = clock.value.add(const Duration(days: 20))
            ..lostRenewAnswers = 1;
          final openVpn = _RecoveryOpenVpn();
          final controller = await connectOpenVpn(
            clock,
            api,
            openVpn,
            killSwitch: killSwitch,
            store: store,
          );
          final guard = _RestingGuard(controller);
          clock.advance(const Duration(days: 10));
          openVpn.connected = false;

          for (var second = 0; second < 60; second++) {
            await tester.pump(const Duration(seconds: 1));
          }
          await pumpNativeRecovery(tester);

          guard.expectResting(tester);
          expect(api.renewedCsrs, hasLength(2));
          expect(api.renewedCsrs.toSet(), hasLength(1));
          expect(api.countedRenewals, 1);
          expect(openVpn.importedNotAfter.last, api.renewedNotAfter);
          expect(controller.vpnStatus, VpnStatus.connected);
          expect(store.renewalDevice, isNull);
          expect(openVpn.deleteProfileCalls, 0);
          controller.dispose();
        },
      );

      testWidgets(
        'un renouvellement livré dont l’import échoue est rejoué gratuitement '
        'par la tentative suivante (${mode(killSwitch)})',
        (tester) async {
          final clock = _Clock();
          final store = _RecoveryStore(
            protocol: 'openvpn',
            killSwitch: killSwitch,
          );
          final api = _RecoveryApi(clock: clock)
            ..storedNotAfter = clock.value.add(const Duration(days: 20));
          final openVpn = _RecoveryOpenVpn();
          final controller = await connectOpenVpn(
            clock,
            api,
            openVpn,
            killSwitch: killSwitch,
            store: store,
          );
          final guard = _RestingGuard(controller);
          // The node is restarting: the first import of the renewal fails.
          var failures = 1;
          openVpn.importFailureCode = (activation) =>
              activation.notAfter == api.renewedNotAfter && failures-- > 0
              ? 'openvpn_connection_timeout'
              : null;
          clock.advance(const Duration(days: 10));
          openVpn.connected = false;

          for (var second = 0; second < 60; second++) {
            await tester.pump(const Duration(seconds: 1));
          }
          await pumpNativeRecovery(tester);

          guard.expectResting(tester);
          expect(api.renewedCsrs, hasLength(2));
          expect(api.renewedCsrs.toSet(), hasLength(1));
          expect(api.countedRenewals, 1);
          expect(controller.vpnStatus, VpnStatus.connected);
          expect(store.renewalDevice, isNull);
          controller.dispose();
        },
      );

      testWidgets('après un 429, aucun renouvellement n’est renvoyé avant '
          'l’instant donné, et le certificat encore valide porte le tunnel '
          '(${mode(killSwitch)})', (tester) async {
        final clock = _Clock();
        final api = _RecoveryApi(clock: clock)
          ..storedNotAfter = clock.value.add(const Duration(days: 20))
          ..renewFailures = [
            const ApiException(
              statusCode: 429,
              errorCode: 'rate_limited',
              observedHttpStatus: 429,
              retryAfterSeconds: 1800,
            ),
          ];
        final openVpn = _RecoveryOpenVpn();
        final controller = await connectOpenVpn(
          clock,
          api,
          openVpn,
          killSwitch: killSwitch,
        );
        final guard = _RestingGuard(controller);
        clock.advance(const Duration(days: 10));
        openVpn.connected = false;

        // The whole automatic cycle runs within the half hour.
        for (var second = 0; second < 180; second++) {
          await tester.pump(const Duration(seconds: 1));
        }
        await pumpNativeRecovery(tester);

        guard.expectResting(tester);
        expect(api.renewCalls, 1);
        // Ten days of validity are left: that certificate reconnects.
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.deviceEnrollmentIssue, isNull);
        expect(openVpn.disconnectCalls, 0);

        // Within the half hour, a new connection sends no renewal.
        await runCommand(tester, controller.toggleConnection());
        await runCommand(tester, controller.toggleConnection());
        guard.expectResting(tester);
        expect(api.renewCalls, 1);
        expect(controller.vpnStatus, VpnStatus.connected);

        // Past the instant, the next connection sends it again.
        clock.advance(const Duration(minutes: 31));
        await runCommand(tester, controller.toggleConnection());
        await runCommand(tester, controller.toggleConnection());
        guard.expectResting(tester);
        expect(api.renewCalls, 2);
        expect(controller.vpnStatus, VpnStatus.connected);
        controller.dispose();
      });

      testWidgets(
        'un profil révoqué arrête les reconnexions automatiques sur sa carte, '
        'qui se résout en un clic (${mode(killSwitch)})',
        (tester) async {
          final clock = _Clock();
          final api = _RecoveryApi(clock: clock)
            ..storedNotAfter = clock.value.add(const Duration(days: 20))
            ..renewFailures = [
              const ApiException(
                statusCode: 409,
                errorCode: 'openvpn_profile_revoked',
                observedHttpStatus: 409,
              ),
            ];
          final openVpn = _RecoveryOpenVpn();
          final controller = await connectOpenVpn(
            clock,
            api,
            openVpn,
            killSwitch: killSwitch,
          );
          final guard = _RestingGuard(controller);
          clock.advance(const Duration(days: 10));
          openVpn.connected = false;

          for (var second = 0; second < 180; second++) {
            await tester.pump(const Duration(seconds: 1));
          }
          await pumpNativeRecovery(tester);

          // One request: the same one would get the same answer.
          guard.expectResting(tester);
          expect(api.renewCalls, 1);
          expect(
            controller.deviceEnrollmentIssue?.kind,
            DeviceEnrollmentIssueKind.openVpnProfileRevoked,
          );
          expect(openVpn.disconnectCalls, 0);
          if (killSwitch) {
            expect(controller.vpnStatus, VpnStatus.blocked);
            expect(openVpn.protectionActive, isTrue);
          }

          // The server removed the revoked profile: a new key enrolls.
          api.storedCsr = null;
          await runCommand(tester, controller.replaceRevokedOpenVpnProfile());
          guard.expectResting(tester);
          expect(openVpn.deleteProfileCalls, 1);
          expect(controller.vpnStatus, VpnStatus.connected);
          expect(controller.deviceEnrollmentIssue, isNull);
          controller.dispose();
        },
      );
    }

    testWidgets(
      'une réponse perdue est rejouée avec le même CSR après un redémarrage '
      'de l’application',
      (tester) async {
        final clock = _Clock();
        final store = _RecoveryStore(protocol: 'openvpn', killSwitch: false);
        final api = _RecoveryApi(clock: clock)
          ..storedNotAfter = clock.value.add(const Duration(days: 10))
          ..lostRenewAnswers = 1;
        // The server revoked the previous certificate when it issued the
        // renewal whose answer was lost: only the renewed one is accepted.
        final openVpn = _RecoveryOpenVpn()
          ..server = api
          ..importFailureCode = (activation) =>
              activation.notAfter == api.renewedNotAfter
              ? null
              : 'openvpn_client_certificate_rejected';
        final controller = AppController(
          api: api,
          store: store,
          wireguard: _RecoveryWireGuard(),
          openVpn: openVpn..available = true,
          window: _ConnectivityWindow(),
          now: clock.call,
        );
        await controller.initialize();
        await runCommand(tester, controller.toggleConnection());
        expect(api.countedRenewals, 1);
        expect(controller.vpnStatus, isNot(VpnStatus.connected));
        expect(store.renewalDevice, 'device-1');
        final pendingCsr = api.renewedCsrs.single;
        expect(store.renewalCsrSha256, _sha256(pendingCsr));
        controller.dispose();

        // The application starts again and connects at launch.
        store.autoConnect = true;
        final restarted = AppController(
          api: api,
          store: store,
          wireguard: _RecoveryWireGuard(),
          openVpn: openVpn,
          window: _ConnectivityWindow(),
          now: clock.call,
        );
        await restarted.initialize();
        await pumpNativeRecovery(tester);

        expect(restarted.vpnStatus, VpnStatus.connected);
        expect(api.renewedCsrs, [pendingCsr, pendingCsr]);
        expect(api.countedRenewals, 1);
        expect(openVpn.importedNotAfter.last, api.renewedNotAfter);
        expect(store.renewalDevice, isNull);
        restarted.dispose();
      },
    );

    testWidgets(
      'un changement d’emplacement renouvelle avant de connecter le nouveau '
      'nœud un certificat qui expire dans les 14 jours',
      (tester) async {
        final clock = _Clock();
        final api = _RecoveryApi(clock: clock)
          ..catalogue = const [location, otherLocation]
          ..storedNotAfter = clock.value.add(const Duration(days: 20));
        final openVpn = _RecoveryOpenVpn();
        final controller = await connectOpenVpn(
          clock,
          api,
          openVpn,
          killSwitch: true,
        );
        final guard = _RestingGuard(controller);
        clock.advance(const Duration(days: 10));

        expect(
          await controller.prepareLocationChange(otherLocation),
          LocationChangePreparation.confirmationRequired,
        );
        await runCommand(tester, controller.confirmPreparedLocationChange());
        await pumpNativeRecovery(tester);

        guard.expectResting(tester);
        expect(api.migrationCalls, 1);
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(api.countedRenewals, 1);
        expect(openVpn.importedEndpoints.last, '203.0.113.20');
        expect(openVpn.importedNotAfter.last, api.renewedNotAfter);
        controller.dispose();
      },
    );
  });
}

class _Clock {
  DateTime value = DateTime.utc(2026, 8, 25);
  DateTime call() => value;
  void advance(Duration duration) => value = value.add(duration);
}

class _ConnectivityWindow extends WindowBridge {
  Future<void> Function(WindowsConnectivityEvent event)? listener;

  @override
  Future<String> deviceName() async => 'FuzeVPN 0.1.0 -- Windows';

  @override
  Future<bool> isLaunchAtStartupEnabled() async => false;

  @override
  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent event) handler,
  ) {
    listener = handler;
  }

  @override
  void stopConnectivityListener() => listener = null;

  Future<void> emit(WindowsConnectivityEvent event) async {
    await listener?.call(event);
  }
}

class _RecoveryStore extends SecureStore {
  _RecoveryStore({
    required this.protocol,
    bool automaticReconnect = true,
    bool killSwitch = true,
  }) : automaticReconnectSetting = automaticReconnect,
       killSwitchSetting = killSwitch;

  final String protocol;
  final bool automaticReconnectSetting;
  final bool killSwitchSetting;
  bool autoConnect = false;
  // The persisted renewal marker: a device id and its pending CSR's SHA-256.
  String? renewalDevice;
  String? renewalCsrSha256;

  @override
  Future<String?> openVpnRenewalDeviceId() async => renewalDevice;
  @override
  Future<String?> openVpnRenewalCsrSha256() async =>
      renewalDevice == null ? null : renewalCsrSha256;
  @override
  Future<void> saveOpenVpnRenewalDeviceId(
    String deviceId, {
    String? csrSha256,
  }) async {
    renewalDevice = deviceId;
    renewalCsrSha256 = csrSha256;
  }

  @override
  Future<void> clearOpenVpnRenewalDeviceId() async {
    renewalDevice = null;
    renewalCsrSha256 = null;
  }

  @override
  Future<void> saveSelectedLocation(String value) async {}
  @override
  Future<void> saveLocationMigration(StoredLocationMigration value) async {}
  @override
  Future<void> clearLocationMigration() async {}

  @override
  Future<SecuritySettings> securitySettings() async => SecuritySettings(
    killSwitch: killSwitchSetting,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: automaticReconnectSetting,
  );
  @override
  Future<SplitTunnelSettings> splitTunnelSettings() async =>
      SplitTunnelSettings.disabled;

  @override
  Future<String?> token() async => 'session-not-logged';
  @override
  Future<String?> selectedLocation() async => location.id;
  @override
  Future<String?> currentDeviceId() async => device.deviceId;
  @override
  Future<String?> vpnProtocol() async => protocol;
  @override
  Future<String?> themeMode() async => 'light';
  @override
  Future<String?> appLanguage() async => 'fr';
  @override
  Future<String?> killSwitch() async => killSwitchSetting ? 'true' : 'false';
  @override
  Future<String?> dnsProtection() async => 'true';
  @override
  Future<String?> automaticReconnect() async =>
      automaticReconnectSetting ? 'true' : 'false';
  @override
  Future<String?> autoConnectOnLaunch() async => autoConnect ? 'true' : 'false';
  @override
  Future<String?> windowsNotifications() async => 'true';
  @override
  Future<List<String>> favoriteLocationIds() async => const [];
  @override
  Future<List<String>> recentLocationIds() async => const [];
  @override
  Future<StoredLocationMigration?> locationMigration() async => null;
  @override
  Future<void> saveCurrentDeviceId(String value) async {}
  @override
  Future<void> clearCurrentDeviceId() async {}
  @override
  Future<void> saveVpnProtocol(String value) async {}
}

class _RecoveryApi extends ApiClient {
  _RecoveryApi({this.trace, this.clock})
    : super(baseUri: Uri.parse('http://localhost/'));

  @override
  Future<Subscription> subscription(String token) async => const Subscription(
    status: SubscriptionStatus.active,
    hasAccess: true,
    renewsAutomatically: false,
    cancelAtPeriodEnd: false,
  );

  final List<String>? trace;
  final _Clock? clock;
  int registerCalls = 0;
  int bootstrapInvalidations = 0;
  bool failRenew = false;

  // The device's OpenVPN profile as the server keeps it: the certificate
  // issued for one CSR. That exact CSR replays it for free while it is
  // valid (exact-CSR recovery); any other creation or renewal counts
  // against the server's limit.
  String? storedCsr;
  // The expiry of the certificate a creation issues, then of the stored one.
  // Far from expiry by default, whatever the real date.
  DateTime storedNotAfter = DateTime.utc(2099);
  DateTime renewedNotAfter = DateTime.utc(2099, 6);
  int serial = 0;
  final csrBySerial = <int, String>{};
  int createCalls = 0;
  int renewCalls = 0;
  int countedCreates = 0;
  int countedRenewals = 0;
  final renewedCsrs = <String>[];
  // Answers given to the next counted renewals, before anything is issued.
  List<ApiException> renewFailures = [];
  // Answers lost once the server issued the renewal.
  int lostRenewAnswers = 0;
  // The location, hence the node, the device is assigned to. A location
  // migration moves it at once (the migration answers ready).
  Location deviceLocation = location;
  List<Location> catalogue = const [location];
  int migrationCalls = 0;

  bool get _storedValid =>
      storedNotAfter.isAfter(clock?.call() ?? DateTime.now());

  String get _nodeEndpoint =>
      deviceLocation.id == location.id ? '198.51.100.10' : '203.0.113.20';

  String csrOf(OpenVpnActivation activation) =>
      csrBySerial[int.parse(activation.certificatePem.split('-')[1])] ?? '';

  OpenVpnActivation _activation(String deviceId) => OpenVpnActivation(
    deviceId: deviceId,
    protocol: 'openvpn',
    certificatePem: 'certificate-$serial-not-logged',
    caCertificatePem: 'ca-not-logged',
    tlsCryptV2ClientKey: 'tls-key-not-logged',
    endpoint: _nodeEndpoint,
    dns: const ['10.10.0.1'],
    address: '10.10.0.2/24',
    serverName: 'frankfurt-01.openvpn.fuzevpn.internal',
    remoteCertTlsServer: true,
    ciphers: const ['AES-256-GCM'],
    notAfter: storedNotAfter,
  );

  OpenVpnActivation _issue(String deviceId, String csrPem) {
    serial++;
    storedCsr = csrPem;
    csrBySerial[serial] = csrPem;
    return _activation(deviceId);
  }

  @override
  void invalidateBootstrapCache() {
    bootstrapInvalidations++;
    super.invalidateBootstrapCache();
  }

  @override
  Future<List<Location>> locations() async => catalogue;
  @override
  Future<UserProfile> me(String token) async => profile;
  @override
  Future<DeviceList> devices(String token) async {
    trace?.add('api.devices');
    return DeviceList(
      limit: 2,
      devices: [
        VpnDevice(
          deviceId: device.deviceId,
          name: device.name,
          location: deviceLocation,
          createdAt: null,
        ),
      ],
    );
  }

  @override
  Future<LocationMigration> startLocationMigration({
    required String token,
    required String deviceId,
    required String locationId,
  }) async {
    migrationCalls++;
    final source = deviceLocation;
    deviceLocation = catalogue.firstWhere((item) => item.id == locationId);
    return LocationMigration(
      migrationId: 'migration-$migrationCalls',
      deviceId: deviceId,
      sourceLocationId: source.id,
      targetLocationId: locationId,
      status: LocationMigrationStatus.ready,
      retryAfterSeconds: 2,
    );
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registerCalls++;
    trace?.add('api.register');
    return const DeviceConfiguration(
      deviceId: 'device-1',
      address: '10.10.0.2/24',
      dns: ['10.10.0.1'],
      serverPublicKey: 'public-key-not-logged',
      endpoint: '198.51.100.10:51820',
      allowedIps: ['0.0.0.0/0'],
    );
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    createCalls++;
    trace?.add('api.openvpn_profile');
    if (csrPem == storedCsr && _storedValid) return _activation(deviceId);
    countedCreates++;
    if (storedCsr != null) {
      // Another key, or a certificate that expired: the server no longer
      // recovers it.
      throw const ApiException(
        statusCode: 409,
        errorCode: 'openvpn_profile_exists',
        observedHttpStatus: 409,
      );
    }
    return _issue(deviceId, csrPem);
  }

  @override
  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    renewCalls++;
    renewedCsrs.add(csrPem);
    trace?.add('api.openvpn_renew');
    if (failRenew) {
      throw const ApiException(
        statusCode: 503,
        errorCode: 'service_unavailable',
      );
    }
    if (csrPem == storedCsr && _storedValid) return _activation(deviceId);
    countedRenewals++;
    if (renewFailures.isNotEmpty) throw renewFailures.removeAt(0);
    storedNotAfter = renewedNotAfter;
    final renewed = _issue(deviceId, csrPem);
    if (lostRenewAnswers > 0) {
      lostRenewAnswers--;
      throw const ApiException(statusCode: 408, errorCode: 'request_timeout');
    }
    return renewed;
  }
}

class _RecoveryWireGuard extends WireGuardBridge
    with NativeProtectionStatusFixture {
  _RecoveryWireGuard({this.trace});

  final List<String>? trace;
  bool cacheAvailable = true;
  bool connected = false;
  bool protectionActive = false;
  bool failConnect = false;
  bool failPrepare = false;
  bool failDisconnect = false;
  int prepareCalls = 0;
  int connectCalls = 0;
  int disconnectCalls = 0;
  Completer<void>? connectGate;

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    trace?.add('wireguard.prepare');
    if (failPrepare) {
      throw PlatformException(code: 'network_protection_failed');
    }
    protectionActive = true;
  }

  @override
  Future<bool> reconnect() async {
    if (!protectionActive || !cacheAvailable) return false;
    connectCalls++;
    if (failConnect) {
      connected = false;
      throw PlatformException(code: 'wireguard_start_failed');
    }
    connected = true;
    return true;
  }

  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<bool> isNetworkProtectionActive() async => protectionActive;
  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      'public-key-not-logged';
  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectCalls++;
    trace?.add('wireguard.connect');
    await connectGate?.future;
    if (failConnect) {
      connected = false;
      throw PlatformException(code: 'wireguard_start_failed');
    }
    connected = true;
    protectionActive = true;
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    if (failDisconnect) {
      throw PlatformException(code: 'broker_response_timeout');
    }
    connected = false;
    protectionActive = false;
  }
}

class _RecoveryOpenVpn extends OpenVpnBridge
    with NativeProtectionStatusFixture {
  _RecoveryOpenVpn({this.trace});

  final List<String>? trace;
  bool cacheAvailable = true;
  bool available = false;
  bool connected = false;
  bool protectionActive = false;
  bool failConnect = false;
  bool failPrepare = false;
  bool failDisconnect = false;
  int failProtectionReads = 0;
  int prepareCalls = 0;
  int importCalls = 0;
  int disconnectCalls = 0;
  int suspendCalls = 0;
  int reconnectCalls = 0;
  int renewCsrCalls = 0;
  int deleteProfileCalls = 0;
  // The OpenVPN server's verdict on the certificate the broker replays.
  String? reconnectFailureCode;
  String? Function(OpenVpnActivation activation)? importFailureCode;
  final importedNotAfter = <DateTime>[];
  final importedEndpoints = <String>[];

  // The native identity keeps one active and at most one pending key; a
  // tunnel that connects with the pending key's certificate promotes it.
  _RecoveryApi? server;
  String activeCsr = 'csr-not-logged';
  String? pendingCsr;
  int _keys = 0;

  @override
  void configureNetworkProtection({
    required bool killSwitch,
    required bool dnsProtection,
    required bool webRtcProtection,
  }) {
    super.configureNetworkProtection(
      killSwitch: killSwitch,
      dnsProtection: dnsProtection,
      webRtcProtection: webRtcProtection,
    );
    appliedKillSwitch = killSwitch;
  }

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    trace?.add('openvpn.prepare');
    if (failPrepare) {
      throw PlatformException(code: 'network_protection_failed');
    }
    protectionActive = true;
  }

  @override
  Future<bool> reconnect() async {
    if (!protectionActive || !cacheAvailable) return false;
    reconnectCalls++;
    importCalls++;
    trace?.add('openvpn.reconnect');
    if (reconnectFailureCode case final code?) {
      connected = false;
      throw PlatformException(code: code);
    }
    if (failConnect) {
      connected = false;
      throw PlatformException(code: 'openvpn_connection_timeout');
    }
    connected = true;
    return true;
  }

  @override
  Future<bool> isAvailable() async => available;
  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<bool> isNetworkProtectionActive() async {
    if (failProtectionReads > 0) {
      failProtectionReads--;
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return protectionActive;
  }

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async {
    trace?.add('openvpn.csr');
    return activeCsr;
  }

  @override
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async {
    renewCsrCalls++;
    trace?.add('openvpn.renew_csr');
    return pendingCsr ??= 'renew-csr-${++_keys}-not-logged';
  }

  @override
  Future<void> suspendForMigration() async {
    suspendCalls++;
    trace?.add('openvpn.suspend');
    connected = false;
  }

  /// Deletes the local identity: the next GetCsr mints a new active key.
  @override
  Future<void> deleteProfile() async {
    deleteProfileCalls++;
    trace?.add('openvpn.delete_profile');
    connected = false;
    activeCsr = 'csr-${++_keys}-not-logged';
    pendingCsr = null;
  }

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importCalls++;
    trace?.add('openvpn.connect');
    importedNotAfter.add(activation.notAfter);
    importedEndpoints.add(activation.endpoint);
    if (importFailureCode?.call(activation) case final code?) {
      connected = false;
      throw PlatformException(code: code);
    }
    if (failConnect) {
      connected = false;
      throw PlatformException(code: 'openvpn_connection_timeout');
    }
    connected = true;
    protectionActive = appliedKillSwitch;
    // CONNECTED promotes the pending key whose certificate this is.
    final csr = server?.csrOf(activation);
    if (csr != null && csr == pendingCsr) {
      activeCsr = csr;
      pendingCsr = null;
    }
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    if (failDisconnect) {
      throw PlatformException(code: 'broker_response_timeout');
    }
    connected = false;
    protectionActive = false;
  }
}
