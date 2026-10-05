// SPDX-License-Identifier: MPL-2.0
import 'native_protection_status_fixture.dart';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
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

  @override
  Future<SecuritySettings> securitySettings() async => SecuritySettings(
    killSwitch: killSwitchSetting,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: automaticReconnectSetting,
  );

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
  Future<String?> autoConnectOnLaunch() async => 'false';
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
  _RecoveryApi({this.trace}) : super(baseUri: Uri.parse('http://localhost/'));

  final List<String>? trace;
  int registerCalls = 0;
  bool failRenew = false;

  @override
  Future<List<Location>> locations() async => const [location];
  @override
  Future<UserProfile> me(String token) async => profile;
  @override
  Future<DeviceList> devices(String token) async {
    trace?.add('api.devices');
    return const DeviceList(limit: 2, devices: [device]);
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
    trace?.add('api.openvpn_profile');
    return OpenVpnActivation(
      deviceId: deviceId,
      protocol: 'openvpn',
      certificatePem: 'certificate-not-logged',
      caCertificatePem: 'ca-not-logged',
      tlsCryptV2ClientKey: 'tls-key-not-logged',
      endpoint: '198.51.100.10',
      dns: const ['10.10.0.1'],
      address: '10.10.0.2/24',
      serverName: 'frankfurt-01.openvpn.fuzevpn.internal',
      remoteCertTlsServer: true,
      ciphers: const ['AES-256-GCM'],
      notAfter: DateTime.utc(2027),
    );
  }

  @override
  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    trace?.add('api.openvpn_renew');
    if (failRenew) {
      throw const ApiException(
        statusCode: 503,
        errorCode: 'service_unavailable',
      );
    }
    return OpenVpnActivation(
      deviceId: deviceId,
      protocol: 'openvpn',
      certificatePem: 'certificate-not-logged',
      caCertificatePem: 'ca-not-logged',
      tlsCryptV2ClientKey: 'tls-key-not-logged',
      endpoint: '198.51.100.10',
      dns: const ['10.10.0.1'],
      address: '10.10.0.2/24',
      serverName: 'frankfurt-01.openvpn.fuzevpn.internal',
      remoteCertTlsServer: true,
      ciphers: const ['AES-256-GCM'],
      notAfter: DateTime.utc(2027),
    );
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
    importCalls++;
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
    return 'csr-not-logged';
  }

  @override
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async {
    trace?.add('openvpn.renew_csr');
    return 'renew-csr-not-logged';
  }

  @override
  Future<void> suspendForMigration() async {
    suspendCalls++;
    trace?.add('openvpn.suspend');
    connected = false;
  }

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importCalls++;
    trace?.add('openvpn.connect');
    if (failConnect) {
      connected = false;
      throw PlatformException(code: 'openvpn_connection_timeout');
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
