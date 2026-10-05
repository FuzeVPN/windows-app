// SPDX-License-Identifier: MPL-2.0
import 'native_protection_status_fixture.dart';

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

void main() {
  const dualLocation = Location(
    id: 'frankfurt-01',
    city: 'Frankfurt',
    countryCode: 'DE',
    displayName: 'Frankfurt 1',
    supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
  );
  const openVpnOnlyLocation = Location(
    id: 'frankfurt-02',
    city: 'Frankfurt',
    countryCode: 'DE',
    displayName: 'Frankfurt 2',
    supportedProtocols: {VpnProtocol.openVpn},
  );

  AppController makeController({
    required AutomaticApi api,
    required AutomaticWireGuard wireGuard,
    required AutomaticOpenVpn openVpn,
    AutomaticStore? store,
    Location? selected = dualLocation,
    List<Location> locations = const [dualLocation],
  }) =>
      AppController(
          api: api,
          store: store ?? AutomaticStore(),
          wireguard: wireGuard,
          openVpn: openVpn,
        )
        ..profile = const UserProfile(
          userId: 'user-test',
          email: 'client@example.com',
          firstName: 'Client',
          emailVerified: true,
        )
        ..locations = locations
        ..selectedLocation = selected
        ..openVpnRuntimeAvailable = true
        ..protocolPreference = VpnProtocolPreference.automatic;

  test('le mode automatique garde WireGuard lorsqu’il démarre', () async {
    final api = AutomaticApi();
    final wireGuard = AutomaticWireGuard();
    final openVpn = AutomaticOpenVpn();
    final controller = makeController(
      api: api,
      wireGuard: wireGuard,
      openVpn: openVpn,
    );

    await controller.quickConnect();

    expect(controller.vpnStatus, VpnStatus.connected);
    expect(controller.activeProtocol, VpnProtocol.wireGuard);
    expect(openVpn.importCalls, 0);
  });

  test(
    'essaie OpenVPN une seule fois après un échec natif WireGuard',
    () async {
      final api = AutomaticApi();
      final wireGuard = AutomaticWireGuard()..failConnect = true;
      final openVpn = AutomaticOpenVpn();
      final controller = makeController(
        api: api,
        wireGuard: wireGuard,
        openVpn: openVpn,
      );

      await controller.quickConnect();

      expect(wireGuard.connectCalls, 1);
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      expect(controller.protocolPreference, VpnProtocolPreference.automatic);
    },
  );

  test('ne masque pas une erreur API WireGuard par un repli OpenVPN', () async {
    final api = AutomaticApi()
      ..registerError = const ApiException(
        statusCode: 403,
        errorCode: 'email_verification_required',
      );
    final openVpn = AutomaticOpenVpn();
    final controller = makeController(
      api: api,
      wireGuard: AutomaticWireGuard(),
      openVpn: openVpn,
    );

    await controller.quickConnect();

    expect(openVpn.importCalls, 0);
    expect(
      controller.deviceEnrollmentIssue?.kind,
      DeviceEnrollmentIssueKind.emailVerificationRequired,
    );
  });

  test('connexion rapide choisit le premier emplacement compatible', () async {
    final api = AutomaticApi();
    final openVpn = AutomaticOpenVpn();
    final controller = makeController(
      api: api,
      wireGuard: AutomaticWireGuard(),
      openVpn: openVpn,
      selected: null,
      locations: const [openVpnOnlyLocation, dualLocation],
    );

    await controller.quickConnect();

    expect(controller.selectedLocation?.id, dualLocation.id);
    expect(controller.activeProtocol, VpnProtocol.wireGuard);
    expect(openVpn.importCalls, 0);
  });

  test('mémorise explicitement la préférence automatique', () async {
    final store = AutomaticStore();
    final controller = makeController(
      api: AutomaticApi(),
      store: store,
      wireGuard: AutomaticWireGuard(),
      openVpn: AutomaticOpenVpn(),
    );

    await controller.setProtocolPreference(VpnProtocolPreference.automatic);

    expect(store.savedProtocol, 'auto');
    expect(controller.vpnProtocol, VpnProtocol.wireGuard);
  });

  test(
    'un arrêt OpenVPN refusé mais déjà inactif ne bloque pas WireGuard',
    () async {
      final openVpn = AutomaticOpenVpn()..failDisconnect = true;
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: AutomaticWireGuard(),
              openVpn: openVpn,
            )
            ..protocolPreference = VpnProtocolPreference.wireGuard
            ..vpnProtocol = VpnProtocol.wireGuard;

      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
      expect(openVpn.disconnectCalls, 0);
    },
  );

  test(
    'un arrêt WireGuard refusé mais déjà inactif ne bloque pas OpenVPN',
    () async {
      final wireGuard = AutomaticWireGuard()..failDisconnect = true;
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: wireGuard,
              openVpn: AutomaticOpenVpn(),
            )
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..vpnProtocol = VpnProtocol.openVpn;

      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      expect(wireGuard.disconnectCalls, 0);
    },
  );

  test(
    'le succès natif WireGuard reste connecté malgré une lecture transitoire',
    () async {
      final wireGuard = AutomaticWireGuard()..reportDisconnected = true;
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: wireGuard,
              openVpn: AutomaticOpenVpn(),
            )
            ..protocolPreference = VpnProtocolPreference.wireGuard
            ..vpnProtocol = VpnProtocol.wireGuard;

      await controller.quickConnect();

      expect(wireGuard.connectCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
    },
  );

  test(
    'le succès natif OpenVPN reste connecté malgré une lecture transitoire',
    () async {
      final openVpn = AutomaticOpenVpn()..reportDisconnected = true;
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: AutomaticWireGuard(),
              openVpn: openVpn,
            )
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..vpnProtocol = VpnProtocol.openVpn;

      await controller.quickConnect();

      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
    },
  );

  test(
    'récupère WireGuard lorsque le tunnel démarre mais la réponse se perd',
    () async {
      final wireGuard = AutomaticWireGuard()..loseConnectAcknowledgement = true;
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: wireGuard,
              openVpn: AutomaticOpenVpn(),
            )
            ..protocolPreference = VpnProtocolPreference.wireGuard
            ..vpnProtocol = VpnProtocol.wireGuard;

      await controller.quickConnect();

      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
    },
  );

  test(
    'récupère OpenVPN lorsque le tunnel démarre mais la réponse se perd',
    () async {
      final openVpn = AutomaticOpenVpn()..loseConnectAcknowledgement = true;
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: AutomaticWireGuard(),
              openVpn: openVpn,
            )
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..vpnProtocol = VpnProtocol.openVpn;

      await controller.quickConnect();

      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
    },
  );

  test(
    'confirme la coupure WireGuard lorsque sa réponse native se perd',
    () async {
      final wireGuard = AutomaticWireGuard();
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: wireGuard,
              openVpn: AutomaticOpenVpn(),
            )
            ..protocolPreference = VpnProtocolPreference.wireGuard
            ..vpnProtocol = VpnProtocol.wireGuard;
      await controller.quickConnect();
      wireGuard.loseDisconnectAcknowledgement = true;

      await controller.quickConnect();

      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.activeProtocol, isNull);
    },
  );

  test(
    'confirme la coupure OpenVPN lorsque sa réponse native se perd',
    () async {
      final openVpn = AutomaticOpenVpn();
      final controller =
          makeController(
              api: AutomaticApi(),
              wireGuard: AutomaticWireGuard(),
              openVpn: openVpn,
            )
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..vpnProtocol = VpnProtocol.openVpn;
      await controller.quickConnect();
      openVpn.loseDisconnectAcknowledgement = true;

      await controller.quickConnect();

      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.activeProtocol, isNull);
    },
  );

  test('regroupe deux commandes de connexion simultanées', () async {
    final gate = Completer<void>();
    final wireGuard = AutomaticWireGuard()..connectGate = gate;
    final controller = makeController(
      api: AutomaticApi(),
      wireGuard: wireGuard,
      openVpn: AutomaticOpenVpn(),
    );

    final first = controller.quickConnect();
    final second = controller.quickConnect();
    expect(identical(first, second), isTrue);
    await _waitUntil(() => wireGuard.connectCalls == 1);
    gate.complete();
    await Future.wait([first, second]);

    expect(wireGuard.connectCalls, 1);
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  test(
    'une fermeture de session ignore une connexion native tardive',
    () async {
      final gate = Completer<void>();
      final wireGuard = AutomaticWireGuard()..connectGate = gate;
      final controller = makeController(
        api: AutomaticApi(),
        wireGuard: wireGuard,
        openVpn: AutomaticOpenVpn(),
      );

      final connecting = controller.quickConnect();
      await _waitUntil(() => wireGuard.connectCalls == 1);
      final signingOut = controller.signOut();
      gate.complete();
      await Future.wait([connecting, signingOut]);

      expect(wireGuard.connected, isFalse);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.profile, isNull);
    },
  );

  test('100 cycles WireGuard restent sérialisés et cohérents', () async {
    final wireGuard = AutomaticWireGuard();
    final controller =
        makeController(
            api: AutomaticApi(),
            wireGuard: wireGuard,
            openVpn: AutomaticOpenVpn(),
          )
          ..protocolPreference = VpnProtocolPreference.wireGuard
          ..vpnProtocol = VpnProtocol.wireGuard;

    for (var cycle = 0; cycle < 100; cycle++) {
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.connected);
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.disconnected);
    }

    expect(wireGuard.connectCalls, 100);
    expect(wireGuard.disconnectCalls, 100);
  });

  test('100 cycles OpenVPN restent sérialisés et cohérents', () async {
    final openVpn = AutomaticOpenVpn();
    final controller =
        makeController(
            api: AutomaticApi(),
            wireGuard: AutomaticWireGuard(),
            openVpn: openVpn,
          )
          ..protocolPreference = VpnProtocolPreference.openVpn
          ..vpnProtocol = VpnProtocol.openVpn;

    for (var cycle = 0; cycle < 100; cycle++) {
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.connected);
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.disconnected);
    }

    expect(openVpn.importCalls, 100);
    expect(openVpn.disconnectCalls, 100);
  });
}

Future<void> _waitUntil(bool Function() condition) async {
  for (var attempt = 0; attempt < 100 && !condition(); attempt++) {
    await Future<void>.delayed(Duration.zero);
  }
  expect(condition(), isTrue);
}

const _configuration = DeviceConfiguration(
  deviceId: 'device-test',
  address: 'address-not-logged',
  dns: [],
  serverPublicKey: 'public-material-not-logged',
  endpoint: 'endpoint-not-logged',
  allowedIps: [],
);

final _activation = OpenVpnActivation(
  deviceId: 'device-test',
  protocol: 'openvpn',
  certificatePem: 'certificate-not-logged',
  caCertificatePem: 'ca-not-logged',
  tlsCryptV2ClientKey: 'secret-not-logged',
  endpoint: '198.51.100.10',
  dns: const ['1.1.1.1'],
  address: '10.20.0.2/24',
  serverName: 'frankfurt-01.openvpn.internal',
  remoteCertTlsServer: true,
  ciphers: const ['AES-256-GCM'],
  notAfter: DateTime.utc(2027),
);

class AutomaticApi extends ApiClient {
  ApiException? registerError;

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    if (registerError case final error?) throw error;
    return _configuration;
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async => _activation;

  @override
  Future<DeviceList> devices(String token) async => const DeviceList(
    limit: 2,
    devices: [
      VpnDevice(
        deviceId: 'device-test',
        name: 'FuzeVPN — Windows',
        location: Location(
          id: 'frankfurt-01',
          city: 'Frankfurt',
          countryCode: 'DE',
          displayName: 'Frankfurt 1',
          supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
        ),
        createdAt: null,
      ),
    ],
  );
}

class AutomaticStore extends SecureStore {
  String? savedProtocol;

  @override
  Future<String?> token() async => 'token-not-logged';

  @override
  Future<void> saveVpnProtocol(String value) async => savedProtocol = value;

  @override
  Future<void> saveSelectedLocation(String value) async {}

  @override
  Future<void> saveCurrentDeviceId(String value) async {}

  @override
  Future<void> clearCurrentDeviceId() async {}

  @override
  Future<void> clearToken() async {}
}

class AutomaticWireGuard extends WireGuardBridge
    with NativeProtectionStatusFixture {
  bool failConnect = false;
  bool failDisconnect = false;
  bool reportDisconnected = false;
  bool loseConnectAcknowledgement = false;
  bool loseDisconnectAcknowledgement = false;
  bool connected = false;
  bool protectionActive = false;
  int connectCalls = 0;
  int disconnectCalls = 0;
  int suspendCalls = 0;
  Completer<void>? connectGate;

  @override
  Future<void> prepareNetworkProtection() async {}

  @override
  Future<void> suspendForMigration() async {
    suspendCalls++;
    if (failDisconnect) throw PlatformException(code: 'permission_denied');
    connected = false;
  }

  @override
  Future<bool> reconnect() async => false;

  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      'public-key-not-logged';

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectCalls++;
    await connectGate?.future;
    if (failConnect) {
      throw PlatformException(code: 'wireguard_start_failed');
    }
    connected = true;
    protectionActive = true;
    if (loseConnectAcknowledgement) {
      throw PlatformException(code: 'broker_unavailable');
    }
  }

  @override
  Future<bool> isConnected() async => reportDisconnected ? false : connected;

  @override
  Future<bool> isNetworkProtectionActive() async => protectionActive;

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    if (failDisconnect) {
      throw PlatformException(code: 'permission_denied');
    }
    connected = false;
    protectionActive = false;
    if (loseDisconnectAcknowledgement) {
      throw PlatformException(code: 'broker_unavailable');
    }
  }
}

class AutomaticOpenVpn extends OpenVpnBridge
    with NativeProtectionStatusFixture {
  bool connected = false;
  bool protectionActive = false;
  bool failDisconnect = false;
  bool reportDisconnected = false;
  bool loseConnectAcknowledgement = false;
  bool loseDisconnectAcknowledgement = false;
  int importCalls = 0;
  int disconnectCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async {}

  @override
  Future<bool> reconnect() async => false;

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async => 'csr-not-logged';

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importCalls++;
    connected = true;
    protectionActive = true;
    if (loseConnectAcknowledgement) {
      throw PlatformException(code: 'broker_unavailable');
    }
  }

  @override
  Future<bool> isConnected() async => reportDisconnected ? false : connected;

  @override
  Future<bool> isNetworkProtectionActive() async => protectionActive;

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    if (failDisconnect) {
      throw PlatformException(code: 'permission_denied');
    }
    connected = false;
    protectionActive = false;
    if (loseDisconnectAcknowledgement) {
      throw PlatformException(code: 'broker_unavailable');
    }
  }
}
