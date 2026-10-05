// SPDX-License-Identifier: MPL-2.0
import 'native_protection_status_fixture.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';

void main() {
  const location = Location(
    id: 'frankfurt-01',
    city: 'Frankfurt',
    countryCode: 'DE',
    displayName: 'Frankfurt 1',
    supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
  );
  const dualStackLocation = Location(
    id: 'frankfurt-dual',
    city: 'Frankfurt',
    countryCode: 'DE',
    displayName: 'Frankfurt Dual Stack',
    supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
    supportedIpFamilies: {IpFamily.ipv4, IpFamily.ipv6},
  );

  AppController controllerFor(
    FakeApiClient api,
    FakeSecureStore store,
    FakeWireGuardBridge wireguard, [
    FakeOpenVpnBridge? openVpn,
    WindowBridge? window,
  ]) =>
      AppController(
          api: api,
          store: store,
          wireguard: wireguard,
          openVpn: openVpn,
          window: window,
        )
        ..profile = const UserProfile(
          userId: 'user-client',
          email: 'client@example.com',
          firstName: 'Client',
          emailVerified: true,
        )
        ..locations = const [location]
        ..selectedLocation = location
        ..isLoadingLocations = false;

  test('parse les erreurs JSON sans conserver de réponse brute', () {
    final error = ApiException.fromResponse(
      statusCode: 429,
      body: '{"error":"rate_limited","retry_after_seconds":12}',
    );

    expect(error.statusCode, 429);
    expect(error.errorCode, 'rate_limited');
    expect(error.retryAfterSeconds, 12);

    final unsafeResponse = ApiException.fromResponse(
      statusCode: 500,
      body:
          '{"error":"server_error","detail":"access-token-example key-example 198.51.100.7"}',
    );
    expect(unsafeResponse.toString(), isNot(contains('access-token-example')));
    expect(unsafeResponse.toString(), isNot(contains('key-example')));
    expect(unsafeResponse.toString(), isNot(contains('198.51.100.7')));
  });

  test('explique qu’un compte doit confirmer son e-mail', () async {
    final api = FakeApiClient()
      ..registerResults = const [
        ApiException(statusCode: 403, errorCode: 'email_verification_required'),
      ];
    final wireguard = FakeWireGuardBridge();
    final controller = controllerFor(api, FakeSecureStore(), wireguard);

    await controller.toggleConnection();

    expect(
      controller.deviceEnrollmentIssue?.kind,
      DeviceEnrollmentIssueKind.emailVerificationRequired,
    );
    expect(wireguard.resetCalls, 0);
  });

  test('propose la gestion lors de la limite de deux appareils', () async {
    final api = FakeApiClient()
      ..registerResults = const [
        ApiException(statusCode: 409, errorCode: 'device_limit'),
      ]
      ..deviceList = DeviceList(
        limit: 2,
        devices: [
          VpnDevice(
            deviceId: 'device-older',
            name: 'Ancien appareil',
            location: location,
            createdAt: DateTime.utc(2026, 8, 1),
          ),
          VpnDevice(
            deviceId: 'device-latest',
            name: 'Dernier appareil',
            location: location,
            createdAt: DateTime.utc(2026, 8, 2),
          ),
        ],
      );
    final controller = controllerFor(
      api,
      FakeSecureStore(),
      FakeWireGuardBridge(),
    );

    await controller.toggleConnection();

    expect(
      controller.deviceEnrollmentIssue?.kind,
      DeviceEnrollmentIssueKind.deviceLimit,
    );
    expect(
      controller.deviceEnrollmentIssue?.title,
      'Retirez un appareil existant',
    );
    expect(controller.penultimateDevice?.deviceId, 'device-older');
  });

  test('recrée automatiquement une identité WireGuard révoquée', () async {
    final api = FakeApiClient()
      ..registerResults = [
        const ApiException(
          statusCode: 409,
          errorCode: 'device_identity_revoked',
        ),
        fakeConfiguration,
      ];
    final wireguard = FakeWireGuardBridge();
    final controller = controllerFor(api, FakeSecureStore(), wireguard);

    await controller.toggleConnection();

    expect(wireguard.recreateCalls, 1);
    expect(wireguard.resetCalls, 0);
    expect(api.registerCalls, 2);
    expect(controller.vpnStatus, VpnStatus.connected);
    expect(controller.deviceEnrollmentIssue, isNull);
  });

  test('utilise le nom d’appareil dynamique lors de l’inscription', () async {
    final api = FakeApiClient()..registerResults = [fakeConfiguration];
    final controller = controllerFor(
      api,
      FakeSecureStore(),
      FakeWireGuardBridge(),
      null,
      _DeviceNameWindow(),
    );

    await controller.toggleConnection();

    expect(api.registeredNames, ['FuzeVPN 1.2.3 -- Windows 11']);
  });

  test('demande la double pile pour un nouvel appareil compatible', () async {
    final api = FakeApiClient()..registerResults = [fakeDualConfiguration];
    final controller =
        controllerFor(api, FakeSecureStore(), FakeWireGuardBridge())
          ..locations = const [dualStackLocation]
          ..selectedLocation = dualStackLocation;

    await controller.toggleConnection();

    expect(api.registeredIpFamilies, [dualStackIpFamilies]);
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  test('omet les familles IP pour un appareil WireGuard existant', () async {
    final api = FakeApiClient()..registerResults = [fakeDualConfiguration];
    final controller =
        controllerFor(api, FakeSecureStore(), FakeWireGuardBridge())
          ..locations = const [dualStackLocation]
          ..selectedLocation = dualStackLocation
          ..currentDeviceId = 'device-existing';

    await controller.toggleConnection();

    expect(api.registeredIpFamilies, [null]);
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  test(
    'retente une seule fois sans familles si IPv6 est indisponible',
    () async {
      final api = FakeApiClient()
        ..registerResults = const [
          ApiException(statusCode: 503, errorCode: 'ipv6_unavailable'),
          fakeConfiguration,
        ];
      final controller =
          controllerFor(api, FakeSecureStore(), FakeWireGuardBridge())
            ..locations = const [dualStackLocation]
            ..selectedLocation = dualStackLocation;

      await controller.toggleConnection();

      expect(api.registeredIpFamilies, [dualStackIpFamilies, null]);
      expect(controller.vpnStatus, VpnStatus.connected);
    },
  );

  test('propage la double pile à la création OpenVPN uniquement', () async {
    final api = FakeApiClient()
      ..registerResults = [fakeDualConfiguration]
      ..openVpnResults = [fakeDualOpenVpnActivation];
    final controller =
        controllerFor(
            api,
            FakeSecureStore(),
            FakeWireGuardBridge(),
            FakeOpenVpnBridge(),
          )
          ..locations = const [dualStackLocation]
          ..selectedLocation = dualStackLocation
          ..vpnProtocol = VpnProtocol.openVpn
          ..openVpnRuntimeAvailable = true;

    await controller.toggleConnection();

    expect(api.registeredIpFamilies, [dualStackIpFamilies]);
    expect(api.openVpnIpFamilies, [dualStackIpFamilies]);
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  test('retente OpenVPN sans familles si IPv6 devient indisponible', () async {
    final api = FakeApiClient()
      ..registerResults = [fakeDualConfiguration]
      ..openVpnResults = [
        const ApiException(statusCode: 503, errorCode: 'ipv6_unavailable'),
        fakeDualOpenVpnActivation,
      ];
    final controller =
        controllerFor(
            api,
            FakeSecureStore(),
            FakeWireGuardBridge(),
            FakeOpenVpnBridge(),
          )
          ..locations = const [dualStackLocation]
          ..selectedLocation = dualStackLocation
          ..vpnProtocol = VpnProtocol.openVpn
          ..openVpnRuntimeAvailable = true;

    await controller.toggleConnection();

    expect(api.openVpnIpFamilies, [dualStackIpFamilies, null]);
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  test('affiche la limite après la recréation WireGuard automatique', () async {
    final api = FakeApiClient()
      ..registerResults = const [
        ApiException(statusCode: 409, errorCode: 'device_identity_revoked'),
        ApiException(statusCode: 409, errorCode: 'device_limit'),
      ]
      ..deviceList = DeviceList(
        limit: 2,
        devices: [
          VpnDevice(
            deviceId: 'device-one',
            name: 'Premier appareil',
            location: location,
            createdAt: null,
          ),
          VpnDevice(
            deviceId: 'device-two',
            name: 'Deuxième appareil',
            location: location,
            createdAt: null,
          ),
        ],
      );
    final wireguard = FakeWireGuardBridge();
    final controller = controllerFor(api, FakeSecureStore(), wireguard)
      ..currentDeviceId = 'device-removed';

    await controller.toggleConnection();

    expect(wireguard.recreateCalls, 1);
    expect(api.registerCalls, 2);
    expect(
      controller.deviceEnrollmentIssue?.kind,
      DeviceEnrollmentIssueKind.deviceLimit,
    );
    expect(controller.errorMessage, contains('kill switch'));
    expect(controller.vpnStatus, VpnStatus.blocked);
  });

  test(
    'réinscrit OpenVPN après la suppression distante de l’appareil',
    () async {
      final api = FakeApiClient()
        ..registerResults = [fakeConfiguration]
        ..openVpnResults = [fakeOpenVpnActivation];
      final openVpn = FakeOpenVpnBridge();
      final controller =
          controllerFor(api, FakeSecureStore(), FakeWireGuardBridge(), openVpn)
            ..currentDeviceId = 'device-removed'
            ..vpnProtocol = VpnProtocol.openVpn
            ..openVpnRuntimeAvailable = true;

      await controller.toggleConnection();

      expect(controller.currentDeviceId, 'device-new');
      expect(api.registerCalls, 1);
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.deviceEnrollmentIssue, isNull);
      expect(controller.errorMessage, isNull);
    },
  );

  test(
    'affiche la limite OpenVPN au lieu d’une erreur d’emplacement',
    () async {
      final api = FakeApiClient()
        ..registerResults = const [
          ApiException(statusCode: 409, errorCode: 'device_limit'),
        ]
        ..deviceList = DeviceList(
          limit: 2,
          devices: [
            VpnDevice(
              deviceId: 'device-one',
              name: 'Premier appareil',
              location: location,
              createdAt: null,
            ),
            VpnDevice(
              deviceId: 'device-two',
              name: 'Deuxième appareil',
              location: location,
              createdAt: null,
            ),
          ],
        );
      final controller =
          controllerFor(
              api,
              FakeSecureStore(),
              FakeWireGuardBridge(),
              FakeOpenVpnBridge(),
            )
            ..currentDeviceId = 'device-removed'
            ..vpnProtocol = VpnProtocol.openVpn
            ..openVpnRuntimeAvailable = true;

      await controller.toggleConnection();

      expect(
        controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.deviceLimit,
      );
      expect(controller.errorMessage, contains('kill switch'));
      expect(controller.vpnStatus, VpnStatus.blocked);
    },
  );

  test(
    'ne bloque pas OpenVPN quand un appareil n’a pas de localisation',
    () async {
      final api = FakeApiClient()
        ..deviceList = const DeviceList(
          limit: 2,
          devices: [
            VpnDevice(
              deviceId: 'device-chrome',
              name: 'Extension Chrome',
              location: null,
              createdAt: null,
            ),
          ],
        )
        ..openVpnResults = [fakeOpenVpnActivation];
      final openVpn = FakeOpenVpnBridge();
      final controller =
          controllerFor(api, FakeSecureStore(), FakeWireGuardBridge(), openVpn)
            ..currentDeviceId = 'device-chrome'
            ..vpnProtocol = VpnProtocol.openVpn
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..openVpnRuntimeAvailable = true;

      await controller.toggleConnection();

      expect(controller.errorMessage, isNull);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(openVpn.importCalls, 1);
    },
  );

  test('recrée sans planter après le retrait de l’appareil courant', () async {
    final api = FakeApiClient()..registerResults = [fakeConfiguration];
    final wireguard = FakeWireGuardBridge();
    final controller =
        controllerFor(api, FakeSecureStore(), wireguard, FakeOpenVpnBridge())
          ..currentDeviceId = 'device-current'
          ..devices = [
            VpnDevice(
              deviceId: 'device-current',
              name: 'Cet ordinateur',
              location: location,
              createdAt: null,
            ),
          ];

    final result = await controller.revokeDevice(controller.devices.single);
    expect(result, DeviceRevocationResult.revoked);
    expect(wireguard.resetCalls, 1);
    expect(wireguard.identityAvailable, isFalse);

    await controller.toggleConnection();

    expect(wireguard.identityCreations, 1);
    expect(api.registerCalls, 1);
    expect(controller.currentDeviceId, 'device-new');
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  test(
    'ne réinitialise jamais automatiquement une identité déjà liée',
    () async {
      final api = FakeApiClient()
        ..registerResults = const [
          ApiException(statusCode: 409, errorCode: 'device_exists'),
        ];
      final wireguard = FakeWireGuardBridge();
      final controller = controllerFor(api, FakeSecureStore(), wireguard);

      await controller.toggleConnection();

      expect(
        controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.deviceExists,
      );
      expect(wireguard.resetCalls, 0);
      expect(api.registerCalls, 1);
    },
  );

  test(
    'libère uniquement le profil OpenVPN puis déplace WireGuard sans migration',
    () async {
      final api = FakeApiClient()
        ..registerResults = [
          const ApiException(
            statusCode: 409,
            errorCode: 'device_location_locked',
          ),
          fakeConfiguration,
        ];
      final openVpn = FakeOpenVpnBridge();
      final wireguard = FakeWireGuardBridge();
      final controller = controllerFor(
        api,
        FakeSecureStore(),
        wireguard,
        openVpn,
      )..currentDeviceId = 'device-existing';

      await controller.toggleConnection();

      expect(api.revokeOpenVpnProfileCalls, 1);
      expect(openVpn.deleteProfileCalls, 1);
      expect(api.registerCalls, 2);
      expect(wireguard.resetCalls, 0);
      expect(controller.currentDeviceId, 'device-new');
      expect(controller.vpnStatus, VpnStatus.connected);
    },
  );

  test(
    'supprime la session expirée et demande une nouvelle connexion',
    () async {
      final api = FakeApiClient()
        ..registerResults = const [
          ApiException(statusCode: 401, errorCode: 'unauthorized'),
        ];
      final store = FakeSecureStore();
      final controller = controllerFor(api, store, FakeWireGuardBridge());

      await controller.toggleConnection();

      expect(controller.profile, isNull);
      expect(store.clearTokenCalls, 1);
      expect(controller.takeSignInPrompt(), isTrue);
      expect(controller.takeSignInPrompt(), isFalse);
      expect(
        controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.sessionExpired,
      );
    },
  );

  test('attend l’accusé du VPS et réutilise exactement le même CSR', () async {
    final api = FakeApiClient()
      ..openVpnResults = [
        const ApiException(
          statusCode: 409,
          errorCode: 'openvpn_operation_pending',
          retryAfterSeconds: 0,
        ),
        fakeOpenVpnActivation,
      ]
      ..deviceList = const DeviceList(
        limit: 2,
        devices: [
          VpnDevice(
            deviceId: 'device-existing',
            name: 'Cet ordinateur',
            location: location,
            createdAt: null,
          ),
        ],
      );
    final openVpn = FakeOpenVpnBridge();
    final controller =
        controllerFor(api, FakeSecureStore(), FakeWireGuardBridge(), openVpn)
          ..currentDeviceId = 'device-existing'
          ..vpnProtocol = VpnProtocol.openVpn
          ..openVpnRuntimeAvailable = true;

    await controller.toggleConnection();

    expect(api.createOpenVpnCalls, 2);
    expect(api.receivedCsrs, ['csr-not-displayed', 'csr-not-displayed']);
    expect(openVpn.importCalls, 1);
    expect(controller.vpnStatus, VpnStatus.connected);
  });
}

const fakeConfiguration = DeviceConfiguration(
  deviceId: 'device-new',
  address: 'address-not-used-in-test',
  dns: [],
  serverPublicKey: 'server-key-not-used-in-test',
  endpoint: 'endpoint-not-used-in-test',
  allowedIps: [],
);

const fakeDualConfiguration = DeviceConfiguration(
  deviceId: 'device-new',
  address: '10.20.0.2/24',
  addresses: ['10.20.0.2/24', 'fd00::2/128'],
  dns: ['10.20.0.1'],
  serverPublicKey: 'public-key-not-displayed',
  endpoint: '198.51.100.10:51820',
  allowedIps: ['0.0.0.0/0', '::/0'],
  ipFamilies: dualStackIpFamilies,
);

final fakeOpenVpnActivation = OpenVpnActivation(
  deviceId: 'device-existing',
  protocol: 'openvpn',
  certificatePem: 'certificate-not-displayed',
  caCertificatePem: 'ca-not-displayed',
  tlsCryptV2ClientKey: 'tls-key-not-displayed',
  endpoint: '198.51.100.10',
  dns: const ['1.1.1.1'],
  address: '10.20.0.2/24',
  serverName: 'frankfurt-01.openvpn.internal',
  remoteCertTlsServer: true,
  ciphers: const ['AES-256-GCM'],
  notAfter: DateTime.utc(2027, 1, 1),
);

final fakeDualOpenVpnActivation = OpenVpnActivation(
  deviceId: 'device-new',
  protocol: 'openvpn',
  certificatePem: 'certificate-not-displayed',
  caCertificatePem: 'ca-not-displayed',
  tlsCryptV2ClientKey: 'tls-key-not-displayed',
  endpoint: '198.51.100.10',
  dns: const ['1.1.1.1'],
  address: '10.20.0.2/24',
  addresses: const ['10.20.0.2/24', 'fd00::2/128'],
  allowedIps: const ['0.0.0.0/0', '::/0'],
  ipFamilies: dualStackIpFamilies,
  serverName: 'frankfurt-01.openvpn.internal',
  remoteCertTlsServer: true,
  ciphers: const ['AES-256-GCM'],
  notAfter: DateTime.utc(2027, 1, 1),
);

class FakeApiClient extends ApiClient {
  @override
  Future<Subscription> subscription(String token) async => const Subscription(
    status: SubscriptionStatus.active,
    hasAccess: true,
    renewsAutomatically: false,
    cancelAtPeriodEnd: false,
  );

  List<Object> registerResults = const [];
  int registerCalls = 0;
  int revokeOpenVpnProfileCalls = 0;
  int createOpenVpnCalls = 0;
  int revokeDeviceCalls = 0;
  List<Object> openVpnResults = const [];
  List<String> receivedCsrs = [];
  List<String> registeredNames = [];
  List<List<IpFamily>?> registeredIpFamilies = [];
  List<List<IpFamily>?> openVpnIpFamilies = [];
  DeviceList deviceList = const DeviceList(limit: 2, devices: []);

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registerCalls += 1;
    registeredNames.add(name);
    registeredIpFamilies.add(
      ipFamilies == null ? null : List<IpFamily>.unmodifiable(ipFamilies),
    );
    final result = registerResults[registerCalls - 1];
    if (result is DeviceConfiguration) return result;
    throw result;
  }

  @override
  Future<DeviceList> devices(String token) async => deviceList;

  @override
  Future<void> revokeDevice({
    required String token,
    required String deviceId,
  }) async {
    revokeDeviceCalls += 1;
  }

  @override
  Future<void> revokeOpenVpnProfile({
    required String token,
    required String deviceId,
  }) async {
    revokeOpenVpnProfileCalls += 1;
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    createOpenVpnCalls += 1;
    receivedCsrs.add(csrPem);
    openVpnIpFamilies.add(
      ipFamilies == null ? null : List<IpFamily>.unmodifiable(ipFamilies),
    );
    final result = openVpnResults[createOpenVpnCalls - 1];
    if (result is OpenVpnActivation) return result;
    throw result;
  }
}

class _DeviceNameWindow extends WindowBridge {
  @override
  Future<String> deviceName() async => 'FuzeVPN 1.2.3 -- Windows 11';
}

class FakeSecureStore extends SecureStore {
  String? storedToken = 'session-token-not-displayed';
  int clearTokenCalls = 0;

  @override
  Future<String?> token() async => storedToken;

  @override
  Future<void> clearToken() async {
    clearTokenCalls += 1;
    storedToken = null;
  }

  @override
  Future<void> clearCurrentDeviceId() async {}

  @override
  Future<void> clearLocationMigration() async {}

  @override
  Future<void> saveCurrentDeviceId(String value) async {}
}

class FakeWireGuardBridge extends WireGuardBridge
    with NativeProtectionStatusFixture {
  int resetCalls = 0;
  int recreateCalls = 0;
  int prepareCalls = 0;
  int identityCreations = 0;
  bool identityAvailable = true;
  bool connected = false;
  bool protectionActive = false;

  @override
  Future<void> prepareNetworkProtection() async => protectionActive = true;

  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async {
    if (!identityAvailable) {
      identityAvailable = true;
      identityCreations += 1;
    }
    return 'public-key-not-displayed';
  }

  @override
  Future<void> prepareIdentityForAccount(String accountId) async {
    prepareCalls += 1;
  }

  @override
  Future<void> resetIdentity() async {
    resetCalls += 1;
    identityAvailable = false;
    connected = false;
    protectionActive = false;
  }

  @override
  Future<void> recreateIdentityForAccount(String accountId) async {
    recreateCalls += 1;
    identityAvailable = true;
    connected = false;
  }

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connected = true;
    protectionActive = true;
  }

  @override
  Future<bool> isConnected() async => connected;

  @override
  Future<bool> isNetworkProtectionActive() async => protectionActive;

  @override
  Future<void> disconnect() async {
    connected = false;
    protectionActive = false;
  }
}

class FakeOpenVpnBridge extends OpenVpnBridge
    with NativeProtectionStatusFixture {
  int deleteProfileCalls = 0;
  int importCalls = 0;
  bool connected = false;
  bool protectionActive = false;

  @override
  Future<void> prepareNetworkProtection() async => protectionActive = true;

  @override
  Future<void> disconnect() async {
    connected = false;
    protectionActive = false;
  }

  @override
  Future<void> deleteProfile() async {
    deleteProfileCalls += 1;
  }

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async => 'csr-not-displayed';

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importCalls += 1;
    connected = true;
    protectionActive = true;
  }

  @override
  Future<bool> isConnected() async => connected;

  @override
  Future<bool> isNetworkProtectionActive() async => protectionActive;
}
