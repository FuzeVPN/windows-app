// SPDX-License-Identifier: MPL-2.0
import 'native_protection_status_fixture.dart';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
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

  // recentLines is a 1024-line ring shared by every test of this file: once
  // full, its length stops growing. Slices therefore start after a unique
  // marker, and fail instead of passing vacuously if it was evicted.
  var traceMarks = 0;
  String markTrace() {
    final marker = 'trace_mark_${traceMarks++}';
    DiagnosticLog.record(area: 'trace_test', event: marker);
    return marker;
  }

  List<String> traceAfter(String marker) {
    final lines = DiagnosticLog.recentLines;
    final index = lines.lastIndexWhere(
      (line) => line.endsWith(' event=$marker'),
    );
    expect(index, isNot(-1), reason: 'trace marker $marker was evicted');
    return lines.skip(index + 1).toList();
  }

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
    // The bridge returns a new CSR per call: one read per attempt, reused.
    expect(openVpn.csrCalls, 1);
    expect(api.receivedCsrs, ['csr-1', 'csr-1']);
    expect(openVpn.importCalls, 1);
    expect(controller.vpnStatus, VpnStatus.connected);
  });

  const pending = ApiException(
    statusCode: 409,
    errorCode: 'openvpn_operation_pending',
    retryAfterSeconds: 0,
  );
  const protectedStorageMessage =
      'Le stockage protégé de FuzeVPN ne peut pas être utilisé. Réessayez.';
  const killSwitchFailureMessage =
      'La connexion VPN a échoué. Le kill switch bloque toujours le trafic réseau.';
  const openVpnPreparationProgressMessage =
      'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.';

  AppController openVpnControllerFor(
    FakeApiClient api,
    FakeOpenVpnBridge openVpn, {
    FakeSecureStore? store,
    FakeWireGuardBridge? wireguard,
    DateTime Function()? now,
  }) {
    api.deviceList = const DeviceList(
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
    return AppController(
        api: api,
        store: store ?? FakeSecureStore(),
        wireguard: wireguard ?? FakeWireGuardBridge(),
        openVpn: openVpn,
        now: now,
      )
      ..profile = const UserProfile(
        userId: 'user-client',
        email: 'client@example.com',
        firstName: 'Client',
        emailVerified: true,
      )
      ..locations = const [location]
      ..selectedLocation = location
      ..isLoadingLocations = false
      ..currentDeviceId = 'device-existing'
      ..vpnProtocol = VpnProtocol.openVpn
      ..openVpnRuntimeAvailable = true;
  }

  for (final killSwitch in [true, false]) {
    test(
      'Réessayer après openvpn_operation_pending relance la même connexion '
      'sans déconnexion (kill switch ${killSwitch ? 'actif' : 'inactif'})',
      () async {
        final api = FakeApiClient()
          ..openVpnResults = [
            for (var attempt = 0; attempt < 6; attempt++) pending,
            fakeOpenVpnActivation,
          ];
        final openVpn = FakeOpenVpnBridge();
        final wireguard = FakeWireGuardBridge();
        final controller = openVpnControllerFor(
          api,
          openVpn,
          wireguard: wireguard,
        )..killSwitchEnabled = killSwitch;

        await controller.toggleConnection();

        expect(api.createOpenVpnCalls, 6);
        expect(openVpn.csrCalls, 1);
        expect(api.receivedCsrs, everyElement('csr-1'));
        expect(
          controller.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.openVpnOperationPending,
        );
        expect(
          controller.vpnStatus,
          killSwitch ? VpnStatus.blocked : VpnStatus.error,
        );
        expect(openVpn.protectionActive, killSwitch);
        expect(controller.requiresExplicitDisconnect, killSwitch);
        expect(controller.canRetryConnection, isTrue);

        await controller.retryConnection();

        // Toggling here used to release the kill switch and stop: the retry
        // must reuse the same CSR without any disconnect in between.
        expect(openVpn.disconnectCalls, 0);
        expect(wireguard.disconnectCalls, 0);
        expect(api.createOpenVpnCalls, 7);
        // The retry is a new attempt: it reads the CSR once and sends it.
        expect(openVpn.csrCalls, 2);
        expect(api.receivedCsrs.last, 'csr-2');
        expect(openVpn.importCalls, 1);
        expect(openVpn.protectionActive, isTrue);
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.activeProtocol, VpnProtocol.openVpn);
        expect(controller.selectedLocation, location);
        expect(controller.vpnProtocol, VpnProtocol.openVpn);
        expect(controller.deviceEnrollmentIssue, isNull);
      },
    );
  }

  for (final guard in [
    'connected',
    'partial_protection',
    'other_session',
    'migration',
    'signed_out',
    'unconfirmed',
  ]) {
    test('Réessayer reste indisponible et inerte ($guard)', () async {
      final api = FakeApiClient()
        ..openVpnResults = [
          for (var attempt = 0; attempt < 6; attempt++) pending,
          fakeOpenVpnActivation,
        ];
      final openVpn = FakeOpenVpnBridge()
        ..appliedKillSwitch = guard != 'partial_protection'
        ..ownedByAnotherUser = guard == 'other_session';
      final wireguard = FakeWireGuardBridge();
      final controller = openVpnControllerFor(
        api,
        openVpn,
        wireguard: wireguard,
      );
      await controller.toggleConnection();
      expect(api.createOpenVpnCalls, 6);
      switch (guard) {
        case 'connected':
          controller
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.openVpn;
        case 'migration':
          controller.locationMigration = const LocationMigration(
            migrationId: 'synthetic-migration',
            deviceId: 'device-existing',
            sourceLocationId: 'frankfurt-01',
            targetLocationId: 'frankfurt-dual',
            status: LocationMigrationStatus.draining,
            retryAfterSeconds: 2,
          );
        case 'signed_out':
          controller.profile = null;
        case 'unconfirmed':
          // Disconnect releases OpenVPN, but the WireGuard status stays
          // unreadable and its idempotent stop fails: nothing is confirmed,
          // while no tunnel or retained owner is known any more.
          wireguard
            ..statusUnavailable = true
            ..failDisconnect = true;
          await controller.toggleConnection();
          expect(controller.vpnStatus, VpnStatus.error);
          expect(controller.activeProtocol, isNull);
          expect(controller.requiresExplicitDisconnect, isTrue);
          expect(controller.runtimeOwnedByAnotherUser, isFalse);
      }
      final status = controller.vpnStatus;
      final protectionActive = openVpn.protectionActive;
      final openVpnDisconnects = openVpn.disconnectCalls;
      final wireGuardDisconnects = wireguard.disconnectCalls;
      if (guard != 'unconfirmed') {
        expect(protectionActive, isTrue);
        expect(openVpnDisconnects, 0);
      }

      expect(controller.canRetryConnection, isFalse);
      await controller.retryConnection();

      // No API request and no native command after the refused retry.
      expect(api.createOpenVpnCalls, 6);
      expect(api.registerCalls, 0);
      expect(openVpn.csrCalls, 1);
      expect(openVpn.importCalls, 0);
      expect(openVpn.disconnectCalls, openVpnDisconnects);
      expect(openVpn.protectionActive, protectionActive);
      expect(wireguard.connectCalls, 0);
      expect(wireguard.disconnectCalls, wireGuardDisconnects);
      expect(controller.vpnStatus, status);
    });
  }

  test(
    'Réessayer ne laisse jamais un état inactif sous un kill switch conservé',
    () async {
      final api = FakeApiClient()
        ..openVpnResults = [
          for (var attempt = 0; attempt < 6; attempt++) pending,
          fakeOpenVpnActivation,
        ];
      final openVpn = FakeOpenVpnBridge();
      final store = FakeSecureStore();
      final controller = openVpnControllerFor(api, openVpn, store: store);
      await controller.toggleConnection();
      expect(controller.vpnStatus, VpnStatus.blocked);

      // A server migration becomes active after the retry was accepted. Its
      // early exit expects an idle start, yet WFP still blocks the traffic.
      store.onTokenRead = () =>
          controller.locationMigration ??= const LocationMigration(
            migrationId: 'synthetic-migration',
            deviceId: 'device-existing',
            sourceLocationId: 'frankfurt-01',
            targetLocationId: 'frankfurt-dual',
            status: LocationMigrationStatus.draining,
            retryAfterSeconds: 2,
          );
      await controller.retryConnection();

      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(controller.requiresExplicitDisconnect, isTrue);
      expect(openVpn.protectionActive, isTrue);
      expect(openVpn.disconnectCalls, 0);
      expect(api.createOpenVpnCalls, 6);
      // Nothing re-arms this connection after the migration: the plain
      // kill-switch notice replaces the exit's "in progress" text.
      expect(controller.errorMessage, killSwitchFailureMessage);
    },
  );

  test(
    'un échec normal pendant Réessayer ne restaure la protection qu’une fois',
    () async {
      final api = FakeApiClient()
        ..openVpnResults = [
          for (var attempt = 0; attempt < 12; attempt++) pending,
        ];
      final openVpn = FakeOpenVpnBridge();
      final controller = openVpnControllerFor(api, openVpn);
      await controller.toggleConnection();
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(controller.canRetryConnection, isTrue);

      // The native policy loses its full block during the retry: the failed
      // attempt itself already restores an error with partial protection.
      openVpn.appliedKillSwitch = false;
      var readsAtLastRequest = -1;
      api.onCreateOpenVpnProfile = () {
        if (api.createOpenVpnCalls == 12) {
          readsAtLastRequest = openVpn.statusReads;
        }
      };
      await controller.retryConnection();

      expect(api.createOpenVpnCalls, 12);
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.requiresExplicitDisconnect, isTrue);
      expect(controller.errorMessage, contains('protections partielles'));
      expect(readsAtLastRequest, isNot(-1));
      expect(openVpn.statusReads - readsAtLastRequest, 1);
      expect(openVpn.disconnectCalls, 0);
    },
  );

  group('budget d’attente openvpn_operation_pending', () {
    Future<void> pumpSeconds(WidgetTester tester, int seconds) async {
      for (var second = 0; second < seconds; second++) {
        await tester.pump(const Duration(seconds: 1));
      }
    }

    List<String> traceSince(String marker, String event) => traceAfter(marker)
        .where(
          (line) =>
              line.contains('area=openvpn event=$event ') ||
              line.endsWith('area=openvpn event=$event'),
        )
        .toList();

    testWidgets('aboutit à la cinquième tentative dans le budget', (
      tester,
    ) async {
      const retryInTwo = ApiException(
        statusCode: 409,
        errorCode: 'openvpn_operation_pending',
        retryAfterSeconds: 2,
      );
      final api = FakeApiClient()
        ..openVpnHold = const Duration(seconds: 8)
        ..openVpnResults = [
          for (var attempt = 0; attempt < 4; attempt++) retryInTwo,
          fakeOpenVpnActivation,
        ];
      final openVpn = FakeOpenVpnBridge();
      final controller = openVpnControllerFor(
        api,
        openVpn,
        now: () => tester.binding.clock.now().add(api.held),
      );
      final start = markTrace();

      final connecting = controller.toggleConnection();
      await pumpSeconds(tester, 10);
      await connecting;

      expect(api.createOpenVpnCalls, 5);
      expect(openVpn.csrCalls, 1);
      expect(api.receivedCsrs, everyElement('csr-1'));
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      final waits = traceSince(start, 'profile_pending_wait');
      expect(waits, hasLength(4));
      expect(waits.first, contains('attempt=1 '));
      expect(waits.last, contains('attempt=4 '));
      expect(waits, everyElement(contains('count=2')));
      expect(traceSince(start, 'profile_pending_exhausted'), isEmpty);
      controller.dispose();
    });

    testWidgets('s’arrête avant de dépasser l’échéance du budget', (
      tester,
    ) async {
      const retryLater = ApiException(
        statusCode: 409,
        errorCode: 'openvpn_operation_pending',
      );
      final api = FakeApiClient()
        ..openVpnHold = const Duration(seconds: 10)
        ..openVpnResults = [
          for (var attempt = 0; attempt < 6; attempt++) retryLater,
        ];
      final openVpn = FakeOpenVpnBridge();
      final controller = openVpnControllerFor(
        api,
        openVpn,
        now: () => tester.binding.clock.now().add(api.held),
      );
      final start = markTrace();

      final connecting = controller.toggleConnection();
      await pumpSeconds(tester, 15);
      await connecting;

      // 10 s held per request plus the 3 s default wait: a fifth request
      // would start after 52 s, beyond the 45 s budget.
      expect(api.createOpenVpnCalls, 4);
      expect(
        controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.openVpnOperationPending,
      );
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(openVpn.protectionActive, isTrue);
      expect(openVpn.importCalls, 0);
      // The failure replaces the progress notice shown during the waits.
      expect(controller.errorMessage, killSwitchFailureMessage);
      final waits = traceSince(start, 'profile_pending_wait');
      expect(waits, hasLength(3));
      expect(waits, everyElement(contains('attempt=')));
      // No Retry-After: the trace says so instead of the 3 s default.
      expect(waits, everyElement(isNot(contains('count='))));
      final exhausted = traceSince(start, 'profile_pending_exhausted').single;
      expect(exhausted, contains('attempt=4'));
      expect(exhausted, contains('duration_ms=49000'));
      controller.dispose();
    });

    testWidgets('respecte Retry-After et le plafonne à dix secondes', (
      tester,
    ) async {
      final api = FakeApiClient()
        ..openVpnResults = [
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_operation_pending',
            retryAfterSeconds: 7,
          ),
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_operation_pending',
            retryAfterSeconds: 60,
          ),
          fakeOpenVpnActivation,
        ];
      final openVpn = FakeOpenVpnBridge();
      final controller = openVpnControllerFor(
        api,
        openVpn,
        now: () => tester.binding.clock.now(),
      );
      final start = markTrace();

      final connecting = controller.toggleConnection();
      await tester.pump();
      expect(api.createOpenVpnCalls, 1);
      await tester.pump(const Duration(seconds: 6));
      expect(api.createOpenVpnCalls, 1);
      await tester.pump(const Duration(seconds: 1));
      expect(api.createOpenVpnCalls, 2);
      await tester.pump(const Duration(seconds: 9));
      expect(api.createOpenVpnCalls, 2);
      await tester.pump(const Duration(seconds: 1));
      expect(api.createOpenVpnCalls, 3);
      await connecting;

      expect(controller.vpnStatus, VpnStatus.connected);
      // The trace keeps the server's hints, not the applied (capped) delays.
      final waits = traceSince(start, 'profile_pending_wait');
      expect(waits, hasLength(2));
      expect(waits.first, contains('count=7'));
      expect(waits.last, contains('count=60'));
      controller.dispose();
    });

    for (final killSwitch in [true, false]) {
      testWidgets('annonce l’attente sous kill switch puis l’efface '
          '(kill switch ${killSwitch ? 'actif' : 'inactif'})', (tester) async {
        final api = FakeApiClient()
          ..openVpnResults = [
            const ApiException(
              statusCode: 409,
              errorCode: 'openvpn_operation_pending',
              retryAfterSeconds: 2,
            ),
            fakeOpenVpnActivation,
          ];
        final openVpn = FakeOpenVpnBridge();
        final controller = openVpnControllerFor(
          api,
          openVpn,
          now: () => tester.binding.clock.now(),
        )..killSwitchEnabled = killSwitch;

        final connecting = controller.toggleConnection();
        await tester.pump();
        expect(api.createOpenVpnCalls, 1);
        expect(controller.vpnStatus, VpnStatus.preparing);
        expect(controller.isConnectionBusy, isTrue);
        expect(
          controller.errorMessage,
          killSwitch ? openVpnPreparationProgressMessage : isNull,
        );
        await tester.pump(const Duration(seconds: 2));
        await connecting;

        expect(api.createOpenVpnCalls, 2);
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.errorMessage, isNull);
        controller.dispose();
      });
    }

    testWidgets('cesse d’attendre lorsque l’opération est annulée', (
      tester,
    ) async {
      final api = FakeApiClient()
        ..openVpnResults = [
          const ApiException(
            statusCode: 409,
            errorCode: 'openvpn_operation_pending',
            retryAfterSeconds: 5,
          ),
          fakeOpenVpnActivation,
        ];
      final openVpn = FakeOpenVpnBridge();
      final controller = openVpnControllerFor(
        api,
        openVpn,
        now: () => tester.binding.clock.now(),
      );
      final start = markTrace();

      final connecting = controller.toggleConnection();
      await tester.pump();
      expect(api.createOpenVpnCalls, 1);
      final signingOut = controller.signOut();
      await pumpSeconds(tester, 10);
      await signingOut;
      await connecting;

      expect(api.createOpenVpnCalls, 1);
      expect(openVpn.importCalls, 0);
      expect(controller.profile, isNull);
      expect(controller.errorMessage, isNot(openVpnPreparationProgressMessage));
      // The wait was traced, so an empty exhausted list is a real absence.
      expect(traceSince(start, 'profile_pending_wait'), hasLength(1));
      expect(traceSince(start, 'profile_pending_exhausted'), isEmpty);
      controller.dispose();
    });
  });

  test(
    'storage_error sur la liaison WireGuard reste fermé et nomme le stockage',
    () async {
      final api = FakeApiClient()
        ..registerResults = [
          ApiException.fromResponse(
            statusCode: 409,
            body: '{"error":"device_location_locked"}',
          ),
          fakeConfiguration,
          fakeConfiguration,
        ];
      final store = FakeSecureStore()
        ..saveCurrentDeviceIdFailure = PlatformException(
          code: 'storage_error',
          message: 'private native text',
          details: {
            'stage': 'secure_store_replace',
            'win32_error': 32,
            'attempts': 5,
          },
        );
      final wireguard = FakeWireGuardBridge();
      final openVpn = FakeOpenVpnBridge();
      final diagnostics = _RecordingDiagnostics();
      final controller =
          AppController(
              api: api,
              store: store,
              wireguard: wireguard,
              openVpn: openVpn,
              diagnostics: diagnostics,
            )
            ..profile = const UserProfile(
              userId: 'user-client',
              email: 'client@example.com',
              firstName: 'Client',
              emailVerified: true,
            )
            ..locations = const [location]
            ..selectedLocation = location
            ..isLoadingLocations = false
            ..currentDeviceId = 'device-existing'
            ..protocolPreference = VpnProtocolPreference.automatic
            ..openVpnRuntimeAvailable = true
            ..killSwitchEnabled = false;
      final start = markTrace();

      await controller.toggleConnection();

      expect(api.revokeOpenVpnProfileCalls, 1);
      expect(api.registerCalls, 2);
      expect(wireguard.connectCalls, 0);
      // A local write failure is not a native WireGuard failure.
      expect(api.createOpenVpnCalls, 0);
      expect(openVpn.importCalls, 0);
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.errorMessage, protectedStorageMessage);
      expect(
        controller.deviceEnrollmentIssue?.message,
        protectedStorageMessage,
      );
      expect(controller.currentDeviceId, 'device-new');
      expect(store.savedDeviceIds, isEmpty);
      final incident = diagnostics.errors.single;
      expect(incident.code, 'storage_error');
      expect(incident.domain, 'storage');
      expect(incident.nativeCode, 32);
      // The handled release is an ordinary step in the v1 timeline; only the
      // real failure carries a code there.
      final revokeEvents = diagnostics.events.where(
        (event) => event.stage == 'profile_revoke',
      );
      expect(revokeEvents.map((event) => event.event), contains('end'));
      expect(revokeEvents.map((event) => event.code), everyElement(isNull));
      expect(
        diagnostics.events.where((event) => event.code == 'unknown_error'),
        isEmpty,
      );
      expect(
        diagnostics.events,
        contains(
          isA<DiagnosticEvent>()
              .having((event) => event.stage, 'stage', 'storage')
              .having((event) => event.event, 'event', 'error')
              .having((event) => event.code, 'code', 'storage_error'),
        ),
      );
      final trace = traceAfter(start).join('\n');
      expect(
        trace,
        contains(
          'area=wireguard event=openvpn_profile_release_required '
          'code=device_location_locked',
        ),
      );
      expect(
        trace,
        contains('area=wireguard event=openvpn_profile_release_completed'),
      );
      expect(
        trace,
        contains(
          'area=wireguard event=device_binding_failed code=storage_error '
          'stage=secure_store_replace windows_error=32 attempt=5',
        ),
      );
      expect(trace, isNot(contains('event=api_enrollment_failed')));
      expect(trace, isNot(contains('event=native_connect_failed')));
      expect(trace, isNot(contains('private')));

      store.saveCurrentDeviceIdFailure = null;
      await controller.toggleConnection();

      expect(api.registerCalls, 3);
      expect(wireguard.connectCalls, 1);
      expect(store.savedDeviceIds, ['device-new']);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(diagnostics.errors, hasLength(1));
    },
  );

  test('storage_error HRESULT : l’incident garde le domaine hresult', () async {
    final api = FakeApiClient()..registerResults = [fakeConfiguration];
    final store = FakeSecureStore()
      ..saveCurrentDeviceIdFailure = PlatformException(
        code: 'storage_error',
        details: {'stage': 'secure_store_path', 'win32_error': 0x80070057},
      );
    final diagnostics = _RecordingDiagnostics();
    final controller =
        AppController(
            api: api,
            store: store,
            wireguard: FakeWireGuardBridge(),
            openVpn: FakeOpenVpnBridge(),
            diagnostics: diagnostics,
          )
          ..profile = const UserProfile(
            userId: 'user-client',
            email: 'client@example.com',
            firstName: 'Client',
            emailVerified: true,
          )
          ..locations = const [location]
          ..selectedLocation = location
          ..isLoadingLocations = false
          ..killSwitchEnabled = false;

    await controller.toggleConnection();

    final incident = diagnostics.errors.single;
    expect(incident.code, 'storage_error');
    expect(incident.nativeDomain, 'hresult');
    expect(incident.nativeCode, 0x80070057);
  });

  test('storage_error sous kill switch : la carte propose Réessayer sans lever '
      'le blocage', () async {
    final api = FakeApiClient()
      ..registerResults = [fakeConfiguration, fakeConfiguration];
    final store = FakeSecureStore()
      ..saveCurrentDeviceIdFailure = PlatformException(
        code: 'storage_error',
        details: {'stage': 'secure_store_replace', 'win32_error': 32},
      );
    final wireguard = FakeWireGuardBridge();
    final openVpn = FakeOpenVpnBridge();
    final controller = controllerFor(api, store, wireguard, openVpn)
      ..killSwitchEnabled = true;

    await controller.toggleConnection();

    expect(wireguard.connectCalls, 0);
    expect(openVpn.importCalls, 0);
    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(controller.requiresExplicitDisconnect, isTrue);
    expect(wireguard.protectionActive, isTrue);
    // The kill-switch notice takes errorMessage; the card keeps the cause.
    expect(controller.errorMessage, killSwitchFailureMessage);
    expect(
      controller.deviceEnrollmentIssue?.kind,
      DeviceEnrollmentIssueKind.unknown,
    );
    expect(controller.deviceEnrollmentIssue?.message, protectedStorageMessage);
    expect(controller.canRetryConnection, isTrue);

    store.saveCurrentDeviceIdFailure = null;
    await controller.retryConnection();

    expect(wireguard.disconnectCalls, 0);
    expect(openVpn.disconnectCalls, 0);
    expect(wireguard.connectCalls, 1);
    expect(store.savedDeviceIds, ['device-new']);
    expect(controller.vpnStatus, VpnStatus.connected);
    expect(controller.deviceEnrollmentIssue, isNull);
  });

  test(
    'storage_error sur la liaison OpenVPN bloque le profil jusqu’à l’écriture',
    () async {
      final api = FakeApiClient()
        ..registerResults = [fakeConfiguration]
        ..openVpnResults = [fakeOpenVpnActivation]
        // The server lists the device it registered before the local write.
        ..deviceList = const DeviceList(
          limit: 2,
          devices: [
            VpnDevice(
              deviceId: 'device-new',
              name: 'Cet ordinateur',
              location: location,
              createdAt: null,
            ),
          ],
        );
      final store = FakeSecureStore()
        ..saveCurrentDeviceIdFailure = PlatformException(
          code: 'storage_error',
          details: {'stage': 'secure_store_flush', 'win32_error': 112},
        );
      final openVpn = FakeOpenVpnBridge();
      final diagnostics = _RecordingDiagnostics();
      final controller =
          AppController(
              api: api,
              store: store,
              wireguard: FakeWireGuardBridge(),
              openVpn: openVpn,
              diagnostics: diagnostics,
            )
            ..profile = const UserProfile(
              userId: 'user-client',
              email: 'client@example.com',
              firstName: 'Client',
              emailVerified: true,
            )
            ..locations = const [location]
            ..selectedLocation = location
            ..isLoadingLocations = false
            ..vpnProtocol = VpnProtocol.openVpn
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..openVpnRuntimeAvailable = true
            ..killSwitchEnabled = false;
      final start = markTrace();

      await controller.toggleConnection();

      expect(api.registerCalls, 1);
      expect(api.createOpenVpnCalls, 0);
      expect(openVpn.importCalls, 0);
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.errorMessage, protectedStorageMessage);
      expect(controller.currentDeviceId, 'device-new');
      expect(diagnostics.errors.single.code, 'storage_error');
      expect(
        traceAfter(start).join('\n'),
        contains(
          'area=openvpn event=device_binding_failed code=storage_error '
          'stage=secure_store_flush windows_error=112',
        ),
      );

      // The in-memory binding is reused, but never before it is stored.
      await controller.retryConnection();
      expect(api.registerCalls, 1);
      expect(api.createOpenVpnCalls, 0);
      expect(controller.errorMessage, protectedStorageMessage);

      store.saveCurrentDeviceIdFailure = null;
      await controller.retryConnection();

      expect(api.registerCalls, 1);
      expect(store.savedDeviceIds, ['device-new']);
      expect(api.createOpenVpnCalls, 1);
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
    },
  );

  test('la déconnexion du compte oublie une liaison non enregistrée', () async {
    final api = FakeApiClient()
      ..registerResults = [fakeConfiguration]
      ..openVpnResults = [fakeOpenVpnActivation];
    final store = FakeSecureStore()
      ..saveCurrentDeviceIdFailure = PlatformException(code: 'storage_error');
    final openVpn = FakeOpenVpnBridge();
    final controller = controllerFor(api, store, FakeWireGuardBridge(), openVpn)
      ..vpnProtocol = VpnProtocol.openVpn
      ..protocolPreference = VpnProtocolPreference.openVpn
      ..openVpnRuntimeAvailable = true
      ..killSwitchEnabled = false;
    api.deviceList = const DeviceList(
      limit: 2,
      devices: [
        VpnDevice(
          deviceId: 'device-new',
          name: 'Cet ordinateur',
          location: location,
          createdAt: null,
        ),
      ],
    );
    await controller.toggleConnection();
    expect(controller.errorMessage, protectedStorageMessage);
    expect(api.createOpenVpnCalls, 0);

    await controller.signOut();
    expect(controller.profile, isNull);

    // A later account session that already knows this id owes no write
    // left over from the previous one.
    store
      ..saveCurrentDeviceIdFailure = null
      ..storedToken = 'session-token-not-displayed';
    controller
      ..profile = const UserProfile(
        userId: 'user-client',
        email: 'client@example.com',
        firstName: 'Client',
        emailVerified: true,
      )
      ..currentDeviceId = 'device-new';
    await controller.toggleConnection();

    expect(store.savedDeviceIds, isEmpty);
    expect(api.registerCalls, 1);
    expect(api.createOpenVpnCalls, 1);
    expect(controller.vpnStatus, VpnStatus.connected);
  });
}

class _RecordingDiagnostics extends DiagnosticsController {
  _RecordingDiagnostics() : super(api: FakeApiClient());
  final errors = <DiagnosticError>[];
  final events = <DiagnosticEvent>[];

  @override
  void recordEvent(DiagnosticEvent event) {
    events.add(event);
    super.recordEvent(event);
  }

  @override
  void recordTerminalError(
    DiagnosticError error, {
    String protocol = 'unknown',
    String state = 'error',
    bool terminal = true,
  }) {
    errors.add(error);
  }
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

  /// Server time spent on each profile request, for an injected clock.
  Duration openVpnHold = Duration.zero;
  Duration held = Duration.zero;
  void Function()? onCreateOpenVpnProfile;

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
    onCreateOpenVpnProfile?.call();
    held += openVpnHold;
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
  Object? saveCurrentDeviceIdFailure;
  final savedDeviceIds = <String>[];
  void Function()? onTokenRead;

  @override
  Future<String?> token() async {
    onTokenRead?.call();
    return storedToken;
  }

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
  Future<void> saveCurrentDeviceId(String value) async {
    if (saveCurrentDeviceIdFailure case final failure?) throw failure;
    savedDeviceIds.add(value);
  }
}

class FakeWireGuardBridge extends WireGuardBridge
    with NativeProtectionStatusFixture {
  int resetCalls = 0;
  int recreateCalls = 0;
  int prepareCalls = 0;
  int identityCreations = 0;
  int connectCalls = 0;
  int disconnectCalls = 0;
  bool identityAvailable = true;
  bool connected = false;
  bool protectionActive = false;
  bool statusUnavailable = false;
  bool failDisconnect = false;

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
    connectCalls += 1;
    connected = true;
    protectionActive = true;
  }

  @override
  Future<bool> isConnected() async {
    if (statusUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return connected;
  }

  @override
  Future<bool> isNetworkProtectionActive() async {
    if (statusUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return protectionActive;
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls += 1;
    if (failDisconnect) throw PlatformException(code: 'broker_unavailable');
    connected = false;
    protectionActive = false;
  }
}

class FakeOpenVpnBridge extends OpenVpnBridge
    with NativeProtectionStatusFixture {
  int deleteProfileCalls = 0;
  int importCalls = 0;
  int disconnectCalls = 0;
  int csrCalls = 0;
  int statusReads = 0;
  bool connected = false;
  bool protectionActive = false;

  @override
  Future<void> prepareNetworkProtection() async => protectionActive = true;

  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() {
    statusReads += 1;
    return super.networkProtectionStatus();
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls += 1;
    connected = false;
    protectionActive = false;
  }

  @override
  Future<void> deleteProfile() async {
    deleteProfileCalls += 1;
  }

  /// A distinct value per call, so a CSR regenerated within one attempt or
  /// reused across attempts is visible in [FakeApiClient.receivedCsrs].
  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async => 'csr-${++csrCalls}';

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
