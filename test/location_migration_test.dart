// SPDX-License-Identifier: MPL-2.0
import 'native_protection_status_fixture.dart';

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

const frankfurt1 = Location(
  id: 'frankfurt-01',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const frankfurt2 = Location(
  id: 'frankfurt-02',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 2',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const testProfile = UserProfile(
  userId: 'user-1',
  email: 'client@example.test',
  firstName: 'Client',
  emailVerified: true,
);

void main() {
  test('parse strictement les quatre états de migration', () {
    for (final value in ['draining', 'activating', 'ready', 'blocked']) {
      final migration = LocationMigration.fromJson(
        _migrationJson(value),
        expectedDeviceId: 'device-1',
      );
      expect(migration.status, isNotNull);
      expect(migration.retryAfterSeconds, 2);
    }
  });

  test('le client envoie le POST attendu et impose no-store', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    final received = Completer<void>();
    unawaited(
      server.forEach((request) async {
        expect(request.method, 'POST');
        expect(request.uri.path, '/v1/devices/device-1/location-migrations');
        expect(
          request.headers.value(HttpHeaders.authorizationHeader),
          'Bearer session-not-logged',
        );
        expect(
          await utf8.decoder.bind(request).join(),
          '{"location_id":"frankfurt-02"}',
        );
        request.response.headers.set(
          HttpHeaders.cacheControlHeader,
          'no-store',
        );
        request.response.statusCode = HttpStatus.accepted;
        request.response.write(jsonEncode(_migrationJson('draining')));
        await request.response.close();
        received.complete();
      }),
    );
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
    );

    final result = await api.startLocationMigration(
      token: 'session-not-logged',
      deviceId: 'device-1',
      locationId: 'frankfurt-02',
    );
    await received.future;
    expect(result.status, LocationMigrationStatus.draining);
  });

  test('refuse une réponse de migration sans Cache-Control no-store', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(server.close);
    unawaited(
      server.forEach((request) async {
        request.response.statusCode = HttpStatus.ok;
        request.response.write(jsonEncode(_migrationJson('ready')));
        await request.response.close();
      }),
    );
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
    );
    await expectLater(
      api.startLocationMigration(
        token: 'session-not-logged',
        deviceId: 'device-1',
        locationId: 'frankfurt-02',
      ),
      throwsA(isA<ApiException>()),
    );
  });

  test(
    'un appareil sans device_id sélectionne localement sans migration',
    () async {
      final api = MigrationApi();
      final controller = _controller(api: api, device: null);
      final outcome = await controller.prepareLocationChange(frankfurt2);
      expect(outcome, LocationChangePreparation.selectedLocally);
      expect(controller.selectedLocation, frankfurt2);
      expect(api.startCalls, 0);
      controller.dispose();
    },
  );

  test('un appareil déjà sur la cible ne crée pas de migration', () async {
    final api = MigrationApi(device: _device(frankfurt2));
    final controller = _controller(api: api, device: _device(frankfurt2))
      ..vpnProtocol = VpnProtocol.openVpn;
    final outcome = await controller.prepareLocationChange(frankfurt2);
    expect(outcome, LocationChangePreparation.selectedLocally);
    expect(api.startCalls, 0);
    controller.dispose();
  });

  test(
    'une ancienne sélection locale ne bloque pas la première connexion',
    () async {
      final api = MigrationApi(device: _device(frankfurt1));
      final wireguard = MigrationWireGuard();
      final controller = _controller(
        api: api,
        wireguard: wireguard,
        device: _device(frankfurt1),
      )..selectedLocation = frankfurt2;

      await controller.toggleConnection();

      expect(controller.selectedLocation, frankfurt2);
      expect(controller.errorMessage, isNull);
      expect(wireguard.connectCalls, 1);
      controller.dispose();
    },
  );

  test('WireGuard déconnecté sélectionne sans confirmation', () async {
    final api = MigrationApi(device: _device(frankfurt1));
    final controller = _controller(api: api, device: _device(frankfurt1));

    final preparation = await controller.prepareLocationChange(frankfurt2);

    expect(preparation, LocationChangePreparation.selectedLocally);
    expect(controller.selectedLocation, frankfurt2);
    expect(api.startCalls, 0);
    controller.dispose();
  });

  test(
    'WireGuard connecté demande confirmation puis change et se reconnecte',
    () async {
      final api = MigrationApi(device: _device(frankfurt1));
      final wireguard = MigrationWireGuard()..connected = true;
      final controller =
          _controller(
              api: api,
              wireguard: wireguard,
              device: _device(frankfurt1),
            )
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.wireGuard;

      expect(
        await controller.prepareLocationChange(frankfurt2),
        LocationChangePreparation.confirmationRequired,
      );
      expect(controller.selectedLocation, frankfurt1);
      await controller.confirmPreparedLocationChange();
      expect(controller.selectedLocation, frankfurt2);
      expect(api.startCalls, 0);
      expect(wireguard.suspendCalls, 1);
      expect(wireguard.disconnectCalls, 0);
      expect(wireguard.connectCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      controller.dispose();
    },
  );

  test(
    'deux confirmations rapides ne lancent qu’un changement WireGuard',
    () async {
      final api = MigrationApi(device: _device(frankfurt1));
      final wireguard = MigrationWireGuard()..connected = true;
      final controller =
          _controller(
              api: api,
              wireguard: wireguard,
              device: _device(frankfurt1),
            )
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.wireGuard;

      await controller.prepareLocationChange(frankfurt2);
      final first = controller.confirmPreparedLocationChange();
      final second = controller.confirmPreparedLocationChange();
      expect(identical(first, second), isTrue);
      await Future.wait([first, second]);

      expect(wireguard.suspendCalls, 1);
      expect(wireguard.disconnectCalls, 0);
      expect(wireguard.connectCalls, 1);
      expect(controller.selectedLocation, frankfurt2);
      expect(controller.vpnStatus, VpnStatus.connected);
      controller.dispose();
    },
  );

  test('OpenVPN est suspendu sous pré-blocage pendant la migration', () async {
    final api = MigrationApi(device: _device(frankfurt1))
      ..startResult = _migration('draining');
    final openVpn = MigrationOpenVpn()..connected = true;
    final controller =
        _controller(api: api, openVpn: openVpn, device: _device(frankfurt1))
          ..vpnProtocol = VpnProtocol.openVpn
          ..vpnStatus = VpnStatus.connected
          ..activeProtocol = VpnProtocol.openVpn;
    await controller.prepareLocationChange(frankfurt2);
    await controller.startPreparedLocationMigration();
    expect(openVpn.prepareCalls, 1);
    expect(openVpn.suspendCalls, 1);
    expect(openVpn.disconnectCalls, 0);
    expect(openVpn.protectionActive, isTrue);
    expect(controller.vpnStatus, VpnStatus.blocked);
    expect(api.renewCalls, 0);
    controller.dispose();
  });

  test(
    'une déconnexion explicite annule la reconnexion de migration',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startResult = _migration('draining')
        ..pollResults = [_migration('ready')];
      final openVpn = MigrationOpenVpn()..connected = true;
      final controller =
          _controller(api: api, openVpn: openVpn, device: _device(frankfurt1))
            ..openVpnRuntimeAvailable = true
            ..vpnProtocol = VpnProtocol.openVpn
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.openVpn;

      await controller.prepareLocationChange(frankfurt2);
      await controller.startPreparedLocationMigration();
      expect(controller.vpnStatus, VpnStatus.blocked);

      await controller.toggleConnection();
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(openVpn.protectionActive, isFalse);

      api.device = _device(frankfurt2);
      await controller.pollLocationMigrationNow();
      expect(openVpn.importCalls, 0);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      controller.dispose();
    },
  );

  test(
    'OpenVPN déconnecté attend le bouton Connecter avant la migration',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startResult = _migration('draining')
        ..pollResults = [_migration('activating'), _migration('ready')];
      final openVpn = MigrationOpenVpn();
      final controller =
          _controller(api: api, openVpn: openVpn, device: _device(frankfurt1))
            ..openVpnRuntimeAvailable = true
            ..vpnProtocol = VpnProtocol.openVpn;

      final preparation = await controller.prepareLocationChange(frankfurt2);
      expect(preparation, LocationChangePreparation.selectedLocally);
      expect(controller.selectedLocation, frankfurt2);
      expect(api.startCalls, 0);

      await controller.toggleConnection();
      expect(api.startCalls, 1);
      expect(controller.isLocationMigrationActive, isTrue);
      expect(openVpn.importCalls, 0);

      await controller.pollLocationMigrationNow();
      api.device = _device(frankfurt2);
      await controller.pollLocationMigrationNow();
      expect(controller.selectedLocation, frankfurt2);
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      controller.dispose();
    },
  );

  test(
    'une erreur DPAPI après le 202 ne prétend pas que la migration a échoué',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startResult = _migration('draining');
      final store = MigrationStore()..failMigrationSave = true;
      final controller = _controller(
        api: api,
        store: store,
        device: _device(frankfurt1),
      )..vpnProtocol = VpnProtocol.openVpn;

      await controller.prepareLocationChange(frankfurt2);
      await controller.startPreparedLocationMigration();

      expect(api.startCalls, 1);
      expect(controller.isLocationMigrationActive, isTrue);
      expect(controller.locationMigrationError, contains('a bien démarré'));
      expect(
        controller.locationMigrationError,
        isNot(contains('n’a pas pu être démarré')),
      );
      controller.dispose();
    },
  );

  test(
    'OpenVPN reprend le même protocole après ready, sans nouvel appareil',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startResult = _migration('ready')
        ..deviceAfterStart = _device(frankfurt2);
      final openVpn = MigrationOpenVpn()..connected = true;
      final controller =
          _controller(api: api, openVpn: openVpn, device: _device(frankfurt1))
            ..openVpnRuntimeAvailable = true
            ..vpnProtocol = VpnProtocol.openVpn
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.openVpn;
      await controller.prepareLocationChange(frankfurt2);
      await controller.startPreparedLocationMigration();
      expect(controller.currentDeviceId, 'device-1');
      expect(controller.selectedLocation, frankfurt2);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      expect(openVpn.importCalls, 1);
      expect(api.renewCalls, 0);
      controller.dispose();
    },
  );

  test(
    'une migration ready finit si sa cible a disparu du catalogue',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startResult = _migration('draining')
        ..pollResults = [_migration('ready')];
      final store = MigrationStore();
      final openVpn = MigrationOpenVpn();
      final controller =
          _controller(
              api: api,
              store: store,
              openVpn: openVpn,
              device: _device(frankfurt1),
            )
            ..openVpnRuntimeAvailable = true
            ..vpnProtocol = VpnProtocol.openVpn;
      addTearDown(controller.dispose);

      await controller.prepareLocationChange(frankfurt2);
      await controller.startPreparedLocationMigration(connectWhenReady: true);
      expect(store.marker, isNotNull);
      expect(controller.pendingTargetLocation, frankfurt2);

      // A full target disappears from the public catalogue after acceptance.
      controller.locations = const [frankfurt1];
      api.device = _device(frankfurt2);
      await controller.pollLocationMigrationNow();

      expect(api.startCalls, 1);
      expect(api.pollCalls, 1);
      expect(controller.locations, const [frankfurt1]);
      expect(controller.selectedLocation, frankfurt2);
      expect(controller.realDeviceLocation, frankfurt2);
      expect(controller.currentDeviceId, 'device-1');
      expect(controller.locationMigration, isNull);
      expect(controller.pendingTargetLocation, isNull);
      expect(controller.locationMigrationError, isNull);
      expect(store.marker, isNull);
      expect(openVpn.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
    },
  );

  test(
    'un marqueur reprend sa cible absente via les appareils authentifiés',
    () async {
      final api = MigrationApi(device: _device(frankfurt2))
        ..pollResults = [_migration('ready')];
      final store = MigrationStore(
        marker: const StoredLocationMigration(
          migrationId: 'migration-1',
          deviceId: 'device-1',
          targetLocationId: 'frankfurt-02',
          userId: 'user-1',
        ),
      );
      final openVpn = MigrationOpenVpn();
      final controller =
          _controller(
              api: api,
              store: store,
              openVpn: openVpn,
              device: _device(frankfurt1),
            )
            ..locations = const [frankfurt1]
            ..vpnProtocol = VpnProtocol.openVpn;
      addTearDown(controller.dispose);
      expect(controller.pendingTargetLocation, isNull);

      await controller.resumeLocationMigration();

      expect(api.startCalls, 0);
      expect(api.pollCalls, 1);
      expect(controller.locations, const [frankfurt1]);
      expect(controller.devices.single.location, frankfurt2);
      expect(controller.selectedLocation, frankfurt2);
      expect(controller.realDeviceLocation, frankfurt2);
      expect(controller.currentDeviceId, 'device-1');
      expect(controller.locationMigration, isNull);
      expect(controller.pendingTargetLocation, isNull);
      expect(controller.locationMigrationError, isNull);
      expect(store.marker, isNull);
      expect(openVpn.importCalls, 0);
    },
  );

  test(
    'un poll capacity_unavailable conserve la migration et son marqueur',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startResult = _migration('draining')
        ..migrationPollFailure = const ApiException(
          statusCode: 503,
          errorCode: 'capacity_unavailable',
          retryAfterSeconds: 60,
        )
        ..pollResults = [_migration('ready')];
      final store = MigrationStore();
      final controller = _controller(
        api: api,
        store: store,
        device: _device(frankfurt1),
      )..vpnProtocol = VpnProtocol.openVpn;
      addTearDown(controller.dispose);

      await controller.prepareLocationChange(frankfurt2);
      await controller.startPreparedLocationMigration();
      final marker = store.marker;
      expect(marker, isNotNull);
      await controller.pollLocationMigrationNow();

      expect(api.startCalls, 1);
      expect(api.pollCalls, 1);
      expect(controller.isLocationMigrationActive, isTrue);
      expect(controller.locationMigration?.migrationId, 'migration-1');
      expect(controller.pendingTargetLocation, frankfurt2);
      expect(controller.locationMigrationError, contains('momentanément'));
      expect(identical(store.marker, marker), isTrue);
      expect(controller.currentDeviceId, 'device-1');

      api.migrationPollFailure = null;
      api.device = _device(frankfurt2);
      await controller.pollLocationMigrationNow();

      expect(api.startCalls, 1);
      expect(api.pollCalls, 2);
      expect(controller.selectedLocation, frankfurt2);
      expect(controller.locationMigration, isNull);
      expect(controller.locationMigrationError, isNull);
      expect(store.marker, isNull);
    },
  );

  test(
    'un marqueur est repris pour le même compte, jamais pour un autre',
    () async {
      final marker = const StoredLocationMigration(
        migrationId: 'migration-1',
        deviceId: 'device-1',
        targetLocationId: 'frankfurt-02',
        userId: 'user-1',
      );
      final sameAccountApi = MigrationApi(device: _device(frankfurt1))
        ..pollResults = [_migration('activating')];
      final sameStore = MigrationStore(marker: marker);
      final same = _controller(
        api: sameAccountApi,
        store: sameStore,
        device: _device(frankfurt1),
      );
      await same.resumeLocationMigration();
      expect(sameAccountApi.pollCalls, 1);
      expect(
        same.locationMigration?.status,
        LocationMigrationStatus.activating,
      );
      same.dispose();

      final otherApi = MigrationApi(device: _device(frankfurt1));
      final other = _controller(
        api: otherApi,
        store: MigrationStore(
          marker: const StoredLocationMigration(
            migrationId: 'migration-1',
            deviceId: 'device-1',
            targetLocationId: 'frankfurt-02',
            userId: 'different-user',
          ),
        ),
        device: _device(frankfurt1),
      );
      await other.resumeLocationMigration();
      expect(otherApi.pollCalls, 0);
      other.dispose();
    },
  );

  test(
    'une erreur cible conserve le choix visuel et ne réinitialise rien',
    () async {
      final api = MigrationApi(device: _device(frankfurt1))
        ..startError = const ApiException(
          statusCode: 503,
          errorCode: 'target_unavailable',
        );
      final wireguard = MigrationWireGuard();
      final controller = _controller(
        api: api,
        wireguard: wireguard,
        device: _device(frankfurt1),
      )..vpnProtocol = VpnProtocol.openVpn;
      await controller.prepareLocationChange(frankfurt2);
      await controller.startPreparedLocationMigration();
      expect(controller.selectedLocation, frankfurt2);
      expect(controller.locationMigrationError, contains('indisponible'));
      expect(wireguard.resetCalls, 0);
      expect(api.renewCalls, 0);
      controller.dispose();
    },
  );

  for (final rejection in [
    (
      status: 409,
      code: 'server_full',
      message: 'n’a plus de place',
      removesTarget: true,
    ),
    (
      status: 503,
      code: 'capacity_unavailable',
      message: 'ne peut pas être confirmée',
      removesTarget: false,
    ),
  ]) {
    for (final wasConnected in [false, true]) {
      test('${rejection.code} refuse la migration sans attendre le catalogue '
          '(OpenVPN connecté : $wasConnected)', () async {
        final api = _CapacityRejectionMigrationApi()
          ..startError = ApiException(
            statusCode: rejection.status,
            errorCode: rejection.code,
          );
        final store = MigrationStore();
        final wireguard = _CapacityRejectionWireGuard();
        final openVpn = MigrationOpenVpn()..connected = wasConnected;
        final controller =
            _controller(
                api: api,
                store: store,
                wireguard: wireguard,
                openVpn: openVpn,
                device: _device(frankfurt1),
              )
              ..vpnProtocol = VpnProtocol.openVpn
              ..vpnStatus = wasConnected
                  ? VpnStatus.connected
                  : VpnStatus.disconnected
              ..activeProtocol = wasConnected ? VpnProtocol.openVpn : null;
        addTearDown(() {
          controller.dispose();
          if (!api.capacityCatalogueResponse.isCompleted) {
            api.capacityCatalogueResponse.complete(const [frankfurt1]);
          }
        });

        await controller.prepareLocationChange(frankfurt2);
        await controller.startPreparedLocationMigration().timeout(
          const Duration(seconds: 2),
        );

        // Cleanup must finish while the refreshed catalogue is still pending.
        expect(api.capacityCatalogueCalls, 1);
        expect(api.capacityCatalogueResponse.isCompleted, isFalse);
        expect(controller.isLoadingLocations, isTrue);
        expect(controller.isConnectionBusy, isFalse);
        expect(api.startCalls, 1);
        expect(api.pollCalls, 0);
        expect(controller.locationMigrationError, contains(rejection.message));
        expect(
          controller.locationMigrationError,
          contains('Choisissez un autre emplacement'),
        );
        expect(controller.locationMigrationMessage, isNull);
        expect(controller.locationMigration, isNull);
        expect(controller.pendingTargetLocation, isNull);
        expect(controller.isLocationMigrationActive, isFalse);
        expect(store.marker, isNull);
        expect(controller.currentDeviceId, 'device-1');
        expect(controller.realDeviceLocation, frankfurt1);
        expect(controller.profile, same(testProfile));
        expect(wireguard.resetCalls, 0);
        expect(wireguard.connectCalls, 0);
        expect(openVpn.importCalls, 0);
        expect(api.renewCalls, 0);
        expect(
          controller.locations.any((location) => location.id == frankfurt2.id),
          !rejection.removesTarget,
        );
        expect(
          controller.selectedLocation,
          wasConnected
              ? frankfurt1
              : rejection.removesTarget
              ? isNull
              : frankfurt2,
        );
        expect(
          controller.vpnStatus,
          wasConnected ? VpnStatus.blocked : VpnStatus.disconnected,
        );
        expect(openVpn.suspendCalls, wasConnected ? 1 : 0);
        expect(openVpn.disconnectCalls, 0);
        expect(openVpn.protectionActive, wasConnected);
        expect(controller.requiresExplicitDisconnect, wasConnected);
        if (wasConnected) {
          expect(controller.errorMessage, contains(rejection.message));
        }
        expect(controller.errorMessage ?? '', isNot(contains('continue')));
      });
    }
  }

  test(
    'un échec de vérification OpenVPN conserve sa cause sous protection',
    () async {
      final api = _UnavailableDeviceMigrationApi();
      final openVpn = MigrationOpenVpn();
      final controller =
          _controller(api: api, openVpn: openVpn, device: _device(frankfurt1))
            ..openVpnRuntimeAvailable = true
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..vpnProtocol = VpnProtocol.openVpn;
      addTearDown(controller.dispose);

      await controller.toggleConnection();

      expect(openVpn.prepareCalls, 1);
      expect(openVpn.importCalls, 0);
      expect(api.startCalls, 0);
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(controller.requiresExplicitDisconnect, isTrue);
      expect(
        controller.errorMessage,
        'Impossible de vérifier l’emplacement de cet appareil.',
      );
      expect(controller.errorMessage, isNot(contains('continue')));

      await controller.toggleConnection();

      expect(openVpn.protectionActive, isFalse);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.requiresExplicitDisconnect, isFalse);
      expect(controller.errorMessage, isNull);
    },
  );

  test('les exceptions de migration ne contiennent aucun secret de tunnel', () {
    const exception = ApiException(
      statusCode: 503,
      errorCode: 'target_unavailable',
    );
    expect(exception.toString(), isNot(contains('private')));
    expect(exception.toString(), isNot(contains('198.51.100.1')));
    expect(exception.toString(), isNot(contains('token')));
  });
}

Map<String, dynamic> _migrationJson(String status) => {
  'migration_id': 'migration-1',
  'device_id': 'device-1',
  'source_location_id': 'frankfurt-01',
  'target_location_id': 'frankfurt-02',
  'status': status,
  'retry_after_seconds': 2,
};

LocationMigration _migration(String status) => LocationMigration.fromJson(
  _migrationJson(status),
  expectedDeviceId: 'device-1',
);

VpnDevice _device(Location location) => VpnDevice(
  deviceId: 'device-1',
  name: 'FuzeVPN — Windows',
  location: location,
  createdAt: DateTime.utc(2026, 8, 20),
);

AppController _controller({
  required MigrationApi api,
  MigrationStore? store,
  MigrationWireGuard? wireguard,
  MigrationOpenVpn? openVpn,
  VpnDevice? device,
}) {
  final actualStore = store ?? MigrationStore();
  return AppController(
      api: api,
      store: actualStore,
      wireguard: wireguard ?? MigrationWireGuard(),
      openVpn: openVpn ?? MigrationOpenVpn(),
    )
    ..profile = testProfile
    ..locations = const [frankfurt1, frankfurt2]
    ..selectedLocation = frankfurt1
    ..currentDeviceId = device?.deviceId
    ..devices = device == null ? const [] : [device]
    ..realDeviceLocation = device?.location
    ..isLoadingLocations = false;
}

class MigrationApi extends ApiClient {
  MigrationApi({this.device}) : super(baseUri: Uri.parse('http://localhost/'));

  @override
  Future<Subscription> subscription(String token) async => const Subscription(
    status: SubscriptionStatus.active,
    hasAccess: true,
    renewsAutomatically: false,
    cancelAtPeriodEnd: false,
  );

  VpnDevice? device;
  VpnDevice? deviceAfterStart;
  LocationMigration? startResult;
  ApiException? startError;
  ApiException? migrationPollFailure;
  List<LocationMigration> pollResults = [];
  int startCalls = 0;
  int pollCalls = 0;
  int renewCalls = 0;

  @override
  Future<DeviceList> devices(String token) async =>
      DeviceList(limit: 2, devices: device == null ? const [] : [device!]);

  @override
  Future<LocationMigration> startLocationMigration({
    required String token,
    required String deviceId,
    required String locationId,
  }) async {
    startCalls++;
    if (startError != null) throw startError!;
    if (deviceAfterStart != null) device = deviceAfterStart;
    return startResult!;
  }

  @override
  Future<LocationMigration> getLocationMigration({
    required String token,
    required String deviceId,
    required String migrationId,
  }) async {
    pollCalls++;
    if (migrationPollFailure != null) throw migrationPollFailure!;
    return pollResults.removeAt(0);
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async => const DeviceConfiguration(
    deviceId: 'device-1',
    address: 'not-observed',
    dns: [],
    serverPublicKey: 'not-observed',
    endpoint: 'not-observed',
    allowedIps: [],
  );

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async => OpenVpnActivation(
    deviceId: 'device-1',
    protocol: 'openvpn',
    certificatePem: 'not-observed',
    caCertificatePem: 'not-observed',
    tlsCryptV2ClientKey: 'not-observed',
    endpoint: '198.51.100.1',
    dns: const ['1.1.1.1'],
    address: '10.20.0.2/24',
    serverName: 'frankfurt-01.openvpn.internal',
    remoteCertTlsServer: true,
    ciphers: const ['AES-256-GCM'],
    notAfter: DateTime.utc(2026, 9, 1),
  );
}

class _UnavailableDeviceMigrationApi extends MigrationApi {
  _UnavailableDeviceMigrationApi() : super(device: _device(frankfurt1));

  @override
  Future<DeviceList> devices(String token) async => throw const ApiException(
    statusCode: 503,
    errorCode: 'service_unavailable',
  );
}

class _CapacityRejectionMigrationApi extends MigrationApi {
  _CapacityRejectionMigrationApi() : super(device: _device(frankfurt1));

  final capacityCatalogueResponse = Completer<List<Location>>();
  int capacityCatalogueCalls = 0;

  @override
  Future<List<Location>> locations() {
    capacityCatalogueCalls++;
    return capacityCatalogueResponse.future;
  }
}

class _CapacityRejectionWireGuard extends MigrationWireGuard {
  @override
  Future<void> recreateIdentityForAccount(String accountId) async =>
      resetCalls++;
}

class MigrationStore extends SecureStore {
  MigrationStore({this.marker});
  StoredLocationMigration? marker;
  bool failMigrationSave = false;

  @override
  Future<String?> token() async => 'session-not-logged';
  @override
  Future<void> saveSelectedLocation(String value) async {}
  @override
  Future<void> saveCurrentDeviceId(String value) async {}
  @override
  Future<void> clearCurrentDeviceId() async {}
  @override
  Future<void> saveLocationMigration(StoredLocationMigration value) async {
    if (failMigrationSave) throw StateError('simulated secure-store failure');
    marker = value;
  }

  @override
  Future<StoredLocationMigration?> locationMigration() async => marker;
  @override
  Future<void> clearLocationMigration() async => marker = null;
}

class MigrationWireGuard extends WireGuardBridge
    with NativeProtectionStatusFixture {
  bool connected = false;
  bool protectionActive = false;
  int suspendCalls = 0;
  int disconnectCalls = 0;
  int connectCalls = 0;
  int resetCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async => protectionActive = true;
  @override
  Future<void> suspendForMigration() async {
    suspendCalls++;
    connected = false;
  }

  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<bool> isNetworkProtectionActive() async =>
      protectionActive || connected;
  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    connected = false;
    protectionActive = false;
  }

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectCalls++;
    connected = true;
  }

  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      'public-key-not-logged';
  @override
  Future<void> resetIdentity() async => resetCalls++;
}

class MigrationOpenVpn extends OpenVpnBridge
    with NativeProtectionStatusFixture {
  bool connected = false;
  bool protectionActive = false;
  int disconnectCalls = 0;
  int prepareCalls = 0;
  int suspendCalls = 0;
  int importCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    protectionActive = true;
  }

  @override
  Future<void> suspendForMigration() async {
    suspendCalls++;
    connected = false;
  }

  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    connected = false;
    protectionActive = false;
  }

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
  }

  @override
  Future<bool> isNetworkProtectionActive() async => protectionActive;
}
