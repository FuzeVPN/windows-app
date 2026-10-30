// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

import 'native_protection_status_fixture.dart';

const _dual = Location(
  id: 'dual',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Dual',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const _wireGuardOnly = Location(
  id: 'wg-only',
  city: 'Paris',
  countryCode: 'FR',
  displayName: 'WireGuard',
  supportedProtocols: {VpnProtocol.wireGuard},
);
const _openVpnOnly = Location(
  id: 'ovpn-only',
  city: 'London',
  countryCode: 'GB',
  displayName: 'OpenVPN',
  supportedProtocols: {VpnProtocol.openVpn},
);
const _profile = UserProfile(
  userId: 'user-1',
  email: 'client@example.test',
  firstName: 'Client',
  emailVerified: true,
);

LocationMigration _migration(
  String target, {
  LocationMigrationStatus status = LocationMigrationStatus.ready,
}) => LocationMigration(
  migrationId: 'migration-1',
  deviceId: 'device-1',
  sourceLocationId: _dual.id,
  targetLocationId: target,
  status: status,
  retryAfterSeconds: 120,
);
VpnDevice _device(Location? location) => VpnDevice(
  deviceId: 'device-1',
  name: 'Synthetic device',
  location: location,
  createdAt: null,
);

class _Harness {
  _Harness() {
    app =
        AppController(
            api: api,
            store: store,
            wireguard: wireguard,
            openVpn: openVpn,
          )
          ..profile = _profile
          ..locations = const [_dual, _wireGuardOnly, _openVpnOnly]
          ..selectedLocation = _dual
          ..currentDeviceId = 'device-1'
          ..devices = [_device(_dual)]
          ..realDeviceLocation = _dual
          ..openVpnRuntimeAvailable = true
          ..isLoadingLocations = false;
  }
  final api = _Api();
  final store = _Store();
  final wireguard = _WireGuard();
  final openVpn = _OpenVpn();
  late final AppController app;

  void connected(VpnProtocol protocol) {
    app
      ..protocolPreference = VpnProtocolPreference.automatic
      ..vpnProtocol = protocol
      ..vpnStatus = VpnStatus.connected
      ..activeProtocol = protocol
      ..tunnelLocationId = _dual.id;
    if (protocol == VpnProtocol.wireGuard) {
      wireguard.connected = true;
      wireguard.protectionActive = true;
    } else {
      openVpn.connected = true;
      openVpn.protectionActive = true;
    }
  }

  Future<void> pendingMigration() async {
    app.vpnProtocol = VpnProtocol.openVpn;
    api.startResult = _migration(
      _openVpnOnly.id,
      status: LocationMigrationStatus.draining,
    );
    await app.prepareLocationChange(_openVpnOnly);
    await app.startPreparedLocationMigration();
    expect(store.marker, isNotNull);
    expect(app.isLocationMigrationActive, isTrue);
  }

  void dispose() {
    app.dispose();
    api.close();
  }
}

void main() {
  test(
    'LOC01 automatic WireGuard to OpenVPN resolves destination before stopping source',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      h.connected(VpnProtocol.wireGuard);
      h.api.startResult = _migration(_openVpnOnly.id);
      h.api.deviceAfterStart = _device(_openVpnOnly);
      expect(
        await h.app.prepareLocationChange(_openVpnOnly),
        LocationChangePreparation.confirmationRequired,
      );
      await h.app.confirmPreparedLocationChange();
      expect(h.app.selectedLocation?.id, _openVpnOnly.id);
      expect(h.app.activeProtocol, VpnProtocol.openVpn);
      expect(h.app.vpnStatus, VpnStatus.connected);
      expect(h.wireguard.suspendCalls, 1);
      expect(h.wireguard.disconnectCalls, 0);
      expect(h.wireguard.resetCalls, 0);
      expect(h.openVpn.importCalls, 1);
      expect(h.api.startCalls, 1);
    },
  );

  test(
    'LOC01 automatic OpenVPN to WireGuard suspends the actual source',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      h.connected(VpnProtocol.openVpn);
      expect(
        await h.app.prepareLocationChange(_wireGuardOnly),
        LocationChangePreparation.confirmationRequired,
      );
      await h.app.confirmPreparedLocationChange();
      expect(h.app.selectedLocation?.id, _wireGuardOnly.id);
      expect(h.app.activeProtocol, VpnProtocol.wireGuard);
      expect(h.app.vpnStatus, VpnStatus.connected);
      expect(h.openVpn.suspendCalls, 1);
      expect(h.openVpn.disconnectCalls, 0);
      expect(h.wireguard.connectCalls, 1);
      expect(h.api.startCalls, 0);
    },
  );

  test(
    'LOC01 failed cross-protocol migration retains the prepared source protection',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      h.connected(VpnProtocol.wireGuard);
      h.api.startFailure = const ApiException(
        statusCode: 503,
        observedHttpStatus: 503,
        errorCode: 'target_unavailable',
      );
      await h.app.prepareLocationChange(_openVpnOnly);
      await h.app.confirmPreparedLocationChange();
      expect(h.app.vpnStatus, VpnStatus.blocked);
      expect(h.app.requiresExplicitDisconnect, isTrue);
      expect(h.wireguard.protectionActive, isTrue);
      expect(h.wireguard.connected, isFalse);
      expect(h.wireguard.disconnectCalls, 0);
      expect(h.openVpn.disconnectCalls, 0);
      expect(h.openVpn.importCalls, 0);
      expect(h.app.selectedLocation?.id, _dual.id);
    },
  );

  test(
    'LOC01 incompatible destination is rejected before interrupting active tunnel',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      h.connected(VpnProtocol.wireGuard);
      h.app.protocolPreference = VpnProtocolPreference.wireGuard;
      await h.app.prepareLocationChange(_openVpnOnly);
      await h.app.confirmPreparedLocationChange();
      expect(h.app.vpnStatus, VpnStatus.connected);
      expect(h.app.selectedLocation?.id, _dual.id);
      expect(h.wireguard.connected, isTrue);
      expect(h.wireguard.suspendCalls, 0);
      expect(h.wireguard.disconnectCalls, 0);
      expect(h.api.startCalls, 0);
    },
  );

  for (final preference in [
    VpnProtocolPreference.wireGuard,
    VpnProtocolPreference.automatic,
    VpnProtocolPreference.openVpn,
  ]) {
    test(
      'LOC02 refreshLocations then quickConnect respects $preference without saved selection',
      () async {
        final h = _Harness();
        addTearDown(h.dispose);
        h.app
          ..selectedLocation = null
          ..protocolPreference = preference
          ..vpnProtocol = preference == VpnProtocolPreference.openVpn
              ? VpnProtocol.openVpn
              : VpnProtocol.wireGuard;
        h.api.catalogue = preference == VpnProtocolPreference.openVpn
            ? const [_wireGuardOnly, _openVpnOnly]
            : const [_openVpnOnly, _wireGuardOnly];
        // There is no enrolled logical device during the first connection.
        h.app.currentDeviceId = null;
        h.app.devices = const [];
        await h.app.refreshLocations();
        await h.app.quickConnect();
        final expectedProtocol = preference == VpnProtocolPreference.openVpn
            ? VpnProtocol.openVpn
            : VpnProtocol.wireGuard;
        expect(h.app.activeProtocol, expectedProtocol);
        expect(h.app.vpnStatus, VpnStatus.connected);
        expect(
          h.app.selectedLocation?.id,
          expectedProtocol == VpnProtocol.openVpn
              ? _openVpnOnly.id
              : _wireGuardOnly.id,
        );
      },
    );
  }

  test('LOC02 explicit incompatible saved choice is preserved', () async {
    final h = _Harness();
    addTearDown(h.dispose);
    h.app.selectedLocation = null;
    h.api.catalogue = const [_openVpnOnly, _wireGuardOnly];
    await h.app.refreshLocations(_openVpnOnly.id);
    await h.app.quickConnect();
    expect(h.app.selectedLocation?.id, _openVpnOnly.id);
    expect(h.app.vpnStatus, VpnStatus.error);
    expect(h.wireguard.connectCalls, 0);
    expect(h.openVpn.importCalls, 0);
  });

  test(
    'LOC03 missing migration reconciles confirmed source and retains network protection',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.openVpn.protectionActive = true;
      h.app.vpnStatus = VpnStatus.blocked;
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      await h.app.pollLocationMigrationNow();
      expect(h.api.deviceCalls, 1);
      expect(h.app.locationMigration, isNull);
      expect(h.store.marker, isNull);
      expect(h.app.selectedLocation?.id, _dual.id);
      expect(h.app.realDeviceLocation?.id, _dual.id);
      expect(h.app.vpnStatus, VpnStatus.blocked);
      expect(h.openVpn.protectionActive, isTrue);
      expect(h.openVpn.disconnectCalls, 0);
      expect(h.wireguard.disconnectCalls, 0);
      expect(h.openVpn.importCalls, 0);
    },
  );

  test(
    'LOC03 missing migration accepts confirmed destination without reconnecting',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.api.currentDevice = _device(_openVpnOnly);
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      await h.app.pollLocationMigrationNow();
      expect(h.app.locationMigration, isNull);
      expect(h.store.marker, isNull);
      expect(h.app.selectedLocation?.id, _openVpnOnly.id);
      expect(h.openVpn.importCalls, 0);
    },
  );

  for (final deviceUnavailable in [true, false]) {
    test(
      'LOC03 missing migration keeps recovery marker when device state is ${deviceUnavailable ? "unavailable" : "missing location"}',
      () async {
        final h = _Harness();
        addTearDown(h.dispose);
        await h.pendingMigration();
        h.api.deviceFailure = deviceUnavailable
            ? const ApiException(
                statusCode: 503,
                errorCode: 'service_unavailable',
              )
            : null;
        h.api.currentDevice = _device(null);
        h.api.pollFailure = const ApiException(
          statusCode: 404,
          observedHttpStatus: 404,
          errorCode: 'not_found',
        );
        await h.app.pollLocationMigrationNow();
        expect(h.app.isLocationMigrationActive, isTrue);
        expect(h.store.marker, isNotNull);
        expect(h.app.selectedLocation?.id, _openVpnOnly.id);
        expect(h.openVpn.disconnectCalls, 0);
      },
    );
  }

  test(
    'LOC03 terminal reconciliation clears a persisted marker after restart',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      h.store.marker = const StoredLocationMigration(
        migrationId: 'migration-1',
        deviceId: 'device-1',
        targetLocationId: 'ovpn-only',
        userId: 'user-1',
      );
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      await h.app.resumeLocationMigration();
      expect(h.api.deviceCalls, 1);
      expect(h.store.marker, isNull);
      expect(h.app.locationMigration, isNull);
      expect(h.app.selectedLocation?.id, _dual.id);
      expect(h.openVpn.disconnectCalls, 0);
    },
  );

  test(
    'LOC03 cannot discard recovery state when protected marker deletion fails',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.store.failMarkerClear = true;
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      await h.app.pollLocationMigrationNow();
      expect(h.app.isLocationMigrationActive, isTrue);
      expect(h.store.marker, isNotNull);
      h.store.failMarkerClear = false;
      await h.app.pollLocationMigrationNow();
      expect(h.app.locationMigration, isNull);
      expect(h.store.marker, isNull);
    },
  );

  test(
    'LOC03 locally synthesized not_found cannot discard the recovery marker',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        errorCode: 'not_found',
      );
      await h.app.pollLocationMigrationNow();
      expect(h.api.deviceCalls, 0);
      expect(h.app.isLocationMigrationActive, isTrue);
      expect(h.store.marker, isNotNull);
    },
  );

  test(
    'LOC03 confirmed deleted device clears binding without releasing protection',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.api.currentDevice = null;
      h.openVpn.protectionActive = true;
      h.app.vpnStatus = VpnStatus.blocked;
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      await h.app.pollLocationMigrationNow();
      expect(h.app.currentDeviceId, isNull);
      expect(h.app.locationMigration, isNull);
      expect(h.store.marker, isNull);
      expect(h.app.vpnStatus, VpnStatus.blocked);
      expect(h.openVpn.protectionActive, isTrue);
      expect(h.openVpn.disconnectCalls, 0);
      expect(h.wireguard.resetCalls, 0);
    },
  );

  test(
    'LOC03 delayed reconciliation cannot commit to a different account',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.api.devicesGate = Completer<void>();
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      final poll = h.app.pollLocationMigrationNow();
      await h.api.devicesStarted.future;
      h.app.profile = const UserProfile(
        userId: 'user-2',
        email: 'other@example.test',
        firstName: 'Other',
        emailVerified: true,
      );
      h.api.devicesGate!.complete();
      await poll;
      expect(h.store.marker, isNotNull);
      expect(h.app.selectedLocation?.id, _openVpnOnly.id);
      expect(h.openVpn.disconnectCalls, 0);
    },
  );

  test('LOC03 delayed reconciliation cannot erase a newer migration', () async {
    final h = _Harness();
    addTearDown(h.dispose);
    await h.pendingMigration();
    h.api.devicesGate = Completer<void>();
    h.api.pollFailure = const ApiException(
      statusCode: 404,
      observedHttpStatus: 404,
      errorCode: 'not_found',
    );
    final poll = h.app.pollLocationMigrationNow();
    await h.api.devicesStarted.future;
    final newer = LocationMigration(
      migrationId: 'migration-2',
      deviceId: 'device-1',
      sourceLocationId: _dual.id,
      targetLocationId: _wireGuardOnly.id,
      status: LocationMigrationStatus.draining,
      retryAfterSeconds: 120,
    );
    h.app.locationMigration = newer;
    h.store.marker = const StoredLocationMigration(
      migrationId: 'migration-2',
      deviceId: 'device-1',
      targetLocationId: 'wg-only',
      userId: 'user-1',
    );
    h.api.devicesGate!.complete();
    await poll;
    expect(h.app.locationMigration, same(newer));
    expect(h.store.marker?.migrationId, 'migration-2');
  });

  test(
    'LOC03 discarded device response cannot confirm an old cached location',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.api.devicesGate = Completer<void>();
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      final poll = h.app.pollLocationMigrationNow();
      await h.api.devicesStarted.future;
      // Re-enrollment can retain the same logical id while invalidating reads.
      h.app.currentDeviceId = 'device-1';
      h.api.devicesGate!.complete();
      await poll;
      expect(h.app.isLocationMigrationActive, isTrue);
      expect(h.store.marker, isNotNull);
      expect(h.app.selectedLocation?.id, _openVpnOnly.id);
    },
  );

  test(
    'LOC03 device mutation during durable selection cannot erase migration marker',
    () async {
      final h = _Harness();
      addTearDown(h.dispose);
      await h.pendingMigration();
      h.store.selectedWriteGate = Completer<void>();
      h.store.selectedWriteStarted = Completer<void>();
      h.api.pollFailure = const ApiException(
        statusCode: 404,
        observedHttpStatus: 404,
        errorCode: 'not_found',
      );
      final poll = h.app.pollLocationMigrationNow();
      await h.store.selectedWriteStarted!.future;
      // The accepted device snapshot ceases to attest the current binding while
      // its confirmed location is still being written to protected storage.
      h.app.currentDeviceId = 'device-1';
      h.store.selectedWriteGate!.complete();
      await poll;
      expect(h.app.isLocationMigrationActive, isTrue);
      expect(h.store.marker, isNotNull);
      expect(h.app.selectedLocation?.id, _openVpnOnly.id);
    },
  );
}

class _Api extends ApiClient {
  _Api() : super(baseUri: Uri.parse('http://synthetic.invalid/'));
  List<Location> catalogue = const [_dual, _wireGuardOnly, _openVpnOnly];
  VpnDevice? currentDevice = _device(_dual);
  VpnDevice? deviceAfterStart;
  LocationMigration? startResult;
  ApiException? pollFailure;
  ApiException? deviceFailure;
  ApiException? startFailure;
  int deviceCalls = 0;
  int startCalls = 0;
  Completer<void>? devicesGate;
  final devicesStarted = Completer<void>();
  @override
  Future<List<Location>> locations() async => catalogue;
  @override
  Future<Subscription> subscription(String token) async => const Subscription(
    status: SubscriptionStatus.active,
    hasAccess: true,
    renewsAutomatically: false,
    cancelAtPeriodEnd: false,
  );
  @override
  Future<DeviceList> devices(String token) async {
    deviceCalls++;
    if (!devicesStarted.isCompleted) devicesStarted.complete();
    await devicesGate?.future;
    if (deviceFailure case final failure?) throw failure;
    return DeviceList(
      limit: 2,
      devices: currentDevice == null ? const [] : [currentDevice!],
    );
  }

  @override
  Future<LocationMigration> startLocationMigration({
    required String token,
    required String deviceId,
    required String locationId,
  }) async {
    startCalls++;
    if (startFailure case final failure?) throw failure;
    if (deviceAfterStart != null) currentDevice = deviceAfterStart;
    return startResult!;
  }

  @override
  Future<LocationMigration> getLocationMigration({
    required String token,
    required String deviceId,
    required String migrationId,
  }) async {
    if (pollFailure case final failure?) throw failure;
    throw StateError('No synthetic migration update configured');
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    currentDevice = _device(
      catalogue.firstWhere((location) => location.id == locationId),
    );
    return const DeviceConfiguration(
      deviceId: 'device-1',
      address: '10.20.0.2/24',
      dns: ['1.1.1.1'],
      serverPublicKey: 'synthetic-key',
      endpoint: '198.51.100.1:51820',
      allowedIps: ['0.0.0.0/0'],
    );
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async => OpenVpnActivation(
    deviceId: 'device-1',
    protocol: 'openvpn',
    certificatePem: 'synthetic',
    caCertificatePem: 'synthetic',
    tlsCryptV2ClientKey: 'synthetic',
    endpoint: '198.51.100.1',
    dns: const ['1.1.1.1'],
    address: '10.20.0.2/24',
    serverName: 'synthetic.invalid',
    remoteCertTlsServer: true,
    ciphers: const ['AES-256-GCM'],
    notAfter: DateTime.utc(2030),
  );
}

class _Store extends SecureStore {
  StoredLocationMigration? marker;
  bool failMarkerClear = false;
  Completer<void>? selectedWriteGate;
  Completer<void>? selectedWriteStarted;
  @override
  Future<String?> token() async => 'synthetic-token';
  @override
  Future<void> saveSelectedLocation(String id) async {
    final started = selectedWriteStarted;
    if (started != null && !started.isCompleted) started.complete();
    await selectedWriteGate?.future;
  }

  @override
  Future<void> saveCurrentDeviceId(String id) async {}
  @override
  Future<void> clearCurrentDeviceId() async {}
  @override
  Future<void> saveLocationMigration(StoredLocationMigration value) async =>
      marker = value;
  @override
  Future<StoredLocationMigration?> locationMigration() async => marker;
  @override
  Future<void> clearLocationMigration() async {
    if (failMarkerClear) {
      throw StateError('Synthetic protected storage failure');
    }
    marker = null;
  }
}

class _WireGuard extends WireGuardBridge with NativeProtectionStatusFixture {
  bool connected = false;
  bool protectionActive = false;
  int suspendCalls = 0;
  int disconnectCalls = 0;
  int resetCalls = 0;
  int connectCalls = 0;
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
  Future<bool> isNetworkProtectionActive() async => protectionActive;
  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      'synthetic-key';
  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectCalls++;
    connected = true;
    protectionActive = true;
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    connected = false;
    protectionActive = false;
  }

  @override
  Future<void> resetIdentity() async => resetCalls++;
}

class _OpenVpn extends OpenVpnBridge with NativeProtectionStatusFixture {
  bool connected = false;
  bool protectionActive = false;
  int suspendCalls = 0;
  int disconnectCalls = 0;
  int importCalls = 0;
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
  Future<bool> isNetworkProtectionActive() async => protectionActive;
  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async => 'synthetic-csr';
  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importCalls++;
    connected = true;
    protectionActive = true;
  }

  @override
  Future<void> disconnect() async {
    disconnectCalls++;
    connected = false;
    protectionActive = false;
  }
}
