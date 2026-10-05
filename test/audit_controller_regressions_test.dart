// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';

import 'support/audit_fixtures.dart' as fixture;

const _source = Location(
  id: 'source',
  city: 'Source',
  countryCode: 'DE',
  displayName: 'Source',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final protocol in VpnProtocol.values) {
    for (final protection in [
      'killSwitch',
      'dnsProtection',
      'webRtcProtection',
    ]) {
      for (final fail in [false, true]) {
        test('security write reserves connection and commits $protection only '
            'after storage ($protocol, fail=$fail)', () async {
          final store = _Store()
            ..securityGate = Completer<void>()
            ..failSecurityWrite = fail;
          final wg = _WireGuard();
          final ovpn = _OpenVpn();
          final controller = _controller(store: store, wg: wg, ovpn: ovpn)
            ..vpnProtocol = protocol
            ..protocolPreference = protocol == VpnProtocol.wireGuard
                ? VpnProtocolPreference.wireGuard
                : VpnProtocolPreference.openVpn;
          addTearDown(controller.dispose);

          final changing = _change(controller, protection);
          // Reservation must precede the queue's first microtask.
          expect(controller.isConnectionBusy, isTrue);
          await controller.quickConnect();
          await _waitUntil(() => store.securityWrites.isNotEmpty);
          expect(_protection(controller, protection), isTrue);
          expect(wg.connectCalls, 0);
          expect(ovpn.importCalls, 0);
          expect(wg.prepareCalls, 0);
          expect(ovpn.prepareCalls, 0);
          expect(wg.options[protection], isTrue);
          expect(ovpn.options[protection], isTrue);

          store.securityGate!.complete();
          await changing;
          expect(controller.isConnectionBusy, isFalse);
          expect(_protection(controller, protection), fail);
          expect(wg.options[protection], fail);
          expect(ovpn.options[protection], fail);
          expect(controller.securitySettingsError, fail ? isNotNull : isNull);

          await controller.quickConnect();
          expect(controller.vpnStatus, VpnStatus.connected);
          final applied = protocol == VpnProtocol.wireGuard
              ? wg.connectedOptions
              : ovpn.connectedOptions;
          expect(applied![protection], fail);
          expect(
            protocol == VpnProtocol.wireGuard
                ? wg.prepareCalls
                : ovpn.prepareCalls,
            protection == 'killSwitch' && !fail ? 0 : greaterThan(0),
          );
        });
      }
    }
  }

  test('queued security changes preserve each committed preference', () async {
    final store = _Store()..securityGate = Completer<void>();
    final controller = _controller(store: store);
    addTearDown(controller.dispose);
    final first = controller.setKillSwitch(false);
    final second = controller.setDnsProtection(false);
    final third = controller.setWebRtcProtection(false);
    await _waitUntil(() => store.securityWrites.isNotEmpty);
    expect(store.securityWrites, hasLength(1));
    expect(controller.isConnectionBusy, isTrue);
    expect(controller.killSwitchEnabled, isTrue);
    store.securityGate!.complete();
    await Future.wait([first, second, third]);
    expect(store.securityWrites.last.toStorageValue(), 'v3|0|0|0|1');
    expect(controller.killSwitchEnabled, isFalse);
    expect(controller.dnsProtectionEnabled, isFalse);
    expect(controller.webRtcProtectionEnabled, isFalse);
    expect(controller.isConnectionBusy, isFalse);
  });

  test('disposed controllers neither commit nor start queued writes', () async {
    final store = _Store()..securityGate = Completer<void>();
    final wg = _WireGuard();
    final controller = _controller(store: store, wg: wg);
    final first = controller.setKillSwitch(false);
    final second = controller.setDnsProtection(false);
    await _waitUntil(() => store.securityWrites.isNotEmpty);
    controller.dispose();
    store.securityGate!.complete();
    await Future.wait([first, second]);
    await controller.setWebRtcProtection(false);
    expect(store.securityWrites, hasLength(1));
    expect(controller.killSwitchEnabled, isTrue);
    expect(wg.options['killSwitch'], isTrue);
  });

  test(
    'queued protection changes do not modify a newly active tunnel',
    () async {
      final store = _Store()..securityGate = Completer<void>();
      final wg = _WireGuard();
      final controller = _controller(store: store, wg: wg);
      addTearDown(controller.dispose);
      final first = controller.setKillSwitch(false);
      final second = controller.setDnsProtection(false);
      await _waitUntil(() => store.securityWrites.isNotEmpty);
      // Native state can change independently of this window's command queue.
      controller.vpnStatus = VpnStatus.connected;
      controller.activeProtocol = VpnProtocol.wireGuard;
      store.securityGate!.complete();
      await Future.wait([first, second]);
      expect(store.securityWrites, hasLength(1));
      expect(controller.killSwitchEnabled, isTrue);
      expect(controller.dnsProtectionEnabled, isTrue);
      expect(wg.options['killSwitch'], isTrue);
      expect(controller.isConnectionBusy, isFalse);
    },
  );

  test(
    'latest device snapshot wins when requests finish out of order',
    () async {
      final older = Completer<DeviceList>();
      final newer = Completer<DeviceList>();
      final api = _Api()..deviceGates.addAll([older, newer]);
      final controller = _controller(api: api);
      addTearDown(controller.dispose);
      final first = controller.refreshDevices();
      await _waitUntil(() => api.deviceCalls == 1);
      final second = controller.refreshDevices();
      await _waitUntil(() => api.deviceCalls == 2);
      newer.complete(const DeviceList(limit: 5, devices: [fixture.device]));
      await second;
      older.complete(const DeviceList(limit: 1, devices: []));
      await first;
      expect(controller.currentDeviceId, fixture.device.deviceId);
      expect(controller.deviceLimit, 5);
      expect(controller.devices, [fixture.device]);
      expect(controller.isLoadingDevices, isFalse);
    },
  );

  for (final protocol in VpnProtocol.values) {
    test('pre-enrollment GET cannot erase $protocol device binding', () async {
      final older = Completer<DeviceList>();
      final store = _Store()..binding = null;
      final api = _Api()..deviceGates.add(older);
      final controller = _controller(api: api, store: store)
        ..vpnProtocol = protocol
        ..protocolPreference = protocol == VpnProtocol.wireGuard
            ? VpnProtocolPreference.wireGuard
            : VpnProtocolPreference.openVpn;
      addTearDown(controller.dispose);
      final refreshing = controller.refreshDevices();
      await _waitUntil(() => api.deviceCalls == 1);
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.connected);
      older.complete(const DeviceList(limit: 2, devices: []));
      await refreshing;
      expect(controller.currentDeviceId, fixture.device.deviceId);
      expect(store.binding, fixture.device.deviceId);
      expect(controller.realDeviceLocation, _source);
      expect(store.bindingClears, 0);
      expect(controller.isLoadingDevices, isFalse);
    });
  }

  test('pre-revocation GET cannot resurrect a removed device', () async {
    const other = VpnDevice(
      deviceId: 'other-device',
      name: 'Other',
      location: fixture.source,
      createdAt: null,
    );
    final older = Completer<DeviceList>();
    final api = _Api()
      ..accountDevices = [fixture.device, other]
      ..deviceGates.add(older);
    final controller = _controller(api: api);
    addTearDown(controller.dispose);
    final refreshing = controller.refreshDevices();
    await _waitUntil(() => api.deviceCalls == 1);
    expect(
      await controller.revokeDevice(other),
      DeviceRevocationResult.revoked,
    );
    older.complete(
      const DeviceList(limit: 2, devices: [fixture.device, other]),
    );
    await refreshing;
    expect(controller.devices, [fixture.device]);
    expect(controller.currentDeviceId, fixture.device.deviceId);
    expect(controller.isLoadingDevices, isFalse);
  });

  test(
    'pre-revocation GET cannot restore this device after native cleanup',
    () async {
      final older = Completer<DeviceList>();
      final api = _Api()..deviceGates.add(older);
      final store = _Store();
      final wg = _WireGuard()
        ..connected = true
        ..protectionActive = true;
      final controller = _controller(api: api, store: store, wg: wg)
        ..vpnStatus = VpnStatus.connected
        ..activeProtocol = VpnProtocol.wireGuard;
      addTearDown(controller.dispose);
      final refreshing = controller.refreshDevices();
      await _waitUntil(() => api.deviceCalls == 1);
      expect(
        await controller.revokeDevice(fixture.device),
        DeviceRevocationResult.revoked,
      );
      older.complete(const DeviceList(limit: 2, devices: [fixture.device]));
      await refreshing;
      expect(controller.devices, isEmpty);
      expect(controller.currentDeviceId, isNull);
      expect(store.binding, isNull);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(wg.connected, isFalse);
      expect(wg.disconnectCalls, 1);
    },
  );

  test('pre-migration GET cannot clear an accepted migration', () async {
    final older = Completer<DeviceList>();
    final api = _Api()..deviceGates.add(older);
    final controller = _controller(api: api)
      ..pendingTargetLocation = fixture.target;
    addTearDown(controller.dispose);
    final refreshing = controller.refreshDevices();
    await _waitUntil(() => api.deviceCalls == 1);
    await controller.startPreparedLocationMigration();
    expect(controller.locationMigration?.migrationId, 'audit-migration');
    older.complete(const DeviceList(limit: 2, devices: []));
    await refreshing;
    expect(controller.currentDeviceId, fixture.device.deviceId);
    expect(controller.locationMigration?.migrationId, 'audit-migration');
    expect(controller.pendingTargetLocation, fixture.target);
  });

  test(
    'snapshot from before ready commit cannot restore the old location',
    () async {
      final older = Completer<DeviceList>();
      final api = _Api()..migrationStatus = LocationMigrationStatus.ready;
      final store = _Store()..selectionGate = Completer<void>();
      final controller = _controller(api: api, store: store)
        ..pendingTargetLocation = fixture.target;
      addTearDown(controller.dispose);
      final migrating = controller.startPreparedLocationMigration();
      await _waitUntil(() => store.selectionWriteStarted);
      // The final location commit has not happened yet. This GET starts after
      // the migration's own refresh, so a request counter alone cannot reject it.
      api.deviceGates.add(older);
      final refreshing = controller.refreshDevices();
      await _waitUntil(() => api.deviceCalls == 2);
      store.selectionGate!.complete();
      await migrating;
      older.complete(const DeviceList(limit: 2, devices: [fixture.device]));
      await refreshing;
      expect(controller.realDeviceLocation, fixture.target);
      expect(controller.selectedLocation, fixture.target);
      expect(controller.locationMigration, isNull);
      expect(controller.currentDeviceId, fixture.device.deviceId);
    },
  );

  test(
    'confirmed missing device still clears its binding and migration',
    () async {
      final store = _Store();
      final api = _Api()..accountDevices = [];
      final controller = _controller(api: api, store: store);
      addTearDown(controller.dispose);
      await controller.refreshDevices();
      expect(controller.currentDeviceId, isNull);
      expect(controller.realDeviceLocation, isNull);
      expect(store.bindingClears, 1);
      expect(store.migrationClears, 1);
      expect(controller.devicesReachable, isTrue);
    },
  );

  test('mutation during token read releases the loading state', () async {
    final older = Completer<DeviceList>();
    final api = _Api()..deviceGates.add(older);
    final store = _Store();
    final controller = _controller(api: api, store: store);
    addTearDown(controller.dispose);
    final first = controller.refreshDevices();
    await _waitUntil(() => api.deviceCalls == 1);
    store.tokenGate = Completer<String?>();
    final second = controller.refreshDevices();
    controller.currentDeviceId = 'new-device';
    store.tokenGate!.complete('audit-synthetic-token');
    await second;
    expect(controller.isLoadingDevices, isFalse);
    older.complete(const DeviceList(limit: 2, devices: []));
    await first;
    expect(controller.currentDeviceId, 'new-device');
    expect(api.deviceCalls, 1);
  });
}

Future<void> _change(AppController controller, String name) => switch (name) {
  'killSwitch' => controller.setKillSwitch(false),
  'dnsProtection' => controller.setDnsProtection(false),
  _ => controller.setWebRtcProtection(false),
};

bool _protection(AppController controller, String name) => switch (name) {
  'killSwitch' => controller.killSwitchEnabled,
  'dnsProtection' => controller.dnsProtectionEnabled,
  _ => controller.webRtcProtectionEnabled,
};

Future<void> _waitUntil(bool Function() ready) async {
  for (var i = 0; i < 100 && !ready(); i++) {
    await Future<void>.delayed(Duration.zero);
  }
  expect(ready(), isTrue);
}

AppController _controller({
  _Api? api,
  _Store? store,
  _WireGuard? wg,
  _OpenVpn? ovpn,
}) {
  final actualApi = api ?? _Api();
  final actualStore = store ?? _Store();
  return AppController(
      api: actualApi,
      store: actualStore,
      wireguard: wg ?? _WireGuard(),
      openVpn: ovpn ?? _OpenVpn(),
      window: fixture.ProbeWindow(),
    )
    ..profile = fixture.account
    ..locations = [_source, fixture.target]
    ..selectedLocation = _source
    ..currentDeviceId = actualStore.binding
    ..devices = [...actualApi.accountDevices]
    ..realDeviceLocation = actualStore.binding == null ? null : fixture.source
    ..openVpnRuntimeAvailable = true
    ..isInitialized = true
    ..isLoadingLocations = false;
}

class _Store extends fixture.ProbeStore {
  Completer<void>? securityGate;
  Completer<String?>? tokenGate;
  bool failSecurityWrite = false;
  final securityWrites = <SecuritySettings>[];
  String? binding = fixture.device.deviceId;
  int bindingClears = 0;
  int migrationClears = 0;
  StoredLocationMigration? marker;

  @override
  Future<void> saveSecuritySettings(SecuritySettings value) async {
    securityWrites.add(value);
    await securityGate?.future;
    if (failSecurityWrite) throw PlatformException(code: 'storage_io_error');
  }

  @override
  Future<String?> token() async =>
      tokenGate == null ? super.token() : tokenGate!.future;
  @override
  Future<String?> currentDeviceId() async => binding;
  @override
  Future<void> saveCurrentDeviceId(String value) async => binding = value;
  @override
  Future<void> clearCurrentDeviceId() async {
    bindingClears++;
    binding = null;
  }

  @override
  Future<void> saveLocationMigration(StoredLocationMigration value) async =>
      marker = value;
  @override
  Future<void> clearLocationMigration() async {
    migrationClears++;
    marker = null;
  }
}

class _Api extends fixture.ProbeApi {
  List<VpnDevice> accountDevices = [fixture.device];
  LocationMigrationStatus migrationStatus = LocationMigrationStatus.draining;
  final deviceGates = <Completer<DeviceList>>[];
  int deviceCalls = 0;
  @override
  Future<DeviceList> devices(String token) async {
    deviceCalls++;
    if (deviceGates.isNotEmpty) return deviceGates.removeAt(0).future;
    return DeviceList(limit: 2, devices: [...accountDevices]);
  }

  @override
  Future<void> revokeDevice({
    required String token,
    required String deviceId,
  }) async {
    accountDevices = accountDevices
        .where((d) => d.deviceId != deviceId)
        .toList();
  }

  @override
  Future<LocationMigration> startLocationMigration({
    required String token,
    required String deviceId,
    required String locationId,
  }) async {
    if (migrationStatus == LocationMigrationStatus.ready) {
      accountDevices = [
        VpnDevice(
          deviceId: deviceId,
          name: 'Audit',
          location: fixture.target,
          createdAt: null,
        ),
      ];
    }
    return LocationMigration(
      migrationId: 'audit-migration',
      deviceId: deviceId,
      sourceLocationId: fixture.source.id,
      targetLocationId: locationId,
      status: migrationStatus,
      retryAfterSeconds: 60,
    );
  }
}

class _WireGuard extends fixture.ProbeWireGuard {
  Map<String, bool> options = {
    'killSwitch': true,
    'dnsProtection': true,
    'webRtcProtection': true,
  };
  Map<String, bool>? connectedOptions;
  @override
  void configureNetworkProtection({
    required bool killSwitch,
    required bool dnsProtection,
    required bool webRtcProtection,
  }) {
    options = {
      'killSwitch': killSwitch,
      'dnsProtection': dnsProtection,
      'webRtcProtection': webRtcProtection,
    };
    super.configureNetworkProtection(
      killSwitch: killSwitch,
      dnsProtection: dnsProtection,
      webRtcProtection: webRtcProtection,
    );
  }

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectedOptions = {...options};
    appliedKillSwitch = options['killSwitch']!;
    await super.connect(configuration);
  }
}

class _OpenVpn extends fixture.ProbeOpenVpn {
  int prepareCalls = 0;
  Map<String, bool> options = {
    'killSwitch': true,
    'dnsProtection': true,
    'webRtcProtection': true,
  };
  Map<String, bool>? connectedOptions;
  @override
  void configureNetworkProtection({
    required bool killSwitch,
    required bool dnsProtection,
    required bool webRtcProtection,
  }) {
    options = {
      'killSwitch': killSwitch,
      'dnsProtection': dnsProtection,
      'webRtcProtection': webRtcProtection,
    };
    super.configureNetworkProtection(
      killSwitch: killSwitch,
      dnsProtection: dnsProtection,
      webRtcProtection: webRtcProtection,
    );
  }

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    protectionActive = true;
  }

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    connectedOptions = {...options};
    appliedKillSwitch = options['killSwitch']!;
    await super.importAndConnect(activation);
  }
}
