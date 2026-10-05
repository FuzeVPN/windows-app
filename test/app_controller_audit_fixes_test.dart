// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/connection_state_machine.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';

import 'location_migration_test.dart' as fixture;

const _device = VpnDevice(
  deviceId: 'device-1',
  name: 'Test Windows',
  location: fixture.frankfurt1,
  createdAt: null,
);
const _marker = StoredLocationMigration(
  migrationId: 'migration-1',
  deviceId: 'device-1',
  targetLocationId: 'frankfurt-02',
  userId: 'user-1',
);

LocationMigration _migration(String status) => LocationMigration.fromJson({
  'migration_id': 'migration-1',
  'device_id': 'device-1',
  'source_location_id': 'frankfurt-01',
  'target_location_id': 'frankfurt-02',
  'status': status,
  'retry_after_seconds': 1,
}, expectedDeviceId: 'device-1');

AppController _controller({
  _Api? api,
  _Store? store,
  _WireGuard? wireguard,
  _OpenVpn? openVpn,
  DateTime Function()? now,
}) {
  final controller =
      AppController(
          api: api ?? _Api(),
          store: store ?? _Store(),
          wireguard: wireguard ?? _WireGuard(),
          openVpn: openVpn ?? _OpenVpn(),
          now: now,
        )
        ..profile = fixture.testProfile
        ..locations = const [fixture.frankfurt1, fixture.frankfurt2]
        ..selectedLocation = fixture.frankfurt1
        ..currentDeviceId = _device.deviceId
        ..devices = const [_device]
        ..realDeviceLocation = fixture.frankfurt1
        ..openVpnRuntimeAvailable = true
        ..isLoadingLocations = false;
  addTearDown(controller.dispose);
  return controller;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('F03 rejected begin does not leave an orphan operation', () {
    final machine = VpnConnectionStateMachine()
      ..restore(VpnStatus.disconnecting);
    expect(() => machine.begin(VpnStatus.preparing), throwsStateError);
    expect(machine.isBusy, isFalse);
    final operation = machine.begin(VpnStatus.disconnected);
    machine.finish(operation);
    expect(machine.isBusy, isFalse);
  });

  test(
    'F03 current-device deletion excludes Connect until cleanup finishes',
    () async {
      final api = _Api()..revokeGate = Completer<void>();
      final native = _WireGuard()..resetGate = Completer<void>();
      final controller = _controller(api: api, wireguard: native);
      final revocation = controller.revokeDevice(_device);
      expect(controller.isConnectionBusy, isTrue);
      await controller.quickConnect();
      expect(api.registerLocations, isEmpty);
      api.revokeGate!.complete();
      await native.resetStarted.future;
      await controller.quickConnect();
      expect(api.registerLocations, isEmpty);
      native.resetGate!.complete();
      expect(await revocation, DeviceRevocationResult.revoked);
      expect(controller.isConnectionBusy, isFalse);
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(api.registerLocations, ['frankfurt-01']);
    },
  );

  test('F08 absent or invalid devices must not mean an empty account', () {
    for (final value in <Map<String, dynamic>>[
      {},
      {'devices': null},
      {'devices': {}},
      {'devices': [], 'limit': 1.5},
      {'devices': [], 'limit': 0},
      {
        'devices': [{}],
      },
    ]) {
      expect(() => DeviceList.fromJson(value), throwsFormatException);
    }
    expect(DeviceList.fromJson({'devices': []}).devices, isEmpty);
    final extensions = DeviceList.fromJson({
      'devices': [
        {'device_id': 'extension-1', 'location': null},
      ],
    });
    expect(extensions.devices.single.location, isNull);
  });

  test(
    'F08 malformed device response preserves local identity and migration',
    () async {
      final store = _Store()..marker = _marker;
      final api = _Api()..invalidDevices = true;
      final controller = _controller(api: api, store: store);
      await controller.refreshDevices();
      expect(controller.devicesReachable, isFalse);
      expect(controller.currentDeviceId, _device.deviceId);
      expect(store.marker, same(_marker));
      expect(controller.devices.single.deviceId, _device.deviceId);
    },
  );

  test(
    'F09 connect keeps its captured destination during refresh and selection',
    () async {
      final api = _Api()..registerGate = Completer<void>();
      final controller = _controller(api: api);
      final connect = controller.quickConnect();
      await api.registerStarted.future;
      expect(
        await controller.prepareLocationChange(fixture.frankfurt2),
        LocationChangePreparation.unavailable,
      );
      await controller.selectLocation(fixture.frankfurt2);
      api.catalog = [fixture.frankfurt2];
      await controller.refreshLocations();
      expect(controller.selectedLocation, isNull);
      api.registerGate!.complete();
      await connect;
      expect(api.registerLocations, ['frankfurt-01']);
      expect(controller.tunnelLocationId, 'frankfurt-01');
      expect(controller.realDeviceLocation?.id, 'frankfurt-01');
    },
  );

  for (final failure in ['selection', 'marker']) {
    test('F10 ready migration retries failed $failure persistence', () async {
      final store = _Store()..marker = _marker;
      final api = _Api()..pollResults = [_migration('ready')];
      final controller = _controller(api: api, store: store);
      if (failure == 'selection') {
        store.failPreference = true;
      } else {
        store.failMarkerClear = true;
      }
      await controller.resumeLocationMigration();
      expect(controller.isLocationMigrationActive, isTrue);
      expect(
        controller.locationMigrationError,
        contains('confirmation locale'),
      );
      expect(store.marker, same(_marker));
      expect(controller.selectedLocation?.id, 'frankfurt-01');
      store
        ..failPreference = false
        ..failMarkerClear = false;
      await controller.pollLocationMigrationNow();
      expect(controller.isLocationMigrationActive, isFalse);
      expect(controller.locationMigrationError, isNull);
      expect(controller.selectedLocation?.id, 'frankfurt-02');
      expect(store.marker, isNull);
    });
  }

  test(
    'F10 ready resume inside Connect uses its owning operation and reconnects',
    () async {
      final api = _Api()..pollResults = [_migration('ready')];
      final store = _Store()..marker = _marker;
      final native = _OpenVpn();
      final controller = _controller(api: api, store: store, openVpn: native)
        ..selectedLocation = fixture.frankfurt2
        ..vpnProtocol = VpnProtocol.openVpn
        ..protocolPreference = VpnProtocolPreference.openVpn;
      await controller.quickConnect();
      expect(controller.isConnectionBusy, isFalse);
      expect(controller.locationMigration, isNull);
      expect(native.importCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.tunnelLocationId, 'frankfurt-02');
    },
  );

  test('F10 polling ready waits for the existing connection command', () async {
    final api = _Api()
      ..registerGate = Completer<void>()
      ..pollResults = [_migration('ready')];
    final store = _Store()..marker = _marker;
    final controller = _controller(api: api, store: store);
    final connect = controller.quickConnect();
    await api.registerStarted.future;
    controller.locationMigration = _migration('activating');
    final poll = controller.pollLocationMigrationNow();
    await Future<void>.delayed(Duration.zero);
    expect(controller.selectedLocation?.id, 'frankfurt-01');
    api.registerGate!.complete();
    await connect;
    await poll;
    expect(controller.locationMigration, isNull);
    expect(controller.selectedLocation?.id, 'frankfurt-02');
    expect(controller.tunnelLocationId, 'frankfurt-01');
  });

  for (final status in [408, 429, 503]) {
    testWidgets('F11 migration GET retries HTTP $status automatically', (
      tester,
    ) async {
      final api = _Api()
        ..pollError = ApiException(
          statusCode: status,
          errorCode: 'temporary_error',
          retryAfterSeconds: 1,
        )
        ..pollResults = [_migration('ready')];
      final store = _Store()..marker = _marker;
      final controller = _controller(api: api, store: store)
        ..locationMigration = _migration('activating');
      await controller.pollLocationMigrationNow();
      expect(controller.locationMigration, isNotNull);
      expect(store.marker, same(_marker));
      await tester.pump(const Duration(seconds: 1));
      await tester.pump();
      expect(api.pollCalls, 2);
      expect(controller.locationMigration, isNull);
      expect(controller.selectedLocation?.id, 'frankfurt-02');
    });
  }

  test('F14 refreshed locations replace stale capability metadata', () async {
    const replacement = Location(
      id: 'frankfurt-01',
      city: 'Frankfurt',
      countryCode: 'DE',
      displayName: 'Renamed',
      supportedProtocols: {VpnProtocol.openVpn},
    );
    final api = _Api()..catalog = [replacement];
    final controller = _controller(api: api);
    await controller.refreshLocations();
    expect(controller.selectedLocation, same(replacement));
    await controller.quickConnect();
    expect(api.registerLocations, isEmpty);
    expect(controller.errorMessage, contains('compatible'));
    api.catalog = [fixture.frankfurt2];
    await controller.refreshLocations();
    await controller.refreshLocations();
    await controller.quickConnect();
    expect(controller.selectedLocation, isNull);
    expect(api.registerLocations, isEmpty);
    expect(controller.errorMessage, contains('plus disponible'));
  });

  test(
    'F24 failed ordinary preferences preserve the last committed values',
    () async {
      final store = _Store()..failPreference = true;
      final controller = _controller(store: store);
      await controller.setTheme(ThemeMode.dark);
      expect(controller.themeMode, ThemeMode.light);
      await controller.setLanguage(AppLanguage.english);
      expect(controller.language, AppLanguage.system);
      await controller.setProtocolPreference(VpnProtocolPreference.openVpn);
      expect(controller.protocolPreference, VpnProtocolPreference.wireGuard);
      await controller.selectLocation(fixture.frankfurt2);
      expect(controller.selectedLocation, fixture.frankfurt1);
      expect(controller.experienceSettingsError, isNotNull);
      expect(controller.isConnectionBusy, isFalse);
      store.failPreference = false;
      await controller.setTheme(ThemeMode.dark);
      expect(controller.themeMode, ThemeMode.dark);
      expect(controller.experienceSettingsError, isNull);
    },
  );

  test(
    'H05 repeated status failures become unconfirmed and later recover',
    () async {
      final native = _WireGuard()
        ..connected = true
        ..failStatus = true;
      final controller = _controller(wireguard: native)
        ..vpnStatus = VpnStatus.connected
        ..activeProtocol = VpnProtocol.wireGuard
        ..tunnelLocationId = 'frankfurt-01';
      await controller.checkTunnelHealthNow();
      await controller.checkTunnelHealthNow();
      expect(controller.vpnStatus, VpnStatus.connected);
      await controller.checkTunnelHealthNow();
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.requiresExplicitDisconnect, isTrue);
      expect(controller.errorMessage, contains('confirmé'));
      native.failStatus = false;
      await controller.checkTunnelHealthNow();
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.errorMessage, isNull);
      expect(controller.tunnelLocationId, 'frankfurt-01');
    },
  );

  test('F26 connection duration ignores subsequent civil clock jumps', () {
    var now = DateTime.utc(2026, 9, 12);
    final controller = _controller(now: () => now)..connectedAt = now;
    now = now.add(const Duration(days: 7));
    expect(controller.connectedDuration.inSeconds, lessThan(2));
    now = now.subtract(const Duration(days: 14));
    expect(controller.connectedDuration.isNegative, isFalse);
    controller.connectedAt = null;
    expect(controller.connectedDuration, Duration.zero);
  });

  test(
    'OpenVPN cleanup failure retains an explicit retry until cleanup succeeds',
    () async {
      final native = _OpenVpn()
        ..protectionActive = true
        ..disconnectFailureCode = 'openvpn_cleanup_failed';
      final controller = _controller(openVpn: native)
        ..vpnStatus = VpnStatus.blocked
        ..vpnProtocol = VpnProtocol.openVpn
        ..activeProtocol = VpnProtocol.openVpn;
      await controller.quickConnect();
      expect(controller.requiresExplicitDisconnect, isTrue);
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(native.protectionActive, isTrue);
      expect(controller.errorMessage, contains('nettoyage du tunnel OpenVPN'));
      expect(controller.errorMessage, contains('Réessayez la déconnexion'));
      native.disconnectFailureCode = null;
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.requiresExplicitDisconnect, isFalse);
      expect(native.protectionActive, isFalse);
    },
  );

  for (final entry in {
    'openvpn_dns_configuration_failed': 'configurer le DNS du tunnel OpenVPN',
    'openvpn_network_configuration_failed':
        'finaliser la configuration réseau du tunnel OpenVPN',
    'openvpn_cleanup_failed': 'nettoyage du tunnel OpenVPN',
    'openvpn_driver_restart_required': 'redémarrage de Windows',
    'installation_required': 'dossier protégé',
  }.entries) {
    test(
      'retained protection preserves the actionable ${entry.key} diagnostic',
      () async {
        final native = _OpenVpn()..connectFailureCode = entry.key;
        final controller = _controller(openVpn: native)
          ..vpnProtocol = VpnProtocol.openVpn
          ..protocolPreference = VpnProtocolPreference.openVpn;
        await controller.quickConnect();
        expect(controller.vpnStatus, VpnStatus.blocked);
        expect(controller.requiresExplicitDisconnect, isTrue);
        expect(native.protectionActive, isTrue);
        expect(controller.errorMessage, contains(entry.value));
      },
    );
  }

  group('F12 atomic migration persistence', () {
    const channel = MethodChannel('com.fuzevpn/windows_secure_store');
    late Map<String, String> disk;
    var failWrite = false;
    var failDelete = false;
    var failSecurityRead = false;
    late List<MethodCall> calls;
    setUp(() {
      disk = {
        'location_migration_id': 'legacy-1',
        'location_migration_device_id': 'device-1',
        'location_migration_target_location_id': 'frankfurt-01',
        'location_migration_user_id': 'user-1',
      };
      calls = [];
      failWrite = failDelete = failSecurityRead = false;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            final key = call.arguments['key'] as String;
            if (call.method == 'read') {
              if (key == 'security_settings' && failSecurityRead) {
                throw PlatformException(code: 'storage_corrupt');
              }
              return disk[key];
            }
            if (call.method == 'write') {
              if (failWrite) throw PlatformException(code: 'storage_io_error');
              disk[key] = call.arguments['value'] as String;
            }
            if (call.method == 'delete') {
              if (failDelete) {
                throw PlatformException(code: 'storage_access_denied');
              }
              disk.remove(key);
            }
            return null;
          });
    });
    tearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    test(
      'reads complete legacy records and commits a single new record',
      () async {
        final store = SecureStore();
        expect((await store.locationMigration())?.migrationId, 'legacy-1');
        await store.saveLocationMigration(_marker);
        expect(calls.where((call) => call.method == 'write').length, 1);
        expect(jsonDecode(disk['location_migration_state']!)['version'], 1);
        expect((await store.locationMigration())?.migrationId, 'migration-1');
      },
    );

    test('failed replacement preserves the complete previous record', () async {
      final store = SecureStore();
      await store.saveLocationMigration(_marker);
      failWrite = true;
      await expectLater(
        store.saveLocationMigration(
          const StoredLocationMigration(
            migrationId: 'new-2',
            deviceId: 'device-2',
            targetLocationId: 'other',
            userId: 'other',
          ),
        ),
        throwsA(isA<PlatformException>()),
      );
      final recovered = await store.locationMigration();
      expect(recovered?.migrationId, 'migration-1');
      expect(recovered?.deviceId, 'device-1');
      expect(recovered?.userId, 'user-1');
    });

    test(
      'tombstone prevents legacy resurrection after partial deletion',
      () async {
        final store = SecureStore();
        failDelete = true;
        await store.clearLocationMigration();
        expect(disk['location_migration_id'], 'legacy-1');
        expect(await store.locationMigration(), isNull);
      },
    );

    test(
      'an unreadable security record never falls back or overwrites it',
      () async {
        disk['kill_switch'] = 'false';
        failSecurityRead = true;
        await expectLater(
          SecureStore().securitySettings(),
          throwsA(isA<PlatformException>()),
        );
        expect(calls.any((call) => call.method == 'write'), isFalse);
        expect(
          calls.any((call) => call.arguments['key'] == 'kill_switch'),
          isFalse,
        );
      },
    );
  });
}

class _Api extends fixture.MigrationApi {
  _Api() : super(device: _device);
  List<Location> catalog = [fixture.frankfurt1, fixture.frankfurt2];
  bool invalidDevices = false;
  Completer<void>? revokeGate;
  Completer<void>? registerGate;
  final registerStarted = Completer<void>();
  final List<String> registerLocations = [];
  ApiException? pollError;
  @override
  Future<List<Location>> locations() async => catalog;
  @override
  Future<DeviceList> devices(String token) async =>
      invalidDevices ? DeviceList.fromJson({}) : super.devices(token);
  @override
  Future<void> revokeDevice({
    required String token,
    required String deviceId,
  }) async {
    await revokeGate?.future;
    device = null;
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registerLocations.add(locationId);
    if (!registerStarted.isCompleted) registerStarted.complete();
    await registerGate?.future;
    device = _device;
    return super.registerDevice(
      token: token,
      name: name,
      publicKey: publicKey,
      locationId: locationId,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<LocationMigration> getLocationMigration({
    required String token,
    required String deviceId,
    required String migrationId,
  }) async {
    final failure = pollError;
    pollError = null;
    if (failure != null) {
      pollCalls++;
      throw failure;
    }
    return super.getLocationMigration(
      token: token,
      deviceId: deviceId,
      migrationId: migrationId,
    );
  }
}

class _Store extends fixture.MigrationStore {
  bool failPreference = false;
  bool failMarkerClear = false;
  Future<void> _save() async {
    if (failPreference) throw PlatformException(code: 'storage_io_error');
  }

  @override
  Future<void> saveSelectedLocation(String value) => _save();
  @override
  Future<void> saveThemeMode(String value) => _save();
  @override
  Future<void> saveAppLanguage(String value) => _save();
  @override
  Future<void> saveVpnProtocol(String value) => _save();
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async {}
  @override
  Future<void> clearLocationMigration() async {
    if (failMarkerClear) throw PlatformException(code: 'storage_io_error');
    await super.clearLocationMigration();
  }
}

class _WireGuard extends fixture.MigrationWireGuard {
  Completer<void>? resetGate;
  final resetStarted = Completer<void>();
  bool failStatus = false;
  @override
  Future<void> resetIdentity() async {
    if (!resetStarted.isCompleted) resetStarted.complete();
    await resetGate?.future;
    await super.resetIdentity();
  }

  @override
  Future<bool> isConnected() async {
    if (failStatus) throw PlatformException(code: 'broker_unavailable');
    return connected;
  }
}

class _OpenVpn extends fixture.MigrationOpenVpn {
  String? disconnectFailureCode;
  String? connectFailureCode;
  @override
  Future<void> disconnect() async {
    if (disconnectFailureCode case final code?) {
      throw PlatformException(code: code);
    }
    await super.disconnect();
  }

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    if (connectFailureCode case final code?) {
      throw PlatformException(code: code);
    }
    await super.importAndConnect(activation);
  }

  @override
  Future<void> deleteProfile() async {}
}
