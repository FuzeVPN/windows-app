// SPDX-License-Identifier: MPL-2.0
// Behavioral regressions promoted from the Windows audit.
// All API, storage and native tunnel interactions below use local doubles.
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';

import 'automatic_protocol_test.dart' as automatic;
import 'location_migration_test.dart' as migration;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'AUDIT: sign-out preserves the actual network lock after native failure',
    () async {
      final store = _AuditStore();
      final wireGuard = automatic.AutomaticWireGuard()
        ..connected = true
        ..protectionActive = true
        ..failDisconnect = true;
      final controller =
          AppController(
              api: _AuditApi(),
              store: store,
              wireguard: wireGuard,
              openVpn: _AuditOpenVpn(),
              window: _AuditWindow(),
            )
            ..profile = migration.testProfile
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.wireGuard;
      addTearDown(controller.dispose);

      await controller.signOut();

      expect(store.storedToken, isNull);
      expect(wireGuard.connected, isTrue);
      expect(wireGuard.protectionActive, isTrue);
      expect(
        controller.requiresExplicitDisconnect,
        isTrue,
        reason:
            'The still-active tunnel and lock require a visible stop action.',
      );
    },
  );

  test(
    'AUDIT: incompatible quick connect finishes in a terminal UI state',
    () async {
      const incompatible = Location(
        id: 'openvpn-only',
        city: 'Test',
        countryCode: 'DE',
        displayName: 'OpenVPN only',
        supportedProtocols: {VpnProtocol.openVpn},
      );
      final controller =
          AppController(
              api: _AuditApi(),
              store: _AuditStore(),
              wireguard: automatic.AutomaticWireGuard(),
              openVpn: _AuditOpenVpn(),
              window: _AuditWindow(),
            )
            ..profile = migration.testProfile
            ..selectedLocation = incompatible
            ..locations = [incompatible]
            ..protocolPreference = VpnProtocolPreference.wireGuard;
      addTearDown(controller.dispose);

      await controller.quickConnect();

      expect(controller.isConnectionBusy, isFalse);
      expect(controller.errorMessage, contains('compatible'));
      expect(
        controller.vpnStatus,
        isIn([VpnStatus.disconnected, VpnStatus.error]),
        reason: 'No operation remains that could finish preparing.',
      );
    },
  );

  test(
    'AUDIT: immediate ready migration keeps an established OpenVPN connected',
    () async {
      final source = _device(migration.frankfurt1);
      final api = _AuditApi(device: source)
        ..startResult = const LocationMigration(
          migrationId: 'migration-1',
          deviceId: 'device-1',
          sourceLocationId: 'frankfurt-01',
          targetLocationId: 'frankfurt-02',
          status: LocationMigrationStatus.ready,
          retryAfterSeconds: 2,
        )
        ..deviceAfterStart = _device(migration.frankfurt2);
      final openVpn = migration.MigrationOpenVpn();
      final controller =
          AppController(
              api: api,
              store: _AuditStore(),
              wireguard: automatic.AutomaticWireGuard(),
              openVpn: openVpn,
              window: _AuditWindow(),
            )
            ..profile = migration.testProfile
            ..locations = [migration.frankfurt1, migration.frankfurt2]
            ..selectedLocation = migration.frankfurt1
            ..currentDeviceId = source.deviceId
            ..devices = [source]
            ..realDeviceLocation = source.location
            ..openVpnRuntimeAvailable = true
            ..protocolPreference = VpnProtocolPreference.openVpn
            ..vpnProtocol = VpnProtocol.openVpn;
      addTearDown(controller.dispose);

      await controller.prepareLocationChange(migration.frankfurt2);
      await controller.toggleConnection();

      expect(api.startCalls, 1);
      expect(openVpn.importCalls, 1);
      expect(openVpn.connected, isTrue);
      expect(controller.activeProtocol, VpnProtocol.openVpn);
      expect(
        controller.vpnStatus,
        VpnStatus.connected,
        reason:
            'The completed location check must not overwrite native success.',
      );
    },
  );

  test(
    'AUDIT: a temporary offline profile request retains the saved session',
    () async {
      final store = _AuditStore();
      final controller = AppController(
        api: _AuditApi()..offlineProfile = true,
        store: store,
        wireguard: automatic.AutomaticWireGuard(),
        openVpn: _AuditOpenVpn(),
        window: _AuditWindow(),
      );
      addTearDown(controller.dispose);

      await controller.initialize();

      expect(controller.profile, isNull);
      expect(
        store.storedToken,
        'audit-session',
        reason: 'Network failure is not an authentication rejection.',
      );
    },
  );

  testWidgets(
    'AUDIT: native interruption retains intent when network returns',
    (tester) async {
      var now = DateTime.utc(2026, 9, 8);
      final window = _AuditWindow();
      final wireGuard = automatic.AutomaticWireGuard()..connected = true;
      final controller = AppController(
        api: _AuditApi(),
        store: _AuditStore(),
        wireguard: wireGuard,
        openVpn: _AuditOpenVpn(),
        window: window,
        now: () => now,
      );
      try {
        await controller.initialize();
        expect(controller.vpnStatus, VpnStatus.connected);
        // A genuine drop also ends the startup suppression interval.
        now = now.add(const Duration(seconds: 1));

        wireGuard.connected = false;
        await tester.pump(const Duration(seconds: 4));
        await tester.pump(const Duration(seconds: 4));
        await tester.pump();
        expect(controller.vpnStatus, VpnStatus.disconnected);

        await window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await tester.pump();

        expect(
          wireGuard.connectCalls,
          1,
          reason:
              'Automatic reconnect remains enabled after an involuntary drop.',
        );
        expect(controller.vpnStatus, VpnStatus.connected);
      } finally {
        controller.dispose();
      }
    },
  );

  test(
    'sign-out keeps a blocked tunnel stoppable without authentication',
    () async {
      final wireGuard = _CachedWireGuard()
        ..protectionActive = true
        ..failDisconnect = true;
      final controller =
          AppController(
              api: _AuditApi(),
              store: _AuditStore(),
              wireguard: wireGuard,
              openVpn: _AuditOpenVpn(),
              window: _AuditWindow(),
            )
            ..profile = migration.testProfile
            ..vpnStatus = VpnStatus.blocked;
      addTearDown(controller.dispose);

      await controller.signOut();
      expect(controller.profile, isNull);
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(controller.requiresExplicitDisconnect, isTrue);

      wireGuard.failDisconnect = false;
      await controller.quickConnect();
      expect(wireGuard.protectionActive, isFalse);
      expect(controller.requiresExplicitDisconnect, isFalse);
      expect(controller.takeSignInPrompt(), isFalse);
    },
  );

  for (final profileError in [
    const ApiException(statusCode: 401, errorCode: 'unauthorized'),
    const ApiException(statusCode: 503, errorCode: 'service_unavailable'),
  ]) {
    test(
      'startup handles profile HTTP ${profileError.statusCode} correctly',
      () async {
        final store = _AuditStore();
        final controller = AppController(
          api: _AuditApi()..profileError = profileError,
          store: store,
          wireguard: automatic.AutomaticWireGuard(),
          openVpn: _AuditOpenVpn(),
          window: _AuditWindow(),
        );
        addTearDown(controller.dispose);
        await controller.initialize();
        expect(
          store.storedToken,
          profileError.statusCode == 401 ? isNull : equals('audit-session'),
        );
        expect(controller.profile, isNull);
      },
    );
  }

  for (final protocol in VpnProtocol.values) {
    for (final cacheAvailable in [true, false]) {
      testWidgets(
        'native ${protocol.name} resume with cache=$cacheAvailable never calls blocked API',
        (tester) async {
          var now = DateTime.utc(2026, 9, 8);
          final api = _AuditApi();
          final window = _AuditWindow();
          final wireGuard = _CachedWireGuard()
            ..cacheAvailable = cacheAvailable
            ..connected = protocol == VpnProtocol.wireGuard
            ..protectionActive = protocol == VpnProtocol.wireGuard;
          final openVpn = _CachedOpenVpn()
            ..cacheAvailable = cacheAvailable
            ..connected = protocol == VpnProtocol.openVpn
            ..protectionActive = protocol == VpnProtocol.openVpn;
          final controller = AppController(
            api: api,
            store: _AuditStore(),
            wireguard: wireGuard,
            openVpn: openVpn,
            window: window,
            now: () => now,
          );
          try {
            await controller.initialize();
            final apiCalls = api.calls;
            api.forbidCalls = true;
            now = now.add(const Duration(seconds: 11));
            wireGuard.connected = false;
            openVpn.connected = false;

            await window.emit(WindowsConnectivityEvent.networkAvailable);
            await tester.pump(const Duration(seconds: 3));
            await tester.pump();

            expect(api.calls, apiCalls);
            expect(wireGuard.reconnectCalls + openVpn.reconnectCalls, 1);
            expect(
              controller.vpnStatus,
              cacheAvailable ? VpnStatus.connected : VpnStatus.blocked,
            );
            expect(controller.requiresExplicitDisconnect, isTrue);
            if (cacheAvailable) {
              expect(
                controller.tunnelLocationId,
                isNull,
                reason:
                    'A reopened interface cannot infer the native cache destination from its saved choice.',
              );
            }
          } finally {
            controller.dispose();
          }
        },
      );
    }
  }

  test(
    'a late location poll cannot recreate migration state after sign-out',
    () async {
      final gate = Completer<LocationMigration>();
      final api = _AuditApi(device: _device(migration.frankfurt1))
        ..pollGate = gate;
      final controller =
          AppController(
              api: api,
              store: _AuditStore(),
              wireguard: automatic.AutomaticWireGuard(),
              openVpn: _AuditOpenVpn(),
              window: _AuditWindow(),
            )
            ..profile = migration.testProfile
            ..currentDeviceId = 'device-1'
            ..locations = [migration.frankfurt1, migration.frankfurt2]
            ..selectedLocation = migration.frankfurt1
            ..locationMigration = _migration(LocationMigrationStatus.draining)
            ..pendingTargetLocation = migration.frankfurt2;
      addTearDown(controller.dispose);

      final polling = controller.pollLocationMigrationNow();
      await Future<void>.delayed(Duration.zero);
      expect(api.pollCalls, 1);
      await controller.signOut();
      gate.complete(_migration(LocationMigrationStatus.ready));
      await polling;

      expect(controller.profile, isNull);
      expect(controller.locationMigration, isNull);
      expect(controller.pendingTargetLocation, isNull);
      expect(controller.isLocationMigrationActive, isFalse);
      expect(controller.selectedLocation, migration.frankfurt1);
    },
  );

  testWidgets(
    'unknown protection prevents API fallback after missing native cache',
    (tester) async {
      var now = DateTime.utc(2026, 9, 8);
      final api = _AuditApi();
      final window = _AuditWindow();
      final wireGuard = _CachedWireGuard()
        ..connected = true
        ..cacheAvailable = false;
      final controller = AppController(
        api: api,
        store: _AuditStore(),
        wireguard: wireGuard,
        openVpn: _AuditOpenVpn(),
        window: window,
        now: () => now,
      );
      try {
        await controller.initialize();
        final apiCalls = api.calls;
        api.forbidCalls = true;
        wireGuard.statusUnavailable = true;
        now = now.add(const Duration(seconds: 11));
        await window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await tester.pump();
        expect(api.calls, apiCalls);
        expect(wireGuard.reconnectCalls, 1);
        expect(controller.vpnStatus, VpnStatus.error);
        expect(controller.errorMessage, contains('ne peut pas être confirmé'));
        expect(controller.requiresExplicitDisconnect, isTrue);
      } finally {
        controller.dispose();
      }
    },
  );

  test(
    'an unconfirmed native stop remains explicitly stoppable after sign-out',
    () async {
      final wireGuard = _CachedWireGuard()
        ..connected = true
        ..statusUnavailable = true
        ..failDisconnect = true;
      final controller =
          AppController(
              api: _AuditApi(),
              store: _AuditStore(),
              wireguard: wireGuard,
              openVpn: _AuditOpenVpn(),
              window: _AuditWindow(),
            )
            ..profile = migration.testProfile
            ..vpnStatus = VpnStatus.connected
            ..activeProtocol = VpnProtocol.wireGuard;
      addTearDown(controller.dispose);
      await controller.signOut();
      expect(controller.profile, isNull);
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.requiresExplicitDisconnect, isTrue);
      wireGuard.statusUnavailable = false;
      wireGuard.failDisconnect = false;
      await controller.quickConnect();
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(controller.requiresExplicitDisconnect, isFalse);
      expect(wireGuard.connected, isFalse);
    },
  );

  test(
    'startup does not interpret an unavailable native status as disconnected',
    () async {
      final api = _AuditApi()..forbidCalls = true;
      final wireGuard = _CachedWireGuard()..statusUnavailable = true;
      final openVpn = _AuditOpenVpn();
      final controller = AppController(
        api: api,
        store: _AuditStore(),
        wireguard: wireGuard,
        openVpn: openVpn,
        window: _AuditWindow(),
      );
      addTearDown(controller.dispose);
      await controller.initialize();
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.runtimeVerificationPending, isTrue);
      expect(controller.requiresExplicitDisconnect, isFalse);
      expect(controller.isInitialized, isTrue);
      expect(api.calls, 0);
      expect(wireGuard.connectCalls, 0);
      expect(wireGuard.reconnectCalls, 0);
      expect(wireGuard.disconnectCalls, 0);
      expect(openVpn.importCalls, 0);
      expect(openVpn.disconnectCalls, 0);
    },
  );

  for (final protocol in VpnProtocol.values) {
    for (final cacheAvailable in [true, false]) {
      test(
        'startup ${protocol.name} lock resumes cache=$cacheAvailable before API',
        () async {
          final wireGuard = _CachedWireGuard()
            ..cacheAvailable = cacheAvailable
            ..protectionActive = protocol == VpnProtocol.wireGuard;
          final openVpn = _CachedOpenVpn()
            ..cacheAvailable = cacheAvailable
            ..protectionActive = protocol == VpnProtocol.openVpn;
          final api = _AuditApi()
            ..apiAllowed = () => wireGuard.connected || openVpn.connected;
          final store = _AuditStore();
          final controller = AppController(
            api: api,
            store: store,
            wireguard: wireGuard,
            openVpn: openVpn,
            window: _AuditWindow(),
          );
          addTearDown(controller.dispose);
          await controller.initialize();
          expect(wireGuard.reconnectCalls + openVpn.reconnectCalls, 1);
          expect(api.deniedCalls, 0);
          expect(store.storedToken, 'audit-session');
          expect(
            controller.vpnStatus,
            cacheAvailable ? VpnStatus.connected : VpnStatus.blocked,
          );
          expect(
            controller.profile,
            cacheAvailable ? migration.testProfile : isNull,
          );
          if (!cacheAvailable) expect(api.calls, 0);
        },
      );
    }
  }

  testWidgets(
    'startup native resume retries after network returns before validating session',
    (tester) async {
      final wireGuard = _CachedWireGuard()
        ..protectionActive = true
        ..failConnect = true;
      final api = _AuditApi()..apiAllowed = () => wireGuard.connected;
      final window = _AuditWindow();
      final controller = AppController(
        api: api,
        store: _AuditStore(),
        wireguard: wireGuard,
        openVpn: _AuditOpenVpn(),
        window: window,
      );
      try {
        await controller.initialize();
        expect(controller.vpnStatus, VpnStatus.blocked);
        expect(controller.profile, isNull);
        expect(api.calls, 0);
        wireGuard.failConnect = false;
        await window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await tester.pump();
        expect(wireGuard.reconnectCalls, 2);
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.profile, migration.testProfile);
        expect(api.deniedCalls, 0);
        expect(api.calls, greaterThan(0));
      } finally {
        controller.dispose();
      }
    },
  );

  testWidgets(
    'F09 cached reconnect retains the confirmed destination after a new selection',
    (tester) async {
      var now = DateTime.utc(2026, 9, 12);
      final native = _CachedWireGuard();
      final window = _AuditWindow();
      final controller = AppController(
        api: _AuditApi(),
        store: _AuditStore(),
        wireguard: native,
        openVpn: _AuditOpenVpn(),
        window: window,
        now: () => now,
      );
      try {
        await controller.initialize();
        await controller.quickConnect();
        expect(controller.tunnelLocationId, 'frankfurt-01');
        native.connected = false;
        now = now.add(const Duration(seconds: 20));
        await controller.checkTunnelHealthNow();
        await controller.checkTunnelHealthNow();
        expect(controller.vpnStatus, VpnStatus.blocked);
        await controller.selectLocation(migration.frankfurt2);
        await window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await tester.pump();
        expect(native.reconnectCalls, 1);
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.selectedLocation, migration.frankfurt2);
        expect(controller.tunnelLocationId, 'frankfurt-01');
      } finally {
        controller.dispose();
      }
    },
  );
}

LocationMigration _migration(LocationMigrationStatus status) =>
    LocationMigration(
      migrationId: 'migration-1',
      deviceId: 'device-1',
      sourceLocationId: 'frankfurt-01',
      targetLocationId: 'frankfurt-02',
      status: status,
      retryAfterSeconds: 2,
    );

VpnDevice _device(Location location) => VpnDevice(
  deviceId: 'device-1',
  name: 'Audit device',
  location: location,
  createdAt: DateTime.utc(2026, 8, 20),
);

class _AuditApi extends migration.MigrationApi {
  _AuditApi({super.device});
  bool offlineProfile = false;
  ApiException? profileError;
  Completer<LocationMigration>? pollGate;
  bool forbidCalls = false;
  bool Function()? apiAllowed;
  int deniedCalls = 0;
  int calls = 0;

  void _beforeCall() {
    calls++;
    if (forbidCalls || apiAllowed?.call() == false) {
      deniedCalls++;
      throw StateError('API calls forbidden while WFP is active');
    }
  }

  @override
  Future<List<Location>> locations() async {
    _beforeCall();
    return [migration.frankfurt1, migration.frankfurt2];
  }

  @override
  Future<UserProfile> me(String token) async {
    _beforeCall();
    if (offlineProfile) throw const SocketException('Audit offline simulation');
    if (profileError != null) throw profileError!;
    return migration.testProfile;
  }

  @override
  Future<DeviceList> devices(String token) {
    _beforeCall();
    return super.devices(token);
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) {
    _beforeCall();
    return super.registerDevice(
      token: token,
      name: name,
      publicKey: publicKey,
      locationId: locationId,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) {
    _beforeCall();
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<LocationMigration> getLocationMigration({
    required String token,
    required String deviceId,
    required String migrationId,
  }) {
    _beforeCall();
    if (pollGate != null) {
      pollCalls++;
      return pollGate!.future;
    }
    return super.getLocationMigration(
      token: token,
      deviceId: deviceId,
      migrationId: migrationId,
    );
  }
}

class _AuditStore extends migration.MigrationStore {
  String? storedToken = 'audit-session';

  @override
  Future<String?> token() async => storedToken;
  @override
  Future<void> clearToken() async => storedToken = null;
  @override
  Future<SecuritySettings> securitySettings() async =>
      SecuritySettings.secureDefaults;
  @override
  Future<String?> themeMode() async => 'light';
  @override
  Future<String?> vpnProtocol() async => 'wireguard';
  @override
  Future<String?> appLanguage() async => 'fr';
  @override
  Future<String?> autoConnectOnLaunch() async => 'false';
  @override
  Future<String?> windowsNotifications() async => 'false';
  @override
  Future<String?> selectedLocation() async => migration.frankfurt1.id;
  @override
  Future<String?> currentDeviceId() async => null;
  @override
  Future<List<String>> favoriteLocationIds() async => [];
  @override
  Future<List<String>> recentLocationIds() async => [];
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async {}
}

class _AuditOpenVpn extends automatic.AutomaticOpenVpn {
  @override
  Future<bool> isAvailable() async => false;
}

class _CachedWireGuard extends automatic.AutomaticWireGuard {
  bool cacheAvailable = true;
  bool statusUnavailable = false;
  int reconnectCalls = 0;

  @override
  Future<bool> isConnected() async {
    if (statusUnavailable) throw PlatformException(code: 'broker_unavailable');
    return connected;
  }

  @override
  Future<bool> isNetworkProtectionActive() async {
    if (statusUnavailable) throw PlatformException(code: 'broker_unavailable');
    return protectionActive;
  }

  @override
  Future<bool> reconnect() async {
    reconnectCalls++;
    if (!cacheAvailable) return false;
    if (failConnect) throw PlatformException(code: 'wireguard_start_failed');
    connected = true;
    return true;
  }
}

class _CachedOpenVpn extends _AuditOpenVpn {
  bool cacheAvailable = true;
  int reconnectCalls = 0;

  @override
  Future<bool> reconnect() async {
    reconnectCalls++;
    if (!cacheAvailable) return false;
    connected = true;
    return true;
  }
}

class _AuditWindow extends WindowBridge {
  Future<void> Function(WindowsConnectivityEvent event)? listener;
  @override
  Future<String> deviceName() async => 'FuzeVPN regression test';
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
