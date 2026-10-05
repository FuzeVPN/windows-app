// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'automatic_protocol_test.dart'
    show AutomaticApi, AutomaticStore, AutomaticWireGuard, AutomaticOpenVpn;

const _requested = Location(
  id: 'frankfurt-01',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const _alternative = Location(
  id: 'paris-01',
  city: 'Paris',
  countryCode: 'FR',
  displayName: 'Paris 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const _profile = UserProfile(
  userId: 'capacity-test-user',
  email: 'capacity@example.invalid',
  firstName: 'Capacity',
  emailVerified: true,
);

enum _Operation { wireGuard, openVpnCreate, openVpnRenew }

const _capacityErrors = [
  (
    error: ApiException(statusCode: 409, errorCode: 'server_full'),
    kind: DeviceEnrollmentIssueKind.serverFull,
  ),
  (
    error: ApiException(statusCode: 503, errorCode: 'capacity_unavailable'),
    kind: DeviceEnrollmentIssueKind.capacityUnavailable,
  ),
];

void main() {
  for (final operation in _Operation.values) {
    for (final rejection in _capacityErrors) {
      test(
        '${operation.name}: ${rejection.error.errorCode} refreshes without delaying completion or retrying',
        () async {
          final fixture = _Fixture(operation, error: rejection.error);
          addTearDown(fixture.controller.dispose);
          var connectionCompleted = false;
          final connection = fixture.start().then((_) {
            connectionCompleted = true;
          });

          await _waitUntil(() => fixture.api.locationRequests.length == 1);
          await _waitUntil(() => connectionCompleted);
          await connection;

          expect(fixture.controller.isConnectionBusy, isFalse);
          expect(fixture.controller.isLoadingLocations, isTrue);
          expect(
            fixture.controller.deviceEnrollmentIssue?.kind,
            rejection.kind,
          );
          final issue = fixture.controller.deviceEnrollmentIssue!;
          expect(issue.title, isNotEmpty);
          expect(issue.message, contains('emplacement'));
          fixture.expectNoConnectionOrIdentityChanges();
          fixture.expectSingleAttempt();

          final full = rejection.kind == DeviceEnrollmentIssueKind.serverFull;
          expect(
            fixture.controller.locations.map((location) => location.id),
            full ? [_alternative.id] : [_requested.id, _alternative.id],
          );
          expect(
            fixture.controller.selectedLocation?.id,
            full ? isNull : _requested.id,
          );
          if (!full) {
            expect(issue.title.toLowerCase(), isNot(contains('complet')));
            expect(
              issue.message.toLowerCase(),
              isNot(contains('plus de place')),
            );
          }

          fixture.api.locationRequests.single.complete(
            full ? const [_alternative] : const [_requested, _alternative],
          );
          await _waitUntil(() => !fixture.controller.isLoadingLocations);

          expect(fixture.api.locationRequests, hasLength(1));
          expect(fixture.controller.deviceEnrollmentIssue, same(issue));
          expect(
            fixture.controller.selectedLocation?.id,
            full ? isNull : _requested.id,
          );
          if (full) {
            await fixture.controller.quickConnect();
            fixture.expectSingleAttempt();
            fixture.expectNoConnectionOrIdentityChanges();
            expect(fixture.controller.selectedLocation, isNull);
          }
        },
      );

      test(
        '${operation.name}: failed catalogue refresh preserves ${rejection.error.errorCode}',
        () async {
          final fixture = _Fixture(operation, error: rejection.error);
          addTearDown(fixture.controller.dispose);
          final connection = fixture.start();
          await _waitUntil(() => fixture.api.locationRequests.length == 1);
          final issue = fixture.controller.deviceEnrollmentIssue;

          fixture.api.locationRequests.single.completeError(
            const ApiException(statusCode: 502, errorCode: 'bad_gateway'),
          );
          await connection;
          await _waitUntil(() => !fixture.controller.isLoadingLocations);

          expect(fixture.controller.apiReachable, isFalse);
          expect(fixture.controller.isConnectionBusy, isFalse);
          expect(fixture.controller.deviceEnrollmentIssue, same(issue));
          expect(
            fixture.controller.deviceEnrollmentIssue?.kind,
            rejection.kind,
          );
          expect(issue!.title, isNotEmpty);
          expect(issue.message, contains('emplacement'));
          expect(fixture.api.locationRequests, hasLength(1));
          if (rejection.kind == DeviceEnrollmentIssueKind.serverFull) {
            expect(fixture.controller.locations, [_alternative]);
            expect(fixture.controller.selectedLocation, isNull);
          } else {
            expect(fixture.controller.locations, [_requested, _alternative]);
            expect(fixture.controller.selectedLocation, same(_requested));
          }
          fixture.expectSingleAttempt();
          fixture.expectNoConnectionOrIdentityChanges();
        },
      );
    }

    for (final mismatch in const [
      ApiException(statusCode: 503, errorCode: 'server_full'),
      ApiException(statusCode: 409, errorCode: 'capacity_unavailable'),
      ApiException(statusCode: 409, errorCode: 'server_error'),
      ApiException(statusCode: 503, errorCode: 'service_unavailable'),
    ]) {
      test(
        '${operation.name}: ${mismatch.statusCode}/${mismatch.errorCode} is not a capacity rejection',
        () async {
          final fixture = _Fixture(operation, error: mismatch);
          addTearDown(fixture.controller.dispose);

          await fixture.start();

          expect(
            fixture.controller.deviceEnrollmentIssue?.kind,
            isNot(
              isIn([
                DeviceEnrollmentIssueKind.serverFull,
                DeviceEnrollmentIssueKind.capacityUnavailable,
              ]),
            ),
          );
          expect(fixture.api.locationRequests, isEmpty);
          expect(fixture.controller.locations, [_requested, _alternative]);
          expect(fixture.controller.selectedLocation, same(_requested));
          fixture.expectSingleAttempt();
          fixture.expectNoConnectionOrIdentityChanges();
        },
      );
    }
  }

  test(
    'a request started before server_full cannot reintroduce the removed server',
    () async {
      final fixture = _Fixture(
        _Operation.wireGuard,
        error: _capacityErrors.first.error,
      );
      addTearDown(fixture.controller.dispose);
      final olderRefresh = fixture.controller.refreshLocations();
      await _waitUntil(() => fixture.api.locationRequests.length == 1);

      final connection = fixture.start();
      await _waitUntil(() => fixture.api.locationRequests.length == 2);
      final issue = fixture.controller.deviceEnrollmentIssue;
      fixture.api.locationRequests.first.complete(const [
        _requested,
        _alternative,
      ]);
      await olderRefresh;

      expect(fixture.controller.locations, [_alternative]);
      expect(fixture.controller.selectedLocation, isNull);
      expect(fixture.controller.isLoadingLocations, isTrue);
      expect(fixture.controller.deviceEnrollmentIssue, same(issue));

      fixture.api.locationRequests.last.complete(const [_alternative]);
      await connection;
      await _waitUntil(() => !fixture.controller.isLoadingLocations);
      expect(fixture.controller.locations, [_alternative]);
      expect(fixture.controller.selectedLocation, isNull);
    },
  );

  for (final failOlder in [false, true]) {
    test(
      'a late ${failOlder ? 'failure' : 'response'} cannot overwrite the newer catalogue',
      () async {
        final fixture = _Fixture(_Operation.wireGuard);
        addTearDown(fixture.controller.dispose);
        final olderRefresh = fixture.controller.refreshLocations();
        final newerRefresh = fixture.controller.refreshLocations();

        fixture.api.locationRequests.last.complete(const [_alternative]);
        await newerRefresh;
        expect(fixture.controller.locations, [_alternative]);
        expect(fixture.controller.selectedLocation, isNull);
        expect(fixture.controller.apiReachable, isTrue);
        expect(fixture.controller.isLoadingLocations, isFalse);

        if (failOlder) {
          fixture.api.locationRequests.first.completeError(
            const ApiException(statusCode: 502, errorCode: 'bad_gateway'),
          );
        } else {
          fixture.api.locationRequests.first.complete(const [
            _requested,
            _alternative,
          ]);
        }
        await olderRefresh;

        expect(fixture.controller.locations, [_alternative]);
        expect(fixture.controller.selectedLocation, isNull);
        expect(fixture.controller.apiReachable, isTrue);
        expect(fixture.controller.isLoadingLocations, isFalse);
      },
    );
  }

  test(
    'an empty catalogue clears the selection without starting a connection',
    () async {
      final fixture = _Fixture(_Operation.wireGuard);
      addTearDown(fixture.controller.dispose);
      final refresh = fixture.controller.refreshLocations();
      fixture.api.locationRequests.single.complete(const []);
      await refresh;

      await fixture.controller.quickConnect();

      expect(fixture.controller.locations, isEmpty);
      expect(fixture.controller.selectedLocation, isNull);
      expect(fixture.controller.isConnectionBusy, isFalse);
      expect(fixture.api.registerCalls, 0);
      expect(fixture.api.createCalls, 0);
      fixture.expectNoConnectionOrIdentityChanges();
    },
  );

  test(
    'renewal removes the actual full server and preserves a different selection',
    () async {
      final fixture = _Fixture(
        _Operation.openVpnRenew,
        error: _capacityErrors.first.error,
      );
      addTearDown(fixture.controller.dispose);
      fixture.controller.selectedLocation = _alternative;

      final renewal = fixture.start();
      await _waitUntil(() => fixture.api.locationRequests.length == 1);

      expect(
        fixture.controller.deviceEnrollmentIssue?.kind,
        DeviceEnrollmentIssueKind.serverFull,
      );
      expect(fixture.controller.locations, [_alternative]);
      expect(fixture.controller.selectedLocation, same(_alternative));
      expect(fixture.controller.realDeviceLocation, same(_requested));

      fixture.api.locationRequests.single.complete(const [_alternative]);
      await renewal;
      await _waitUntil(() => !fixture.controller.isLoadingLocations);

      expect(fixture.controller.locations, [_alternative]);
      expect(fixture.controller.selectedLocation, same(_alternative));
      expect(fixture.api.locationRequests, hasLength(1));
      fixture.expectSingleAttempt();
      fixture.expectNoConnectionOrIdentityChanges();
    },
  );

  for (final protocol in VpnProtocol.values) {
    testWidgets(
      '${protocol.name}: a filtered catalogue retains the active tunnel and permits cached reconnect',
      (tester) async {
        final fixture = _Fixture(
          protocol == VpnProtocol.wireGuard
              ? _Operation.wireGuard
              : _Operation.openVpnCreate,
        );
        try {
          final initialization = fixture.controller.initialize();
          for (
            var attempt = 0;
            attempt < 100 && fixture.api.locationRequests.isEmpty;
            attempt++
          ) {
            await tester.pump();
          }
          expect(fixture.api.locationRequests, hasLength(1));
          fixture.api.locationRequests.single.complete(const [
            _requested,
            _alternative,
          ]);
          await initialization;
          await fixture.controller.quickConnect();
          expect(fixture.controller.vpnStatus, VpnStatus.connected);
          expect(fixture.controller.tunnelLocation?.id, _requested.id);
          final registerCalls = fixture.api.registerCalls;
          final createCalls = fixture.api.createCalls;
          final nativeConnectCalls = fixture.wireGuard.connectCalls;
          final nativeImportCalls = fixture.openVpn.importCalls;

          final refresh = fixture.controller.refreshLocations();
          fixture.api.locationRequests.last.complete(const []);
          await refresh;

          expect(fixture.controller.selectedLocation, isNull);
          expect(fixture.controller.tunnelLocation?.id, _requested.id);
          expect(
            fixture.controller.tunnelLocation?.displayName,
            _requested.displayName,
          );
          expect(fixture.controller.vpnStatus, VpnStatus.connected);
          fixture.clock = fixture.clock.add(const Duration(seconds: 13));
          await fixture.window.emit(WindowsConnectivityEvent.systemResumed);
          await tester.pump(const Duration(seconds: 2));
          await tester.pump();

          expect(
            fixture.wireGuard.reconnectCalls,
            protocol == VpnProtocol.wireGuard ? 1 : 0,
          );
          expect(
            fixture.openVpn.reconnectCalls,
            protocol == VpnProtocol.openVpn ? 1 : 0,
          );
          expect(fixture.controller.vpnStatus, VpnStatus.connected);
          expect(fixture.controller.activeProtocol, protocol);
          expect(fixture.controller.tunnelLocation?.id, _requested.id);
          expect(fixture.controller.selectedLocation, isNull);
          expect(fixture.api.registerCalls, registerCalls);
          expect(fixture.api.createCalls, createCalls);
          expect(fixture.api.renewCalls, 0);
          expect(fixture.api.locationRequests, hasLength(2));
          expect(fixture.wireGuard.connectCalls, nativeConnectCalls);
          expect(fixture.openVpn.importCalls, nativeImportCalls);
          expect(fixture.wireGuard.resetCalls, 0);
          expect(fixture.wireGuard.recreateCalls, 0);
          expect(fixture.openVpn.deleteCalls, 0);
        } finally {
          fixture.controller.dispose();
        }
      },
    );
  }
}

Future<void> _waitUntil(bool Function() condition) async {
  for (var attempt = 0; attempt < 100 && !condition(); attempt++) {
    await Future<void>.delayed(Duration.zero);
  }
  expect(condition(), isTrue);
}

class _Fixture {
  _Fixture(this.operation, {ApiException? error}) {
    api = _CapacityApi(operation, error);
    store = _CapacityStore(
      operation == _Operation.wireGuard ? 'auto' : 'openvpn',
    );
    controller =
        AppController(
            api: api,
            store: store,
            wireguard: wireGuard,
            openVpn: openVpn,
            window: window,
            updates: _NoUpdates(),
            now: () => clock,
          )
          ..profile = _profile
          ..currentDeviceId = 'device-test'
          ..locations = const [_requested, _alternative]
          ..selectedLocation = _requested
          ..realDeviceLocation = operation == _Operation.openVpnRenew
              ? _requested
              : null
          ..isLoadingLocations = false
          ..openVpnRuntimeAvailable = true
          ..protocolPreference = operation == _Operation.wireGuard
              ? VpnProtocolPreference.automatic
              : VpnProtocolPreference.openVpn
          ..vpnProtocol = operation == _Operation.wireGuard
              ? VpnProtocol.wireGuard
              : VpnProtocol.openVpn;
  }

  final _Operation operation;
  late final _CapacityApi api;
  late final _CapacityStore store;
  late final AppController controller;
  final wireGuard = _CapacityWireGuard();
  final openVpn = _CapacityOpenVpn();
  final window = _CapacityWindow();
  DateTime clock = DateTime.utc(2026, 9, 26);

  Future<void> start() => operation == _Operation.openVpnRenew
      ? controller.renewOpenVpnProfile()
      : controller.quickConnect();

  void expectSingleAttempt() {
    expect(api.registerCalls, operation == _Operation.wireGuard ? 1 : 0);
    expect(api.createCalls, operation == _Operation.openVpnCreate ? 1 : 0);
    expect(api.renewCalls, operation == _Operation.openVpnRenew ? 1 : 0);
  }

  void expectNoConnectionOrIdentityChanges() {
    expect(wireGuard.connectCalls, 0);
    expect(openVpn.importCalls, 0);
    expect(wireGuard.reconnectCalls, 0);
    expect(openVpn.reconnectCalls, 0);
    expect(wireGuard.resetCalls, 0);
    expect(wireGuard.recreateCalls, 0);
    expect(openVpn.deleteCalls, 0);
    expect(store.clearDeviceCalls, 0);
    expect(store.clearTokenCalls, 0);
    expect(controller.currentDeviceId, 'device-test');
    expect(controller.profile, same(_profile));
  }
}

class _CapacityApi extends AutomaticApi {
  _CapacityApi(this.operation, this.error);
  final _Operation operation;
  final ApiException? error;
  final locationRequests = <Completer<List<Location>>>[];
  int registerCalls = 0;
  int createCalls = 0;
  int renewCalls = 0;

  @override
  Future<List<Location>> locations() {
    final request = Completer<List<Location>>();
    locationRequests.add(request);
    return request.future;
  }

  @override
  Future<UserProfile> me(String token) async => _profile;

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registerCalls++;
    if (operation == _Operation.wireGuard && error != null) throw error!;
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
  }) async {
    createCalls++;
    if (operation == _Operation.openVpnCreate && error != null) throw error!;
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    renewCalls++;
    if (error != null) throw error!;
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }
}

class _CapacityStore extends AutomaticStore {
  _CapacityStore(this.protocol);
  final String protocol;
  int clearDeviceCalls = 0;
  int clearTokenCalls = 0;

  @override
  Future<void> clearCurrentDeviceId() async {
    clearDeviceCalls++;
  }

  @override
  Future<void> clearToken() async {
    clearTokenCalls++;
  }

  @override
  Future<String?> selectedLocation() async => _requested.id;
  @override
  Future<String?> currentDeviceId() async => 'device-test';
  @override
  Future<String?> vpnProtocol() async => protocol;
  @override
  Future<String?> themeMode() async => 'light';
  @override
  Future<String?> appLanguage() async => 'fr';
  @override
  Future<SecuritySettings> securitySettings() async =>
      SecuritySettings.secureDefaults;
  @override
  Future<String?> autoConnectOnLaunch() async => 'false';
  @override
  Future<String?> windowsNotifications() async => 'false';
  @override
  Future<List<String>> favoriteLocationIds() async => const [];
  @override
  Future<List<String>> recentLocationIds() async => const [];
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async {}
  @override
  Future<StoredLocationMigration?> locationMigration() async => null;
}

class _CapacityWireGuard extends AutomaticWireGuard {
  int resetCalls = 0;
  int recreateCalls = 0;
  int reconnectCalls = 0;

  @override
  Future<void> resetIdentity() async {
    resetCalls++;
  }

  @override
  Future<void> recreateIdentityForAccount(String accountId) async {
    recreateCalls++;
  }

  @override
  Future<bool> reconnect() async {
    reconnectCalls++;
    connected = true;
    protectionActive = true;
    return true;
  }
}

class _CapacityOpenVpn extends AutomaticOpenVpn {
  int deleteCalls = 0;
  int reconnectCalls = 0;

  @override
  Future<bool> isAvailable() async => true;
  @override
  Future<void> deleteProfile() async {
    deleteCalls++;
  }

  @override
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async => 'renewal-csr-not-logged';
  @override
  Future<bool> reconnect() async {
    reconnectCalls++;
    connected = true;
    protectionActive = true;
    return true;
  }
}

class _CapacityWindow extends WindowBridge {
  Future<void> Function(WindowsConnectivityEvent)? listener;

  @override
  Future<String> deviceName() async => 'Capacity test -- Windows';
  @override
  Future<bool> isLaunchAtStartupEnabled() async => false;
  @override
  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent) handler,
  ) {
    listener = handler;
  }

  @override
  void stopConnectivityListener() {
    listener = null;
  }

  Future<void> emit(WindowsConnectivityEvent event) async {
    await listener?.call(event);
  }
}

class _NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}
