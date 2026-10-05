// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';

// Reuse the audit's local doubles without invoking its diagnostic test main.
// The assertions here require the corrected behavior, independently of the
// historical audit probes (which intentionally describe the old defects).
import 'support/audit_fixtures.dart' as audit;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final failPersistence in [false, true]) {
    test(
      'server change keeps WFP throughout pending storage (failure=$failPersistence)',
      () async {
        final wg = audit.ProbeWireGuard()
          ..connected = true
          ..protectionActive = true;
        final store = audit.ProbeStore()..selectionGate = Completer<void>();
        final controller = audit.makeController(wg: wg, store: store)
          ..profile = audit.account
          ..currentDeviceId = audit.device.deviceId
          ..devices = [audit.device]
          ..locations = [audit.source, audit.target]
          ..selectedLocation = audit.source
          ..realDeviceLocation = audit.source
          ..activeProtocol = VpnProtocol.wireGuard
          ..vpnStatus = VpnStatus.connected;
        addTearDown(controller.dispose);
        await controller.prepareLocationChange(audit.target);
        final changing = controller.confirmPreparedLocationChange();
        for (var i = 0; i < 100 && !store.selectionWriteStarted; i++) {
          await Future<void>.delayed(Duration.zero);
        }
        expect(store.selectionWriteStarted, isTrue);
        expect(wg.connected, isFalse);
        expect(wg.protectionActive, isTrue);
        expect(wg.suspendCalls, 1);
        expect(wg.disconnectCalls, 0);
        expect(wg.prepareCalls, 1);
        if (failPersistence) {
          store.selectionGate!.completeError(
            StateError('Local storage failed'),
          );
        } else {
          store.selectionGate!.complete();
        }
        await changing;
        expect(wg.protectionActive, isTrue);
        expect(
          controller.vpnStatus,
          failPersistence ? VpnStatus.blocked : VpnStatus.connected,
        );
        expect(controller.requiresExplicitDisconnect, isTrue);
      },
    );
  }

  testWidgets(
    'health loss schedules its first reconnect without a Windows event',
    (tester) async {
      final wg = audit.ProbeWireGuard()
        ..connected = true
        ..protectionActive = true;
      final controller = audit.makeController(wg: wg);
      await controller.initialize();
      wg.connected = false;
      await tester.pump(const Duration(seconds: 4));
      await tester.pump(const Duration(seconds: 4));
      expect(controller.vpnStatus, VpnStatus.blocked);
      await tester.pump(const Duration(seconds: 2));
      expect(wg.reconnectCalls, 0);
      await tester.pump(const Duration(seconds: 1));
      expect(wg.reconnectCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      controller.dispose();
    },
  );

  testWidgets('automatic recovery uses bounded backoff and leaves WFP active', (
    tester,
  ) async {
    final wg = _FailingReconnectWireGuard()
      ..connected = true
      ..protectionActive = true;
    final controller = audit.makeController(wg: wg);
    await controller.initialize();
    wg.connected = false;
    await tester.pump(const Duration(seconds: 4));
    await tester.pump(const Duration(seconds: 4));
    var attempts = 0;
    for (final seconds in [3, 6, 12, 24, 48]) {
      await tester.pump(Duration(seconds: seconds));
      await tester.pump();
      expect(wg.reconnectCalls, ++attempts);
      expect(wg.protectionActive, isTrue);
    }
    await tester.pump(const Duration(minutes: 3));
    expect(wg.reconnectCalls, 5);
    expect(controller.vpnStatus, VpnStatus.blocked);
    controller.dispose();
  });

  testWidgets('explicit disconnect cancels a delayed health recovery', (
    tester,
  ) async {
    final wg = audit.ProbeWireGuard()
      ..connected = true
      ..protectionActive = true;
    final controller = audit.makeController(wg: wg);
    await controller.initialize();
    wg.connected = false;
    await tester.pump(const Duration(seconds: 4));
    await tester.pump(const Duration(seconds: 4));
    await controller.toggleConnection();
    await tester.pump(const Duration(minutes: 2));
    expect(wg.reconnectCalls, 0);
    expect(controller.vpnStatus, VpnStatus.disconnected);
    controller.dispose();
  });

  testWidgets(
    'network return restores saved account and startup auto-connect',
    (tester) async {
      final api = audit.ProbeApi()..offline = true;
      final store = audit.ProbeStore()..autoConnect = true;
      final window = audit.ProbeWindow();
      final wg = audit.ProbeWireGuard();
      final controller = audit.makeController(
        api: api,
        store: store,
        window: window,
        wg: wg,
      );
      await controller.initialize();
      expect(controller.profile, isNull);
      api.offline = false;
      await window.listener!(WindowsConnectivityEvent.networkAvailable);
      expect(api.meCalls, 2);
      expect(controller.profile, audit.account);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(wg.connectCalls, 1);
      controller.dispose();
    },
  );

  test(
    'remote revoke remains successful and both local storage cleanups are attempted',
    () async {
      final api = audit.ProbeApi();
      final store = _FailingCleanupStore();
      final controller = audit.makeController(api: api, store: store)
        ..profile = audit.account
        ..devices = [audit.device]
        ..currentDeviceId = audit.device.deviceId;
      addTearDown(controller.dispose);
      expect(
        await controller.revokeDevice(audit.device),
        DeviceRevocationResult.revokedWithLocalCleanupWarning,
      );
      expect(api.revoked, isTrue);
      expect(controller.devices, isEmpty);
      expect(store.cleanupCalls, ['device', 'migration']);
      expect(controller.deviceErrorMessage, contains('a été retiré'));
    },
  );

  for (final appliedKillSwitch in [false, true]) {
    testWidgets(
      'retained state uses native full-block flag ($appliedKillSwitch), not saved preference',
      (tester) async {
        final wg = audit.ProbeWireGuard()
          ..connected = true
          ..protectionActive = true
          ..appliedKillSwitch = appliedKillSwitch;
        final store = audit.ProbeStore()
          ..killSwitchSetting = !appliedKillSwitch;
        final controller = audit.makeController(wg: wg, store: store);
        await controller.initialize();
        wg.connected = false;
        await tester.pump(const Duration(seconds: 4));
        await tester.pump(const Duration(seconds: 4));
        expect(
          controller.vpnStatus,
          appliedKillSwitch ? VpnStatus.blocked : VpnStatus.error,
        );
        expect(controller.requiresExplicitDisconnect, isTrue);
        if (!appliedKillSwitch) {
          expect(controller.errorMessage, contains('partielles'));
          expect(
            controller.errorMessage,
            isNot(contains('kill switch bloque')),
          );
        }
        controller.dispose();
      },
    );
  }

  testWidgets(
    'unavailable structured status never promotes filter presence into a full-block claim',
    (tester) async {
      final wg = _LegacyStatusWireGuard()
        ..connected = true
        ..protectionActive = true;
      final controller = audit.makeController(wg: wg);
      await controller.initialize();
      wg.connected = false;
      await tester.pump(const Duration(seconds: 4));
      await tester.pump(const Duration(seconds: 4));
      expect(controller.vpnStatus, VpnStatus.error);
      expect(controller.requiresExplicitDisconnect, isTrue);
      expect(controller.errorMessage, contains('ne peut pas être confirmé'));
      controller.dispose();
    },
  );

  test(
    'another Windows owner prevents account preparation and connection mutations',
    () async {
      final wg = audit.ProbeWireGuard()
        ..connected = true
        ..protectionActive = true
        ..ownedByAnotherUser = true;
      final api = _TrackingLoginApi();
      final controller = audit.makeController(wg: wg, api: api);
      addTearDown(controller.dispose);
      await controller.initialize();
      expect(controller.runtimeOwnedByAnotherUser, isTrue);
      await controller.quickConnect();
      expect(wg.disconnectCalls, 0);
      expect(wg.connectCalls, 0);
      expect(
        await controller.signIn(
          email: 'audit@example.invalid',
          password: 'test-only',
        ),
        isFalse,
      );
      expect(api.loginCalls, 0);
      expect(controller.errorMessage, contains('autre session Windows'));
    },
  );
}

class _FailingReconnectWireGuard extends audit.ProbeWireGuard {
  @override
  Future<bool> reconnect() async {
    reconnectCalls++;
    throw PlatformException(code: 'wireguard_start_failed');
  }
}

class _FailingCleanupStore extends audit.ProbeStore {
  final List<String> cleanupCalls = [];
  @override
  Future<void> clearCurrentDeviceId() async {
    cleanupCalls.add('device');
    throw PlatformException(code: 'secure_store_error');
  }

  @override
  Future<void> clearLocationMigration() async {
    cleanupCalls.add('migration');
    throw PlatformException(code: 'secure_store_error');
  }
}

class _LegacyStatusWireGuard extends audit.ProbeWireGuard {
  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async =>
      throw MissingPluginException();
}

class _TrackingLoginApi extends audit.ProbeApi {
  int loginCalls = 0;
  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    loginCalls++;
    return const AuthSession(accessToken: 'synthetic-only');
  }
}
