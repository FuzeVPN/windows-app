// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';

import 'location_migration_test.dart' as fixture;

class _Store extends fixture.MigrationStore {
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async {}
}

class _WireGuard extends fixture.MigrationWireGuard {
  Completer<bool>? nextStatus;
  bool failStatus = false;
  Completer<void>? disconnectGate;
  final disconnectStarted = Completer<void>();
  bool failDisconnect = false;

  @override
  Future<bool> isConnected() async {
    final pending = nextStatus;
    nextStatus = null;
    if (pending != null) return pending.future;
    if (failStatus) throw PlatformException(code: 'broker_unavailable');
    return connected;
  }

  @override
  Future<void> disconnect() async {
    if (!disconnectStarted.isCompleted) disconnectStarted.complete();
    await disconnectGate?.future;
    if (failDisconnect) throw PlatformException(code: 'wireguard_stop_failed');
    await super.disconnect();
  }
}

class _OpenVpn extends fixture.MigrationOpenVpn {
  Completer<NetworkProtectionStatus>? nextProtection;
  final protectionStarted = Completer<void>();

  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    final pending = nextProtection;
    nextProtection = null;
    if (pending != null) {
      if (!protectionStarted.isCompleted) protectionStarted.complete();
      return pending.future;
    }
    return super.networkProtectionStatus();
  }
}

AppController _controller(_WireGuard wireguard, _OpenVpn openVpn) =>
    AppController(
        api: fixture.MigrationApi(),
        store: _Store(),
        wireguard: wireguard,
        openVpn: openVpn,
      )
      ..profile = fixture.testProfile
      ..selectedLocation = fixture.frankfurt1
      ..locations = const [fixture.frankfurt1, fixture.frankfurt2]
      ..automaticReconnectEnabled = false
      ..vpnStatus = VpnStatus.connected
      ..activeProtocol = VpnProtocol.wireGuard;

const _inactive = NetworkProtectionStatus(
  active: false,
  killSwitch: true,
  phase: 'inactive',
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final reconnect in [false, true]) {
    test('CC01 stale protection snapshot cannot overwrite completed '
        '${reconnect ? 'disconnect and reconnect' : 'disconnect'}', () async {
      final wireguard = _WireGuard()..protectionActive = true;
      final openVpn = _OpenVpn()
        ..nextProtection = Completer<NetworkProtectionStatus>();
      final pendingProtection = openVpn.nextProtection!;
      final controller = _controller(wireguard, openVpn);
      addTearDown(controller.dispose);

      await controller.checkTunnelHealthNow();
      final oldHealth = controller.checkTunnelHealthNow();
      await openVpn.protectionStarted.future;
      await controller.toggleConnection();
      expect(controller.vpnStatus, VpnStatus.disconnected);
      if (reconnect) await controller.toggleConnection();

      pendingProtection.complete(_inactive);
      await oldHealth;

      expect(
        controller.vpnStatus,
        reconnect ? VpnStatus.connected : VpnStatus.disconnected,
      );
      expect(controller.errorMessage, isNull);
      expect(controller.requiresExplicitDisconnect, reconnect);
      expect(wireguard.protectionActive, reconnect);
      expect(openVpn.protectionActive, isFalse);
      expect(
        controller.activeProtocol,
        reconnect ? VpnProtocol.wireGuard : null,
      );
    });
  }

  test(
    'CC01 old negative health result cannot count against a new tunnel',
    () async {
      final wireguard = _WireGuard()..protectionActive = true;
      final controller = _controller(wireguard, _OpenVpn());
      addTearDown(controller.dispose);
      await controller.checkTunnelHealthNow();

      final pendingStatus = Completer<bool>();
      wireguard.nextStatus = pendingStatus;
      final oldHealth = controller.checkTunnelHealthNow();
      await controller.toggleConnection();
      await controller.toggleConnection();
      expect(controller.vpnStatus, VpnStatus.connected);

      pendingStatus.complete(false);
      await oldHealth;

      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.activeProtocol, VpnProtocol.wireGuard);
      expect(controller.errorMessage, isNull);
    },
  );

  test(
    'CC01 old failed health query cannot count against a new tunnel',
    () async {
      final wireguard = _WireGuard()..connected = true;
      final controller = _controller(wireguard, _OpenVpn());
      addTearDown(controller.dispose);
      final pendingStatus = Completer<bool>();
      wireguard.nextStatus = pendingStatus;
      final oldHealth = controller.checkTunnelHealthNow();
      await controller.toggleConnection();
      await controller.toggleConnection();

      pendingStatus.completeError(
        PlatformException(code: 'broker_unavailable'),
      );
      await oldHealth;
      wireguard.failStatus = true;
      await controller.checkTunnelHealthNow();
      await controller.checkTunnelHealthNow();

      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.errorMessage, isNull);
    },
  );

  test(
    'CC01 consecutive negative checks belong to the current tunnel',
    () async {
      final wireguard = _WireGuard()..protectionActive = true;
      final controller = _controller(wireguard, _OpenVpn());
      addTearDown(controller.dispose);
      await controller.checkTunnelHealthNow();
      await controller.toggleConnection();
      await controller.toggleConnection();

      wireguard.connected = false;
      await controller.checkTunnelHealthNow();

      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.errorMessage, isNull);
      await controller.checkTunnelHealthNow();
      expect(controller.vpnStatus, VpnStatus.blocked);
    },
  );

  for (final failDisconnect in [false, true]) {
    test('CC02 pending ${failDisconnect ? 'failed' : 'successful'} disconnect '
        'finishes quietly after disposal', () async {
      final gate = Completer<void>();
      final wireguard = _WireGuard()
        ..connected = true
        ..disconnectGate = gate
        ..failDisconnect = failDisconnect;
      final controller = _controller(wireguard, _OpenVpn());
      final pendingDisconnect = controller.toggleConnection();
      await wireguard.disconnectStarted.future;
      final completed = expectLater(pendingDisconnect, completes);

      controller.dispose();
      gate.complete();
      await completed;
      expect(wireguard.connected, failDisconnect);
    });
  }
}
