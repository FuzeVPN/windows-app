// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _UnavailableWireGuard extends fixtures.ProbeWireGuard {
  @override
  Future<bool> isConnected() async => throw PlatformException(
    code: 'broker_unavailable',
    message: 'private-endpoint.example.invalid',
    details: {'token': 'private-synthetic-token'},
  );

  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async =>
      throw PlatformException(code: 'runtime_status_unavailable');

  @override
  Future<bool> isNetworkProtectionActive() async =>
      throw PlatformException(code: 'broker_unavailable');
}

class _NoUpdateCheck extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'startup trace captures native failure stage without private details',
    () async {
      final events = <({String area, String event, String? code})>[];
      final stop = DiagnosticLog.observe((area, event, code) {
        events.add((area: area, event: event, code: code));
      });
      addTearDown(stop);
      final app = AppController(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        wireguard: _UnavailableWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        window: fixtures.ProbeWindow(),
        updates: _NoUpdateCheck(),
      );
      addTearDown(app.dispose);
      await app.initialize();
      final trace = events.where((e) => e.area == 'runtime_state').toList();
      final startupFailure = trace.singleWhere(
        (entry) => entry.event == 'startup_wireguard_connected_failed',
      );
      expect(startupFailure.code, 'broker_unavailable');
      expect(
        trace,
        contains((
          area: 'runtime_state',
          event: 'recovery_wireguard_connected',
          code: 'unknown',
        )),
      );
      expect(
        trace,
        contains((
          area: 'runtime_state',
          event: 'recovery_openvpn_connected',
          code: 'false',
        )),
      );
      expect(
        trace,
        contains((
          area: 'runtime_state',
          event: 'recovery_wireguard_protection_snapshot_failed',
          code: 'runtime_status_unavailable',
        )),
      );
      expect(
        trace,
        contains((
          area: 'runtime_state',
          event: 'recovery_wireguard_protection_fallback',
          code: 'unknown',
        )),
      );
      expect(
        trace,
        contains((
          area: 'runtime_state',
          event: 'recovery_openvpn_protection_snapshot',
          code: 'false',
        )),
      );
      expect(trace.toString(), isNot(contains('private')));
      expect(app.vpnStatus, VpnStatus.error);
      expect(app.requiresExplicitDisconnect, isFalse);
      expect(app.runtimeVerificationPending, isTrue);
      expect(app.runtimeVerificationErrorCode, 'broker_unavailable');
      expect(app.profile, isNull);
      await DiagnosticLog.flush();
    },
  );
}
