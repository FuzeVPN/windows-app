// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _TraceStore extends fixtures.ProbeStore {
  bool unreadableTheme = false;
  int clearCalls = 0;

  @override
  Future<String?> themeMode() async {
    if (unreadableTheme) {
      throw PlatformException(
        code: 'storage_access_denied',
        message: 'private-storage-location',
        details: {'win32_error': 5, 'private': 'must-not-be-logged'},
      );
    }
    return 'light';
  }

  @override
  Future<void> clearToken() async {
    clearCalls++;
  }
}

class _QuietUpdates extends WindowsUpdateController {
  _QuietUpdates() : super(api: fixtures.ProbeApi());

  @override
  Future<void> checkForUpdates() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'startup logs swallowed storage and catalogue errors without changing recovery',
    () async {
      final entries = <({String area, String event, String? code})>[];
      final stop = DiagnosticLog.observe((area, event, code) {
        entries.add((area: area, event: event, code: code));
      });
      addTearDown(stop);
      final store = _TraceStore()..unreadableTheme = true;
      final api = fixtures.ProbeApi()..offline = true;
      final wireguard = fixtures.ProbeWireGuard();
      final openVpn = fixtures.ProbeOpenVpn();
      final updates = _QuietUpdates();
      addTearDown(updates.dispose);
      final controller = AppController(
        api: api,
        store: store,
        wireguard: wireguard,
        openVpn: openVpn,
        window: fixtures.ProbeWindow(),
        updates: updates,
      );
      addTearDown(controller.dispose);

      await controller.initialize();

      expect(controller.isInitialized, isTrue);
      expect(controller.themeMode, ThemeMode.light);
      expect(controller.apiReachable, isFalse);
      expect(controller.savedSessionVerificationPending, isTrue);
      expect(store.clearCalls, 0);
      expect(wireguard.prepareCalls, 0);
      expect(wireguard.connectCalls, 0);
      expect(openVpn.importCalls, 0);
      expect(entries, contains((area: 'startup', event: 'begin', code: null)));
      expect(
        entries,
        contains((area: 'locations', event: 'failed', code: 'network_error')),
      );
      expect(
        entries,
        contains((
          area: 'account',
          event: 'saved_session_verification_pending',
          code: 'network_error',
        )),
      );
      expect(
        entries.any(
          (entry) => entry.area == 'startup' && entry.event == 'failed',
        ),
        isTrue,
      );
      expect(entries.toString(), isNot(contains('private-storage-location')));
      expect(entries.toString(), isNot(contains('must-not-be-logged')));
      expect(entries.toString(), isNot(contains('audit-synthetic-token')));
    },
  );

  test(
    'successful startup traces runtime before catalogue and preserves idle VPN',
    () async {
      final entries = <({String area, String event, String? code})>[];
      final stop = DiagnosticLog.observe((area, event, code) {
        entries.add((area: area, event: event, code: code));
      });
      addTearDown(stop);
      final wireguard = fixtures.ProbeWireGuard();
      final openVpn = fixtures.ProbeOpenVpn();
      final updates = _QuietUpdates();
      addTearDown(updates.dispose);
      final controller = AppController(
        api: fixtures.ProbeApi(),
        store: _TraceStore(),
        wireguard: wireguard,
        openVpn: openVpn,
        window: fixtures.ProbeWindow(),
        updates: updates,
      );
      addTearDown(controller.dispose);

      await controller.initialize();

      final runtime = entries.indexWhere(
        (entry) => entry.event == 'startup_wireguard_connected',
      );
      final catalogue = entries.indexWhere(
        (entry) => entry.area == 'locations' && entry.event == 'begin',
      );
      expect(runtime, greaterThanOrEqualTo(0));
      expect(catalogue, greaterThan(runtime));
      expect(
        entries,
        contains((area: 'locations', event: 'completed', code: null)),
      );
      expect(
        entries,
        contains((area: 'startup', event: 'completed', code: 'initialized')),
      );
      expect(controller.apiReachable, isTrue);
      expect(controller.profile, fixtures.account);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(wireguard.connectCalls, 0);
      expect(wireguard.prepareCalls, 0);
      expect(openVpn.importCalls, 0);
    },
  );
}
