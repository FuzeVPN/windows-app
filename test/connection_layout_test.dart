// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

class _ConnectionLayoutController extends ConnectionUxController {
  int connectionRequests = 0;

  @override
  Future<void> quickConnect() async {
    connectionRequests++;
  }
}

void main() {
  testWidgets('connection controls remain visible at the normal window size', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1080, 640);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);

    for (final status in VpnStatus.values) {
      final app = _ConnectionLayoutController()..vpnStatus = status;
      await tester.pumpWidget(FuzeVpnApp(controller: app));
      await tester.pumpAndSettle();
      final primary = find.byKey(const ValueKey('connection-primary-action'));
      final chooseLocation = find.byKey(
        const ValueKey('connection-location-action'),
      );
      for (final control in [primary, chooseLocation]) {
        expect(control.hitTestable(), findsOneWidget, reason: status.name);
        expect(tester.getRect(control).bottom, lessThanOrEqualTo(640));
      }
      await tester.tap(primary);
      await tester.pump();
      expect(app.connectionRequests, 1, reason: status.name);
      await tester.tap(chooseLocation);
      await tester.pumpAndSettle();
      expect(app.section, AppSection.locations, reason: status.name);
      expect(tester.takeException(), isNull, reason: status.name);
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();
    }
  });

  testWidgets('connected summary identifies the active tunnel and protocol', (
    tester,
  ) async {
    final app = _ConnectionLayoutController()
      ..vpnStatus = VpnStatus.connected
      ..tunnelLocationId = 'de-1'
      ..vpnProtocol = VpnProtocol.wireGuard
      ..activeProtocol = VpnProtocol.openVpn
      ..connectedAt = DateTime.now().subtract(const Duration(minutes: 2));
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
    expect(find.text('Frankfurt 1'), findsOneWidget);
    expect(find.text('Frankfurt 2'), findsNothing);
    expect(find.text('Protocole VPN : OpenVPN'), findsOneWidget);
    expect(find.textContaining('Durée de connexion :'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
    app.dispose();
  });

  testWidgets(
    'an unconfirmed tunnel never presents the selected location as active',
    (tester) async {
      final app = _ConnectionLayoutController()
        ..vpnStatus = VpnStatus.connected;
      await tester.pumpWidget(FuzeVpnApp(controller: app));
      await tester.pumpAndSettle();
      expect(find.text('Emplacement du tunnel non confirmé'), findsOneWidget);
      expect(find.text('Frankfurt 2'), findsNothing);
      expect(find.textContaining('Durée de connexion :'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();
    },
  );
}
