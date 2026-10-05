// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixture;

class _LanguageStore extends fixture.ProbeStore {
  Completer<void>? writeGate;
  final writes = <String>[];

  @override
  Future<void> saveAppLanguage(String value) async {
    writes.add(value);
    await writeGate?.future;
  }
}

class _MenuController extends AppController {
  _MenuController({required _LanguageStore store, required this.openVpn})
    : super(
        api: fixture.ProbeApi(),
        store: store,
        wireguard: fixture.ProbeWireGuard(),
        openVpn: openVpn,
        window: fixture.ProbeWindow(),
      ) {
    isInitialized = true;
    profile = fixture.account;
    isLoadingLocations = false;
    locations = [fixture.source];
    selectedLocation = fixture.source;
    section = AppSection.settings;
    language = AppLanguage.french;
    vpnProtocol = VpnProtocol.openVpn;
    activeProtocol = VpnProtocol.openVpn;
    vpnStatus = VpnStatus.connected;
  }

  final fixture.ProbeOpenVpn openVpn;

  @override
  Future<void> initialize() async {}
}

Future<_MenuController> _afterOpenVpnDisconnect(
  WidgetTester tester,
  _LanguageStore store,
) async {
  tester.view.physicalSize = const Size(1280, 900);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final controller = _MenuController(
    store: store,
    openVpn: fixture.ProbeOpenVpn()
      ..connected = true
      ..protectionActive = true,
  );
  addTearDown(controller.dispose);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
  await controller.toggleConnection();
  await tester.pumpAndSettle();
  expect(controller.vpnStatus, VpnStatus.disconnected);
  expect(controller.openVpn.disconnectCalls, 1);
  expect(controller.openVpn.protectionActive, isFalse);
  return controller;
}

Future<void> _chooseLanguage(WidgetTester tester, AppLanguage language) async {
  await tester.tap(find.byType(DropdownButton<AppLanguage>));
  await tester.pumpAndSettle();
  final menu = find.byType(Scrollable).last;
  tester.state<ScrollableState>(menu).position.jumpTo(0);
  await tester.pumpAndSettle();
  final option = find.descendant(
    of: menu,
    matching: find.text(language.nativeName),
  );
  await tester.scrollUntilVisible(option, 160, scrollable: menu);
  await tester.pumpAndSettle();
  await tester.tap(option);
  await tester.pumpAndSettle();
}

void main() {
  testWidgets(
    'all language menu selections survive an explicit OpenVPN disconnect',
    (tester) async {
      final store = _LanguageStore();
      final controller = await _afterOpenVpnDisconnect(tester, store);
      for (final language in AppLanguage.sortedValues.skip(1)) {
        await _chooseLanguage(tester, language);
        expect(controller.language, language, reason: language.name);
        expect(
          tester
              .widget<DropdownButton<AppLanguage>>(
                find.byType(DropdownButton<AppLanguage>),
              )
              .value,
          language,
          reason: language.name,
        );
        expect(controller.vpnStatus, VpnStatus.disconnected);
        expect(controller.openVpn.disconnectCalls, 1);
        expect(controller.openVpn.importCalls, 0);
        expect(controller.openVpn.protectionActive, isFalse);
        expect(tester.takeException(), isNull, reason: language.name);
      }
      expect(
        store.writes,
        AppLanguage.sortedValues
            .skip(1)
            .map((language) => language.storageValue),
      );
    },
  );

  testWidgets(
    'open language menu survives controller notifications after disconnect',
    (tester) async {
      final controller = await _afterOpenVpnDisconnect(
        tester,
        _LanguageStore(),
      );
      await tester.tap(find.byType(DropdownButton<AppLanguage>));
      await tester.pumpAndSettle();
      for (var notification = 0; notification < 3; notification++) {
        controller.notifyListeners();
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }
      final menu = find.byType(Scrollable).last;
      tester.state<ScrollableState>(menu).position.jumpTo(0);
      await tester.pumpAndSettle();
      final option = find.descendant(
        of: menu,
        matching: find.text(AppLanguage.english.nativeName),
      );
      await tester.scrollUntilVisible(option, 160, scrollable: menu);
      await tester.tap(option);
      await tester.pumpAndSettle();
      expect(controller.language, AppLanguage.english);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'pending language selection can finish after the settings page is removed',
    (tester) async {
      final store = _LanguageStore()..writeGate = Completer<void>();
      final controller = await _afterOpenVpnDisconnect(tester, store);
      await _chooseLanguage(tester, AppLanguage.english);
      expect(controller.language, AppLanguage.french);
      controller.selectSection(AppSection.connection);
      await tester.pumpAndSettle();
      store.writeGate!.complete();
      await tester.pumpAndSettle();
      expect(controller.language, AppLanguage.english);
      expect(controller.vpnStatus, VpnStatus.disconnected);
      expect(tester.takeException(), isNull);
      expect(find.text('VPN connection'), findsOneWidget);
    },
  );
}
