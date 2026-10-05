// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/app_shell.dart';
import 'package:fuzevpn_windows/app_theme.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

class _DeviceController extends AppController {
  _DeviceController() {
    isInitialized = true;
    isLoadingLocations = false;
    section = AppSection.devices;
    language = AppLanguage.french;
    profile = const UserProfile(
      userId: 'device-layout-user',
      email: 'device-layout@example.invalid',
      firstName: 'Test',
      emailVerified: true,
    );
    deviceLimit = 4;
    devices = List.generate(
      4,
      (index) => VpnDevice(
        deviceId: 'device-$index',
        name: [
          'Ordinateur Windows',
          'Téléphone',
          'Tablette',
          'Portable',
        ][index],
        location: null,
        createdAt: DateTime(2026, 9, 10 + index),
      ),
    );
  }

  final revoked = <String>[];

  @override
  Future<void> initialize() async {}

  @override
  Future<void> refreshDevices() async {}

  @override
  bool isCurrentDevice(VpnDevice device) => device.deviceId == 'device-0';

  @override
  Future<DeviceRevocationResult> revokeDevice(VpnDevice device) async {
    revoked.add(device.deviceId);
    return DeviceRevocationResult.revoked;
  }
}

void _setSize(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

void main() {
  testWidgets('four devices and their actions fit a 1080 by 640 window', (
    tester,
  ) async {
    _setSize(tester, const Size(1080, 640));
    final controller = _DeviceController();
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pumpAndSettle();

    expect(find.text('Appareils : 4 / 4'), findsOneWidget);
    expect(find.text('Cet appareil'), findsOneWidget);
    for (final device in controller.devices) {
      final row = find.byKey(ValueKey('device-row-${device.deviceId}'));
      final action = find.byKey(ValueKey('device-remove-${device.deviceId}'));
      expect(action.hitTestable(), findsOneWidget);
      expect(tester.getRect(row).bottom, lessThanOrEqualTo(640));
      expect(tester.getSize(row).height, lessThan(100));
      expect(tester.getSize(action).height, greaterThanOrEqualTo(44));
    }
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  for (final language in [AppLanguage.german, AppLanguage.arabic]) {
    testWidgets(
      'device rows reflow with long names and large ${language.name} text',
      (tester) async {
        _setSize(tester, const Size(360, 800));
        final controller = _DeviceController();
        const longName =
            'Ordinateur professionnel personnel avec un nom très long — '
            'ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ';
        controller.devices = [
          VpnDevice(
            deviceId: 'device-0',
            name: longName,
            location: null,
            createdAt: DateTime(2026, 9, 10),
          ),
        ];
        await tester.pumpWidget(
          MaterialApp(
            locale: language.locale,
            supportedLocales: AppStrings.supportedLocales,
            localizationsDelegates: const [
              AppLocalizations.delegate,
              GlobalMaterialLocalizations.delegate,
              GlobalWidgetsLocalizations.delegate,
              GlobalCupertinoLocalizations.delegate,
            ],
            theme: AppTheme.light(locale: language.locale),
            builder: (context, child) => MediaQuery(
              data: MediaQuery.of(
                context,
              ).copyWith(textScaler: TextScaler.linear(1.8)),
              child: child!,
            ),
            home: Scaffold(body: DevicesPage(controller: controller)),
          ),
        );
        await tester.pumpAndSettle();
        final action = find.byKey(const ValueKey('device-remove-device-0'));
        await tester.ensureVisible(action);
        await tester.pumpAndSettle();

        expect(find.text(longName), findsOneWidget);
        expect(action.hitTestable(), findsOneWidget);
        expect(tester.getRect(action).left, greaterThanOrEqualTo(0));
        expect(tester.getRect(action).right, lessThanOrEqualTo(360));
        expect(
          Directionality.of(tester.element(action)),
          language == AppLanguage.arabic
              ? TextDirection.rtl
              : TextDirection.ltr,
        );
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      },
    );
  }

  testWidgets(
    'compact removal actions still require the correct confirmation',
    (tester) async {
      _setSize(tester, const Size(1080, 640));
      final controller = _DeviceController();
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const ValueKey('device-remove-device-0')));
      await tester.pumpAndSettle();
      expect(
        find.textContaining('Cet appareil est utilisé ici.'),
        findsOneWidget,
      );
      expect(controller.revoked, isEmpty);
      await tester.tap(find.text('Annuler'));
      await tester.pumpAndSettle();
      expect(controller.revoked, isEmpty);

      await tester.tap(find.byKey(const ValueKey('device-remove-device-1')));
      await tester.pumpAndSettle();
      expect(find.textContaining('« Téléphone »'), findsOneWidget);
      expect(controller.revoked, isEmpty);
      await tester.tap(find.widgetWithText(FilledButton, 'Retirer'));
      await tester.pumpAndSettle();
      expect(controller.revoked, ['device-1']);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    },
  );
}
