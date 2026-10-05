// SPDX-License-Identifier: MPL-2.0
// Visual review uses synthetic state only. No account, VPN or network operation.
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';
import 'package:intl/intl.dart' show DateFormat;

import 'connection_ux_test.dart' show ConnectionUxController;

class _PreviewController extends ConnectionUxController {
  String previewSubscriptionState = 'active';

  @override
  Future<void> refreshSubscription() async {
    isLoadingSubscription = previewSubscriptionState == 'loading';
    subscriptionErrorMessage = previewSubscriptionState == 'error'
        ? 'Les informations de votre abonnement ne peuvent pas être chargées pour le moment. Réessayez.'
        : null;
    subscription = isLoadingSubscription || subscriptionErrorMessage != null
        ? null
        : Subscription.fromJson({
            'status': previewSubscriptionState,
            'has_access': true,
            'offer_id': 'synthetic-preview',
            'expires_at': '2027-10-01T16:00:00Z',
            'renews_automatically': previewSubscriptionState != 'canceled',
            'cancel_at_period_end': previewSubscriptionState == 'canceled',
            'next_charge_at': '2027-10-01T16:00:00Z',
          });
    notifyListeners();
  }

  // A visual capture must never submit credentials or operate a real tunnel.
  @override
  Future<bool> signIn({required String email, required String password}) =>
      throw StateError('A visual preview cannot authenticate.');

  @override
  Future<void> quickConnect() =>
      throw StateError('A visual preview cannot operate the VPN.');

  @override
  Future<void> signOut() =>
      throw StateError('A visual preview cannot change an account.');

  @override
  Future<void> refreshDevices() =>
      throw StateError('A visual preview cannot contact the devices API.');

  @override
  Future<void> refreshLocations([String? savedLocation]) =>
      throw StateError('A visual preview cannot contact the locations API.');
}

class _PreviewScenario {
  const _PreviewScenario(
    this.name, {
    this.section = AppSection.connection,
    this.theme = ThemeMode.light,
    this.status = VpnStatus.disconnected,
    this.language = AppLanguage.french,
    this.size = const Size(1080, 640),
    this.textScale = 1,
    this.signedOut = false,
    this.openAccount = false,
    this.migration = false,
    this.scrollSubscription = false,
  });

  final String name;
  final AppSection section;
  final ThemeMode theme;
  final VpnStatus status;
  final AppLanguage language;
  final Size size;
  final double textScale;
  final bool signedOut;
  final bool openAccount;
  final bool migration;
  final bool scrollSubscription;
}

const _previewScenarios = [
  _PreviewScenario('connection'),
  _PreviewScenario('connection-dark', theme: ThemeMode.dark),
  _PreviewScenario('connected', status: VpnStatus.connected),
  _PreviewScenario(
    'connected-dark',
    status: VpnStatus.connected,
    theme: ThemeMode.dark,
  ),
  _PreviewScenario('blocked', migration: true),
  _PreviewScenario('devices', section: AppSection.devices),
  _PreviewScenario(
    'devices-dark',
    section: AppSection.devices,
    theme: ThemeMode.dark,
  ),
  _PreviewScenario('settings', section: AppSection.settings),
  _PreviewScenario(
    'settings-dark',
    section: AppSection.settings,
    theme: ThemeMode.dark,
  ),
  _PreviewScenario('locations', section: AppSection.locations),
  _PreviewScenario(
    'locations-dark',
    section: AppSection.locations,
    theme: ThemeMode.dark,
  ),
  _PreviewScenario('diagnostic', section: AppSection.help),
  _PreviewScenario(
    'diagnostic-dark',
    section: AppSection.help,
    theme: ThemeMode.dark,
  ),
  _PreviewScenario('sign-in', signedOut: true),
  _PreviewScenario('sign-in-dark', signedOut: true, theme: ThemeMode.dark),
  _PreviewScenario('account', openAccount: true),
  _PreviewScenario('account-dark', openAccount: true, theme: ThemeMode.dark),
  _PreviewScenario('account-canceled', openAccount: true),
  _PreviewScenario('account-loading', openAccount: true),
  _PreviewScenario('account-error', openAccount: true),
  _PreviewScenario('account-zoom', openAccount: true, textScale: 2),
  _PreviewScenario(
    'account-small-zoom',
    openAccount: true,
    textScale: 2,
    size: Size(640, 360),
  ),
  _PreviewScenario(
    'account-small-details',
    openAccount: true,
    scrollSubscription: true,
    size: Size(640, 360),
  ),
  _PreviewScenario(
    'account-small-zoom-details',
    openAccount: true,
    scrollSubscription: true,
    textScale: 2,
    size: Size(640, 360),
  ),
  _PreviewScenario('connection-ar', language: AppLanguage.arabic),
  _PreviewScenario(
    'devices-small',
    section: AppSection.devices,
    size: Size(640, 480),
  ),
  _PreviewScenario('connection-small', size: Size(640, 360)),
  _PreviewScenario(
    'devices-compact',
    section: AppSection.devices,
    size: Size(640, 360),
  ),
  _PreviewScenario('sign-in-small', signedOut: true, size: Size(640, 360)),
  _PreviewScenario('account-small', openAccount: true, size: Size(640, 360)),
  _PreviewScenario('connection-zoom', textScale: 2),
  _PreviewScenario(
    'connection-ar-zoom',
    language: AppLanguage.arabic,
    textScale: 2,
  ),
];

void main() {
  testWidgets('visual review of desktop layout with synthetic data', (
    tester,
  ) async {
    await tester.runAsync(() async {
      final archivo = File('assets/fonts/Archivo-Variable.ttf');
      expect(
        await archivo.exists(),
        isTrue,
        reason: 'Archivo must be captured.',
      );
      final archivoLoader = FontLoader('Archivo')
        ..addFont(
          Future.value(ByteData.sublistView(await archivo.readAsBytes())),
        );
      await archivoLoader.load();
      for (final entry in {
        'Segoe UI Variable Display': 'C:/Windows/Fonts/SegUIVar.ttf',
        'Segoe UI': 'C:/Windows/Fonts/segoeui.ttf',
        'Roboto': 'C:/Windows/Fonts/segoeui.ttf',
        'Tahoma': 'C:/Windows/Fonts/tahoma.ttf',
        'MaterialIcons':
            '.toolchain/flutter/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
      }.entries) {
        final file = File(entry.value);
        if (!await file.exists()) continue;
        final loader = FontLoader(entry.key)
          ..addFont(
            Future.value(ByteData.sublistView(await file.readAsBytes())),
          );
        await loader.load();
      }
    });
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1080, 640);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    for (final scenario in _previewScenarios) {
      tester.view.physicalSize = scenario.size;
      tester.platformDispatcher.textScaleFactorTestValue = scenario.textScale;
      final app = _PreviewController()
        ..previewSubscriptionState = switch (scenario.name) {
          'account-canceled' => 'canceled',
          'account-loading' => 'loading',
          'account-error' => 'error',
          _ => 'active',
        }
        ..section = scenario.section
        ..language = scenario.language
        ..vpnStatus = scenario.status
        ..activeProtocol = null
        ..apiReachable = true
        ..isLoadingDevices = false
        ..devicesReachable = true
        ..themeMode = scenario.theme
        ..profile = scenario.signedOut
            ? null
            : const UserProfile(
                userId: 'synthetic-preview',
                email: 'alex@example.invalid',
                firstName: 'Alex',
                emailVerified: true,
              );
      if (scenario.section == AppSection.devices) {
        app.deviceLimit = 5;
        app.currentDeviceId = 'preview-0';
        app.devices = [
          for (var i = 0; i < 4; i++)
            VpnDevice(
              deviceId: 'preview-$i',
              name: [
                'PC principal',
                'Ordinateur portable',
                'PC du salon',
                'Ordinateur de travail',
              ][i],
              location: app.locations.first,
              createdAt: DateTime(2026, 9, 12 + i),
            ),
        ];
      } else if (scenario.status == VpnStatus.connected) {
        app.activeProtocol = VpnProtocol.openVpn;
        app.tunnelLocationId = app.selectedLocation!.id;
        app.connectedAt = DateTime.now().subtract(const Duration(minutes: 12));
      } else if (scenario.migration) {
        app.simulateMigration();
      } else if (scenario.section == AppSection.locations) {
        app.locations = [
          ...app.locations,
          const Location(
            id: 'nl-preview',
            city: 'Amsterdam',
            countryCode: 'NL',
            displayName: 'Amsterdam 1',
          ),
          const Location(
            id: 'fr-preview',
            city: 'Paris',
            countryCode: 'FR',
            displayName: 'Paris 1',
          ),
          const Location(
            id: 'gb-preview',
            city: 'London',
            countryCode: 'GB',
            displayName: 'London 1',
          ),
        ];
      }
      final key = GlobalKey();
      await tester.pumpWidget(
        RepaintBoundary(
          key: key,
          child: FuzeVpnApp(controller: app),
        ),
      );
      await tester.pumpAndSettle();
      if (scenario.openAccount) {
        final account = find.byTooltip('Mon compte');
        expect(account, findsOneWidget, reason: scenario.name);
        await tester.ensureVisible(account);
        await tester.tap(account);
        await tester.pumpAndSettle();
        if (scenario.scrollSubscription) {
          final expiration = DateFormat.yMMMMd(
            'fr',
          ).add_Hm().format(app.subscription!.expiresAt!.toLocal());
          final expirationFact = find
              .ancestor(
                of: find.text(expiration).first,
                matching: find.byType(Row),
              )
              .first;
          await Scrollable.ensureVisible(
            tester.element(expirationFact),
            alignment: 0,
          );
          await tester.pumpAndSettle();
        }
      }
      if (scenario.signedOut) {
        expect(find.byType(AlertDialog), findsOneWidget, reason: scenario.name);
        final email = find.byWidgetPredicate(
          (widget) =>
              widget is TextField &&
              widget.keyboardType == TextInputType.emailAddress,
        );
        final password = find.byWidgetPredicate(
          (widget) => widget is TextField && widget.obscureText,
        );
        await tester.enterText(email, 'alex@example.invalid');
        await tester.enterText(password, 'synthetic-preview-only');
        FocusManager.instance.primaryFocus?.unfocus();
        await tester.pumpAndSettle();
      }
      await tester.runAsync(
        () => precacheImage(
          const AssetImage('assets/branding/fuzevpn-emblem-512.png'),
          key.currentContext!,
        ),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull, reason: scenario.name);
      final boundary =
          key.currentContext!.findRenderObject()! as RenderRepaintBoundary;
      await tester.runAsync(() async {
        final image = await boundary.toImage(pixelRatio: 1);
        try {
          final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
          const stage = String.fromEnvironment(
            'UX_STAGE',
            defaultValue: 'after',
          );
          final file = File(
            'build/previews/interface/$stage/${scenario.name}.png',
          );
          await file.parent.create(recursive: true);
          await file.writeAsBytes(bytes!.buffer.asUint8List());
        } finally {
          image.dispose();
        }
      });
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();
    }
  });
}
