// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

const preparationMessage =
    'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.';
const protectionInformation =
    'La préparation continue. Internet reste bloqué jusqu’à la connexion ou à l’arrêt des protections.';

class ConnectionUxController extends AppController {
  ConnectionUxController() {
    isInitialized = true;
    isLoadingLocations = false;
    language = AppLanguage.french;
    profile = const UserProfile(
      userId: 'synthetic-ux',
      email: 'ux@example.invalid',
      firstName: 'Test',
      emailVerified: true,
    );
    locations = const [
      Location(
        id: 'de-1',
        city: 'Frankfurt',
        countryCode: 'DE',
        displayName: 'Frankfurt 1',
      ),
      Location(
        id: 'de-2',
        city: 'Frankfurt',
        countryCode: 'DE',
        displayName: 'Frankfurt 2',
      ),
    ];
    selectedLocation = locations.last;
    activeProtocol = VpnProtocol.openVpn;
    vpnProtocol = VpnProtocol.openVpn;
  }

  @override
  Future<void> initialize() async {}

  void simulateMigration() {
    vpnStatus = VpnStatus.blocked;
    locationMigration = const LocationMigration(
      migrationId: 'synthetic-migration',
      deviceId: 'synthetic-device',
      sourceLocationId: 'de-1',
      targetLocationId: 'de-2',
      status: LocationMigrationStatus.draining,
      retryAfterSeconds: 2,
    );
    locationMigrationMessage = 'Retrait de l’accès à Frankfurt 1…';
    errorMessage = preparationMessage;
  }
}

void main() {
  testWidgets('both progress notices fit the normal window without scrolling', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    for (final size in [
      const Size(1080, 640),
      const Size(1280, 720),
      const Size(1064, 640),
    ]) {
      tester.view.physicalSize = size;
      final app = ConnectionUxController()..simulateMigration();
      await tester.pumpWidget(FuzeVpnApp(controller: app));
      await tester.pumpAndSettle();
      for (final text in [
        'Retrait de l’accès à Frankfurt 1…',
        protectionInformation,
      ]) {
        final notice = find.text(text);
        expect(notice, findsOneWidget);
        final rect = tester.getRect(notice);
        expect(rect.top, greaterThanOrEqualTo(0), reason: '$size / $text');
        expect(
          rect.bottom,
          lessThanOrEqualTo(size.height),
          reason: '$size / $text',
        );
      }
      expect(find.text('Frankfurt 2'), findsOneWidget);
      expect(find.text('Action requise'), findsNothing);
      expect(find.text('Réessayer'), findsNothing);
      expect(find.text('Information'), findsOneWidget);
      expect(find.text('Trafic bloqué'), findsOneWidget);
      expect(
        find.widgetWithText(FilledButton, 'Déconnecter').hitTestable(),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      app.dispose();
    }
  });

  testWidgets('a real failure retaining protection still offers diagnostics', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1080, 640);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    final app = ConnectionUxController()
      ..vpnStatus = VpnStatus.blocked
      ..errorMessage =
          'La déconnexion VPN n’a pas pu être confirmée. Réessayez la déconnexion.';
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
    expect(find.text('À vérifier'), findsOneWidget);
    expect(find.text('Information'), findsNothing);
    expect(
      find.widgetWithText(OutlinedButton, 'Diagnostic').hitTestable(),
      findsOneWidget,
    );
    await tester.tap(find.widgetWithText(OutlinedButton, 'Diagnostic'));
    await tester.pumpAndSettle();
    expect(app.section, AppSection.help);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    app.dispose();
  });

  testWidgets('the same migration message is shown only once', (tester) async {
    final app = ConnectionUxController()..simulateMigration();
    app.errorMessage = app.locationMigrationMessage;
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
    expect(find.text(app.locationMigrationMessage!), findsOneWidget);
    expect(find.text('Action requise'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
    app.dispose();
  });
}
