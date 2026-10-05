// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

void main() {
  const sizes = [
    Size(1280, 720),
    Size(1440, 900),
    Size(900, 700),
    Size(640, 360),
  ];
  const statuses = <VpnStatus, String>{
    VpnStatus.disconnected: 'Non protégé',
    VpnStatus.connected: 'Protégé',
    VpnStatus.blocked: 'Trafic bloqué',
    VpnStatus.error: 'Connexion impossible',
  };

  testWidgets('rend tous les états aux tailles cibles en clair et sombre', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);

    for (final size in sizes) {
      tester.view.physicalSize = size;
      for (final mode in [ThemeMode.light, ThemeMode.dark]) {
        for (final status in statuses.entries) {
          final controller = _ResponsiveController()
            ..themeMode = mode
            ..vpnStatus = status.key;
          await tester.pumpWidget(FuzeVpnApp(controller: controller));
          await tester.pump();

          expect(find.text(status.value), findsOneWidget);
          expect(find.bySemanticsLabel('FuzeVPN'), findsOneWidget);
          expect(
            tester.takeException(),
            isNull,
            reason: '$size / $mode / ${status.key}',
          );
          final context = tester.element(find.byType(Scaffold).first);
          expect(
            Theme.of(context).brightness,
            mode == ThemeMode.dark ? Brightness.dark : Brightness.light,
          );

          await tester.pumpWidget(const SizedBox.shrink());
          controller.dispose();
        }
      }
    }
  });

  test('les dix langues historiques conservent leurs états essentiels', () {
    const expected = <AppLanguage, List<String>>{
      AppLanguage.french: ['Connexion', 'Trafic bloqué', 'Déconnecter'],
      AppLanguage.english: ['Connection', 'Traffic blocked', 'Disconnect'],
      AppLanguage.spanish: ['Conexión', 'Tráfico bloqueado', 'Desconectar'],
      AppLanguage.german: ['Verbindung', 'Datenverkehr blockiert', 'Trennen'],
      AppLanguage.brazilianPortuguese: [
        'Conexão',
        'Tráfego bloqueado',
        'Desconectar',
      ],
      AppLanguage.italian: ['Connessione', 'Traffico bloccato', 'Disconnetti'],
      AppLanguage.dutch: [
        'Verbinding',
        'Verkeer geblokkeerd',
        'Verbinding verbreken',
      ],
      AppLanguage.polish: ['Połączenie', 'Ruch zablokowany', 'Rozłącz'],
      AppLanguage.swedish: ['Anslutning', 'Trafik blockerad', 'Koppla från'],
      AppLanguage.danish: [
        'Forbindelse',
        'Trafik blokeret',
        'Afbryd forbindelse',
      ],
    };

    for (final entry in expected.entries) {
      final strings = AppStrings.forLanguage(entry.key);
      expect(strings.text('Connexion'), entry.value[0]);
      expect(strings.text('Trafic bloqué'), entry.value[1]);
      expect(strings.text('Déconnecter'), entry.value[2]);
    }
  });

  testWidgets('toutes les pages acceptent trente langues et le texte agrandi', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final errorHandler = FlutterError.onError;
    FlutterError.onError = (details) {
      debugPrint(details.toString());
      errorHandler?.call(details);
    };
    addTearDown(() => FlutterError.onError = errorHandler);
    for (final size in [
      const Size(640, 360),
      const Size(900, 700),
      const Size(1280, 720),
    ]) {
      tester.view.physicalSize = size;
      for (final scale in [1.0, 1.5, 2.0]) {
        tester.platformDispatcher.textScaleFactorTestValue = scale;
        for (final language in AppLanguage.values.where(
          (value) => value != AppLanguage.system,
        )) {
          for (final section in AppSection.values) {
            final controller = _ResponsiveController()
              ..language = language
              ..section = section;
            await tester.pumpWidget(FuzeVpnApp(controller: controller));
            await tester.pump();
            expect(
              tester.takeException(),
              isNull,
              reason: '$size / $scale / $language / $section',
            );
            await tester.pumpWidget(const SizedBox.shrink());
            controller.dispose();
          }
        }
      }
    }
  });

  testWidgets('reste possible de déconnecter sans session de compte', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 720);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    for (final status in [VpnStatus.connected, VpnStatus.blocked]) {
      final controller = _DisconnectWithoutSessionController()
        ..profile = null
        ..vpnStatus = status;
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pump();
      expect(find.byType(AlertDialog), findsNothing);
      await tester.tap(find.widgetWithText(FilledButton, 'Déconnecter'));
      await tester.pump();
      expect(controller.disconnectRequests, 1);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    }
  });
}

class _DisconnectWithoutSessionController extends _ResponsiveController {
  int disconnectRequests = 0;

  @override
  bool takeSignInPrompt() => true;

  @override
  Future<void> quickConnect() async {
    disconnectRequests++;
  }
}

class _ResponsiveController extends AppController {
  _ResponsiveController() {
    language = AppLanguage.french;
    isInitialized = true;
    profile = const UserProfile(
      userId: 'user-client',
      email: 'client@example.com',
      firstName: 'Client',
      emailVerified: true,
    );
    isLoadingLocations = false;
    locations = const [
      Location(
        id: 'frankfurt-01',
        city: 'Frankfurt',
        countryCode: 'DE',
        displayName: 'Frankfurt 1',
      ),
    ];
    selectedLocation = locations.first;
  }

  @override
  Future<void> initialize() async {}
}
