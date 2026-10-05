// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

void main() {
  final locations = [
    const Location(
      id: 'frankfurt-01',
      city: 'Frankfurt',
      countryCode: 'DE',
      displayName: 'Frankfurt 1',
    ),
    const Location(
      id: 'frankfurt-02',
      city: 'Frankfurt',
      countryCode: 'DE',
      displayName: 'Frankfurt 2',
    ),
  ];

  Future<void> pumpApp(
    WidgetTester tester,
    TestController controller, {
    Size size = const Size(1280, 720),
    double devicePixelRatio = 1,
  }) async {
    controller.language = AppLanguage.french;
    tester.view.physicalSize = Size(
      size.width * devicePixelRatio,
      size.height * devicePixelRatio,
    );
    tester.view.devicePixelRatio = devicePixelRatio;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pump();
  }

  testWidgets('affiche chaque état de connexion sans inventer de métriques', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false;

    for (final entry in <VpnStatus, String>{
      VpnStatus.disconnected: 'Non protégé',
      VpnStatus.preparing: 'Préparation de la connexion',
      VpnStatus.connecting: 'Connexion en cours',
      VpnStatus.connected: 'Protégé',
      VpnStatus.disconnecting: 'Déconnexion en cours',
      VpnStatus.blocked: 'Trafic bloqué',
      VpnStatus.error: 'Connexion impossible',
    }.entries) {
      controller.vpnStatus = entry.key;
      await pumpApp(tester, controller);
      expect(find.text(entry.value), findsOneWidget);
      expect(find.textContaining('0 octet'), findsNothing);
      expect(find.textContaining('00:00'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets('permet de sélectionner un emplacement réel reçu par l’API', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Emplacements'));
    await tester.pumpAndSettle();
    expect(find.text('Allemagne'), findsOneWidget);
    expect(
      find.byKey(const ValueKey('location-server-frankfurt-01')),
      findsNothing,
    );
    await tester.tap(find.byKey(const ValueKey('location-open-country-DE')));
    await tester.pumpAndSettle();
    await tester.tap(
      find.byKey(const ValueKey('location-open-city-DE-frankfurt')),
    );
    await tester.pumpAndSettle();
    expect(find.text('Frankfurt 1'), findsOneWidget);
    expect(find.text('Frankfurt 2'), findsOneWidget);
    expect(find.text('Frankfurt · Allemagne'), findsNWidgets(2));
    expect(find.byKey(const ValueKey('country-flag-DE')), findsNWidgets(2));

    await tester.tap(find.text('Frankfurt 2'));
    await tester.pumpAndSettle();
    expect(controller.selectedLocation?.id, 'frankfurt-02');
  });

  testWidgets('recherche un emplacement sans inventer de données', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Emplacements'));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const ValueKey('location-search')),
      'Frankfurt 2',
    );
    await tester.pump();

    expect(find.text('Frankfurt 2'), findsNWidgets(2));
    expect(find.text('Frankfurt 1'), findsNothing);
    expect(find.textContaining('ms'), findsNothing);
  });

  testWidgets('affiche les drapeaux pour tout code ISO valide', (tester) async {
    const flagLocations = [
      Location(
        id: 'sydney',
        city: 'Sydney',
        countryCode: 'au',
        displayName: 'Sydney',
      ),
      Location(
        id: 'tokyo',
        city: 'Tokyo',
        countryCode: 'JP',
        displayName: 'Tokyo',
      ),
      Location(
        id: 'new-york',
        city: 'New York',
        countryCode: 'US',
        displayName: 'New York',
      ),
    ];
    final controller = TestController()
      ..locations = flagLocations
      ..selectedLocation = flagLocations.first
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Emplacements'));
    await tester.pumpAndSettle();

    expect(find.byKey(const ValueKey('country-flag-AU')), findsOneWidget);
    expect(find.byKey(const ValueKey('country-flag-JP')), findsOneWidget);
    expect(find.byKey(const ValueKey('country-flag-US')), findsOneWidget);
    expect(
      find.descendant(
        of: find.byKey(const ValueKey('country-flag-AU')),
        matching: find.byType(CustomPaint),
      ),
      findsOneWidget,
    );
    expect(
      find.descendant(
        of: find.byKey(const ValueKey('country-flag-JP')),
        matching: find.byType(CustomPaint),
      ),
      findsOneWidget,
    );
    expect(
      find.descendant(
        of: find.byKey(const ValueKey('country-flag-US')),
        matching: find.byType(CustomPaint),
      ),
      findsOneWidget,
    );
    expect(find.text('AU'), findsNothing);
    expect(find.text('JP'), findsNothing);
    expect(find.text('US'), findsNothing);
    expect(find.byIcon(Icons.flag_outlined), findsNothing);
  });

  testWidgets('affiche une durée seulement après confirmation native', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false
      ..vpnStatus = VpnStatus.connected
      ..connectedAt = DateTime.now().subtract(const Duration(seconds: 65));
    await pumpApp(tester, controller);

    expect(find.textContaining('Durée de connexion'), findsOneWidget);
    expect(find.textContaining('01:0'), findsOneWidget);
    expect(find.textContaining('octet'), findsNothing);
    expect(find.textContaining('IP publique'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('ouvre directement l’onglet Appareils depuis la limite', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false
      ..deviceEnrollmentIssue = const DeviceEnrollmentIssue(
        kind: DeviceEnrollmentIssueKind.deviceLimit,
        title: 'Retirez un appareil existant',
        message: 'Retirez un appareil existant avant de vous reconnecter.',
      );
    await pumpApp(tester, controller);

    expect(find.text('Retirez un appareil existant'), findsOneWidget);
    await tester.ensureVisible(find.text('Gérer mes appareils'));
    await tester.tap(find.text('Gérer mes appareils'));
    await tester.pumpAndSettle();

    expect(controller.section, AppSection.devices);
    expect(find.text('Appareils'), findsWidgets);
  });

  test('lit la liste d’appareils sans données WireGuard sensibles', () {
    final deviceList = DeviceList.fromJson({
      'limit': 2,
      'devices': [
        {
          'device_id': 'device-chrome',
          'name': 'Extension Chrome',
          'location': null,
          'created_at': null,
        },
        {
          'device_id': 'device-windows',
          'name': 'FuzeVPN — Windows',
          'location': {
            'id': 'frankfurt-01',
            'display_name': 'Frankfurt 1',
            'city': 'Frankfurt',
            'country_code': 'DE',
          },
          'created_at': '2026-08-10T10:30:00Z',
        },
      ],
    });

    expect(deviceList.limit, 2);
    expect(deviceList.devices, hasLength(2));
    expect(deviceList.devices.first.location, isNull);
    expect(deviceList.devices.last.deviceId, 'device-windows');
    expect(deviceList.devices.last.location?.displayName, 'Frankfurt 1');
  });

  testWidgets('affiche un appareil sans dépendre de sa localisation', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false
      ..devices = const [
        VpnDevice(
          deviceId: 'device-chrome',
          name: 'Extension Chrome',
          location: null,
          createdAt: null,
        ),
      ]
      ..devicesReachable = true;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Appareils'));
    await tester.pumpAndSettle();

    expect(find.text('Extension Chrome'), findsOneWidget);
    expect(find.textContaining('Frankfurt'), findsNothing);
    expect(find.byIcon(Icons.flag_outlined), findsNothing);
  });

  test('lit l’identifiant stable qui lie l’identité WireGuard au compte', () {
    final profile = UserProfile.fromJson({
      'user_id': 'a9e9844d-6fc0-4b34-a524-8f0d77f3df81',
      'email': 'client@example.com',
      'first_name': 'Client',
      'email_verified': true,
    });

    expect(profile.userId, 'a9e9844d-6fc0-4b34-a524-8f0d77f3df81');
  });

  testWidgets('garde la connexion au premier plan sans session', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false
      ..profile = null;
    await pumpApp(tester, controller);
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsOneWidget);
    expect(find.text('Annuler'), findsNothing);

    await tester.sendKeyEvent(LogicalKeyboardKey.escape);
    await tester.pump();
    expect(find.byType(AlertDialog), findsOneWidget);
  });

  testWidgets('mémorise le choix du thème dans le contrôleur', (tester) async {
    final controller = TestController()
      ..locations = locations
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Réglages'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Sombre'));
    await tester.pump();

    expect(controller.themeMode, ThemeMode.dark);

    await tester.tap(find.text('Système'));
    await tester.pump();
    expect(controller.themeMode, ThemeMode.system);
  });

  testWidgets('affiche les drapeaux dans la liste des langues', (tester) async {
    final controller = TestController()
      ..locations = locations
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Réglages'));
    await tester.pumpAndSettle();
    await tester.tap(find.byType(DropdownButtonFormField<AppLanguage>));
    await tester.pumpAndSettle();

    expect(find.byIcon(Icons.language_outlined), findsWidgets);
    final menu = find.byType(Scrollable).last;
    tester.state<ScrollableState>(menu).position.jumpTo(0);
    await tester.pumpAndSettle();
    for (final language in AppLanguage.sortedValues.skip(1)) {
      final flag = find.descendant(
        of: menu,
        matching: find.byKey(
          ValueKey('country-flag-${language.flagCountryCode}'),
        ),
      );
      await tester.scrollUntilVisible(flag, 160, scrollable: menu);
      await tester.pumpAndSettle();
      expect(flag, findsOneWidget, reason: language.nativeName);
    }
  });

  testWidgets('choisit WireGuard par défaut et prépare OpenVPN', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    expect(controller.vpnProtocol, VpnProtocol.wireGuard);
    expect(controller.protocolPreference, VpnProtocolPreference.wireGuard);
    await tester.tap(find.byTooltip('Réglages'));
    await tester.pumpAndSettle();
    await tester.tap(
      find.byKey(const ValueKey('settings-category-connection')),
    );
    await tester.pumpAndSettle();
    expect(find.text('Protocole VPN'), findsOneWidget);

    await tester.ensureVisible(find.text('OpenVPN'));
    await tester.tap(find.text('OpenVPN'));
    await tester.pump();
    expect(controller.vpnProtocol, VpnProtocol.openVpn);
    expect(find.textContaining('OpenVPN sera disponible'), findsNothing);

    await tester.tap(find.text('Automatique'));
    await tester.pump();
    expect(controller.protocolPreference, VpnProtocolPreference.automatic);
    expect(find.textContaining('WireGuard est prioritaire'), findsOneWidget);
  });

  testWidgets('active les protections réseau et masque le réglage IPv6', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Réglages'));
    await tester.pumpAndSettle();
    expect(controller.killSwitchEnabled, isTrue);
    expect(controller.dnsProtectionEnabled, isTrue);
    expect(controller.webRtcProtectionEnabled, isTrue);
    expect(controller.automaticReconnectEnabled, isTrue);
    await tester.tap(find.byKey(const ValueKey('settings-category-privacy')));
    await tester.pumpAndSettle();
    expect(find.text('Protection IPv6'), findsNothing);
    final killSwitch = find.widgetWithText(SwitchListTile, 'Kill switch');
    await tester.ensureVisible(killSwitch);
    await tester.tap(killSwitch);
    await tester.pump();
    expect(controller.killSwitchEnabled, isFalse);

    final webRtc = find.widgetWithText(SwitchListTile, 'Protection WebRTC');
    await tester.ensureVisible(webRtc);
    await tester.tap(webRtc);
    await tester.pump();
    expect(controller.webRtcProtectionEnabled, isFalse);

    await tester.tap(
      find.byKey(const ValueKey('settings-category-connection')),
    );
    await tester.pumpAndSettle();
    final reconnect = find.widgetWithText(
      SwitchListTile,
      'Reconnexion automatique',
    );
    await tester.ensureVisible(reconnect);
    await tester.tap(reconnect);
    await tester.pump();
    expect(controller.automaticReconnectEnabled, isFalse);
  });

  testWidgets('verrouille les réglages réseau pendant une connexion', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..isLoadingLocations = false
      ..vpnStatus = VpnStatus.connected;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Réglages'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('settings-category-privacy')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(
      find.text('Déconnectez le VPN pour modifier ces protections.'),
    );
    expect(
      find.text('Déconnectez le VPN pour modifier ces protections.'),
      findsOneWidget,
    );
    final tile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Kill switch'),
    );
    expect(tile.onChanged, isNull);
    final webRtcTile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Protection WebRTC'),
    );
    expect(webRtcTile.onChanged, isNull);
  });

  testWidgets(
    'garde la déconnexion disponible pendant le blocage fail-closed',
    (tester) async {
      final controller = TestController()
        ..locations = locations
        ..isLoadingLocations = false
        ..vpnStatus = VpnStatus.blocked;
      await pumpApp(tester, controller);

      expect(find.text('Trafic bloqué'), findsOneWidget);
      expect(find.text('Déconnecter'), findsOneWidget);

      await tester.tap(find.byTooltip('Réglages'));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('settings-category-privacy')));
      await tester.pumpAndSettle();
      final tile = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'Kill switch'),
      );
      expect(tile.onChanged, isNull);
    },
  );

  testWidgets('explique clairement une erreur de liste d’emplacements', (
    tester,
  ) async {
    final controller = TestController()
      ..isLoadingLocations = false
      ..apiReachable = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Emplacements'));
    await tester.pumpAndSettle();
    expect(find.text('Service indisponible'), findsOneWidget);
    expect(find.text('Réessayer'), findsOneWidget);
  });

  testWidgets('conserve une mise en page sans débordement à 1440 × 900', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false;
    await pumpApp(tester, controller, size: const Size(1440, 900));

    expect(find.text('Connexion VPN'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('retire les mentions promotionnelles WireGuard des réglages', (
    tester,
  ) async {
    final controller = TestController()
      ..locations = locations
      ..selectedLocation = locations.first
      ..isLoadingLocations = false;
    await pumpApp(tester, controller);

    await tester.tap(find.byTooltip('Réglages'));
    await tester.pumpAndSettle();
    await tester.tap(
      find.byKey(const ValueKey('settings-category-connection')),
    );
    await tester.pumpAndSettle();
    expect(find.text('Module WireGuard'), findsNothing);
    expect(find.text('Intégré à FuzeVPN'), findsNothing);
    expect(
      find.text(
        'WireGuard est le protocole actif par défaut. OpenVPN est disponible lorsque l’emplacement sélectionné le propose.',
      ),
      findsNothing,
    );
  });

  testWidgets(
    'reste utilisable dans une fenêtre compacte et expose les actions',
    (tester) async {
      final controller = TestController()
        ..locations = locations
        ..isLoadingLocations = false;
      final semantics = tester.ensureSemantics();
      await pumpApp(
        tester,
        controller,
        size: const Size(640, 360),
        devicePixelRatio: 2,
      );

      expect(find.text('FuzeVPN'), findsOneWidget);
      expect(find.bySemanticsLabel('État VPN : Non protégé'), findsOneWidget);
      expect(find.bySemanticsLabel('Connexion rapide'), findsOneWidget);
      expect(tester.takeException(), isNull);
      semantics.dispose();
    },
  );
}

class TestController extends AppController {
  TestController() {
    profile = const UserProfile(
      userId: 'user-client',
      email: 'client@example.com',
      firstName: 'Client',
      emailVerified: true,
    );
  }

  @override
  Future<void> initialize() async {
    isInitialized = true;
    notifyListeners();
  }

  @override
  Future<void> selectLocation(Location value) async {
    selectedLocation = value;
    notifyListeners();
  }

  @override
  Future<LocationChangePreparation> prepareLocationChange(
    Location value,
  ) async {
    await selectLocation(value);
    return LocationChangePreparation.selectedLocally;
  }

  @override
  Future<void> setTheme(ThemeMode value) async {
    themeMode = value;
    notifyListeners();
  }

  @override
  Future<void> setVpnProtocol(VpnProtocol value) async {
    vpnProtocol = value;
    protocolPreference = value == VpnProtocol.openVpn
        ? VpnProtocolPreference.openVpn
        : VpnProtocolPreference.wireGuard;
    notifyListeners();
  }

  @override
  Future<void> setProtocolPreference(VpnProtocolPreference value) async {
    protocolPreference = value;
    vpnProtocol = value == VpnProtocolPreference.openVpn
        ? VpnProtocol.openVpn
        : VpnProtocol.wireGuard;
    notifyListeners();
  }

  @override
  Future<void> setKillSwitch(bool value) async {
    killSwitchEnabled = value;
    notifyListeners();
  }

  @override
  Future<void> setDnsProtection(bool value) async {
    dnsProtectionEnabled = value;
    notifyListeners();
  }

  @override
  Future<void> setWebRtcProtection(bool value) async {
    webRtcProtectionEnabled = value;
    notifyListeners();
  }

  @override
  Future<void> setAutomaticReconnect(bool value) async {
    automaticReconnectEnabled = value;
    notifyListeners();
  }

  @override
  Future<void> refreshLocations([String? savedLocation]) async {
    isLoadingLocations = false;
    notifyListeners();
  }
}
