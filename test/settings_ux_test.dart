// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';
import 'package:fuzevpn_windows/windows_update_panel.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _SettingsController extends AppController {
  _SettingsController()
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
      ) {
    profile = fixtures.account;
    language = AppLanguage.french;
    section = AppSection.settings;
    isInitialized = true;
  }

  @override
  Future<void> initialize() async {}

  void rebuild() => notifyListeners();
}

Finder _category(String name) =>
    find.byKey(ValueKey('settings-category-$name'));

Future<void> _select(WidgetTester tester, String name) async {
  await tester.tap(_category(name));
  await tester.pumpAndSettle();
  expect(tester.widget<ChoiceChip>(_category(name)).selected, isTrue);
}

void main() {
  Future<void> mount(WidgetTester tester, _SettingsController app) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1280, 720);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(app.dispose);
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
  }

  testWidgets('settings categories give direct access to every existing option', (
    tester,
  ) async {
    final app = _SettingsController();
    await mount(tester, app);
    expect(find.byType(ChoiceChip), findsNWidgets(4));
    expect(find.byType(SegmentedButton<ThemeMode>), findsOneWidget);
    expect(find.byType(DropdownButtonFormField<AppLanguage>), findsOneWidget);
    expect(
      find.widgetWithText(SwitchListTile, 'Lancer avec Windows'),
      findsOneWidget,
    );
    expect(
      find.widgetWithText(SwitchListTile, 'Notifications Windows'),
      findsOneWidget,
    );
    expect(find.widgetWithText(SwitchListTile, 'Kill switch'), findsNothing);

    await _select(tester, 'connection');
    expect(
      find.widgetWithText(SwitchListTile, 'Connexion au démarrage'),
      findsOneWidget,
    );
    expect(
      find.widgetWithText(SwitchListTile, 'Reconnexion automatique'),
      findsOneWidget,
    );
    expect(find.byType(SegmentedButton<VpnProtocolPreference>), findsOneWidget);
    expect(find.byType(SegmentedButton<ThemeMode>), findsNothing);

    await _select(tester, 'privacy');
    for (final label in [
      'Kill switch',
      'Protection DNS',
      'Protection WebRTC',
      'Envoyer automatiquement les rapports d’erreurs importants',
    ]) {
      expect(find.widgetWithText(SwitchListTile, label), findsOneWidget);
    }
    expect(
      find.text(
        'Codes d’erreur et contexte technique liés à votre compte. Conservation sur le serveur : 30 jours. Aucun journal brut ni historique de navigation.',
      ),
      findsOneWidget,
    );
    await _select(tester, 'updates');
    expect(find.byType(WindowsUpdatePanel), findsOneWidget);
    final content = find.byKey(const ValueKey('settings-content-updates'));
    expect(
      find.descendant(of: content, matching: find.text('Gérer mon compte')),
      findsNothing,
    );
    expect(
      find.descendant(of: content, matching: find.text('Se déconnecter')),
      findsNothing,
    );
    expect(app.vpnStatus, VpnStatus.disconnected);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'category access remains visible after scrolling a compact window',
    (tester) async {
      final app = _SettingsController();
      await mount(tester, app);
      tester.view.physicalSize = const Size(640, 360);
      await tester.pumpAndSettle();
      final before = tester.getTopLeft(_category('privacy'));
      await tester.drag(
        find.byKey(const ValueKey('settings-content-general')),
        const Offset(0, -600),
      );
      await tester.pumpAndSettle();
      expect(tester.getTopLeft(_category('privacy')), before);
      await _select(tester, 'privacy');
      expect(
        find.widgetWithText(SwitchListTile, 'Kill switch'),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('category navigation preserves connection protection guards', (
    tester,
  ) async {
    final app = _SettingsController()
      ..vpnStatus = VpnStatus.connected
      ..activeProtocol = VpnProtocol.wireGuard;
    await mount(tester, app);
    await _select(tester, 'privacy');
    for (final label in [
      'Kill switch',
      'Protection DNS',
      'Protection WebRTC',
    ]) {
      expect(
        tester
            .widget<SwitchListTile>(find.widgetWithText(SwitchListTile, label))
            .onChanged,
        isNull,
      );
    }
    expect(
      find.text('Déconnectez le VPN pour modifier ces protections.'),
      findsOneWidget,
    );
    await _select(tester, 'connection');
    expect(
      tester
          .widget<SegmentedButton<VpnProtocolPreference>>(
            find.byType(SegmentedButton<VpnProtocolPreference>),
          )
          .onSelectionChanged,
      isNull,
    );
    expect(
      tester
          .widget<SwitchListTile>(
            find.widgetWithText(SwitchListTile, 'Reconnexion automatique'),
          )
          .onChanged,
      isNotNull,
    );
    expect(app.vpnStatus, VpnStatus.connected);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'compact selector opens privacy and updates at 200 percent text in pt-BR',
    (tester) async {
      final app = _SettingsController()
        ..language = AppLanguage.brazilianPortuguese;
      final strings = AppStrings.forLanguage(AppLanguage.brazilianPortuguese);
      await mount(tester, app);
      tester.view.physicalSize = const Size(640, 360);
      tester.platformDispatcher.textScaleFactorTestValue = 2;
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      await tester.pumpAndSettle();

      final selector = find.byKey(const ValueKey('settings-category-selector'));
      expect(selector, findsOneWidget);
      expect(find.byType(ChoiceChip), findsNothing);
      expect(tester.takeException(), isNull);

      Future<void> selectCategory(String label) async {
        await tester.tap(selector);
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        final option = find.text(strings.text(label)).last;
        await tester.ensureVisible(option);
        await tester.tap(option);
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      }

      await selectCategory('Confidentialité');
      final privacy = find.byKey(const ValueKey('settings-content-privacy'));
      expect(privacy, findsOneWidget);
      for (final label in [
        'Kill switch',
        'Protection DNS',
        'Protection WebRTC',
      ]) {
        expect(
          find.descendant(
            of: privacy,
            matching: find.widgetWithText(SwitchListTile, strings.text(label)),
          ),
          findsOneWidget,
        );
      }

      await selectCategory('Mises à jour');
      final updates = find.byKey(const ValueKey('settings-content-updates'));
      expect(updates, findsOneWidget);
      expect(find.byType(WindowsUpdatePanel), findsOneWidget);
      expect(
        find.descendant(
          of: updates,
          matching: find.text(strings.text('Rechercher une mise à jour')),
        ),
        findsOneWidget,
      );
      expect(privacy, findsNothing);
      expect(app.vpnStatus, VpnStatus.disconnected);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'all settings categories fit narrow and desktop windows in ten languages',
    (tester) async {
      final app = _SettingsController();
      await mount(tester, app);
      for (final size in [const Size(640, 360), const Size(1440, 900)]) {
        tester.view.physicalSize = size;
        for (final language in AppLanguage.values.where(
          (value) => value != AppLanguage.system,
        )) {
          app.language = language;
          app.rebuild();
          await tester.pumpAndSettle();
          for (final category in [
            'general',
            'connection',
            'privacy',
            'updates',
          ]) {
            await _select(tester, category);
            expect(
              tester.takeException(),
              isNull,
              reason: '$size / $language / $category',
            );
          }
        }
      }
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
