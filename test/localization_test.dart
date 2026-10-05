// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';

void main() {
  test('résout les langues avec français comme repli', () {
    expect(AppStrings.resolveLocale(const Locale('fr')), const Locale('fr'));
    expect(
      AppStrings.resolveLocale(const Locale('en', 'US')),
      const Locale('en'),
    );
    expect(AppStrings.resolveLocale(const Locale('es')), const Locale('es'));
    expect(AppStrings.resolveLocale(const Locale('de')), const Locale('de'));
    expect(
      AppStrings.resolveLocale(const Locale('pt', 'BR')),
      const Locale('pt', 'BR'),
    );
    expect(
      AppStrings.resolveLocale(const Locale('pt', 'PT')),
      const Locale('pt', 'BR'),
    );
    expect(AppStrings.resolveLocale(const Locale('it')), const Locale('it'));
    expect(AppStrings.resolveLocale(const Locale('nl')), const Locale('nl'));
    expect(AppStrings.resolveLocale(const Locale('pl')), const Locale('pl'));
    expect(AppStrings.resolveLocale(const Locale('sv')), const Locale('sv'));
    expect(AppStrings.resolveLocale(const Locale('da')), const Locale('da'));
    expect(AppStrings.resolveLocale(const Locale('ja')), const Locale('ja'));
    expect(AppStrings.resolveLocale(const Locale('zz')), const Locale('fr'));
  });

  test('traduit les libellés de navigation et du menu Windows', () {
    expect(
      AppStrings.forLanguage(AppLanguage.english).text('Connexion'),
      'Connection',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.spanish).text('Réglages'),
      'Ajustes',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.german).text('Quitter FuzeVPN'),
      'FuzeVPN beenden',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.french).text('Appareils'),
      'Appareils',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.dutch).text('Connexion'),
      'Verbinding',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.brazilianPortuguese).text('Connexion'),
      'Conexão',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.italian).text('Réglages'),
      'Impostazioni',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.polish).text('Appareils'),
      'Urządzenia',
    );
    expect(AppStrings.forLanguage(AppLanguage.swedish).text('Aide'), 'Hjälp');
    expect(
      AppStrings.forLanguage(AppLanguage.danish).text('Déconnecter'),
      'Afbryd forbindelse',
    );
  });

  test('traduit le réglage de protection WebRTC', () {
    const description =
        'Bloque les communications WebRTC qui tentent de sortir en dehors du tunnel VPN.';

    expect(
      AppStrings.forLanguage(AppLanguage.english).text('Protection WebRTC'),
      'WebRTC protection',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.spanish).text(description),
      'Bloquea las comunicaciones WebRTC que intenten salir fuera del túnel VPN.',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.german).text(description),
      'Blockiert WebRTC-Verbindungen, die versuchen, den VPN-Tunnel zu umgehen.',
    );
    expect(
      AppStrings.forLanguage(AppLanguage.dutch).text(description),
      'Blokkeert WebRTC-verkeer dat buiten de VPN-tunnel probeert te gaan.',
    );
  });

  test('associe un repère visuel à chaque langue', () {
    final strings = AppStrings.forLanguage(AppLanguage.french);
    expect(strings.languageFlag(AppLanguage.system), '🌐');
    expect(strings.languageFlag(AppLanguage.french), '🇫🇷');
    expect(strings.languageFlag(AppLanguage.english), '🇬🇧');
    expect(strings.languageFlag(AppLanguage.spanish), '🇪🇸');
    expect(strings.languageFlag(AppLanguage.german), '🇩🇪');
    expect(strings.languageFlag(AppLanguage.brazilianPortuguese), '🇧🇷');
    expect(strings.languageFlag(AppLanguage.italian), '🇮🇹');
    expect(strings.languageFlag(AppLanguage.dutch), '🇳🇱');
    expect(strings.languageFlag(AppLanguage.polish), '🇵🇱');
    expect(strings.languageFlag(AppLanguage.swedish), '🇸🇪');
    expect(strings.languageFlag(AppLanguage.danish), '🇩🇰');
  });

  test('le sélecteur commence par système et trie les noms affichés', () {
    final languages = AppLanguage.sortedValues;
    expect(languages.first, AppLanguage.system);
    expect(languages.toSet(), AppLanguage.values.toSet());
    expect(languages, hasLength(31));
    final names = languages
        .skip(1)
        .map((value) => value.nativeSortKey)
        .toList();
    expect(names, orderedEquals([...names]..sort()));
    expect(
      languages.indexOf(AppLanguage.czech),
      lessThan(languages.indexOf(AppLanguage.danish)),
    );
    expect(
      languages.indexOf(AppLanguage.czech),
      greaterThan(languages.indexOf(AppLanguage.indonesian)),
    );
  });

  test('chaque langue dispose de tout le catalogue', () {
    for (final language in AppLanguage.values) {
      expect(
        AppStrings.hasCompleteCatalog(language),
        isTrue,
        reason: language.name,
      );
    }
  });

  test('mémorise le choix manuel de langue', () async {
    final store = _LanguageStore();
    final controller = AppController(store: store);
    await controller.setLanguage(AppLanguage.german);
    expect(controller.language, AppLanguage.german);
    expect(store.language, 'de');
    controller.dispose();
  });

  test('mémorise le portugais brésilien sans perdre la région', () async {
    final store = _LanguageStore();
    final controller = AppController(store: store);

    await controller.setLanguage(AppLanguage.brazilianPortuguese);

    expect(controller.language.locale, const Locale('pt', 'BR'));
    expect(store.language, 'pt_BR');
    expect(
      AppLanguageLocale.fromStorage('pt_BR'),
      AppLanguage.brazilianPortuguese,
    );
    controller.dispose();
  });

  testWidgets('applique immédiatement la locale sélectionnée', (tester) async {
    await tester.pumpWidget(
      MaterialApp(
        locale: const Locale('en'),
        supportedLocales: AppStrings.supportedLocales,
        localizationsDelegates: const [AppLocalizations.delegate],
        home: Builder(builder: (context) => Text(context.tr('Connexion'))),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Connection'), findsOneWidget);
  });
}

class _LanguageStore extends SecureStore {
  String? language;
  @override
  Future<void> saveAppLanguage(String value) async => language = value;
}
