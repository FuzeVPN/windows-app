// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_theme.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/date_time_format.dart';
import 'package:fuzevpn_windows/l10n/framework_editing_labels.dart';
import 'package:fuzevpn_windows/l10n/framework_localizations.dart';

void main() {
  setUpAll(initializeAppDateFormatting);

  test('languages without Intl data keep readable dates without throwing', () {
    final date = DateTime(2026, 10, 28, 9, 5);
    for (final code in ['ha', 'zz']) {
      expect(formatAppDateTime(date, Locale(code)), '2026-10-28 09:05');
      expect(
        formatAppDateTime(date, Locale(code), accessible: true),
        '2026-10-28 09:05',
      );
    }
    expect(
      formatAppDateTime(date, const Locale('mg')),
      '28 Oktobra 2026 09:05',
    );
  });
  test(
    'requested writing systems and legacy identifiers resolve explicitly',
    () {
      expect(AppLanguage.punjabi.locale!.scriptCode, 'Guru');
      expect(AppLanguage.azerbaijani.locale!.scriptCode, 'Latn');
      expect(AppLanguage.uzbek.locale!.scriptCode, 'Latn');
      expect(AppLanguage.serbian.locale!.scriptCode, 'Cyrl');
      expect(AppLanguageLocale.fromStorage('pa-Guru'), AppLanguage.punjabi);
      expect(AppLanguageLocale.fromStorage('az-Latn'), AppLanguage.azerbaijani);
      expect(AppLanguageLocale.fromStorage('sr-Cyrl'), AppLanguage.serbian);
      expect(AppLanguageLocale.fromStorage('iw'), AppLanguage.hebrew);
      for (final locale in [
        const Locale.fromSubtags(languageCode: 'pa', scriptCode: 'Arab'),
        const Locale.fromSubtags(languageCode: 'az', scriptCode: 'Arab'),
        const Locale.fromSubtags(languageCode: 'uz', scriptCode: 'Cyrl'),
        const Locale.fromSubtags(languageCode: 'sr', scriptCode: 'Latn'),
        const Locale('pa', 'PK'),
      ]) {
        expect(AppStrings.resolveLocale(locale), const Locale('fr'));
      }
      for (final language in AppLanguage.values.where(
        (l) => l.locale != null,
      )) {
        expect(AppLanguageLocale.fromLocale(language.locale), language);
        expect(AppLanguageLocale.fromStorage(language.storageValue), language);
      }
    },
  );

  test('complex scripts retain joined spacing and Windows font fallback', () {
    for (final code in [
      'bn',
      'ne',
      'si',
      'ta',
      'te',
      'mr',
      'gu',
      'pa',
      'kn',
      'ml',
      'or',
    ]) {
      final theme = AppTheme.light(locale: Locale(code));
      expect(theme.textTheme.headlineLarge!.letterSpacing, 0, reason: code);
      expect(
        theme.textTheme.bodyMedium!.fontFamilyFallback,
        contains('Nirmala UI'),
        reason: code,
      );
    }
    expect(
      AppTheme.light(
        locale: const Locale('my'),
      ).textTheme.bodyMedium!.fontFamilyFallback,
      contains('Myanmar Text'),
    );
    for (final code in ['km', 'lo']) {
      expect(
        AppTheme.light(
          locale: Locale(code),
        ).textTheme.bodyMedium!.fontFamilyFallback,
        contains('Leelawadee UI'),
      );
    }
  });

  testWidgets('all 70 locales load application and framework controls', (
    tester,
  ) async {
    final languages = AppLanguage.values
        .where((l) => l != AppLanguage.system)
        .toList();
    expect(languages, hasLength(70));
    for (final language in languages) {
      var built = false;
      await tester.pumpWidget(
        MaterialApp(
          key: ValueKey(language),
          locale: language.locale,
          supportedLocales: AppStrings.supportedLocales,
          localizationsDelegates: const [
            AppLocalizations.delegate,
            ...appFrameworkLocalizationsDelegates,
          ],
          theme: AppTheme.light(locale: language.locale),
          home: Builder(
            builder: (context) {
              built = true;
              final material = MaterialLocalizations.of(context);
              expect(AppStrings.hasCompleteCatalog(language), isTrue);
              final cupertino = CupertinoLocalizations.of(context);
              expect(Localizations.localeOf(context), language.locale);
              expect(
                Directionality.of(context),
                language.isRightToLeft ? TextDirection.rtl : TextDirection.ltr,
              );
              expect(
                AppLocalizations.of(context).strings.text('Annuler'),
                AppStrings.forLanguage(language).text('Annuler'),
              );
              expect(material.cancelButtonLabel, isNotEmpty);
              expect(cupertino.cancelButtonLabel, isNotEmpty);
              final editing =
                  frameworkEditingLabels[language.locale!.languageCode];
              if (editing != null &&
                  const {
                    'ha',
                    'mg',
                    'so',
                    'yo',
                    'ig',
                    'rw',
                  }.contains(language.storageValue)) {
                expect(material.copyButtonLabel, editing[1]);
                expect(cupertino.copyButtonLabel, editing[1]);
                expect(
                  material.cancelButtonLabel,
                  AppStrings.forLanguage(language).text('Annuler'),
                );
              }
              if (language == AppLanguage.pashto) {
                expect(
                  cupertino.copyButtonLabel,
                  frameworkEditingLabels['ps']![1],
                );
              }
              return const Scaffold(body: TextField());
            },
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(built, isTrue, reason: language.storageValue);
      expect(tester.takeException(), isNull, reason: language.storageValue);
    }
  });
}
