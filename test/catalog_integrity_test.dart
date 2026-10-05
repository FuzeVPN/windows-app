// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/generated_catalogs.dart';

void main() {
  test(
    'the 30 complete compiled catalogs match their editable JSON sources',
    () {
      expect(translationCatalogs, hasLength(30));
      expect(AppStrings.supportedLocales, hasLength(30));
      expect(
        sourceCatalog,
        jsonDecode(File('lib/l10n/catalogs/source.json').readAsStringSync()),
      );
      for (final language in AppLanguage.values.where(
        (l) => l != AppLanguage.system,
      )) {
        final code = language.storageValue;
        final catalog = translationCatalogs[code]!;
        expect(AppStrings.hasCompleteCatalog(language), isTrue, reason: code);
        expect(catalog.keys.toSet(), sourceCatalog.keys.toSet(), reason: code);
        expect(
          catalog,
          jsonDecode(File('lib/l10n/catalogs/$code.json').readAsStringSync()),
          reason: code,
        );
        for (final entry in catalog.entries) {
          expect(entry.value.trim(), isNotEmpty, reason: '$code: ${entry.key}');
          expect(
            entry.value,
            isNot(contains('\uFFFD')),
            reason: '$code: ${entry.key}',
          );
          expect(
            _parameters(entry.value),
            _parameters(sourceCatalog[entry.key]!),
            reason: '$code: ${entry.key}',
          );
          if (code != 'fr') {
            for (final name in ['FuzeVPN', 'WireGuard', 'OpenVPN', 'Windows']) {
              if (sourceCatalog[entry.key]!.contains(name)) {
                expect(
                  entry.value,
                  contains(name),
                  reason: '$code: ${entry.key}',
                );
              }
            }
            if (sourceCatalog[entry.key]!.length > 45) {
              expect(
                entry.value,
                isNot(sourceCatalog[entry.key]),
                reason: 'Untranslated sentence: $code: ${entry.key}',
              );
            }
          }
          if (!entry.key.startsWith('@country:')) {
            expect(
              AppStrings.forLanguage(language).text(entry.key),
              entry.value,
              reason: '$code: ${entry.key}',
            );
          }
        }
        // A nonempty catalog is insufficient: unrelated failures must not all
        // collapse into a generic error which hides the cause or user action.
        final longSourcesByTarget = <String, Set<String>>{};
        for (final entry in catalog.entries) {
          if (sourceCatalog[entry.key]!.length > 60) {
            longSourcesByTarget
                .putIfAbsent(entry.value, () => <String>{})
                .add(sourceCatalog[entry.key]!);
          }
        }
        for (final entry in longSourcesByTarget.entries) {
          expect(
            entry.value.length,
            lessThan(3),
            reason: '$code: different messages collapsed into ${entry.key}',
          );
        }
        final countryNames = catalog.entries
            .where((entry) => entry.key.startsWith('@country:'))
            .map((entry) => entry.value)
            .toSet();
        for (final entry in catalog.entries.where(
          (entry) => !entry.key.startsWith('@country:'),
        )) {
          expect(
            countryNames,
            isNot(contains(entry.value)),
            reason: '$code: country name shifted into UI text ${entry.key}',
          );
        }
      }
    },
  );

  test(
    'every persisted language round trips and has a native name and flag',
    () {
      for (final language in AppLanguage.values) {
        expect(AppLanguageLocale.fromStorage(language.storageValue), language);
        expect(language.nativeName, isNotEmpty);
        if (language != AppLanguage.system) {
          expect(AppLanguageLocale.fromLocale(language.locale), language);
          expect(language.flagCountryCode, matches(RegExp(r'^[A-Z]{2}$')));
        }
      }
      expect(
        AppLanguageLocale.fromStorage('pt-BR'),
        AppLanguage.brazilianPortuguese,
      );
      expect(AppLanguageLocale.fromStorage('no'), AppLanguage.norwegian);
      expect(AppLanguageLocale.fromStorage('tl'), AppLanguage.filipino);
      expect(AppLanguageLocale.fromStorage('unknown'), AppLanguage.system);
    },
  );

  test(
    'Chinese script takes precedence over region; system regions resolve correctly',
    () {
      for (final region in ['TW', 'HK', 'MO']) {
        expect(
          AppLanguageLocale.fromLocale(Locale('zh', region)),
          AppLanguage.traditionalChinese,
        );
      }
      for (final region in ['CN', 'SG']) {
        expect(
          AppLanguageLocale.fromLocale(Locale('zh', region)),
          AppLanguage.simplifiedChinese,
        );
      }
      expect(
        AppLanguageLocale.fromLocale(
          const Locale.fromSubtags(
            languageCode: 'zh',
            scriptCode: 'Hans',
            countryCode: 'TW',
          ),
        ),
        AppLanguage.simplifiedChinese,
      );
      expect(
        AppLanguageLocale.fromLocale(
          const Locale.fromSubtags(
            languageCode: 'zh',
            scriptCode: 'Hant',
            countryCode: 'CN',
          ),
        ),
        AppLanguage.traditionalChinese,
      );
      expect(
        AppStrings.resolveLocale(const Locale('zh', 'HK')),
        const Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hant'),
      );
      expect(AppStrings.resolveLocale(null), const Locale('fr'));
    },
  );

  test('only Arabic Persian and Urdu use right to left layout', () {
    expect(AppLanguage.values.where((l) => l.isRightToLeft).toSet(), {
      AppLanguage.arabic,
      AppLanguage.persian,
      AppLanguage.urdu,
    });
  });

  test(
    'dynamic controller messages preserve substitutions and follow language changes',
    () {
      for (final language in AppLanguage.values) {
        final strings = AppStrings.forLanguage(language);
        for (final location in ['Frankfurt 1', '東京 {server}']) {
          expect(
            strings.text('Retrait de l’accès à $location…'),
            strings
                .text('Retrait de l’accès à {location}…')
                .replaceAll('{location}', location),
          );
          expect(
            strings.text('Activation sur $location…'),
            strings
                .text('Activation sur {location}…')
                .replaceAll('{location}', location),
          );
        }
        expect(
          strings.text('Réessayez dans 42 secondes.'),
          strings
              .text('Réessayez dans {seconds} secondes.')
              .replaceAll('{seconds}', '42'),
        );
        expect(strings.text('An unknown message'), 'An unknown message');
      }
    },
  );

  test('country names are translated and searchable across every catalog', () {
    for (final country in sourceCatalog.keys.where(
      (key) => key.startsWith('@country:'),
    )) {
      final code = country.substring('@country:'.length);
      for (final language in AppLanguage.values.where(
        (l) => l != AppLanguage.system,
      )) {
        final strings = AppStrings.forLanguage(language);
        final translated =
            translationCatalogs[language.storageValue]![country]!;
        expect(strings.countryName(' ${code.toLowerCase()} '), translated);
        expect(strings.countryMatches(code, translated), isTrue);
      }
    }
    expect(AppStrings.forLanguage(AppLanguage.english).countryName('zz'), 'ZZ');
  });
}

List<String> _parameters(String text) => RegExp(
  r'\{[A-Za-z_][A-Za-z0-9_]*\}',
).allMatches(text).map((match) => match.group(0)!).toList()..sort();
