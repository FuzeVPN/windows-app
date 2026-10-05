// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';

import 'generated_catalogs.dart';

/// Persist stable locale identifiers; `system` follows Windows.
enum AppLanguage {
  system,
  english,
  spanish,
  brazilianPortuguese,
  german,
  french,
  arabic,
  turkish,
  japanese,
  indonesian,
  russian,
  italian,
  korean,
  polish,
  dutch,
  hindi,
  vietnamese,
  ukrainian,
  thai,
  simplifiedChinese,
  traditionalChinese,
  persian,
  urdu,
  filipino,
  malay,
  romanian,
  czech,
  swedish,
  danish,
  norwegian,
  greek;

  /// Endonym order, independent of the currently selected interface language.
  /// Latin accents are ignored; deterministic Unicode order keeps other scripts together.
  static final List<AppLanguage> sortedValues = List.unmodifiable([
    AppLanguage.system,
    ...(AppLanguage.values
        .where((language) => language != AppLanguage.system)
        .toList()
      ..sort((a, b) => a.nativeSortKey.compareTo(b.nativeSortKey))),
  ]);
}

extension AppLanguageLocale on AppLanguage {
  Locale? get locale => switch (this) {
    AppLanguage.system => null,
    AppLanguage.english => const Locale('en'),
    AppLanguage.spanish => const Locale('es'),
    AppLanguage.brazilianPortuguese => const Locale('pt', 'BR'),
    AppLanguage.german => const Locale('de'),
    AppLanguage.french => const Locale('fr'),
    AppLanguage.arabic => const Locale('ar'),
    AppLanguage.turkish => const Locale('tr'),
    AppLanguage.japanese => const Locale('ja'),
    AppLanguage.indonesian => const Locale('id'),
    AppLanguage.russian => const Locale('ru'),
    AppLanguage.italian => const Locale('it'),
    AppLanguage.korean => const Locale('ko'),
    AppLanguage.polish => const Locale('pl'),
    AppLanguage.dutch => const Locale('nl'),
    AppLanguage.hindi => const Locale('hi'),
    AppLanguage.vietnamese => const Locale('vi'),
    AppLanguage.ukrainian => const Locale('uk'),
    AppLanguage.thai => const Locale('th'),
    AppLanguage.simplifiedChinese => const Locale.fromSubtags(
      languageCode: 'zh',
      scriptCode: 'Hans',
    ),
    AppLanguage.traditionalChinese => const Locale.fromSubtags(
      languageCode: 'zh',
      scriptCode: 'Hant',
    ),
    AppLanguage.persian => const Locale('fa'),
    AppLanguage.urdu => const Locale('ur'),
    AppLanguage.filipino => const Locale('fil'),
    AppLanguage.malay => const Locale('ms'),
    AppLanguage.romanian => const Locale('ro'),
    AppLanguage.czech => const Locale('cs'),
    AppLanguage.swedish => const Locale('sv'),
    AppLanguage.danish => const Locale('da'),
    AppLanguage.norwegian => const Locale('nb'),
    AppLanguage.greek => const Locale('el'),
  };

  String get storageValue => switch (this) {
    AppLanguage.system => 'system',
    AppLanguage.english => 'en',
    AppLanguage.spanish => 'es',
    AppLanguage.brazilianPortuguese => 'pt_BR',
    AppLanguage.german => 'de',
    AppLanguage.french => 'fr',
    AppLanguage.arabic => 'ar',
    AppLanguage.turkish => 'tr',
    AppLanguage.japanese => 'ja',
    AppLanguage.indonesian => 'id',
    AppLanguage.russian => 'ru',
    AppLanguage.italian => 'it',
    AppLanguage.korean => 'ko',
    AppLanguage.polish => 'pl',
    AppLanguage.dutch => 'nl',
    AppLanguage.hindi => 'hi',
    AppLanguage.vietnamese => 'vi',
    AppLanguage.ukrainian => 'uk',
    AppLanguage.thai => 'th',
    AppLanguage.simplifiedChinese => 'zh_Hans',
    AppLanguage.traditionalChinese => 'zh_Hant',
    AppLanguage.persian => 'fa',
    AppLanguage.urdu => 'ur',
    AppLanguage.filipino => 'fil',
    AppLanguage.malay => 'ms',
    AppLanguage.romanian => 'ro',
    AppLanguage.czech => 'cs',
    AppLanguage.swedish => 'sv',
    AppLanguage.danish => 'da',
    AppLanguage.norwegian => 'nb',
    AppLanguage.greek => 'el',
  };

  String get nativeName => switch (this) {
    AppLanguage.system => 'Système',
    AppLanguage.english => 'English',
    AppLanguage.spanish => 'Español',
    AppLanguage.brazilianPortuguese => 'Português (Brasil)',
    AppLanguage.german => 'Deutsch',
    AppLanguage.french => 'Français',
    AppLanguage.arabic => 'العربية',
    AppLanguage.turkish => 'Türkçe',
    AppLanguage.japanese => '日本語',
    AppLanguage.indonesian => 'Bahasa Indonesia',
    AppLanguage.russian => 'Русский',
    AppLanguage.italian => 'Italiano',
    AppLanguage.korean => '한국어',
    AppLanguage.polish => 'Polski',
    AppLanguage.dutch => 'Nederlands',
    AppLanguage.hindi => 'हिन्दी',
    AppLanguage.vietnamese => 'Tiếng Việt',
    AppLanguage.ukrainian => 'Українська',
    AppLanguage.thai => 'ไทย',
    AppLanguage.simplifiedChinese => '简体中文',
    AppLanguage.traditionalChinese => '繁體中文',
    AppLanguage.persian => 'فارسی',
    AppLanguage.urdu => 'اردو',
    AppLanguage.filipino => 'Filipino',
    AppLanguage.malay => 'Bahasa Melayu',
    AppLanguage.romanian => 'Română',
    AppLanguage.czech => 'Čeština',
    AppLanguage.swedish => 'Svenska',
    AppLanguage.danish => 'Dansk',
    AppLanguage.norwegian => 'Norsk bokmål',
    AppLanguage.greek => 'Ελληνικά',
  };

  /// Latin accents do not move endonyms after Z; other scripts use Unicode order.
  String get nativeSortKey {
    var key = nativeName.toLowerCase();
    const groups = {
      'a': 'áàâäãåāăą',
      'c': 'çćč',
      'd': 'ďđ',
      'e': 'éèêëēĕėęěếềểễệ',
      'i': 'íìîïīĭįı',
      'n': 'ñńň',
      'o': 'óòôöõøōŏő',
      'r': 'řŕ',
      's': 'śšş',
      't': 'ťţ',
      'u': 'úùûüūŭůűų',
      'y': 'ýÿ',
      'z': 'źżž',
    };
    for (final group in groups.entries) {
      for (final rune in group.value.runes) {
        key = key.replaceAll(String.fromCharCode(rune), group.key);
      }
    }
    return key;
  }

  String? get flagCountryCode => switch (this) {
    AppLanguage.system => null,
    AppLanguage.english => 'GB',
    AppLanguage.spanish => 'ES',
    AppLanguage.brazilianPortuguese => 'BR',
    AppLanguage.german => 'DE',
    AppLanguage.french => 'FR',
    AppLanguage.arabic => 'SA',
    AppLanguage.turkish => 'TR',
    AppLanguage.japanese => 'JP',
    AppLanguage.indonesian => 'ID',
    AppLanguage.russian => 'RU',
    AppLanguage.italian => 'IT',
    AppLanguage.korean => 'KR',
    AppLanguage.polish => 'PL',
    AppLanguage.dutch => 'NL',
    AppLanguage.hindi => 'IN',
    AppLanguage.vietnamese => 'VN',
    AppLanguage.ukrainian => 'UA',
    AppLanguage.thai => 'TH',
    AppLanguage.simplifiedChinese => 'CN',
    AppLanguage.traditionalChinese => 'TW',
    AppLanguage.persian => 'IR',
    AppLanguage.urdu => 'PK',
    AppLanguage.filipino => 'PH',
    AppLanguage.malay => 'MY',
    AppLanguage.romanian => 'RO',
    AppLanguage.czech => 'CZ',
    AppLanguage.swedish => 'SE',
    AppLanguage.danish => 'DK',
    AppLanguage.norwegian => 'NO',
    AppLanguage.greek => 'GR',
  };

  bool get isRightToLeft =>
      this == AppLanguage.arabic ||
      this == AppLanguage.persian ||
      this == AppLanguage.urdu;

  static AppLanguage fromStorage(String? value) {
    final normalized = value?.replaceAll('-', '_');
    if (normalized == 'pt') return AppLanguage.brazilianPortuguese;
    if (normalized == 'no') return AppLanguage.norwegian;
    if (normalized == 'tl') return AppLanguage.filipino;
    if (normalized == 'zh') return AppLanguage.simplifiedChinese;
    if (normalized == 'zh_TW' ||
        normalized == 'zh_HK' ||
        normalized == 'zh_MO') {
      return AppLanguage.traditionalChinese;
    }
    if (normalized == 'zh_CN' || normalized == 'zh_SG') {
      return AppLanguage.simplifiedChinese;
    }
    for (final language in AppLanguage.values) {
      if (language.storageValue == normalized) return language;
    }
    return AppLanguage.system;
  }

  static AppLanguage fromLocale(Locale? locale) {
    if (locale == null) return AppLanguage.french;
    final code = locale.languageCode.toLowerCase();
    if (code == 'zh') {
      final script = locale.scriptCode?.toLowerCase();
      if (script == 'hant') return AppLanguage.traditionalChinese;
      if (script == 'hans') return AppLanguage.simplifiedChinese;
      return const [
            'TW',
            'HK',
            'MO',
          ].contains(locale.countryCode?.toUpperCase())
          ? AppLanguage.traditionalChinese
          : AppLanguage.simplifiedChinese;
    }
    final selected = fromStorage(code);
    return selected == AppLanguage.system ? AppLanguage.french : selected;
  }
}

/// Catalogs are compiled into the app and available synchronously to the tray.
class AppStrings {
  const AppStrings._(this.language);
  final AppLanguage language;
  static AppStrings forLanguage(AppLanguage language) => AppStrings._(language);

  static const supportedLocales = [
    Locale('en'),
    Locale('es'),
    Locale('pt', 'BR'),
    Locale('de'),
    Locale('fr'),
    Locale('ar'),
    Locale('tr'),
    Locale('ja'),
    Locale('id'),
    Locale('ru'),
    Locale('it'),
    Locale('ko'),
    Locale('pl'),
    Locale('nl'),
    Locale('hi'),
    Locale('vi'),
    Locale('uk'),
    Locale('th'),
    Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hans'),
    Locale.fromSubtags(languageCode: 'zh', scriptCode: 'Hant'),
    Locale('fa'),
    Locale('ur'),
    Locale('fil'),
    Locale('ms'),
    Locale('ro'),
    Locale('cs'),
    Locale('sv'),
    Locale('da'),
    Locale('nb'),
    Locale('el'),
  ];

  static Locale resolveLocale(Locale? locale) =>
      AppLanguageLocale.fromLocale(locale).locale!;

  String get _catalogCode =>
      language == AppLanguage.system ? 'fr' : language.storageValue;
  String text(String french) {
    final catalog = translationCatalogs[_catalogCode];
    final exact = catalog?[french];
    if (exact != null) return exact;
    // Controllers retain their original messages for state comparisons. Translate
    // their three interpolated forms only at rendering, preserving user data.
    for (final template in _legacyTemplates) {
      final match = template.pattern.firstMatch(french);
      if (match != null) {
        return (catalog?[template.source] ?? template.source).replaceAll(
          template.parameter,
          match.group(1)!,
        );
      }
    }
    return french;
  }

  static final _legacyTemplates = [
    (
      pattern: RegExp(r'^Retrait de l’accès à (.+)…$', dotAll: true),
      source: 'Retrait de l’accès à {location}…',
      parameter: '{location}',
    ),
    (
      pattern: RegExp(r'^Activation sur (.+)…$', dotAll: true),
      source: 'Activation sur {location}…',
      parameter: '{location}',
    ),
    (
      pattern: RegExp(r'^Réessayez dans ([0-9]+) secondes\.$'),
      source: 'Réessayez dans {seconds} secondes.',
      parameter: '{seconds}',
    ),
  ];

  String countryName(String code) {
    final normalized = code.trim().toUpperCase();
    final key = '@country:$normalized';
    return translationCatalogs[_catalogCode]?[key] ??
        sourceCatalog[key] ??
        normalized;
  }

  bool countryMatches(String code, String query) {
    final normalized = code.trim().toUpperCase();
    final search = query.trim().toLowerCase();
    return normalized.toLowerCase().contains(search) ||
        translationCatalogs.values.any(
          (catalog) =>
              catalog['@country:$normalized']?.toLowerCase().contains(search) ??
              false,
        );
  }

  static bool hasCompleteCatalog(AppLanguage language) {
    final code = language == AppLanguage.system ? 'fr' : language.storageValue;
    final candidate = translationCatalogs[code];
    return candidate != null &&
        candidate.length == sourceCatalog.length &&
        sourceCatalog.keys.every(
          (key) => candidate[key]?.trim().isNotEmpty ?? false,
        );
  }

  String languageName(AppLanguage value) =>
      value == AppLanguage.system ? text('Système') : value.nativeName;

  String languageFlag(AppLanguage value) => switch (value) {
    AppLanguage.system => '🌐',
    AppLanguage.english => '🇬🇧',
    AppLanguage.spanish => '🇪🇸',
    AppLanguage.brazilianPortuguese => '🇧🇷',
    AppLanguage.german => '🇩🇪',
    AppLanguage.french => '🇫🇷',
    AppLanguage.arabic => '🇸🇦',
    AppLanguage.turkish => '🇹🇷',
    AppLanguage.japanese => '🇯🇵',
    AppLanguage.indonesian => '🇮🇩',
    AppLanguage.russian => '🇷🇺',
    AppLanguage.italian => '🇮🇹',
    AppLanguage.korean => '🇰🇷',
    AppLanguage.polish => '🇵🇱',
    AppLanguage.dutch => '🇳🇱',
    AppLanguage.hindi => '🇮🇳',
    AppLanguage.vietnamese => '🇻🇳',
    AppLanguage.ukrainian => '🇺🇦',
    AppLanguage.thai => '🇹🇭',
    AppLanguage.simplifiedChinese => '🇨🇳',
    AppLanguage.traditionalChinese => '🇹🇼',
    AppLanguage.persian => '🇮🇷',
    AppLanguage.urdu => '🇵🇰',
    AppLanguage.filipino => '🇵🇭',
    AppLanguage.malay => '🇲🇾',
    AppLanguage.romanian => '🇷🇴',
    AppLanguage.czech => '🇨🇿',
    AppLanguage.swedish => '🇸🇪',
    AppLanguage.danish => '🇩🇰',
    AppLanguage.norwegian => '🇳🇴',
    AppLanguage.greek => '🇬🇷',
  };
}

class AppLocalizations {
  const AppLocalizations(this.locale);
  final Locale locale;
  AppStrings get strings =>
      AppStrings.forLanguage(AppLanguageLocale.fromLocale(locale));
  static AppLocalizations of(BuildContext context) =>
      Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  static const delegate = _AppLocalizationsDelegate();
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();
  @override
  bool isSupported(Locale locale) => AppStrings.supportedLocales.any(
    (item) => item.languageCode == locale.languageCode,
  );
  @override
  Future<AppLocalizations> load(Locale locale) async =>
      AppLocalizations(AppStrings.resolveLocale(locale));
  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

extension AppLocalizationContext on BuildContext {
  String tr(String french) => AppLocalizations.of(this).strings.text(french);
}
