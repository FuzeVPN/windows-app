// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';

import '../core/browser_auth.dart' show BrowserAuthPageTexts;
import 'generated_catalogs.dart';
import 'date_time_format.dart';

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
  greek,
  bengali,
  swahili,
  burmese,
  khmer,
  uzbek,
  nepali,
  sinhala,
  tamil,
  telugu,
  marathi,
  gujarati,
  hausa,
  amharic,
  hungarian,
  bulgarian,
  finnish,
  slovak,
  croatian,
  serbian,
  hebrew,
  punjabi,
  kannada,
  malayalam,
  odia,
  pashto,
  lithuanian,
  latvian,
  estonian,
  slovenian,
  albanian,
  kazakh,
  azerbaijani,
  armenian,
  georgian,
  lao,
  malagasy,
  somali,
  yoruba,
  igbo,
  kinyarwanda;

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
    AppLanguage.bengali => const Locale('bn'),
    AppLanguage.swahili => const Locale('sw'),
    AppLanguage.burmese => const Locale('my'),
    AppLanguage.khmer => const Locale('km'),
    AppLanguage.uzbek => const Locale.fromSubtags(
      languageCode: 'uz',
      scriptCode: 'Latn',
    ),
    AppLanguage.nepali => const Locale('ne'),
    AppLanguage.sinhala => const Locale('si'),
    AppLanguage.tamil => const Locale('ta'),
    AppLanguage.telugu => const Locale('te'),
    AppLanguage.marathi => const Locale('mr'),
    AppLanguage.gujarati => const Locale('gu'),
    AppLanguage.hausa => const Locale.fromSubtags(
      languageCode: 'ha',
      scriptCode: 'Latn',
    ),
    AppLanguage.amharic => const Locale('am'),
    AppLanguage.hungarian => const Locale('hu'),
    AppLanguage.bulgarian => const Locale('bg'),
    AppLanguage.finnish => const Locale('fi'),
    AppLanguage.slovak => const Locale('sk'),
    AppLanguage.croatian => const Locale('hr'),
    AppLanguage.serbian => const Locale.fromSubtags(
      languageCode: 'sr',
      scriptCode: 'Cyrl',
    ),
    AppLanguage.hebrew => const Locale('he'),
    AppLanguage.punjabi => const Locale.fromSubtags(
      languageCode: 'pa',
      scriptCode: 'Guru',
    ),
    AppLanguage.kannada => const Locale('kn'),
    AppLanguage.malayalam => const Locale('ml'),
    AppLanguage.odia => const Locale('or'),
    AppLanguage.pashto => const Locale('ps'),
    AppLanguage.lithuanian => const Locale('lt'),
    AppLanguage.latvian => const Locale('lv'),
    AppLanguage.estonian => const Locale('et'),
    AppLanguage.slovenian => const Locale('sl'),
    AppLanguage.albanian => const Locale('sq'),
    AppLanguage.kazakh => const Locale('kk'),
    AppLanguage.azerbaijani => const Locale.fromSubtags(
      languageCode: 'az',
      scriptCode: 'Latn',
    ),
    AppLanguage.armenian => const Locale('hy'),
    AppLanguage.georgian => const Locale('ka'),
    AppLanguage.lao => const Locale('lo'),
    AppLanguage.malagasy => const Locale('mg'),
    AppLanguage.somali => const Locale('so'),
    AppLanguage.yoruba => const Locale('yo'),
    AppLanguage.igbo => const Locale('ig'),
    AppLanguage.kinyarwanda => const Locale('rw'),
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
    AppLanguage.bengali => 'bn',
    AppLanguage.swahili => 'sw',
    AppLanguage.burmese => 'my',
    AppLanguage.khmer => 'km',
    AppLanguage.uzbek => 'uz',
    AppLanguage.nepali => 'ne',
    AppLanguage.sinhala => 'si',
    AppLanguage.tamil => 'ta',
    AppLanguage.telugu => 'te',
    AppLanguage.marathi => 'mr',
    AppLanguage.gujarati => 'gu',
    AppLanguage.hausa => 'ha',
    AppLanguage.amharic => 'am',
    AppLanguage.hungarian => 'hu',
    AppLanguage.bulgarian => 'bg',
    AppLanguage.finnish => 'fi',
    AppLanguage.slovak => 'sk',
    AppLanguage.croatian => 'hr',
    AppLanguage.serbian => 'sr',
    AppLanguage.hebrew => 'he',
    AppLanguage.punjabi => 'pa',
    AppLanguage.kannada => 'kn',
    AppLanguage.malayalam => 'ml',
    AppLanguage.odia => 'or',
    AppLanguage.pashto => 'ps',
    AppLanguage.lithuanian => 'lt',
    AppLanguage.latvian => 'lv',
    AppLanguage.estonian => 'et',
    AppLanguage.slovenian => 'sl',
    AppLanguage.albanian => 'sq',
    AppLanguage.kazakh => 'kk',
    AppLanguage.azerbaijani => 'az',
    AppLanguage.armenian => 'hy',
    AppLanguage.georgian => 'ka',
    AppLanguage.lao => 'lo',
    AppLanguage.malagasy => 'mg',
    AppLanguage.somali => 'so',
    AppLanguage.yoruba => 'yo',
    AppLanguage.igbo => 'ig',
    AppLanguage.kinyarwanda => 'rw',
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
    AppLanguage.bengali => 'বাংলা',
    AppLanguage.swahili => 'Kiswahili',
    AppLanguage.burmese => 'မြန်မာ',
    AppLanguage.khmer => 'ខ្មែរ',
    AppLanguage.uzbek => 'O‘zbekcha',
    AppLanguage.nepali => 'नेपाली',
    AppLanguage.sinhala => 'සිංහල',
    AppLanguage.tamil => 'தமிழ்',
    AppLanguage.telugu => 'తెలుగు',
    AppLanguage.marathi => 'मराठी',
    AppLanguage.gujarati => 'ગુજરાતી',
    AppLanguage.hausa => 'Hausa',
    AppLanguage.amharic => 'አማርኛ',
    AppLanguage.hungarian => 'Magyar',
    AppLanguage.bulgarian => 'Български',
    AppLanguage.finnish => 'Suomi',
    AppLanguage.slovak => 'Slovenčina',
    AppLanguage.croatian => 'Hrvatski',
    AppLanguage.serbian => 'Српски',
    AppLanguage.hebrew => 'עברית',
    AppLanguage.punjabi => 'ਪੰਜਾਬੀ',
    AppLanguage.kannada => 'ಕನ್ನಡ',
    AppLanguage.malayalam => 'മലയാളം',
    AppLanguage.odia => 'ଓଡ଼ିଆ',
    AppLanguage.pashto => 'پښتو',
    AppLanguage.lithuanian => 'Lietuvių',
    AppLanguage.latvian => 'Latviešu',
    AppLanguage.estonian => 'Eesti',
    AppLanguage.slovenian => 'Slovenščina',
    AppLanguage.albanian => 'Shqip',
    AppLanguage.kazakh => 'Қазақша',
    AppLanguage.azerbaijani => 'Azərbaycanca',
    AppLanguage.armenian => 'Հայերեն',
    AppLanguage.georgian => 'ქართული',
    AppLanguage.lao => 'ລາວ',
    AppLanguage.malagasy => 'Malagasy',
    AppLanguage.somali => 'Soomaali',
    AppLanguage.yoruba => 'Yorùbá',
    AppLanguage.igbo => 'Igbo',
    AppLanguage.kinyarwanda => 'Ikinyarwanda',
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
    AppLanguage.bengali => 'BD',
    AppLanguage.swahili => 'KE',
    AppLanguage.burmese => 'MM',
    AppLanguage.khmer => 'KH',
    AppLanguage.uzbek => 'UZ',
    AppLanguage.nepali => 'NP',
    AppLanguage.sinhala => 'LK',
    AppLanguage.tamil => 'IN',
    AppLanguage.telugu => 'IN',
    AppLanguage.marathi => 'IN',
    AppLanguage.gujarati => 'IN',
    AppLanguage.hausa => 'NG',
    AppLanguage.amharic => 'ET',
    AppLanguage.hungarian => 'HU',
    AppLanguage.bulgarian => 'BG',
    AppLanguage.finnish => 'FI',
    AppLanguage.slovak => 'SK',
    AppLanguage.croatian => 'HR',
    AppLanguage.serbian => 'RS',
    AppLanguage.hebrew => 'IL',
    AppLanguage.punjabi => 'IN',
    AppLanguage.kannada => 'IN',
    AppLanguage.malayalam => 'IN',
    AppLanguage.odia => 'IN',
    AppLanguage.pashto => 'AF',
    AppLanguage.lithuanian => 'LT',
    AppLanguage.latvian => 'LV',
    AppLanguage.estonian => 'EE',
    AppLanguage.slovenian => 'SI',
    AppLanguage.albanian => 'AL',
    AppLanguage.kazakh => 'KZ',
    AppLanguage.azerbaijani => 'AZ',
    AppLanguage.armenian => 'AM',
    AppLanguage.georgian => 'GE',
    AppLanguage.lao => 'LA',
    AppLanguage.malagasy => 'MG',
    AppLanguage.somali => 'SO',
    AppLanguage.yoruba => 'NG',
    AppLanguage.igbo => 'NG',
    AppLanguage.kinyarwanda => 'RW',
  };

  bool get isRightToLeft =>
      this == AppLanguage.arabic ||
      this == AppLanguage.persian ||
      this == AppLanguage.urdu ||
      this == AppLanguage.hebrew ||
      this == AppLanguage.pashto;

  static AppLanguage fromStorage(String? value) {
    final normalized = value?.replaceAll('-', '_');
    if (normalized == 'pt') return AppLanguage.brazilianPortuguese;
    if (normalized == 'no') return AppLanguage.norwegian;
    if (normalized == 'tl') return AppLanguage.filipino;
    if (normalized == 'iw') return AppLanguage.hebrew;
    for (final (code, script, language) in [
      ('pa', 'Guru', AppLanguage.punjabi),
      ('az', 'Latn', AppLanguage.azerbaijani),
      ('uz', 'Latn', AppLanguage.uzbek),
      ('sr', 'Cyrl', AppLanguage.serbian),
      ('ha', 'Latn', AppLanguage.hausa),
    ]) {
      if (normalized == '${code}_$script') return language;
    }
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
    final requiredScript = selected.locale?.scriptCode;
    if (requiredScript != null &&
        locale.scriptCode != null &&
        locale.scriptCode!.toLowerCase() != requiredScript.toLowerCase()) {
      return AppLanguage.french;
    }
    if (locale.scriptCode == null &&
        ((selected == AppLanguage.punjabi && locale.countryCode == 'PK') ||
            (selected == AppLanguage.azerbaijani &&
                locale.countryCode == 'IR') ||
            (selected == AppLanguage.uzbek && locale.countryCode == 'AF'))) {
      return AppLanguage.french;
    }
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
    Locale('bn'),
    Locale('sw'),
    Locale('my'),
    Locale('km'),
    Locale.fromSubtags(languageCode: 'uz', scriptCode: 'Latn'),
    Locale('ne'),
    Locale('si'),
    Locale('ta'),
    Locale('te'),
    Locale('mr'),
    Locale('gu'),
    Locale.fromSubtags(languageCode: 'ha', scriptCode: 'Latn'),
    Locale('am'),
    Locale('hu'),
    Locale('bg'),
    Locale('fi'),
    Locale('sk'),
    Locale('hr'),
    Locale.fromSubtags(languageCode: 'sr', scriptCode: 'Cyrl'),
    Locale('he'),
    Locale.fromSubtags(languageCode: 'pa', scriptCode: 'Guru'),
    Locale('kn'),
    Locale('ml'),
    Locale('or'),
    Locale('ps'),
    Locale('lt'),
    Locale('lv'),
    Locale('et'),
    Locale('sl'),
    Locale('sq'),
    Locale('kk'),
    Locale.fromSubtags(languageCode: 'az', scriptCode: 'Latn'),
    Locale('hy'),
    Locale('ka'),
    Locale('lo'),
    Locale('mg'),
    Locale('so'),
    Locale('yo'),
    Locale('ig'),
    Locale('rw'),
  ];

  static Locale resolveLocale(Locale? locale) =>
      AppLanguageLocale.fromLocale(locale).locale!;

  String get _catalogCode =>
      language == AppLanguage.system ? 'fr' : language.storageValue;

  BrowserAuthPageTexts get browserAuthPageTexts => BrowserAuthPageTexts(
    languageTag: (language.locale ?? const Locale('fr')).toLanguageTag(),
    isRightToLeft: language.isRightToLeft,
    receivedTitle: text('Autorisation reçue'),
    receivedMessage: text('Revenez dans FuzeVPN pour terminer la connexion.'),
    deniedTitle: text('Autorisation refusée'),
    deniedMessage: text('La connexion a été annulée dans le navigateur.'),
    invalidTitle: text('Demande invalide'),
    invalidMessage: text(
      'La réponse de connexion du navigateur est invalide. Recommencez depuis FuzeVPN.',
    ),
  );

  // Noun labels followed by values keep the same grammatical form for every
  // count in every language, including zero and compound numbers.
  String serverCount(int count) =>
      text('Serveurs : {count}').replaceAll('{count}', '$count');

  String cityCount(int count) =>
      text('Villes : {count}').replaceAll('{count}', '$count');

  String retryAfter(int seconds) => _retryDelay('$seconds');

  String _retryDelay(String seconds) => text(
    'Délai avant réessai : {seconds} s.',
  ).replaceAll('{seconds}', seconds);

  String text(String french) {
    final catalog = translationCatalogs[_catalogCode];
    final exact = catalog?[french];
    if (exact != null) return exact;
    final retry = _retryPattern.firstMatch(french);
    if (retry != null) return _retryDelay(retry.group(1)!);
    // Controllers retain their original messages for state comparisons. Translate
    // their interpolated forms only at rendering, preserving user data.
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

  static final _retryPattern = RegExp(r'^Réessayez dans ([0-9]+) secondes\.$');

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
    AppLanguage.bengali => '🇧🇩',
    AppLanguage.swahili => '🇰🇪',
    AppLanguage.burmese => '🇲🇲',
    AppLanguage.khmer => '🇰🇭',
    AppLanguage.uzbek => '🇺🇿',
    AppLanguage.nepali => '🇳🇵',
    AppLanguage.sinhala => '🇱🇰',
    AppLanguage.tamil => '🇮🇳',
    AppLanguage.telugu => '🇮🇳',
    AppLanguage.marathi => '🇮🇳',
    AppLanguage.gujarati => '🇮🇳',
    AppLanguage.hausa => '🇳🇬',
    AppLanguage.amharic => '🇪🇹',
    AppLanguage.hungarian => '🇭🇺',
    AppLanguage.bulgarian => '🇧🇬',
    AppLanguage.finnish => '🇫🇮',
    AppLanguage.slovak => '🇸🇰',
    AppLanguage.croatian => '🇭🇷',
    AppLanguage.serbian => '🇷🇸',
    AppLanguage.hebrew => '🇮🇱',
    AppLanguage.punjabi => '🇮🇳',
    AppLanguage.kannada => '🇮🇳',
    AppLanguage.malayalam => '🇮🇳',
    AppLanguage.odia => '🇮🇳',
    AppLanguage.pashto => '🇦🇫',
    AppLanguage.lithuanian => '🇱🇹',
    AppLanguage.latvian => '🇱🇻',
    AppLanguage.estonian => '🇪🇪',
    AppLanguage.slovenian => '🇸🇮',
    AppLanguage.albanian => '🇦🇱',
    AppLanguage.kazakh => '🇰🇿',
    AppLanguage.azerbaijani => '🇦🇿',
    AppLanguage.armenian => '🇦🇲',
    AppLanguage.georgian => '🇬🇪',
    AppLanguage.lao => '🇱🇦',
    AppLanguage.malagasy => '🇲🇬',
    AppLanguage.somali => '🇸🇴',
    AppLanguage.yoruba => '🇳🇬',
    AppLanguage.igbo => '🇳🇬',
    AppLanguage.kinyarwanda => '🇷🇼',
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
  Future<AppLocalizations> load(Locale locale) async {
    await initializeAppDateFormatting();
    return AppLocalizations(AppStrings.resolveLocale(locale));
  }

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

extension AppLocalizationContext on BuildContext {
  String tr(String french) => AppLocalizations.of(this).strings.text(french);
}
