// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/cupertino.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'app_localizations.dart';
import 'framework_editing_labels.dart';

/// Keep the application's locale even where Flutter has no framework catalog.
/// Supported Flutter translations remain authoritative for standard controls.
const appFrameworkLocalizationsDelegates = <LocalizationsDelegate<dynamic>>[
  _MaterialDelegate(),
  _WidgetsDelegate(),
  _CupertinoDelegate(),
];

class _MaterialDelegate extends LocalizationsDelegate<MaterialLocalizations> {
  const _MaterialDelegate();
  @override
  bool isSupported(Locale locale) =>
      AppLocalizations.delegate.isSupported(locale);
  @override
  Future<MaterialLocalizations> load(Locale locale) =>
      GlobalMaterialLocalizations.delegate.isSupported(locale)
      ? GlobalMaterialLocalizations.delegate.load(locale)
      : SynchronousFuture(_AppMaterialLocalizations(locale));
  @override
  bool shouldReload(_MaterialDelegate old) => false;
}

class _AppMaterialLocalizations extends DefaultMaterialLocalizations {
  _AppMaterialLocalizations(Locale locale)
    : strings = AppStrings.forLanguage(AppLanguageLocale.fromLocale(locale)),
      editing = frameworkEditingLabels[locale.languageCode]!;
  final AppStrings strings;
  final List<String> editing;
  @override
  String get cutButtonLabel => editing[0];
  @override
  String get copyButtonLabel => editing[1];
  @override
  String get pasteButtonLabel => editing[2];
  @override
  String get selectAllButtonLabel => editing[3];
  @override
  String get clearButtonTooltip => editing[4];
  @override
  String get searchFieldLabel => editing[5];
  @override
  String get lookUpButtonLabel => editing[6];
  @override
  String get shareButtonLabel => editing[7];
  @override
  String get continueButtonLabel => strings.text('Continuer');
  @override
  String get cancelButtonLabel => strings.text('Annuler');
  @override
  String get closeButtonLabel => strings.text('Fermer');
  @override
  String get closeButtonTooltip => closeButtonLabel;
  @override
  String get modalBarrierDismissLabel => closeButtonLabel;
}

class _WidgetsDelegate extends LocalizationsDelegate<WidgetsLocalizations> {
  const _WidgetsDelegate();
  @override
  bool isSupported(Locale locale) =>
      AppLocalizations.delegate.isSupported(locale);
  @override
  Future<WidgetsLocalizations> load(Locale locale) =>
      GlobalWidgetsLocalizations.delegate.isSupported(locale)
      ? GlobalWidgetsLocalizations.delegate.load(locale)
      : SynchronousFuture(const DefaultWidgetsLocalizations());
  @override
  bool shouldReload(_WidgetsDelegate old) => false;
}

class _CupertinoDelegate extends LocalizationsDelegate<CupertinoLocalizations> {
  const _CupertinoDelegate();
  @override
  bool isSupported(Locale locale) =>
      AppLocalizations.delegate.isSupported(locale);
  @override
  Future<CupertinoLocalizations> load(Locale locale) =>
      GlobalCupertinoLocalizations.delegate.isSupported(locale)
      ? GlobalCupertinoLocalizations.delegate.load(locale)
      : SynchronousFuture(_AppCupertinoLocalizations(locale));
  @override
  bool shouldReload(_CupertinoDelegate old) => false;
}

class _AppCupertinoLocalizations extends DefaultCupertinoLocalizations {
  _AppCupertinoLocalizations(Locale locale)
    : strings = AppStrings.forLanguage(AppLanguageLocale.fromLocale(locale)),
      editing = frameworkEditingLabels[locale.languageCode]!;
  final AppStrings strings;
  final List<String> editing;
  @override
  String get cutButtonLabel => editing[0];
  @override
  String get copyButtonLabel => editing[1];
  @override
  String get pasteButtonLabel => editing[2];
  @override
  String get selectAllButtonLabel => editing[3];
  @override
  String get clearButtonLabel => editing[4];
  @override
  String get searchTextFieldPlaceholderLabel => editing[5];
  @override
  String get lookUpButtonLabel => editing[6];
  @override
  String get shareButtonLabel => editing[7];
  @override
  String get cancelButtonLabel => strings.text('Annuler');
  @override
  String get modalBarrierDismissLabel => strings.text('Fermer');
}
