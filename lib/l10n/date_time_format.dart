// SPDX-License-Identifier: MPL-2.0
import 'dart:ui' show Locale;

import 'package:intl/date_symbol_data_local.dart';
import 'package:intl/intl.dart';

Future<void> initializeAppDateFormatting() => initializeDateFormatting();

/// Script tags need not have their own Intl data. Dates stay unambiguous when
/// Intl has no data for the selected language: use a numeric ISO date and time.
String formatAppDateTime(
  DateTime date,
  Locale locale, {
  bool accessible = false,
}) {
  final local = date.toLocal();
  final tag = locale.toString();
  final dataLocale = DateFormat.localeExists(tag)
      ? tag
      : DateFormat.localeExists(locale.languageCode)
      ? locale.languageCode
      : null;
  if (dataLocale == null) {
    String pad(int value) => value.toString().padLeft(2, '0');
    return '${local.year.toString().padLeft(4, '0')}-${pad(local.month)}-'
        '${pad(local.day)} ${pad(local.hour)}:${pad(local.minute)}';
  }
  return (accessible
          ? DateFormat.yMMMMEEEEd(dataLocale).add_Hm()
          : DateFormat.yMMMMd(dataLocale).add_Hm())
      .format(local);
}
