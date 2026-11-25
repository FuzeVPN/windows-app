// SPDX-License-Identifier: MPL-2.0
import 'dart:ui' show Locale;

import 'package:intl/intl.dart';

/// Bytes received from and sent to the VPN server by the current tunnel, as
/// the tunnel engine counts them on the transport.
class TrafficStatistics {
  const TrafficStatistics({required this.received, required this.sent});

  final int received;
  final int sent;

  /// Reads a native reply. Anything but two non-negative counters is no
  /// value: the figures are informative and never guessed.
  static TrafficStatistics? fromChannel(Object? value) {
    if (value is! Map) return null;
    final received = value['received'];
    final sent = value['sent'];
    if (received is! int || sent is! int || received < 0 || sent < 0) {
      return null;
    }
    return TrafficStatistics(received: received, sent: sent);
  }

  @override
  bool operator ==(Object other) =>
      other is TrafficStatistics &&
      other.received == received &&
      other.sent == sent;

  @override
  int get hashCode => Object.hash(received, sent);
}

/// Formats [bytes] with binary multiples (1 Ko = 1 024 o), as Windows does:
/// at most three significant figures, one decimal below 10.
/// [translate] receives one of the catalog templates `{value} o`,
/// `{value} Ko`, `{value} Mo`, `{value} Go` or `{value} To`.
String formatByteCount(
  int bytes,
  Locale locale,
  String Function(String template) translate,
) {
  final count = bytes < 0 ? 0 : bytes;
  var unit = 0;
  var value = count.toDouble();
  // Thresholds are applied before rounding, so no unit ever shows 1 000.
  while (unit < 4 && value >= 999.5) {
    value /= 1024;
    unit++;
  }
  final template = switch (unit) {
    0 => translate('{value} o'),
    1 => translate('{value} Ko'),
    2 => translate('{value} Mo'),
    3 => translate('{value} Go'),
    _ => translate('{value} To'),
  };
  final pattern = unit == 0 || value >= 9.95 ? '0' : '0.0';
  return template.replaceAll(
    '{value}',
    NumberFormat(pattern, _numberLocale(locale)).format(value),
  );
}

String _numberLocale(Locale locale) {
  final tag = locale.toString();
  if (NumberFormat.localeExists(tag)) return tag;
  if (NumberFormat.localeExists(locale.languageCode)) {
    return locale.languageCode;
  }
  return 'en';
}
