// SPDX-License-Identifier: MPL-2.0

/// The account's DNS ad blocker (`/v1/me/dns-filter`). The servers' resolver
/// applies it to every device of the account, WireGuard and OpenVPN alike,
/// within seconds and without a reconnection.
class DnsFilterSettings {
  const DnsFilterSettings({required this.adBlocking, required this.available});

  /// The account's choice.
  final bool adBlocking;

  /// False while the blocker is switched off for everyone: the choice stays
  /// stored and editable, but nothing is filtered.
  final bool available;

  /// Strict reading: anything but the two booleans is not an answer.
  factory DnsFilterSettings.fromJson(Map<String, dynamic> json) {
    final adBlocking = json['ad_blocking'];
    final available = json['available'];
    if (adBlocking is! bool || available is! bool) {
      throw const FormatException('Réponse du bloqueur de pub invalide.');
    }
    return DnsFilterSettings(adBlocking: adBlocking, available: available);
  }

  @override
  bool operator ==(Object other) =>
      other is DnsFilterSettings &&
      other.adBlocking == adBlocking &&
      other.available == available;

  @override
  int get hashCode => Object.hash(adBlocking, available);
}
