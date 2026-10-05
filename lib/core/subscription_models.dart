// SPDX-License-Identifier: MPL-2.0
/// Public billing state. Access is reported by the API independently of the
/// status: for example, a canceled subscription can still cover a paid period.
enum SubscriptionStatus {
  inactive,
  active,
  pastDue,
  expired,
  canceled,
  withdrawn,
  unknown,
}

class Subscription {
  const Subscription({
    required this.status,
    required this.hasAccess,
    required this.renewsAutomatically,
    required this.cancelAtPeriodEnd,
    this.offerId,
    this.startedAt,
    this.expiresAt,
    this.provider,
    this.nextChargeAt,
    this.moneyBackEligibleUntil,
  });

  final SubscriptionStatus status;
  final bool hasAccess;
  final String? offerId;
  final DateTime? startedAt;
  final DateTime? expiresAt;
  final bool renewsAutomatically;
  final String? provider;
  final bool cancelAtPeriodEnd;
  final DateTime? nextChargeAt;
  final DateTime? moneyBackEligibleUntil;

  factory Subscription.fromJson(Map<String, dynamic> json) {
    final rawStatus = json['status'];
    if (rawStatus is! String || rawStatus.isEmpty) {
      throw const FormatException('Invalid subscription status.');
    }
    final status = switch (rawStatus) {
      'inactive' => SubscriptionStatus.inactive,
      'active' => SubscriptionStatus.active,
      'past_due' => SubscriptionStatus.pastDue,
      'expired' => SubscriptionStatus.expired,
      'canceled' => SubscriptionStatus.canceled,
      'withdrawn' => SubscriptionStatus.withdrawn,
      _ => SubscriptionStatus.unknown,
    };
    bool requiredBoolean(String key) {
      final value = json[key];
      if (value is! bool) {
        throw const FormatException('Invalid subscription flag.');
      }
      return value;
    }

    String? optionalText(String key) {
      final value = json[key];
      if (value == null) return null;
      if (value is! String ||
          value.isEmpty ||
          value.length > 256 ||
          value.contains(RegExp(r'[\x00-\x1f\x7f]'))) {
        throw const FormatException('Invalid subscription field.');
      }
      return value;
    }

    final hasAccess = requiredBoolean('has_access');
    return Subscription(
      status: status,
      // An unrecognized server state cannot be advertised as active access.
      hasAccess: status != SubscriptionStatus.unknown && hasAccess,
      offerId: optionalText('offer_id'),
      startedAt: _subscriptionTimestamp(json['started_at']),
      expiresAt: _subscriptionTimestamp(json['expires_at']),
      renewsAutomatically: requiredBoolean('renews_automatically'),
      provider: optionalText('provider'),
      cancelAtPeriodEnd: requiredBoolean('cancel_at_period_end'),
      nextChargeAt: _subscriptionTimestamp(json['next_charge_at']),
      moneyBackEligibleUntil: _subscriptionTimestamp(
        json['money_back_eligible_until'],
      ),
    );
  }
}

DateTime? _subscriptionTimestamp(Object? value) {
  if (value == null) return null;
  if (value is! String) {
    throw const FormatException('Invalid subscription timestamp.');
  }
  // DateTime.parse accepts rollover dates and local times. Billing dates must
  // represent an explicit instant, without normalizing an impossible date.
  final match = RegExp(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$',
  ).firstMatch(value);
  if (match == null) {
    throw const FormatException('Invalid subscription timestamp.');
  }
  final fields = [for (var i = 1; i <= 6; i++) int.parse(match.group(i)!)];
  final date = DateTime.utc(fields[0], fields[1], fields[2]);
  final zone = match.group(7)!;
  if (fields[0] < 1 ||
      date.year != fields[0] ||
      date.month != fields[1] ||
      date.day != fields[2] ||
      fields[3] > 23 ||
      fields[4] > 59 ||
      fields[5] > 59 ||
      (zone != 'Z' &&
          (int.parse(zone.substring(1, 3)) > 23 ||
              int.parse(zone.substring(4, 6)) > 59))) {
    throw const FormatException('Invalid subscription timestamp.');
  }
  return DateTime.parse(value).toUtc();
}
