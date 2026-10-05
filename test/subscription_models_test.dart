// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/models.dart';

Map<String, dynamic> subscriptionJson({String status = 'active'}) => {
  'status': status,
  'has_access': true,
  'offer_id': 'premium-yearly',
  'started_at': '2026-10-01T12:30:00Z',
  'expires_at': '2027-10-01T14:30:00+02:00',
  'renews_automatically': true,
  'provider': 'stripe',
  'cancel_at_period_end': false,
  'next_charge_at': '2027-10-01T12:30:00Z',
  'money_back_eligible_until': '2026-10-31T12:30:00.123456Z',
};

void main() {
  test('known subscription states preserve API access independently', () {
    const states = {
      'inactive': SubscriptionStatus.inactive,
      'active': SubscriptionStatus.active,
      'past_due': SubscriptionStatus.pastDue,
      'expired': SubscriptionStatus.expired,
      'canceled': SubscriptionStatus.canceled,
      'withdrawn': SubscriptionStatus.withdrawn,
    };
    for (final entry in states.entries) {
      for (final access in [true, false]) {
        final parsed = Subscription.fromJson({
          ...subscriptionJson(status: entry.key),
          'has_access': access,
        });
        expect(parsed.status, entry.value);
        expect(parsed.hasAccess, access);
      }
    }
  });

  test(
    'unknown status never grants access and nullable fields stay absent',
    () {
      final parsed = Subscription.fromJson({
        'status': 'future_state',
        'has_access': true,
        'renews_automatically': false,
        'cancel_at_period_end': false,
      });
      expect(parsed.status, SubscriptionStatus.unknown);
      expect(parsed.hasAccess, isFalse);
      expect(parsed.offerId, isNull);
      expect(parsed.provider, isNull);
      expect(parsed.startedAt, isNull);
      expect(parsed.expiresAt, isNull);
      expect(parsed.nextChargeAt, isNull);
      expect(parsed.moneyBackEligibleUntil, isNull);
    },
  );

  test('subscription dates are explicit instants normalized to UTC', () {
    final parsed = Subscription.fromJson(subscriptionJson());
    expect(parsed.startedAt, DateTime.utc(2026, 10, 1, 12, 30));
    expect(parsed.expiresAt, DateTime.utc(2027, 10, 1, 12, 30));
    expect(parsed.moneyBackEligibleUntil!.microsecond, 456);
    expect(parsed.expiresAt!.isUtc, isTrue);
  });

  test('invalid and ambiguous timestamps cannot silently roll over', () {
    for (final key in [
      'started_at',
      'expires_at',
      'next_charge_at',
      'money_back_eligible_until',
    ]) {
      for (final value in [
        '',
        '2026-10-01',
        '2026-10-01T12:30:00',
        '2026-02-30T12:30:00Z',
        '2026-13-01T12:30:00Z',
        '2026-10-01T24:00:00Z',
        '2026-10-01T12:60:00Z',
        '2026-10-01T12:30:60Z',
        '2026-10-01T12:30:00+24:00',
        '2026-10-01T12:30:00+02:60',
        12345,
        {},
      ]) {
        expect(
          () => Subscription.fromJson({...subscriptionJson(), key: value}),
          throwsFormatException,
          reason: '$key / $value',
        );
      }
      expect(
        () => Subscription.fromJson({...subscriptionJson(), key: null}),
        returnsNormally,
      );
    }
  });

  test(
    'required booleans are never inferred from missing or truthy values',
    () {
      for (final key in [
        'has_access',
        'renews_automatically',
        'cancel_at_period_end',
      ]) {
        for (final value in [null, 1, 0, 'true', 'false']) {
          expect(
            () => Subscription.fromJson({...subscriptionJson(), key: value}),
            throwsFormatException,
          );
        }
        expect(
          () => Subscription.fromJson(subscriptionJson()..remove(key)),
          throwsFormatException,
        );
      }
      for (final key in ['offer_id', 'provider']) {
        expect(
          () => Subscription.fromJson({...subscriptionJson(), key: 42}),
          throwsFormatException,
        );
      }
    },
  );
}
