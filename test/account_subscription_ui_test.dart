// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';
import 'package:intl/intl.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

Subscription _subscription({
  String status = 'active',
  bool hasAccess = true,
  bool cancelAtPeriodEnd = false,
  bool renewsAutomatically = true,
  String? expiresAt = '2027-10-01T16:00:00Z',
  String? nextChargeAt = '2027-10-01T16:00:00Z',
}) => Subscription.fromJson({
  'status': status,
  'has_access': hasAccess,
  'renews_automatically': renewsAutomatically,
  'cancel_at_period_end': cancelAtPeriodEnd,
  'expires_at': expiresAt,
  'next_charge_at': nextChargeAt,
});

class _SubscriptionUiController extends ConnectionUxController {
  Subscription? response = _subscription();
  String? failure;
  Completer<void>? pending;
  int refreshes = 0;

  @override
  Future<void> refreshSubscription() async {
    refreshes++;
    isLoadingSubscription = true;
    notifyListeners();
    await pending?.future;
    subscription = response;
    subscriptionErrorMessage = failure;
    isLoadingSubscription = false;
    notifyListeners();
  }
}

Future<void> _openAccount(
  WidgetTester tester,
  _SubscriptionUiController controller,
) async {
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
  expect(controller.refreshes, 0);
  final strings = AppStrings.forLanguage(controller.language);
  await tester.tap(find.byTooltip(strings.text('Mon compte')));
  await tester.pumpAndSettle();
}

Future<void> _closeApp(
  WidgetTester tester,
  _SubscriptionUiController controller,
) async {
  await tester.pumpWidget(const SizedBox.shrink());
  controller.dispose();
}

void main() {
  for (final entry in {
    'inactive': 'Inactif',
    'active': 'Actif',
    'past_due': 'Paiement en retard',
    'expired': 'Expiré',
    'canceled': 'Annulé',
    'withdrawn': 'Rétracté',
  }.entries) {
    testWidgets(
      'account shows API status ${entry.key} independently of access',
      (tester) async {
        final app = _SubscriptionUiController()
          ..response = _subscription(status: entry.key, hasAccess: false);
        await _openAccount(tester, app);
        expect(app.refreshes, 1);
        expect(find.text(entry.value), findsOneWidget);
        expect(find.text('Non autorisé'), findsOneWidget);
        expect(find.text('Autorisé'), findsNothing);
        expect(tester.takeException(), isNull);
        await _closeApp(tester, app);
      },
    );
  }

  testWidgets('a canceled paid period retains API access and no next charge', (
    tester,
  ) async {
    final app = _SubscriptionUiController()
      ..response = _subscription(status: 'canceled', cancelAtPeriodEnd: true);
    await _openAccount(tester, app);
    expect(find.text('Annulé'), findsOneWidget);
    expect(find.text('Autorisé'), findsOneWidget);
    expect(find.text('Annulé à la fin de la période'), findsOneWidget);
    expect(find.text('Prochaine échéance'), findsNothing);
    await _closeApp(tester, app);
  });

  testWidgets('missing dates stay unavailable and renewal follows API flags', (
    tester,
  ) async {
    final app = _SubscriptionUiController()
      ..response = _subscription(expiresAt: null, nextChargeAt: null);
    await _openAccount(tester, app);
    expect(find.text('Expiration'), findsOneWidget);
    expect(find.text('Prochaine échéance'), findsOneWidget);
    expect(find.text('Indisponible'), findsNWidgets(2));
    expect(find.text('Automatique'), findsOneWidget);
    await _closeApp(tester, app);
  });

  testWidgets('an unknown API status never advertises confirmed access', (
    tester,
  ) async {
    final app = _SubscriptionUiController()
      ..response = _subscription(status: 'future_server_state');
    await _openAccount(tester, app);
    expect(find.text('Statut indisponible'), findsOneWidget);
    expect(find.text('Indisponible'), findsOneWidget);
    expect(find.text('Autorisé'), findsNothing);
    expect(find.text('Non autorisé'), findsNothing);
    await _closeApp(tester, app);
  });

  testWidgets('disabled automatic renewal does not show a future charge', (
    tester,
  ) async {
    final app = _SubscriptionUiController()
      ..response = _subscription(renewsAutomatically: false);
    await _openAccount(tester, app);
    expect(find.text('Désactivé'), findsOneWidget);
    expect(find.text('Prochaine échéance'), findsNothing);
    await _closeApp(tester, app);
  });

  testWidgets('loading resolves locally and a retry preserves tunnel errors', (
    tester,
  ) async {
    const failure =
        'Les informations de votre abonnement ne peuvent pas être chargées pour le moment. Réessayez.';
    final pending = Completer<void>();
    final app = _SubscriptionUiController()
      ..pending = pending
      ..response = null
      ..failure = failure
      ..errorMessage = 'Erreur du tunnel indépendante.';
    await _openAccount(tester, app);
    expect(find.text('Chargement de l’abonnement…'), findsOneWidget);
    expect(
      find.byKey(const ValueKey('account-subscription-retry')),
      findsNothing,
    );
    pending.complete();
    await tester.pumpAndSettle();
    expect(find.text(failure), findsOneWidget);
    expect(app.errorMessage, 'Erreur du tunnel indépendante.');
    app
      ..pending = null
      ..response = _subscription()
      ..failure = null;
    final retry = find.byKey(const ValueKey('account-subscription-retry'));
    await tester.ensureVisible(retry);
    await tester.tap(retry);
    await tester.pumpAndSettle();
    expect(app.refreshes, 2);
    expect(find.text('Actif'), findsOneWidget);
    expect(find.text(failure), findsNothing);
    expect(app.errorMessage, 'Erreur du tunnel indépendante.');
    expect(tester.takeException(), isNull);
    await _closeApp(tester, app);
  });

  testWidgets(
    'subscription dates render in all 30 supported language locales',
    (tester) async {
      for (final language in AppLanguage.values.where(
        (language) => language != AppLanguage.system,
      )) {
        final app = _SubscriptionUiController()..language = language;
        await _openAccount(tester, app);
        final locale = language.locale!.toString();
        final expiry = DateFormat.yMMMMd(
          locale,
        ).add_Hm().format(app.response!.expiresAt!.toLocal());
        expect(find.text(expiry), findsNWidgets(2), reason: language.name);
        expect(tester.takeException(), isNull, reason: language.name);
        await _closeApp(tester, app);
      }
    },
  );

  for (final language in [AppLanguage.french, AppLanguage.arabic]) {
    testWidgets(
      'subscription dates and account controls remain accessible at 200% ${language.name}',
      (tester) async {
        tester.view.devicePixelRatio = 1;
        tester.view.physicalSize = const Size(640, 360);
        tester.platformDispatcher.textScaleFactorTestValue = 2;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
        final app = _SubscriptionUiController()..language = language;
        final strings = AppStrings.forLanguage(language);
        await _openAccount(tester, app);
        final locale = language.locale!.toString();
        final expires = app.response!.expiresAt!.toLocal();
        final expected = DateFormat.yMMMMd(locale).add_Hm().format(expires);
        expect(find.text(expected), findsNWidgets(2));
        final expiry = find.text(strings.text('Expiration'));
        await tester.ensureVisible(expiry);
        await tester.pumpAndSettle();
        final signOut = find.widgetWithText(
          FilledButton,
          strings.text('Se déconnecter du compte'),
        );
        await tester.ensureVisible(signOut);
        await tester.pumpAndSettle();
        expect(signOut.hitTestable(), findsOneWidget);
        expect(find.text(strings.text('Fermer')).hitTestable(), findsOneWidget);
        expect(tester.takeException(), isNull);
        await _closeApp(tester, app);
      },
    );
  }
}
