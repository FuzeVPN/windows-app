// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

const _subscriptionIssue = DeviceEnrollmentIssue(
  kind: DeviceEnrollmentIssueKind.subscriptionRequired,
  title: 'Abonnement requis',
  message:
      'Le service demande un abonnement pour autoriser cette connexion VPN. Consultez « Mon compte » pour vérifier l’état de votre abonnement.',
);

class _SubscriptionRequiredController extends ConnectionUxController {
  int subscriptionRefreshes = 0;
  int connectionToggles = 0;

  @override
  Future<void> refreshSubscription() async {
    subscriptionRefreshes++;
    subscription = Subscription.fromJson({
      'status': 'inactive',
      'has_access': false,
      'renews_automatically': false,
      'cancel_at_period_end': false,
    });
    notifyListeners();
  }

  @override
  Future<void> toggleConnection() async {
    connectionToggles++;
  }
}

void main() {
  for (final language in [AppLanguage.french, AppLanguage.english]) {
    for (final status in [
      VpnStatus.disconnected,
      VpnStatus.error,
      VpnStatus.blocked,
    ]) {
      testWidgets(
        '${language.name} subscription refusal opens account without toggling ${status.name}',
        (tester) async {
          tester.view.devicePixelRatio = 1;
          tester.view.physicalSize = const Size(1080, 720);
          addTearDown(tester.view.resetPhysicalSize);
          addTearDown(tester.view.resetDevicePixelRatio);
          final app = _SubscriptionRequiredController()
            ..language = language
            ..vpnStatus = status
            ..killSwitchEnabled = true
            ..deviceEnrollmentIssue = _subscriptionIssue;
          final profile = app.profile;
          final strings = AppStrings.forLanguage(language);
          await tester.pumpWidget(FuzeVpnApp(controller: app));
          await tester.pumpAndSettle();

          expect(
            find.text(strings.text(_subscriptionIssue.title)),
            findsOneWidget,
          );
          expect(
            find.text(strings.text(_subscriptionIssue.message)),
            findsOneWidget,
          );
          expect(
            find.widgetWithText(OutlinedButton, strings.text('Réessayer')),
            findsNothing,
          );
          expect(find.text(strings.text('Connexion impossible')), findsNothing);
          final primary = find.byKey(
            const ValueKey('connection-primary-action'),
          );
          if (status == VpnStatus.blocked) {
            expect(find.text(strings.text('Trafic bloqué')), findsOneWidget);
            expect(
              find.descendant(
                of: primary,
                matching: find.text(strings.text('Déconnecter')),
              ),
              findsOneWidget,
            );
          } else {
            expect(
              find.descendant(
                of: primary,
                matching: find.text(strings.text('Mon compte')),
              ),
              findsOneWidget,
            );
          }
          final account = status == VpnStatus.blocked
              ? find.widgetWithText(OutlinedButton, strings.text('Mon compte'))
              : primary;
          expect(account, findsOneWidget);
          await tester.ensureVisible(account);
          await tester.tap(account);
          await tester.pumpAndSettle();

          expect(find.byType(AlertDialog), findsOneWidget);
          expect(
            find.byKey(const ValueKey('account-subscription-panel')),
            findsOneWidget,
          );
          expect(find.text(strings.text('Inactif')), findsOneWidget);
          expect(find.text(strings.text('Non autorisé')), findsOneWidget);
          expect(
            find.text(
              strings.text(
                'Déconnectez le VPN pour consulter votre abonnement.',
              ),
            ),
            findsNothing,
          );
          expect(app.subscriptionRefreshes, 1);
          expect(app.connectionToggles, 0);
          expect(app.profile, same(profile));
          expect(app.vpnStatus, status);
          expect(app.killSwitchEnabled, isTrue);
          expect(tester.takeException(), isNull);

          await tester.pumpWidget(const SizedBox.shrink());
          app.dispose();
        },
      );
    }
  }
}
