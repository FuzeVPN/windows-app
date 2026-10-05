// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

void main() {
  testWidgets('capacity refusals offer the filtered locations in all languages', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(640, 360);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    const issues = [
      DeviceEnrollmentIssue(
        kind: DeviceEnrollmentIssueKind.serverFull,
        title: 'Serveur complet',
        message:
            'Ce serveur n’a plus de place. Choisissez un autre emplacement.',
      ),
      DeviceEnrollmentIssue(
        kind: DeviceEnrollmentIssueKind.capacityUnavailable,
        title: 'Disponibilité non confirmée',
        message:
            'La disponibilité de ce serveur ne peut pas être confirmée pour le moment. Choisissez un autre emplacement ou réessayez plus tard.',
      ),
    ];
    for (final language in AppLanguage.values.where(
      (value) => value != AppLanguage.system,
    )) {
      for (final issue in issues) {
        final controller = ConnectionUxController()
          ..language = language
          ..vpnStatus = VpnStatus.error
          ..deviceEnrollmentIssue = issue;
        // Public catalogue contains only the surviving entry, even if the
        // rejected one used to be a favourite or the most recent destination.
        controller.locations = [controller.locations.first];
        controller.selectedLocation = null;
        controller.favoriteLocationIds = {'de-2'};
        controller.recentLocationIds = ['de-2'];
        final strings = AppStrings.forLanguage(language);
        await tester.pumpWidget(FuzeVpnApp(controller: controller));
        await tester.pumpAndSettle();
        expect(find.text(strings.text(issue.title)), findsOneWidget);
        expect(find.text(strings.text(issue.message)), findsOneWidget);
        final choose = find
            .widgetWithText(
              OutlinedButton,
              strings.text('Choisir un emplacement'),
            )
            .last;
        await tester.ensureVisible(choose);
        await tester.pumpAndSettle();
        await tester.tap(choose);
        await tester.pumpAndSettle();
        expect(controller.section, AppSection.locations);
        final country = find.byKey(const ValueKey('location-open-country-DE'));
        await tester.ensureVisible(country);
        await tester.pumpAndSettle();
        await tester.tap(country);
        await tester.pumpAndSettle();
        expect(
          find.byKey(const ValueKey('location-select-city-DE-frankfurt')),
          findsOneWidget,
        );
        expect(find.textContaining('Frankfurt 1'), findsOneWidget);
        expect(find.text('Frankfurt 2'), findsNothing);
        expect(
          tester.takeException(),
          isNull,
          reason: '${language.name}/${issue.kind}',
        );
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      }
    }
  });
}
