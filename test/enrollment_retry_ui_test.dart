// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

const _pendingIssue = DeviceEnrollmentIssue(
  kind: DeviceEnrollmentIssueKind.openVpnOperationPending,
  title: 'OpenVPN indisponible',
  message:
      'La création du profil OpenVPN est en cours. Réessayez dans quelques instants.',
);

const _retryIssues = [
  _pendingIssue,
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.openVpnProfileExists,
    title: 'OpenVPN indisponible',
    message: 'Un profil OpenVPN existe déjà pour cet appareil.',
  ),
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.rateLimited,
    title: 'Trop de tentatives',
    message: 'Réessayez dans quelques instants.',
  ),
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.unknown,
    title: 'Connexion impossible',
    message: 'Une connexion VPN n’a pas pu être établie. Réessayez plus tard.',
  ),
];

/// A failed attempt that still retains the kill switch: the hero offers
/// Disconnect, so the card's retry must not be the same toggle.
class _BlockedRetryController extends ConnectionUxController {
  _BlockedRetryController() {
    activeProtocol = null;
    vpnStatus = VpnStatus.blocked;
    errorMessage =
        'La connexion VPN a échoué. Le kill switch bloque toujours le trafic réseau.';
  }

  int retries = 0;
  int toggles = 0;
  bool busy = false;

  @override
  bool get isConnectionBusy => busy || super.isConnectionBusy;

  @override
  Future<void> retryConnection() async {
    retries++;
  }

  @override
  Future<void> toggleConnection() async {
    toggles++;
  }
}

Future<void> _pump(WidgetTester tester, AppController controller) async {
  tester.view.physicalSize = const Size(1280, 900);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
}

Finder _retryButton(AppStrings strings) =>
    find.widgetWithText(OutlinedButton, strings.text('Réessayer'));

Finder _optionsButton(AppStrings strings) =>
    find.widgetWithText(OutlinedButton, strings.text('Voir les options'));

const _nodeUnavailableIssue = DeviceEnrollmentIssue(
  kind: DeviceEnrollmentIssueKind.nodeUnavailable,
  title: 'Emplacement indisponible',
  message:
      'Cet emplacement est momentanément indisponible. Choisissez Frankfurt 1 ou Frankfurt 2, ou réessayez plus tard.',
);

void main() {
  testWidgets('every language retries instead of disconnecting', (
    tester,
  ) async {
    for (final language in AppLanguage.values.where(
      (value) => value != AppLanguage.system,
    )) {
      final controller = _BlockedRetryController()
        ..language = language
        ..deviceEnrollmentIssue = _pendingIssue;
      final strings = AppStrings.forLanguage(language);
      await _pump(tester, controller);

      final retry = _retryButton(strings);
      expect(retry, findsOneWidget, reason: language.name);
      await tester.tap(retry);
      await tester.pumpAndSettle();

      expect(controller.retries, 1, reason: language.name);
      expect(controller.toggles, 0, reason: language.name);
      expect(
        find.descendant(
          of: find.byKey(const ValueKey('connection-primary-action')),
          matching: find.text(strings.text('Déconnecter')),
        ),
        findsOneWidget,
        reason: language.name,
      );
      expect(tester.takeException(), isNull, reason: language.name);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    }
  });

  for (final issue in _retryIssues) {
    testWidgets('${issue.kind.name} retries without toggling', (tester) async {
      final controller = _BlockedRetryController()
        ..deviceEnrollmentIssue = issue;
      final strings = AppStrings.forLanguage(AppLanguage.french);
      await _pump(tester, controller);

      await tester.tap(_retryButton(strings));
      await tester.pumpAndSettle();

      expect(controller.retries, 1);
      expect(controller.toggles, 0);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });
  }

  testWidgets('node unavailable dialog retries instead of disconnecting', (
    tester,
  ) async {
    final controller = _BlockedRetryController()
      ..deviceEnrollmentIssue = _nodeUnavailableIssue;
    final strings = AppStrings.forLanguage(AppLanguage.french);
    await _pump(tester, controller);
    expect(controller.canRetryConnection, isTrue);

    await tester.tap(_optionsButton(strings));
    await tester.pumpAndSettle();
    final retry = find.descendant(
      of: find.byType(AlertDialog),
      matching: find.widgetWithText(FilledButton, strings.text('Réessayer')),
    );
    expect(retry, findsOneWidget);
    await tester.tap(retry);
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsNothing);
    expect(controller.retries, 1);
    expect(controller.toggles, 0);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  for (final unavailable in ['tunnel_active', 'migration']) {
    testWidgets(
      'node unavailable dialog hides retry when it cannot be honoured '
      '($unavailable)',
      (tester) async {
        final controller = _BlockedRetryController()
          ..deviceEnrollmentIssue = _nodeUnavailableIssue;
        switch (unavailable) {
          case 'tunnel_active':
            controller.activeProtocol = VpnProtocol.openVpn;
          case 'migration':
            controller.locationMigration = const LocationMigration(
              migrationId: 'synthetic-migration',
              deviceId: 'synthetic-device',
              sourceLocationId: 'de-1',
              targetLocationId: 'de-2',
              status: LocationMigrationStatus.draining,
              retryAfterSeconds: 2,
            );
        }
        final strings = AppStrings.forLanguage(AppLanguage.french);
        await _pump(tester, controller);
        expect(controller.canRetryConnection, isFalse);

        await tester.tap(_optionsButton(strings));
        await tester.pumpAndSettle();
        final dialog = find.byType(AlertDialog);
        expect(dialog, findsOneWidget);
        expect(
          find.descendant(
            of: dialog,
            matching: find.text(strings.text('Réessayer')),
          ),
          findsNothing,
        );
        for (final label in ['Choisir un emplacement', 'Annuler']) {
          expect(
            find.descendant(
              of: dialog,
              matching: find.text(strings.text(label)),
            ),
            findsOneWidget,
            reason: label,
          );
        }
        await tester.tap(
          find.descendant(
            of: dialog,
            matching: find.text(strings.text('Annuler')),
          ),
        );
        await tester.pumpAndSettle();

        expect(controller.retries, 0);
        expect(controller.toggles, 0);
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      },
    );
  }

  for (final unavailable in ['busy', 'tunnel_active', 'migration']) {
    testWidgets('retry is hidden when it cannot be honoured ($unavailable)', (
      tester,
    ) async {
      final controller = _BlockedRetryController()
        ..deviceEnrollmentIssue = _pendingIssue;
      switch (unavailable) {
        case 'busy':
          controller.busy = true;
        case 'tunnel_active':
          controller.activeProtocol = VpnProtocol.openVpn;
        case 'migration':
          controller.locationMigration = const LocationMigration(
            migrationId: 'synthetic-migration',
            deviceId: 'synthetic-device',
            sourceLocationId: 'de-1',
            targetLocationId: 'de-2',
            status: LocationMigrationStatus.draining,
            retryAfterSeconds: 2,
          );
      }
      final strings = AppStrings.forLanguage(AppLanguage.french);
      await _pump(tester, controller);

      expect(controller.canRetryConnection, isFalse);
      expect(find.text(strings.text(_pendingIssue.message)), findsOneWidget);
      expect(_retryButton(strings), findsNothing);
      expect(controller.toggles, 0);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });
  }
}
