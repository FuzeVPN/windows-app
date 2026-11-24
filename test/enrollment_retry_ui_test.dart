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

// These issues renew the certificate (a new key) instead of retrying.
const _renewalIssues = [
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.openVpnProfileExists,
    title: 'OpenVPN indisponible',
    message: 'Un profil OpenVPN existe déjà pour cet appareil.',
  ),
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.openVpnProfileRevoked,
    title: 'OpenVPN indisponible',
    message: 'Le profil OpenVPN a été révoqué. Renouvelez-le pour continuer.',
  ),
];

/// A failed attempt that still retains the kill switch: the hero offers
/// Disconnect, so the card's retry must not be the same toggle.
class _BlockedRetryController extends ConnectionUxController {
  _BlockedRetryController() {
    activeProtocol = null;
    vpnStatus = VpnStatus.blocked;
    currentDeviceId = 'synthetic-device';
    errorMessage =
        'La connexion VPN a échoué. Le kill switch bloque toujours le trafic réseau.';
  }

  int retries = 0;
  int renewals = 0;
  int replacements = 0;
  int toggles = 0;
  bool busy = false;

  @override
  bool get isConnectionBusy => busy || super.isConnectionBusy;

  @override
  Future<void> retryConnection() async {
    retries++;
  }

  @override
  Future<void> renewOpenVpnProfile() async {
    renewals++;
  }

  @override
  Future<void> replaceRevokedOpenVpnProfile() async {
    replacements++;
  }

  @override
  Future<void> toggleConnection() async {
    toggles++;
  }

  int resends = 0;
  final identityResets = <bool>[];

  @override
  Future<void> resendVerificationEmail() async {
    resends++;
    verificationEmailNotice = _sentNotice;
    notifyListeners();
  }

  @override
  Future<void> retryAfterIdentityReset({
    bool replaceCurrentDevice = false,
  }) async {
    identityResets.add(replaceCurrentDevice);
  }
}

const _sentNotice =
    'E-mail envoyé. Ouvrez le lien qu’il contient, puis réessayez de vous connecter.';
const _cooldownNotice =
    'Un e-mail vient d’être envoyé. Vous pourrez en demander un autre dans {seconds} s.';

const _emailIssue = DeviceEnrollmentIssue(
  kind: DeviceEnrollmentIssueKind.emailVerificationRequired,
  title: 'Adresse e-mail à confirmer',
  message: 'Confirmez votre adresse e-mail avant d’ajouter cet appareil VPN.',
);

const _identityIssues = {
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.localIdentityUnavailable,
    title: 'Identité VPN à renouveler',
    message:
        'L’identité VPN enregistrée sur ce PC est illisible. Créez-en une nouvelle pour cet appareil uniquement.',
  ): true,
  DeviceEnrollmentIssue(
    kind: DeviceEnrollmentIssueKind.deviceIdentityRevoked,
    title: 'Identité VPN à renouveler',
    message:
        'Cette identité VPN a été retirée. Créez-en une nouvelle pour continuer.',
  ): false,
};

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

Finder _renewButton(AppStrings strings) =>
    find.widgetWithText(OutlinedButton, strings.text('Renouveler le profil'));

Finder _optionsButton(AppStrings strings) =>
    find.widgetWithText(OutlinedButton, strings.text('Voir les options'));

const _nodeUnavailableIssue = DeviceEnrollmentIssue(
  kind: DeviceEnrollmentIssueKind.nodeUnavailable,
  title: 'Emplacement indisponible',
  message:
      'Cet emplacement est momentanément indisponible. Choisissez un autre emplacement ou réessayez plus tard.',
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

  for (final issue in _renewalIssues) {
    testWidgets('${issue.kind.name} renews instead of retrying', (
      tester,
    ) async {
      final controller = _BlockedRetryController()
        ..deviceEnrollmentIssue = issue;
      final strings = AppStrings.forLanguage(AppLanguage.french);
      await _pump(tester, controller);

      expect(controller.canRenewOpenVpnProfile, isTrue);
      expect(_retryButton(strings), findsNothing);
      await tester.tap(_renewButton(strings));
      await tester.pumpAndSettle();

      // The server refuses to renew a revoked profile: the same label
      // replaces its identity instead.
      final revoked =
          issue.kind == DeviceEnrollmentIssueKind.openVpnProfileRevoked;
      expect(controller.renewals, revoked ? 0 : 1);
      expect(controller.replacements, revoked ? 1 : 0);
      expect(controller.retries, 0);
      expect(controller.toggles, 0);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });
  }

  for (final (unavailable, issue) in [
    for (final unavailable in ['busy', 'migration', 'signed_out'])
      for (final issue in _renewalIssues.take(2)) (unavailable, issue),
  ]) {
    testWidgets('renewal is hidden when it cannot be honoured '
        '($unavailable, ${issue.kind.name})', (tester) async {
      final controller = _BlockedRetryController()
        ..deviceEnrollmentIssue = issue;
      switch (unavailable) {
        case 'busy':
          controller.busy = true;
        case 'migration':
          controller.locationMigration = const LocationMigration(
            migrationId: 'synthetic-migration',
            deviceId: 'synthetic-device',
            sourceLocationId: 'de-1',
            targetLocationId: 'de-2',
            status: LocationMigrationStatus.draining,
            retryAfterSeconds: 2,
          );
        case 'signed_out':
          controller.currentDeviceId = null;
      }
      final strings = AppStrings.forLanguage(AppLanguage.french);
      await _pump(tester, controller);

      expect(controller.canRenewOpenVpnProfile, isFalse);
      expect(find.text(strings.text(issue.message)), findsOneWidget);
      expect(_renewButton(strings), findsNothing);
      expect(_retryButton(strings), findsNothing);
      expect(controller.renewals, 0);
      expect(controller.replacements, 0);
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

  testWidgets('the e-mail card resends from the app in every language', (
    tester,
  ) async {
    for (final language in AppLanguage.values.where(
      (value) => value != AppLanguage.system,
    )) {
      final controller = _BlockedRetryController()
        ..language = language
        ..deviceEnrollmentIssue = _emailIssue;
      final strings = AppStrings.forLanguage(language);
      await _pump(tester, controller);

      expect(find.byKey(const ValueKey('notice-card-detail')), findsNothing);
      await tester.tap(
        find.widgetWithText(OutlinedButton, strings.text('Renvoyer l’e-mail')),
      );
      await tester.pumpAndSettle();
      expect(controller.resends, 1, reason: language.name);
      expect(
        tester
            .widget<Text>(find.byKey(const ValueKey('notice-card-detail')))
            .data,
        strings.text(_sentNotice),
        reason: language.name,
      );

      controller
        ..verificationEmailNotice = _cooldownNotice
        ..verificationEmailRetryAfterSeconds = 42
        ..notifyListeners();
      await tester.pumpAndSettle();
      final cooldown = tester
          .widget<Text>(find.byKey(const ValueKey('notice-card-detail')))
          .data!;
      expect(cooldown, contains('42'), reason: language.name);
      expect(cooldown, isNot(contains('{seconds}')), reason: language.name);
      expect(tester.takeException(), isNull, reason: language.name);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    }
  });

  for (final entry in _identityIssues.entries) {
    testWidgets('${entry.key.kind.name} creates a new identity '
        '(replacing this device: ${entry.value})', (tester) async {
      final controller = _BlockedRetryController()
        ..deviceEnrollmentIssue = entry.key;
      final strings = AppStrings.forLanguage(AppLanguage.french);
      await _pump(tester, controller);

      await tester.tap(
        find.widgetWithText(
          OutlinedButton,
          strings.text('Créer une nouvelle identité'),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, 'Continuer'));
      await tester.pumpAndSettle();

      expect(controller.identityResets, [entry.value]);
      expect(controller.toggles, 0);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });
  }
}
