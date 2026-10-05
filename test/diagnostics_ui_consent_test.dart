// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/diagnostics_store.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

const _consentLabel =
    'Envoyer automatiquement les rapports d’erreurs importants';
const _saveFailure =
    'Ce choix n’a pas pu être enregistré. Il pourrait être perdu au redémarrage. Réessayez.';

class _Diagnostics extends DiagnosticsController {
  bool saved = false;
  bool consent = false;
  Completer<bool>? saveGate;
  final queued = <QueuedDiagnosticReport>[];
  final cancelled = <String>[];

  @override
  bool get hasSession => true;
  @override
  bool get automaticConsent => consent;
  @override
  List<QueuedDiagnosticReport> get pendingReports => List.unmodifiable(queued);
  @override
  Future<bool> setAutomaticConsent(bool enabled) async {
    final success = await (saveGate?.future ?? Future.value(saved));
    if (success) consent = enabled;
    notifyListeners();
    return success;
  }

  @override
  Future<Map<String, Object?>?> runChecks() async => {
    'checks': [
      {'id': 'dns', 'result': 'unknown'},
    ],
  };

  @override
  Future<bool> sendPreparedReport(FrozenDiagnosticReport report) async {
    queued.add(
      QueuedDiagnosticReport(
        report: report,
        expiresAt: report.createdAt.add(const Duration(hours: 24)),
      ),
    );
    notifyListeners();
    return false;
  }

  @override
  Future<void> cancel(String reportId) async {
    cancelled.add(reportId);
    queued.removeWhere((r) => r.reportId == reportId);
    notifyListeners();
  }
}

class _UiController extends AppController {
  _UiController(_Diagnostics diagnostics)
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        diagnostics: diagnostics,
      ) {
    language = AppLanguage.french;
    profile = fixtures.account;
    section = AppSection.help;
    isInitialized = true;
  }

  @override
  Future<void> initialize() async {}

  void changeAccount() {
    profile = const UserProfile(
      userId: 'second-synthetic-account',
      email: 'second@example.invalid',
      firstName: 'Second',
      emailVerified: true,
    );
    notifyListeners();
  }

  void rebuild() => notifyListeners();
}

Future<void> _mount(WidgetTester tester, _UiController app) async {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(1280, 1000);
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(app.dispose);
  await tester.pumpWidget(FuzeVpnApp(controller: app));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('manual send selection belongs to the current account', (
    tester,
  ) async {
    final app = _UiController(_Diagnostics());
    await _mount(tester, app);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    expect(
      tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
      isTrue,
    );
    app.rebuild();
    await tester.pump();
    expect(
      tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
      isTrue,
    );
    app.changeAccount();
    await tester.pump();
    expect(
      tester.widget<CheckboxListTile>(find.byType(CheckboxListTile)).value,
      isFalse,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'settings reports a failed consent save and clears it after retry',
    (tester) async {
      final diagnostics = _Diagnostics();
      final app = _UiController(diagnostics)..section = AppSection.settings;
      await _mount(tester, app);
      await tester.tap(find.byKey(const ValueKey('settings-category-privacy')));
      await tester.pumpAndSettle();
      final control = find.widgetWithText(SwitchListTile, _consentLabel);
      await tester.ensureVisible(control);
      await tester.pumpAndSettle();
      await tester.tap(control);
      await tester.pumpAndSettle();
      expect(find.text(_saveFailure), findsOneWidget);
      expect(tester.widget<SwitchListTile>(control).value, isFalse);
      diagnostics.saved = true;
      await tester.tap(control);
      await tester.pumpAndSettle();
      expect(find.text(_saveFailure), findsNothing);
      expect(tester.widget<SwitchListTile>(control).value, isTrue);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('late consent failure from a previous account is not displayed', (
    tester,
  ) async {
    final diagnostics = _Diagnostics()..saveGate = Completer<bool>();
    final app = _UiController(diagnostics)..section = AppSection.settings;
    await _mount(tester, app);
    await tester.tap(find.byKey(const ValueKey('settings-category-privacy')));
    await tester.pumpAndSettle();
    final control = find.widgetWithText(SwitchListTile, _consentLabel);
    await tester.ensureVisible(control);
    await tester.pumpAndSettle();
    await tester.tap(control);
    await tester.pump();
    expect(tester.widget<SwitchListTile>(control).onChanged, isNull);
    app.changeAccount();
    await tester.pump();
    diagnostics.saveGate!.complete(false);
    await tester.pumpAndSettle();
    expect(find.text(_saveFailure), findsNothing);
    expect(tester.widget<SwitchListTile>(control).onChanged, isNotNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('withdrawing the checkbox cancels only its own pending report', (
    tester,
  ) async {
    final diagnostics = _Diagnostics();
    final old = diagnostics.prepareManualReport()!;
    await diagnostics.sendPreparedReport(old);
    final app = _UiController(diagnostics);
    await _mount(tester, app);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pump();
    await tester.tap(find.text('Diagnostiquer'));
    await tester.pumpAndSettle();
    final created = app.preparedDiagnosticReport!.reportId;
    expect(diagnostics.queued.length, 2);
    await tester.tap(find.byType(CheckboxListTile));
    await tester.pumpAndSettle();
    expect(diagnostics.cancelled, [created]);
    expect(diagnostics.queued.single.reportId, old.reportId);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('failed and unknown checks explain suitable next actions', (
    tester,
  ) async {
    final app = _UiController(_Diagnostics())
      ..diagnosticResults = {
        'checks': [
          {
            'id': 'api_reachability',
            'result': 'failed',
            'code': 'request_timeout',
          },
          {'id': 'dns', 'result': 'failed'},
          {'id': 'driver_availability', 'result': 'failed'},
          {'id': 'kill_switch', 'result': 'unknown'},
          {'id': 'routing', 'result': 'unknown'},
        ],
      };
    await _mount(tester, app);
    expect(
      find.text(
        'Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.',
      ),
      findsOneWidget,
    );
    expect(
      find.text(
        'Déconnectez puis reconnectez manuellement le VPN, puis relancez le diagnostic. Si le problème persiste, contactez l’assistance.',
      ),
      findsOneWidget,
    );
    expect(
      find.text(
        'Le pilote VPN doit être vérifié. Contactez l’assistance avant de le modifier.',
      ),
      findsOneWidget,
    );
    expect(
      find.text(
        'Cette protection n’est pas confirmée. Ne supposez pas que le trafic est bloqué. Vérifiez les réglages et contactez l’assistance si le problème persiste.',
      ),
      findsOneWidget,
    );
    expect(
      find.text(
        'Cette mesure est indisponible. Relancez le diagnostic. Si elle reste indéterminée, contactez l’assistance.',
      ),
      findsOneWidget,
    );
    expect(find.text('Terminer la déconnexion'), findsNothing);
    expect(app.diagnosticRepairRunning, isFalse);
    for (final size in [const Size(640, 360), const Size(1280, 720)]) {
      tester.view.physicalSize = size;
      for (final language in [AppLanguage.french, AppLanguage.german]) {
        app.language = language;
        app.rebuild();
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull, reason: '$size $language');
      }
    }
    await tester.pumpWidget(const SizedBox.shrink());
  });
}
