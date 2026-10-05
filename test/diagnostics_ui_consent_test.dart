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
  Completer<Map<String, Object?>?>? runGate;
  int runCount = 0;
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
  Future<Map<String, Object?>?> runChecks() async {
    runCount++;
    if (runGate case final gate?) return gate.future;
    return {
      'checks': [
        {'id': 'dns', 'result': 'unknown'},
      ],
    };
  }

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

Future<void> _waitForDiagnostic(_UiController app) async {
  final deadline = Stopwatch()..start();
  while (app.diagnosticRunning || app.diagnosticExportRunning) {
    if (deadline.elapsed > const Duration(seconds: 10)) {
      throw StateError('Diagnostic did not complete.');
    }
    await Future<void>.delayed(const Duration(milliseconds: 5));
  }
}

void main() {
  testWidgets(
    'one diagnostic action discloses sending and has no extra steps',
    (tester) async {
      final app = _UiController(_Diagnostics());
      await _mount(tester, app);
      expect(find.widgetWithText(FilledButton, 'Diagnostic'), findsOneWidget);
      expect(find.byType(CheckboxListTile), findsNothing);
      for (final oldAction in [
        'Diagnostiquer',
        'Consulter le rapport',
        'Consulter le diagnostic',
        'Chronologie locale',
        'Copier le diagnostic local',
        'Copier le diagnostic complet',
        'Envoyer ce rapport',
      ]) {
        expect(find.text(oldAction), findsNothing);
      }
      expect(
        find.textContaining('puis les transmet à l’assistance FuzeVPN'),
        findsOneWidget,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

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

  testWidgets(
    'one click queues its diagnostic and permits cancelling delivery',
    (tester) async {
      final diagnostics = _Diagnostics();
      final app = _UiController(diagnostics);
      await _mount(tester, app);
      await tester.runAsync(() async {
        await tester.tap(find.widgetWithText(FilledButton, 'Diagnostic'));
        await _waitForDiagnostic(app);
      });
      await tester.pumpAndSettle();
      final created = app.preparedDiagnosticReport!.reportId;
      expect(diagnostics.queued, hasLength(1));
      expect(diagnostics.queued.single.reportId, created);
      expect(find.text('Rapport en attente d’envoi.'), findsOneWidget);
      expect(find.text('Diagnostic complet'), findsOneWidget);
      final cancel = find.widgetWithText(TextButton, 'Annuler l’envoi');
      await tester.ensureVisible(cancel);
      await tester.tap(cancel);
      await tester.pumpAndSettle();
      expect(diagnostics.cancelled, [created]);
      expect(diagnostics.queued, isEmpty);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('diagnostic action prevents overlapping collections', (
    tester,
  ) async {
    final diagnostics = _Diagnostics()
      ..runGate = Completer<Map<String, Object?>?>();
    final app = _UiController(diagnostics);
    await _mount(tester, app);
    await tester.runAsync(
      () => tester.tap(find.widgetWithText(FilledButton, 'Diagnostic')),
    );
    await tester.pump();
    final running = find.widgetWithText(FilledButton, 'Diagnostic en cours…');
    expect(running, findsOneWidget);
    expect(tester.widget<FilledButton>(running).onPressed, isNull);
    expect(diagnostics.queued, isEmpty);
    await tester.runAsync(() async {
      diagnostics.runGate!.complete({
        'checks': [
          {'id': 'dns', 'result': 'unknown'},
        ],
      });
      await _waitForDiagnostic(app);
    });
    await tester.pumpAndSettle();
    expect(diagnostics.runCount, 1);
    expect(diagnostics.queued, hasLength(1));
    expect(find.widgetWithText(FilledButton, 'Diagnostic'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final failure in [
    const DiagnosticsFailure('invalid_diagnostic', httpStatus: 422),
    const DiagnosticsFailure(
      'private-secret-should-not-appear',
      httpStatus: 999,
    ),
  ]) {
    testWidgets('delivery failure exposes a safe code and real HTTP status', (
      tester,
    ) async {
      final diagnostics = _Diagnostics()..lastFailure = failure;
      final app = _UiController(diagnostics);
      await _mount(tester, app);
      final known = failure.code == 'invalid_diagnostic';
      expect(
        find.text(
          'Code d’erreur : ${known ? 'invalid_diagnostic' : 'unknown_error'}',
        ),
        findsOneWidget,
      );
      expect(find.text('HTTP : 422'), known ? findsOneWidget : findsNothing);
      expect(find.text('HTTP : 999'), findsNothing);
      expect(
        find.textContaining('private-secret-should-not-appear'),
        findsNothing,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

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
        'La tentative de connexion réseau a échoué. Cela ne permet pas de déterminer si le service est indisponible.',
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
