// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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
const _localOnly =
    'Diagnostic complet collecté sur cet appareil. Vous pouvez le copier ou l’envoyer à l’assistance.';
const _copyKey = ValueKey('diagnostic-copy');
const _sendKey = ValueKey('diagnostic-send');

class _Diagnostics extends DiagnosticsController {
  bool saved = false;
  bool consent = false;
  bool sending = false;
  Completer<bool>? saveGate;
  Completer<Map<String, Object?>?>? runGate;
  Completer<void>? sendGate;
  int runCount = 0;
  final sent = <String>[];
  final queued = <QueuedDiagnosticReport>[];
  final cancelled = <String>[];
  final retried = <String>[];

  @override
  bool get hasSession => true;
  @override
  bool get isSending => sending;
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
    sent.add(report.reportId);
    await sendGate?.future;
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

  @override
  Future<bool> retry(String reportId) async {
    retried.add(reportId);
    return false;
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
  testWidgets('paused delivery resumes the existing report from its card', (
    tester,
  ) async {
    final diagnostics = _Diagnostics();
    final report = diagnostics.prepareManualReport()!;
    diagnostics.queued.add(
      QueuedDiagnosticReport(
        report: report,
        expiresAt: report.createdAt.add(const Duration(hours: 24)),
        attempts: 6,
        automaticAttempts: 5,
      ),
    );
    final app = _UiController(diagnostics);
    await _mount(tester, app);
    expect(
      find.text('Envoi suspendu : réessayez manuellement.'),
      findsOneWidget,
    );
    final retry = find.widgetWithText(TextButton, 'Réessayer');
    expect(retry, findsOneWidget);
    await tester.ensureVisible(retry);
    await tester.tap(retry);
    await tester.pumpAndSettle();
    expect(diagnostics.retried, [report.reportId]);
    expect(diagnostics.queued.single.report, same(report));
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final blocked in ['authentication', 'terminal', 'sending']) {
    testWidgets('$blocked delivery does not offer a manual retry', (
      tester,
    ) async {
      final diagnostics = _Diagnostics()..sending = blocked == 'sending';
      final report = diagnostics.prepareManualReport()!;
      diagnostics.queued.add(
        QueuedDiagnosticReport(
          report: report,
          expiresAt: report.createdAt.add(const Duration(hours: 24)),
          attempts: 6,
          automaticAttempts: 5,
          pausedForAuth: blocked == 'authentication',
          terminalCode: blocked == 'terminal' ? 'invalid_diagnostic' : null,
        ),
      );
      await _mount(tester, _UiController(diagnostics));
      expect(find.widgetWithText(TextButton, 'Réessayer'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    });
  }

  testWidgets(
    'the Diagnostics tab holds the consent and discloses when it sends',
    (tester) async {
      final app = _UiController(_Diagnostics());
      await _mount(tester, app);
      final run = find.widgetWithText(FilledButton, 'Diagnostic');
      expect(run, findsOneWidget);
      expect(find.byType(CheckboxListTile), findsNothing);
      final consent = find.widgetWithText(SwitchListTile, _consentLabel);
      expect(consent, findsOneWidget);
      expect(tester.widget<SwitchListTile>(consent).value, isFalse);
      expect(tester.widget<SwitchListTile>(consent).onChanged, isNotNull);
      // The switch sits in the Diagnostic surface, above its action.
      expect(
        tester.getBottomLeft(consent).dy,
        lessThanOrEqualTo(tester.getTopLeft(run).dy),
      );
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
      // Nothing has been collected yet, so nothing can be copied or sent.
      expect(find.byKey(_copyKey), findsNothing);
      expect(find.byKey(_sendKey), findsNothing);
      expect(
        find.textContaining('puis les transmet à l’assistance FuzeVPN'),
        findsNothing,
      );
      expect(
        find.textContaining(
          'Si l’envoi automatique est activé, ils sont transmis à l’assistance FuzeVPN ; sinon, seulement lorsque vous appuyez sur « Envoyer ».',
        ),
        findsOneWidget,
      );
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('no settings category holds the diagnostic consent', (
    tester,
  ) async {
    final app = _UiController(_Diagnostics())..section = AppSection.settings;
    await _mount(tester, app);
    for (final category in ['general', 'connection', 'privacy', 'updates']) {
      await tester.tap(find.byKey(ValueKey('settings-category-$category')));
      await tester.pumpAndSettle();
      expect(
        find.widgetWithText(SwitchListTile, _consentLabel),
        findsNothing,
        reason: category,
      );
    }
    expect(find.text('Rapports techniques facultatifs.'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'the Diagnostics tab reports a failed consent save and clears it after retry',
    (tester) async {
      final diagnostics = _Diagnostics();
      final app = _UiController(diagnostics);
      await _mount(tester, app);
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
    final app = _UiController(diagnostics);
    await _mount(tester, app);
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
    'with automatic consent one click queues its diagnostic and permits cancelling delivery',
    (tester) async {
      final diagnostics = _Diagnostics()..consent = true;
      final app = _UiController(diagnostics);
      await _mount(tester, app);
      expect(
        tester
            .widget<SwitchListTile>(
              find.widgetWithText(SwitchListTile, _consentLabel),
            )
            .value,
        isTrue,
      );
      await tester.runAsync(() async {
        await tester.tap(find.widgetWithText(FilledButton, 'Diagnostic'));
        await _waitForDiagnostic(app);
      });
      await tester.pumpAndSettle();
      final created = app.preparedDiagnosticReport!.reportId;
      expect(diagnostics.sent, [created]);
      expect(diagnostics.queued, hasLength(1));
      expect(diagnostics.queued.single.reportId, created);
      expect(
        find.text('Diagnostic complet conservé, en attente d’envoi.'),
        findsOneWidget,
      );
      expect(find.text('Rapport en attente d’envoi.'), findsOneWidget);
      expect(find.text('Diagnostic complet'), findsOneWidget);
      // Already sent automatically: copy remains, no explicit send is offered.
      expect(find.byKey(_copyKey), findsOneWidget);
      expect(find.byKey(_sendKey), findsNothing);
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
      ..consent = true
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
    expect(find.byKey(_copyKey), findsNothing);
    expect(find.byKey(_sendKey), findsNothing);
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

  testWidgets(
    'without automatic consent the diagnostic stays local and Envoyer sends it once',
    (tester) async {
      final diagnostics = _Diagnostics()..sendGate = Completer<void>();
      final app = _UiController(diagnostics);
      await _mount(tester, app);
      Future<void> runDiagnostic() async {
        await tester.runAsync(() async {
          await tester.tap(find.widgetWithText(FilledButton, 'Diagnostic'));
          await _waitForDiagnostic(app);
        });
        await tester.pumpAndSettle();
      }

      await runDiagnostic();
      final first = app.preparedDiagnosticReport!.reportId;
      expect(diagnostics.sent, isEmpty);
      expect(diagnostics.queued, isEmpty);
      expect(find.text(_localOnly), findsOneWidget);
      final copy = find.byKey(_copyKey);
      final send = find.byKey(_sendKey);
      expect(
        find.descendant(of: copy, matching: find.text('Copier')),
        findsOneWidget,
      );
      expect(
        find.descendant(of: send, matching: find.text('Envoyer')),
        findsOneWidget,
      );
      expect(find.byIcon(Icons.copy_outlined), findsOneWidget);
      expect(find.byIcon(Icons.send_outlined), findsOneWidget);

      await tester.ensureVisible(send);
      await tester.tap(send);
      await tester.pump();
      // While the report is being handed over, the action shows its progress.
      expect(diagnostics.sent, [first]);
      expect(
        find.descendant(of: send, matching: find.text('Envoi en cours…')),
        findsOneWidget,
      );
      expect(tester.widget<ButtonStyleButton>(send).onPressed, isNull);
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Diagnostic'),
            )
            .onPressed,
        isNull,
      );
      expect(find.byType(LinearProgressIndicator), findsOneWidget);
      diagnostics.sendGate!.complete();
      await tester.pumpAndSettle();
      expect(diagnostics.sent, [first]);
      expect(diagnostics.queued.single.reportId, first);
      expect(send, findsNothing);
      expect(copy, findsOneWidget);
      expect(
        find.text('Diagnostic complet conservé, en attente d’envoi.'),
        findsOneWidget,
      );
      expect(find.text('Rapport en attente d’envoi.'), findsOneWidget);

      // A new diagnostic prepares a new local report which can be sent again.
      diagnostics.sendGate = null;
      await runDiagnostic();
      final second = app.preparedDiagnosticReport!.reportId;
      expect(second, isNot(first));
      expect(diagnostics.sent, [first]);
      expect(find.text(_localOnly), findsOneWidget);
      expect(send, findsOneWidget);
      await tester.ensureVisible(send);
      await tester.tap(send);
      await tester.pumpAndSettle();
      expect(diagnostics.sent, [first, second]);
      expect(send, findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('Copier puts the complete diagnostic on the clipboard', (
    tester,
  ) async {
    final copied = <Object?>[];
    var clipboardFails = false;
    final messenger = tester.binding.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        if (clipboardFails) {
          throw PlatformException(code: 'clipboard_unavailable');
        }
        copied.add((call.arguments as Map)['text']);
      }
      return null;
    });
    addTearDown(
      () => messenger.setMockMethodCallHandler(SystemChannels.platform, null),
    );
    // Copying does not depend on the consent: this report was sent already.
    final app = _UiController(_Diagnostics()..consent = true);
    await _mount(tester, app);
    await tester.runAsync(() async {
      await tester.tap(find.widgetWithText(FilledButton, 'Diagnostic'));
      await _waitForDiagnostic(app);
    });
    await tester.pumpAndSettle();
    final copy = find.byKey(_copyKey);
    await tester.ensureVisible(copy);
    await tester.tap(copy);
    await tester.pumpAndSettle();
    expect(copied, [app.diagnosticLocalExport]);
    expect(copied.single, contains(app.preparedDiagnosticReport!.reportId));
    expect(find.text('Diagnostic local copié.'), findsOneWidget);

    clipboardFails = true;
    await tester.tap(copy);
    await tester.pumpAndSettle();
    expect(copied, hasLength(1));
    expect(find.text('Diagnostic local copié.'), findsNothing);
    expect(
      find.text('Le diagnostic local n’a pas pu être copié. Réessayez.'),
      findsOneWidget,
    );

    // A new diagnostic replaces the report, and the earlier feedback with it.
    await tester.runAsync(() async {
      await tester.tap(find.widgetWithText(FilledButton, 'Diagnostic'));
      await _waitForDiagnostic(app);
    });
    await tester.pumpAndSettle();
    expect(
      find.text('Le diagnostic local n’a pas pu être copié. Réessayez.'),
      findsNothing,
    );
    expect(copy, findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('signed-out diagnostics offer Copier but never Envoyer', (
    tester,
  ) async {
    final diagnostics = _Diagnostics();
    final app = _UiController(diagnostics)..profile = null;
    await _mount(tester, app);
    await tester.tap(find.widgetWithText(TextButton, 'Diagnostic local'));
    await tester.pumpAndSettle();
    final dialog = find.byType(AlertDialog).last;
    final consent = find.descendant(
      of: dialog,
      matching: find.widgetWithText(SwitchListTile, _consentLabel),
    );
    expect(consent, findsOneWidget);
    expect(tester.widget<SwitchListTile>(consent).onChanged, isNull);
    await tester.runAsync(() async {
      await tester.tap(
        find.descendant(
          of: dialog,
          matching: find.widgetWithText(FilledButton, 'Diagnostic'),
        ),
      );
      await _waitForDiagnostic(app);
    });
    await tester.pumpAndSettle();
    expect(
      find.descendant(of: dialog, matching: find.byKey(_copyKey)),
      findsOneWidget,
    );
    expect(find.byKey(_sendKey), findsNothing);
    expect(
      find.descendant(
        of: dialog,
        matching: find.text(
          'Diagnostic complet collecté. Connectez-vous à votre compte pour l’envoyer.',
        ),
      ),
      findsOneWidget,
    );
    expect(diagnostics.sent, isEmpty);
    expect(diagnostics.queued, isEmpty);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('diagnostic actions fit narrow windows with large text', (
    tester,
  ) async {
    final app = _UiController(_Diagnostics());
    await _mount(tester, app);
    await tester.runAsync(() async {
      await tester.tap(find.widgetWithText(FilledButton, 'Diagnostic'));
      await _waitForDiagnostic(app);
    });
    await tester.pumpAndSettle();
    expect(find.byKey(_copyKey), findsOneWidget);
    expect(find.byKey(_sendKey), findsOneWidget);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    for (final size in [const Size(640, 360), const Size(1280, 720)]) {
      tester.view.physicalSize = size;
      for (final scale in [1.0, 2.0]) {
        tester.platformDispatcher.textScaleFactorTestValue = scale;
        for (final language in [
          AppLanguage.french,
          AppLanguage.german,
          AppLanguage.tamil,
          AppLanguage.malayalam,
        ]) {
          app.language = language;
          app.rebuild();
          await tester.pumpAndSettle();
          expect(
            tester.takeException(),
            isNull,
            reason: '$size x$scale $language',
          );
          final strings = AppStrings.forLanguage(language);
          for (final (key, label) in [
            (_copyKey, 'Copier'),
            (_sendKey, 'Envoyer'),
          ]) {
            final action = find.byKey(key);
            expect(action, findsOneWidget, reason: '$size x$scale $language');
            expect(
              find.descendant(
                of: action,
                matching: find.text(strings.text(label)),
              ),
              findsOneWidget,
            );
            // Each action stays inside the window width.
            await tester.ensureVisible(action);
            await tester.pumpAndSettle();
            final rect = tester.getRect(action);
            expect(rect.left, greaterThanOrEqualTo(0));
            expect(rect.right, lessThanOrEqualTo(size.width));
          }
          expect(
            find.widgetWithText(SwitchListTile, strings.text(_consentLabel)),
            findsOneWidget,
          );
        }
      }
    }
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

  for (final requested in [true, false]) {
    testWidgets(
      'a disconnected VPN explains skipped checks without support (kill switch $requested)',
      (tester) async {
        Map<String, Object?> results({required bool otherUser}) => {
          'runtime': {
            'presence': 'present',
            'owned_by_another_user': otherUser,
          },
          'snapshot': {'kill_switch_requested': requested},
          'checks': [
            {'id': 'service_availability', 'result': 'passed'},
            {'id': 'kill_switch', 'result': 'skipped'},
            {'id': 'tunnel_connection', 'result': 'skipped'},
            {'id': 'driver_availability', 'result': 'skipped'},
            {'id': 'api_reachability', 'result': 'passed'},
            {'id': 'connectivity', 'result': 'passed'},
          ],
        };
        final app = _UiController(_Diagnostics())
          ..diagnosticResults = results(otherUser: false);
        await _mount(tester, app);
        final skipped = find.text('Vérifications non exécutées (3)');
        await tester.ensureVisible(skipped);
        await tester.tap(skipped);
        await tester.pumpAndSettle();
        expect(find.text('Aucun tunnel VPN n’est actif.'), findsOneWidget);
        expect(
          find.text('Nécessite une connexion VPN active.'),
          findsNWidgets(requested ? 2 : 1),
        );
        expect(
          find.text('Désactivé'),
          requested ? findsNothing : findsOneWidget,
        );
        expect(find.text('Non exécuté'), findsNWidgets(3));
        expect(find.textContaining('Code d’erreur'), findsNothing);
        expect(
          find.textContaining(RegExp('contactez', caseSensitive: false)),
          findsNothing,
        );
        // Another Windows user's runtime does not prove that no tunnel exists.
        app.diagnosticResults = results(otherUser: true);
        expect(
          app.diagnosticChecks
              .where((check) => check.id != 'kill_switch' || requested)
              .map((check) => check.note),
          everyElement(isNull),
        );
        // A kill switch still holding traffic is never described as idle,
        // even when its runtime is absent.
        app
          ..vpnStatus = VpnStatus.blocked
          ..diagnosticResults = {
            ...results(otherUser: false),
            'runtime': {'presence': 'absent'},
            'checks': [
              {'id': 'service_availability', 'result': 'skipped'},
              {'id': 'kill_switch', 'result': 'skipped'},
              {'id': 'tunnel_connection', 'result': 'skipped'},
              {'id': 'connectivity', 'result': 'skipped'},
            ],
          };
        final notes = {
          for (final check in app.diagnosticChecks) check.id: check.note,
        };
        expect(notes, {
          'service_availability': null,
          'kill_switch': requested ? 'Trafic bloqué par le kill switch' : null,
          'tunnel_connection': null,
          'connectivity': requested ? 'Trafic bloqué par le kill switch' : null,
        });
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }
}
