// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_bridge.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/generated_catalogs.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _Snapshot extends DiagnosticsBridge {
  Completer<void>? gate;
  int calls = 0;
  bool otherUser = false;
  bool cleanup = false;
  @override
  Future<Map<String, Object?>> collectSnapshot() async {
    calls++;
    await gate?.future;
    return {
      'runtime': {
        'presence': 'present',
        'owned_by_another_user': otherUser,
        'cleanup_eligible': cleanup,
      },
      'snapshot': {'kill_switch_verified': true, 'freshness_ms': 12},
      'checks': [
        {'id': 'routing', 'result': 'passed', 'age_ms': 12},
        {'id': 'dns', 'result': 'unknown'},
        {'id': 'cleanup', 'result': cleanup ? 'failed' : 'skipped'},
      ],
    };
  }
}

class _UiController extends AppController {
  _UiController(_Snapshot snapshot)
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        diagnosticsBridge: snapshot,
      ) {
    language = AppLanguage.french;
  }
  @override
  Future<void> initialize() async {}
}

class _RecordingDiagnostics extends DiagnosticsController {
  final terminalErrors = <DiagnosticError>[];
  @override
  void recordTerminalError(
    DiagnosticError error, {
    String protocol = 'unknown',
    String state = 'error',
    bool terminal = true,
  }) {
    if (terminal) terminalErrors.add(error);
  }
}

class _UpdateDiagnosticsFixture extends WindowsUpdateController {
  WindowsUpdateFailure? failure;
  @override
  WindowsUpdateFailure? get error => failure;
  void fail(String code, {int? statusCode}) {
    failure = WindowsUpdateFailure(code, statusCode: statusCode);
    notifyListeners();
  }
}

class _CleanupWireGuard extends fixtures.ProbeWireGuard {
  bool cleanupFails = false;
  bool verificationFails = false;
  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
  @override
  Future<void> disconnect() async {
    if (cleanupFails) {
      disconnectCalls++;
      throw PlatformException(code: 'cleanup_failed');
    }
    await super.disconnect();
  }

  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    if (verificationFails) throw PlatformException(code: 'broker_unavailable');
    return super.networkProtectionStatus();
  }
}

class _SwitchAccountApi extends fixtures.ProbeApi {
  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async => const AuthSession(accessToken: 'synthetic-second-token');
  @override
  Future<UserProfile> me(String token) async => const UserProfile(
    userId: 'second-test-account',
    email: 'second@example.invalid',
    firstName: 'Second',
    emailVerified: true,
  );
}

class _SwitchAccountStore extends fixtures.ProbeStore {
  @override
  Future<void> saveToken(String value) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('fuzevpn/update'),
          (call) async => {
            'version': '0.1.0',
            'windows_build': 22631,
            'arch': 'x64',
            'installation_mode': 'portable',
          },
        );
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('fuzevpn/update'), null);
  });

  test(
    'update cancellation and portable restrictions are not automatic incidents',
    () {
      final diagnostic = _RecordingDiagnostics();
      final updates = _UpdateDiagnosticsFixture();
      final app = AppController(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        diagnostics: diagnostic,
        updates: updates,
      )..profile = fixtures.account;
      addTearDown(app.dispose);
      for (final code in [
        'update_cancelled',
        'update_uac_cancelled',
        'update_busy',
        'update_changed',
        'update_portable_manual',
        'update_installer_manual',
        'update_unsupported',
        'update_not_prepared',
      ]) {
        updates.fail(code);
      }
      expect(diagnostic.terminalErrors, isEmpty);
      updates.fail('update_verification_failed');
      expect(diagnostic.terminalErrors.single.operation, 'update');
      expect(
        diagnostic.terminalErrors.single.code,
        'update_verification_failed',
      );
    },
  );

  test('precise update failures preserve the existing report contract', () {
    final diagnostic = _RecordingDiagnostics();
    final updates = _UpdateDiagnosticsFixture();
    final app = AppController(
      api: fixtures.ProbeApi(),
      store: fixtures.ProbeStore(),
      window: fixtures.ProbeWindow(),
      wireguard: fixtures.ProbeWireGuard(),
      openVpn: fixtures.ProbeOpenVpn(),
      diagnostics: diagnostic,
      updates: updates,
    )..profile = fixtures.account;
    addTearDown(app.dispose);
    final traces = <String>[];
    final stop = DiagnosticLog.observe((area, event, code) {
      if (area == 'update' && event == 'failed') traces.add(code!);
    });
    addTearDown(stop);

    updates.fail('update_hash_mismatch');
    updates.fail('update_hash_mismatch');
    updates.fail('update_download_http_error', statusCode: 503);
    updates.fail('update_application_signature_invalid');

    expect(traces, [
      'update_hash_mismatch',
      'update_download_http_error',
      'update_application_signature_invalid',
    ]);
    expect(diagnostic.terminalErrors.map((error) => error.code), [
      'update_verification_failed',
      'update_download_failed',
      'update_unsigned_application',
    ]);
    expect(diagnostic.terminalErrors[1].httpStatus, 503);
    expect(diagnosticCodes.length, 206);
  });

  test(
    'portable update failures preserve local codes and API v1 categories',
    () {
      final updates = _UpdateDiagnosticsFixture();
      final diagnostic = _RecordingDiagnostics();
      final app = AppController(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        updates: updates,
        diagnostics: diagnostic,
      )..profile = fixtures.account;
      addTearDown(app.dispose);
      updates.fail('update_archive_unsafe');
      updates.fail('update_archive_extract_failed');
      updates.fail('update_portable_replace_failed');
      expect(diagnostic.terminalErrors.map((error) => error.code), [
        'update_verification_failed',
        'update_storage_failed',
        'update_install_failed',
      ]);
      expect(diagnosticCodes.length, 206);
    },
  );

  test(
    'local diagnostics collect observations without sending or mutating VPN',
    () async {
      final bridge = _Snapshot();
      final wg = fixtures.ProbeWireGuard();
      final ovpn = fixtures.ProbeOpenVpn();
      final app = AppController(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: wg,
        openVpn: ovpn,
        diagnosticsBridge: bridge,
      );
      addTearDown(app.dispose);
      await app.runUserDiagnostic(
        send: true,
      ); // No account => no sending, even if requested.
      expect(bridge.calls, 1);
      expect(app.preparedDiagnosticReport, isNotNull);
      expect(app.diagnostics.pendingReports, isEmpty);
      expect(app.diagnostics.receipts, isEmpty);
      expect(
        app.preparedDiagnosticReport!.json.containsKey('runtime'),
        isFalse,
      );
      expect(
        app.preparedDiagnosticReport!.json.toString(),
        isNot(contains('audit-user')),
      );
      expect(
        app.diagnosticChecks
            .firstWhere((c) => c.label == 'Configuration DNS')
            .result,
        'unknown',
      );
      expect(
        app.diagnosticChecks
            .firstWhere((c) => c.label == 'Accès Internet')
            .result,
        'skipped',
      );
      expect(wg.connectCalls, 0);
      expect(wg.disconnectCalls, 0);
      expect(ovpn.importCalls, 0);
      expect(ovpn.disconnectCalls, 0);
      expect(app.vpnStatus, VpnStatus.disconnected);
    },
  );

  test(
    'sign out invalidates a slow collection and cannot leave a sendable report',
    () async {
      final bridge = _Snapshot()..gate = Completer<void>();
      final app = _UiController(bridge);
      addTearDown(app.dispose);
      final collecting = app.runUserDiagnostic();
      while (bridge.calls == 0) {
        await Future<void>.delayed(Duration.zero);
      }
      await app.signOut();
      bridge.gate!.complete();
      await collecting;
      expect(app.preparedDiagnosticReport, isNull);
      expect(app.diagnosticResults, isNull);
      expect(app.diagnosticRunning, isFalse);
    },
  );

  test(
    'direct account replacement invalidates an in-progress collection',
    () async {
      final bridge = _Snapshot()..gate = Completer<void>();
      final app = AppController(
        api: _SwitchAccountApi(),
        store: _SwitchAccountStore(),
        window: fixtures.ProbeWindow(),
        wireguard: _CleanupWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        diagnosticsBridge: bridge,
      )..profile = fixtures.account;
      addTearDown(app.dispose);
      await app.diagnostics.sessionChanged(
        accountId: fixtures.account.userId,
        tokenProvider: () async => 'synthetic-first-token',
      );
      final collecting = app.runUserDiagnostic(send: true);
      while (bridge.calls == 0) {
        await Future<void>.delayed(Duration.zero);
      }
      expect(
        await app.signIn(
          email: 'second@example.invalid',
          password: 'synthetic',
        ),
        isTrue,
      );
      bridge.gate!.complete();
      await collecting;
      expect(app.profile!.userId, 'second-test-account');
      expect(app.preparedDiagnosticReport, isNull);
      expect(app.diagnosticResults, isNull);
      expect(app.diagnostics.pendingReports, isEmpty);
    },
  );

  test('another Windows owner is never offered cleanup', () async {
    final bridge = _Snapshot()
      ..otherUser = true
      ..cleanup = true;
    final app = _UiController(bridge);
    addTearDown(app.dispose);
    await app.runUserDiagnostic();
    expect(app.canRepairDiagnosticCleanup, isFalse);
    await app.repairDiagnosticCleanup();
    expect(app.diagnosticRepairRunning, isFalse);
  });

  for (final verificationFails in [false, true]) {
    test(
      'cleanup repair verifies protection release ($verificationFails)',
      () async {
        final bridge = _Snapshot()..cleanup = true;
        final wg = _CleanupWireGuard()
          ..connected = true
          ..protectionActive = true
          ..verificationFails = verificationFails;
        final app = AppController(
          api: fixtures.ProbeApi(),
          store: fixtures.ProbeStore(),
          window: fixtures.ProbeWindow(),
          wireguard: wg,
          openVpn: fixtures.ProbeOpenVpn(),
          diagnosticsBridge: bridge,
        )..activeProtocol = VpnProtocol.wireGuard;
        addTearDown(app.dispose);
        await app.runUserDiagnostic();
        final before = app.preparedDiagnosticReport!.reportId;
        expect(app.canRepairDiagnosticCleanup, isTrue);
        await app.repairDiagnosticCleanup();
        expect(wg.disconnectCalls, 1);
        expect(bridge.calls, 2);
        final report = app.preparedDiagnosticReport!;
        expect(report.reportId, isNot(before));
        final repair = (report.json['repairs'] as List).single as Map;
        expect(repair['after'], verificationFails ? 'unknown' : 'passed');
        expect(app.diagnostics.pendingReports, isEmpty);
        expect(app.diagnostics.receipts, isEmpty);
        expect(
          app.diagnosticMessage,
          verificationFails
              ? 'Le nettoyage reste non confirmé.'
              : 'La déconnexion et le nettoyage sont confirmés.',
        );
      },
    );
  }

  for (final terminalFailure in [false, true]) {
    test(
      'disconnect reports only unrecovered failure ($terminalFailure)',
      () async {
        final diagnostic = _RecordingDiagnostics();
        final wg = _CleanupWireGuard()
          ..connected = true
          ..protectionActive = true
          ..cleanupFails = terminalFailure
          ..loseDisconnectAcknowledgement = !terminalFailure;
        final app =
            AppController(
                api: fixtures.ProbeApi(),
                store: fixtures.ProbeStore(),
                window: fixtures.ProbeWindow(),
                wireguard: wg,
                openVpn: fixtures.ProbeOpenVpn(),
                diagnostics: diagnostic,
              )
              ..profile = fixtures.account
              ..activeProtocol = VpnProtocol.wireGuard
              ..vpnStatus = VpnStatus.connected;
        addTearDown(app.dispose);
        await app.toggleConnection();
        expect(diagnostic.terminalErrors.length, terminalFailure ? 1 : 0);
        if (terminalFailure) {
          expect(diagnostic.terminalErrors.single.operation, 'disconnect');
        } else {
          expect(app.vpnStatus, VpnStatus.disconnected);
        }
      },
    );
  }

  test(
    'slow diagnostic does not delay disconnect and discards stale results',
    () async {
      final bridge = _Snapshot()..gate = Completer<void>();
      final wg = _CleanupWireGuard()
        ..connected = true
        ..protectionActive = true;
      final app =
          AppController(
              api: fixtures.ProbeApi(),
              store: fixtures.ProbeStore(),
              window: fixtures.ProbeWindow(),
              wireguard: wg,
              openVpn: fixtures.ProbeOpenVpn(),
              diagnosticsBridge: bridge,
            )
            ..activeProtocol = VpnProtocol.wireGuard
            ..vpnStatus = VpnStatus.connected;
      addTearDown(app.dispose);
      final collecting = app.runUserDiagnostic();
      while (bridge.calls == 0) {
        await Future<void>.delayed(Duration.zero);
      }
      await app.toggleConnection().timeout(const Duration(seconds: 2));
      expect(app.vpnStatus, VpnStatus.disconnected);
      expect(bridge.gate!.isCompleted, isFalse);
      bridge.gate!.complete();
      await collecting;
      expect(app.preparedDiagnosticReport, isNull);
    },
  );

  test('diagnostic consent and cleanup messages cover all 30 languages', () {
    const messages = [
      'Diagnostic',
      'Diagnostic complet',
      'Diagnostic complet collecté. Connectez-vous à votre compte pour l’envoyer.',
      'Le bouton Diagnostic collecte les vérifications, l’état du service et les journaux techniques, puis les transmet à l’assistance FuzeVPN. Les secrets et l’historique de navigation sont exclus. Conservation sur le serveur : 30 jours.',
      'En cas d’échec d’envoi, le rapport reste chiffré en attente pendant 24 heures au maximum. Vous pouvez annuler les tentatives restantes.',
      'Cette action réessaie l’arrêt du VPN et son nettoyage. Si elle réussit, le tunnel et ses protections sont retirés. Votre connexion Internet habituelle peut reprendre.',
    ];
    expect(translationCatalogs, hasLength(30));
    for (final key in messages) {
      expect(sourceCatalog, contains(key), reason: key);
      for (final language in AppLanguage.values.where(
        (value) => value != AppLanguage.system,
      )) {
        final translated = translationCatalogs[language.storageValue]![key];
        expect(
          translated?.trim(),
          isNotEmpty,
          reason: '${language.name}: $key',
        );
        expect(AppStrings.forLanguage(language).text(key), translated);
      }
    }
  });

  testWidgets('local diagnostic is accessible while sign-in remains required', (
    tester,
  ) async {
    final app = _UiController(_Snapshot())..isInitialized = true;
    addTearDown(app.dispose);
    await tester.pumpWidget(FuzeVpnApp(controller: app));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Diagnostic local'));
    await tester.pumpAndSettle();
    expect(find.byType(CheckboxListTile), findsNothing);
    expect(find.widgetWithText(FilledButton, 'Diagnostic'), findsOneWidget);
    await tester.tap(find.text('Fermer').last);
    await tester.pumpAndSettle();
    expect(find.byType(TextField), findsNWidgets(2));
    expect(app.profile, isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('diagnostic controls fit supported sizes, themes and languages', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    for (final size in [const Size(640, 360), const Size(1280, 720)]) {
      tester.view.physicalSize = size;
      for (final language in AppLanguage.values.where(
        (l) => l != AppLanguage.system,
      )) {
        for (final theme in [ThemeMode.light, ThemeMode.dark]) {
          final app = _UiController(_Snapshot())
            ..profile = fixtures.account
            ..section = AppSection.help
            ..language = language
            ..themeMode = theme;
          await tester.pumpWidget(FuzeVpnApp(controller: app));
          await tester.pump();
          final action = find.widgetWithText(
            FilledButton,
            AppStrings.forLanguage(language).text('Diagnostic'),
          );
          expect(action, findsOneWidget);
          expect(tester.widget<FilledButton>(action).onPressed, isNotNull);
          expect(find.byType(CheckboxListTile), findsNothing);
          expect(
            tester.takeException(),
            isNull,
            reason: '$size $language $theme',
          );
          await tester.pumpWidget(const SizedBox.shrink());
          app.dispose();
        }
      }
    }
  });
}
