// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/app_shell.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixture;

class _UiController extends AppController {
  _UiController({required fixture.ProbeApi api, fixture.ProbeStore? store})
    : super(
        api: api,
        store: store ?? fixture.ProbeStore(),
        wireguard: fixture.ProbeWireGuard(),
        openVpn: fixture.ProbeOpenVpn(),
        window: fixture.ProbeWindow(),
      ) {
    isInitialized = true;
    profile = fixture.account;
    locations = [fixture.source, fixture.target];
    selectedLocation = fixture.source;
    isLoadingLocations = false;
    language = AppLanguage.french;
    killSwitchEnabled = false;
  }

  int quickConnectCalls = 0;

  @override
  Future<void> initialize() async {}

  @override
  Future<void> quickConnect() {
    quickConnectCalls++;
    return super.quickConnect();
  }

  @override
  Future<bool> signIn({required String email, required String password}) async {
    profile = fixture.account;
    errorMessage = null;
    notifyListeners();
    return true;
  }
}

class _LanguageStore extends fixture.ProbeStore {
  bool fail = true;
  Completer<void>? gate;
  final writes = <String>[];

  @override
  Future<void> saveAppLanguage(String value) async {
    writes.add(value);
    await gate?.future;
    if (fail) throw StateError('Synthetic language-store failure');
  }
}

Future<void> _pumpApp(WidgetTester tester, _UiController controller) async {
  tester.view.physicalSize = const Size(1280, 900);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(FuzeVpnApp(controller: controller));
  await tester.pumpAndSettle();
}

Future<void> _closeApp(WidgetTester tester, AppController controller) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pumpAndSettle();
  expect(tester.takeException(), isNull);
  controller.dispose();
}

Finder get _dialogs => find.byType(AlertDialog, skipOffstage: false);

Future<void> _submitSignIn(WidgetTester tester) async {
  final button = find.widgetWithText(FilledButton, 'Se connecter');
  expect(button, findsOneWidget);
  await tester.tap(button);
  await tester.pumpAndSettle();
}

void main() {
  for (final killSwitch in [false, true]) {
    testWidgets(
      '401 opens one required sign-in and resumes once (kill switch $killSwitch)',
      (tester) async {
        final api = fixture.ProbeApi()
          ..registerError = const ApiException(
            statusCode: 401,
            errorCode: 'unauthorized',
          );
        final controller = _UiController(api: api)
          ..killSwitchEnabled = killSwitch;
        await _pumpApp(tester, controller);
        expect(_dialogs, findsNothing);
        await controller.quickConnect();
        await tester.pumpAndSettle();
        expect(controller.profile, isNull);
        if (killSwitch) {
          expect(controller.vpnStatus, VpnStatus.blocked);
          expect(_dialogs, findsNothing);
          await controller.quickConnect();
          await tester.pumpAndSettle();
        }
        expect(_dialogs, findsOneWidget);
        expect(find.text('Annuler'), findsNothing);
        await tester.tapAt(const Offset(8, 8));
        await tester.pumpAndSettle();
        expect(_dialogs, findsOneWidget);
        final beforeSignIn = controller.quickConnectCalls;
        api.registerError = null;
        await _submitSignIn(tester);
        expect(_dialogs, findsNothing);
        expect(controller.quickConnectCalls, beforeSignIn + 1);
        await _closeApp(tester, controller);
      },
    );
  }

  testWidgets('account and quick-connect requests share their sign-in intent', (
    tester,
  ) async {
    final controller = _UiController(api: fixture.ProbeApi())..profile = null;
    await _pumpApp(tester, controller);
    final accountButton = tester.widget<InkWell>(
      find.descendant(
        of: find.byTooltip('Mon compte', skipOffstage: false),
        matching: find.byType(InkWell, skipOffstage: false),
        skipOffstage: false,
      ),
    );
    final connectButton = tester.widget<FilledButton>(
      find.byKey(
        const ValueKey('connection-primary-action'),
        skipOffstage: false,
      ),
    );
    // Concurrent account and connection actions merge into the existing gate.
    accountButton.onTap!();
    connectButton.onPressed!();
    await tester.pumpAndSettle();
    expect(_dialogs, findsOneWidget);
    expect(find.text('Annuler'), findsNothing);
    await tester.tapAt(const Offset(8, 8));
    await tester.pumpAndSettle();
    expect(_dialogs, findsOneWidget);
    await _submitSignIn(tester);
    expect(_dialogs, findsNothing);
    expect(controller.quickConnectCalls, 1);
    await _closeApp(tester, controller);
  });

  testWidgets('devices and account routes share one optional sign-in', (
    tester,
  ) async {
    final controller = _UiController(api: fixture.ProbeApi())
      ..profile = null
      ..isInitialized = false
      ..section = AppSection.devices;
    await _pumpApp(tester, controller);
    final accountButton = tester.widget<InkWell>(
      find.descendant(
        of: find.byTooltip('Mon compte'),
        matching: find.byType(InkWell),
      ),
    );
    final deviceButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Se connecter'),
    );
    accountButton.onTap!();
    deviceButton.onPressed!();
    await tester.pumpAndSettle();
    expect(_dialogs, findsOneWidget);
    expect(find.text('Annuler'), findsOneWidget);
    controller.isInitialized = true;
    controller.notifyListeners();
    await tester.pumpAndSettle();
    expect(_dialogs, findsOneWidget);
    expect(find.text('Annuler'), findsNothing);
    await tester.tapAt(const Offset(8, 8));
    await tester.pumpAndSettle();
    expect(_dialogs, findsOneWidget);
    await _submitSignIn(tester);
    expect(_dialogs, findsNothing);
    expect(controller.quickConnectCalls, 0);
    await _closeApp(tester, controller);
  });

  testWidgets('standalone devices page retains its sign-in route', (
    tester,
  ) async {
    final controller = _UiController(api: fixture.ProbeApi())
      ..profile = null
      ..isInitialized = false;
    await tester.pumpWidget(
      MaterialApp(
        locale: AppLanguage.french.locale,
        supportedLocales: AppStrings.supportedLocales,
        localizationsDelegates: const [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        home: Scaffold(body: DevicesPage(controller: controller)),
      ),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(OutlinedButton, 'Se connecter'));
    await tester.pumpAndSettle();
    expect(_dialogs, findsOneWidget);
    await tester.tap(find.text('Annuler'));
    await tester.pumpAndSettle();
    expect(_dialogs, findsNothing);
    await _closeApp(tester, controller);
  });

  testWidgets(
    'failed language save restores persisted selection without retry',
    (tester) async {
      final store = _LanguageStore();
      final controller = _UiController(api: fixture.ProbeApi(), store: store)
        ..section = AppSection.settings;
      await _pumpApp(tester, controller);
      final dropdown = find.byType(DropdownButton<AppLanguage>);
      expect(
        tester.widget<DropdownButton<AppLanguage>>(dropdown).value,
        AppLanguage.french,
      );
      tester.widget<DropdownButton<AppLanguage>>(dropdown).onChanged!(
        AppLanguage.english,
      );
      await tester.pumpAndSettle();
      expect(controller.language, AppLanguage.french);
      expect(controller.experienceSettingsError, isNotNull);
      expect(
        tester.widget<DropdownButton<AppLanguage>>(dropdown).value,
        AppLanguage.french,
      );
      expect(store.writes, ['en']);
      store.fail = false;
      tester.widget<DropdownButton<AppLanguage>>(dropdown).onChanged!(
        AppLanguage.english,
      );
      await tester.pumpAndSettle();
      expect(controller.language, AppLanguage.english);
      expect(
        tester.widget<DropdownButton<AppLanguage>>(dropdown).value,
        AppLanguage.english,
      );
      expect(store.writes, ['en', 'en']);
      expect(controller.experienceSettingsError, isNull);
      await _closeApp(tester, controller);
    },
  );

  testWidgets(
    'latest language selection can cancel a pending different language',
    (tester) async {
      final store = _LanguageStore()
        ..fail = false
        ..gate = Completer<void>();
      final controller = _UiController(api: fixture.ProbeApi(), store: store)
        ..section = AppSection.settings;
      await _pumpApp(tester, controller);
      final dropdown = find.byType(DropdownButton<AppLanguage>);
      tester.widget<DropdownButton<AppLanguage>>(dropdown).onChanged!(
        AppLanguage.english,
      );
      await tester.pump();
      expect(controller.language, AppLanguage.french);
      tester.widget<DropdownButton<AppLanguage>>(dropdown).onChanged!(
        AppLanguage.french,
      );
      store.gate!.complete();
      await tester.pumpAndSettle();
      expect(controller.language, AppLanguage.french);
      expect(
        tester.widget<DropdownButton<AppLanguage>>(dropdown).value,
        AppLanguage.french,
      );
      expect(store.writes, ['en', 'fr']);
      await _closeApp(tester, controller);
    },
  );

  testWidgets(
    'language rollback uses latest persisted value for queued saves',
    (tester) async {
      final store = _LanguageStore()..gate = Completer<void>();
      final controller = _UiController(api: fixture.ProbeApi(), store: store)
        ..section = AppSection.settings;
      await _pumpApp(tester, controller);
      final dropdown = find.byType(DropdownButton<AppLanguage>);
      tester.widget<DropdownButton<AppLanguage>>(dropdown).onChanged!(
        AppLanguage.english,
      );
      tester.widget<DropdownButton<AppLanguage>>(dropdown).onChanged!(
        AppLanguage.german,
      );
      await tester.pump();
      store.gate!.complete();
      await tester.pumpAndSettle();
      expect(controller.language, AppLanguage.french);
      expect(
        tester.widget<DropdownButton<AppLanguage>>(dropdown).value,
        AppLanguage.french,
      );
      expect(store.writes, ['en', 'de']);
      await _closeApp(tester, controller);
    },
  );
}
