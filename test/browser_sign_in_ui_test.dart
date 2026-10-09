// SPDX-License-Identifier: MPL-2.0
// Synthetic browser-auth states only: no browser, API or VPN is operated.
import 'dart:async';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixture;

class _BrowserUiController extends AppController {
  _BrowserUiController()
    : super(
        api: fixture.ProbeApi(),
        store: fixture.ProbeStore(),
        wireguard: fixture.ProbeWireGuard(),
        openVpn: fixture.ProbeOpenVpn(),
        window: fixture.ProbeWindow(),
      ) {
    isInitialized = false;
    isLoadingLocations = false;
    language = AppLanguage.french;
    section = AppSection.devices;
    locations = [fixture.source, fixture.target];
    selectedLocation = fixture.source;
    killSwitchEnabled = false;
  }

  Completer<bool>? browserCompletion;
  Future<bool>? reopening;
  int browserStarts = 0;
  int reopenRequests = 0;
  int cancellations = 0;
  int emailSubmissions = 0;
  int quickConnectRequests = 0;

  @override
  Future<void> initialize() async {}

  @override
  Future<bool> signIn({required String email, required String password}) async {
    emailSubmissions++;
    profile = fixture.account;
    notifyListeners();
    return true;
  }

  @override
  Future<void> quickConnect() async {
    quickConnectRequests++;
  }

  @override
  Future<bool> signInWithBrowser() {
    browserStarts++;
    browserSignInErrorMessage = null;
    browserSignInStatus = BrowserSignInStatus.waitingForBrowser;
    browserCompletion = Completer<bool>();
    notifyListeners();
    return browserCompletion!.future;
  }

  @override
  Future<bool> reopenBrowserSignIn() async {
    reopenRequests++;
    final result = await (reopening ?? Future.value(true));
    if (!result) {
      browserSignInErrorMessage = 'Le navigateur n’a pas pu être ouvert.';
      notifyListeners();
    }
    return result;
  }

  @override
  void cancelBrowserSignIn() {
    if (browserSignInStatus == BrowserSignInStatus.completingSignIn) return;
    if (browserSignInStatus == BrowserSignInStatus.idle &&
        browserCompletion == null) {
      return;
    }
    cancellations++;
    browserSignInStatus = BrowserSignInStatus.idle;
    browserSignInErrorMessage = null;
    final pending = browserCompletion;
    browserCompletion = null;
    if (pending != null && !pending.isCompleted) pending.complete(false);
    notifyListeners();
  }

  void setPhase(BrowserSignInStatus phase) {
    browserSignInStatus = phase;
    notifyListeners();
  }

  void finish({required bool success, String? error}) {
    browserSignInStatus = BrowserSignInStatus.idle;
    browserSignInErrorMessage = error;
    errorMessage = error;
    if (success) profile = fixture.account;
    final pending = browserCompletion!;
    browserCompletion = null;
    pending.complete(success);
    notifyListeners();
  }
}

const _browserStart = ValueKey('sign-in-browser');
const _browserWaiting = ValueKey('sign-in-browser-waiting');
const _browserReopen = ValueKey('sign-in-browser-reopen');
const _browserCancel = ValueKey('sign-in-browser-cancel');
const _previewOutput = String.fromEnvironment('BROWSER_UI_PREVIEW_OUTPUT');
bool _previewFontsLoaded = false;

Future<void> _loadPreviewFonts(WidgetTester tester) async {
  if (_previewOutput.isEmpty || _previewFontsLoaded) return;
  await tester.runAsync(() async {
    for (final entry in {
      'Archivo': 'assets/fonts/Archivo-Variable.ttf',
      'Segoe UI': 'C:/Windows/Fonts/segoeui.ttf',
      'Roboto': 'C:/Windows/Fonts/segoeui.ttf',
      'Tahoma': 'C:/Windows/Fonts/tahoma.ttf',
      'MaterialIcons':
          '.toolchain/flutter/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
    }.entries) {
      final file = File(entry.value);
      if (!await file.exists()) continue;
      final loader = FontLoader(entry.key)
        ..addFont(Future.value(ByteData.sublistView(await file.readAsBytes())));
      await loader.load();
    }
  });
  _previewFontsLoaded = true;
}

Future<void> _openSignIn(
  WidgetTester tester,
  _BrowserUiController controller, {
  Size size = const Size(1280, 900),
  double scale = 1,
  GlobalKey? captureKey,
}) async {
  await _loadPreviewFonts(tester);
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  tester.platformDispatcher.textScaleFactorTestValue = scale;
  final app = FuzeVpnApp(controller: controller);
  await tester.pumpWidget(
    captureKey == null ? app : RepaintBoundary(key: captureKey, child: app),
  );
  await tester.pumpAndSettle();
  final signIn = find.widgetWithText(
    OutlinedButton,
    AppStrings.forLanguage(controller.language).text('Se connecter'),
  );
  await tester.ensureVisible(signIn);
  await tester.tap(signIn);
  await tester.pumpAndSettle();
  expect(find.byType(AlertDialog), findsOneWidget);
}

Future<void> _tap(WidgetTester tester, ValueKey<String> key) async {
  final button = find.byKey(key);
  await tester.ensureVisible(button);
  await tester.tap(button);
  // Auth states have an indeterminate progress indicator. Do not settle it.
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 250));
}

Future<void> _close(
  WidgetTester tester,
  _BrowserUiController controller,
) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  expect(tester.takeException(), isNull);
  controller.dispose();
}

void main() {
  testWidgets('browser option preserves the email and password route', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final controller = _BrowserUiController();
    await _openSignIn(tester, controller);
    expect(find.byKey(_browserStart), findsOneWidget);
    expect(find.byType(TextField), findsNWidgets(2));
    await tester.enterText(
      find.byType(TextField).first,
      'test@example.invalid',
    );
    await tester.enterText(find.byType(TextField).last, 'synthetic-password');
    final emailSubmit = find.widgetWithText(FilledButton, 'Se connecter');
    await tester.ensureVisible(emailSubmit);
    await tester.tap(emailSubmit);
    await tester.pumpAndSettle();
    expect(controller.emailSubmissions, 1);
    expect(controller.browserStarts, 0);
    expect(find.byType(AlertDialog), findsNothing);
    await _close(tester, controller);
  });

  testWidgets('waiting is exclusive and cancellation restores email input', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final controller = _BrowserUiController();
    await _openSignIn(tester, controller);
    await tester.enterText(
      find.byType(TextField).first,
      'test@example.invalid',
    );
    await _tap(tester, _browserStart);
    expect(find.byKey(_browserWaiting), findsOneWidget);
    expect(find.byType(TextField), findsNothing);
    expect(find.widgetWithText(FilledButton, 'Se connecter'), findsNothing);
    expect(find.text('Connexion dans le navigateur'), findsOneWidget);
    await tester.tapAt(const Offset(5, 5));
    await tester.pump();
    await tester.binding.handlePopRoute();
    await tester.pump();
    expect(find.byType(AlertDialog), findsOneWidget);
    expect(controller.browserStarts, 1);
    expect(controller.emailSubmissions, 0);
    await _tap(tester, _browserCancel);
    await tester.pumpAndSettle();
    expect(controller.cancellations, 1);
    expect(find.byType(TextField), findsNWidgets(2));
    expect(
      tester.widget<TextField>(find.byType(TextField).first).controller!.text,
      'test@example.invalid',
    );
    expect(find.byKey(_browserStart), findsOneWidget);
    await _close(tester, controller);
  });

  testWidgets('reopening displays its failure without starting another login', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final controller = _BrowserUiController()..reopening = Future.value(false);
    await _openSignIn(tester, controller);
    await _tap(tester, _browserStart);
    await _tap(tester, _browserReopen);
    expect(controller.reopenRequests, 1);
    expect(controller.browserStarts, 1);
    expect(find.text('Le navigateur n’a pas pu être ouvert.'), findsOneWidget);
    expect(find.byKey(_browserWaiting), findsOneWidget);
    await _tap(tester, _browserCancel);
    await _close(tester, controller);
  });

  testWidgets('finalization cannot be cancelled and success closes the route', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final controller = _BrowserUiController();
    await _openSignIn(tester, controller);
    await _tap(tester, _browserStart);
    controller.setPhase(BrowserSignInStatus.completingSignIn);
    await tester.pump();
    expect(find.text('Finalisation de la connexion…'), findsOneWidget);
    expect(find.byKey(_browserCancel), findsNothing);
    expect(find.byKey(_browserReopen), findsNothing);
    await tester.tapAt(const Offset(5, 5));
    await tester.binding.handlePopRoute();
    await tester.pump();
    expect(find.byType(AlertDialog), findsOneWidget);
    controller.finish(success: true);
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(controller.profile, fixture.account);
    expect(controller.emailSubmissions, 0);
    expect(controller.cancellations, 0);
    await _close(tester, controller);
  });

  testWidgets('expiration restores both login methods with an explicit error', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final controller = _BrowserUiController();
    await _openSignIn(tester, controller);
    await _tap(tester, _browserStart);
    const error =
        'La demande de connexion a expiré. Ouvrez à nouveau le navigateur depuis FuzeVPN.';
    controller.finish(success: false, error: error);
    await tester.pumpAndSettle();
    expect(find.text(error), findsOneWidget);
    expect(find.byKey(_browserStart), findsOneWidget);
    expect(find.byType(TextField), findsNWidgets(2));
    await _tap(tester, _browserStart);
    expect(find.text(error), findsNothing);
    await _tap(tester, _browserCancel);
    await _close(tester, controller);
  });

  testWidgets('an old reopen failure cannot affect a later browser attempt', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final reopening = Completer<bool>();
    final controller = _BrowserUiController()..reopening = reopening.future;
    await _openSignIn(tester, controller);
    await _tap(tester, _browserStart);
    await _tap(tester, _browserReopen);
    await _tap(tester, _browserCancel);
    await _tap(tester, _browserStart);
    reopening.completeError(StateError('Synthetic delayed launcher failure'));
    await tester.pump();
    expect(find.text('Le navigateur n’a pas pu être ouvert.'), findsNothing);
    expect(find.byKey(_browserWaiting), findsOneWidget);
    expect(controller.browserStarts, 2);
    await _tap(tester, _browserCancel);
    await _close(tester, controller);
  });

  testWidgets('disposing the dialog cancels its pending browser login', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    final controller = _BrowserUiController();
    await _openSignIn(tester, controller);
    await _tap(tester, _browserStart);
    await _close(tester, controller);
    expect(controller.cancellations, 1);
  });

  testWidgets('browser states wrap at minimum size with enlarged text', (
    tester,
  ) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    for (final mode in [ThemeMode.light, ThemeMode.dark]) {
      for (final language in [
        AppLanguage.french,
        AppLanguage.english,
        AppLanguage.german,
        AppLanguage.arabic,
      ]) {
        final controller = _BrowserUiController()
          ..language = language
          ..themeMode = mode;
        await _openSignIn(
          tester,
          controller,
          size: const Size(640, 360),
          scale: 2,
        );
        expect(
          tester.takeException(),
          isNull,
          reason: '$language / $mode idle',
        );
        final strings = AppStrings.forLanguage(language);
        for (final label in ['Mises à jour', 'Diagnostic local']) {
          final link = find.text(strings.text(label));
          await tester.ensureVisible(link);
          expect(
            link.hitTestable(),
            findsOneWidget,
            reason: '$language / $mode $label must remain reachable',
          );
        }
        for (final field in find.byType(TextField).evaluate()) {
          final input = find.byWidget(field.widget);
          await tester.ensureVisible(input);
          expect(input.hitTestable(), findsOneWidget);
        }
        await _tap(tester, _browserStart);
        expect(
          tester.takeException(),
          isNull,
          reason: '$language / $mode waiting',
        );
        final reopen = find.byKey(_browserReopen);
        await tester.ensureVisible(reopen);
        expect(reopen.hitTestable(), findsOneWidget);
        final cancel = find.byKey(_browserCancel);
        await tester.ensureVisible(cancel);
        expect(cancel.hitTestable(), findsOneWidget);
        controller.setPhase(BrowserSignInStatus.completingSignIn);
        await tester.pump();
        expect(
          tester.takeException(),
          isNull,
          reason: '$language / $mode completing',
        );
        controller.finish(success: true);
        await tester.pumpAndSettle();
        await _close(tester, controller);
      }
    }
  });

  testWidgets('browser dialog visual previews', (tester) async {
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    for (final mode in [ThemeMode.light, ThemeMode.dark]) {
      final controller = _BrowserUiController()..themeMode = mode;
      final boundaryKey = GlobalKey();
      await _openSignIn(
        tester,
        controller,
        size: const Size(1080, 800),
        captureKey: boundaryKey,
      );
      FocusManager.instance.primaryFocus?.unfocus();
      await tester.pumpAndSettle();
      for (final state in ['initial', 'waiting']) {
        if (state == 'waiting') await _tap(tester, _browserStart);
        expect(tester.takeException(), isNull);
        final boundary =
            boundaryKey.currentContext!.findRenderObject()!
                as RenderRepaintBoundary;
        await tester.runAsync(() async {
          final image = await boundary.toImage();
          final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
          final file = File(
            '$_previewOutput/browser-sign-in-${mode.name}-$state.png',
          );
          await file.parent.create(recursive: true);
          await file.writeAsBytes(bytes!.buffer.asUint8List());
          image.dispose();
        });
      }
      await _tap(tester, _browserCancel);
      await _close(tester, controller);
    }
  }, skip: _previewOutput.isEmpty);
}
