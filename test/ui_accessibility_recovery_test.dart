// SPDX-License-Identifier: MPL-2.0
// Synthetic UI states only: no initialization, API, native or VPN operation.
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'support/audit_fixtures.dart' as fixtures;

const _sessionError =
    'Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.';
const _loginError = 'Adresse e-mail ou mot de passe incorrect.';
const _migrationWarning =
    'Souhaitez-vous vraiment changer de serveur ? Votre connexion VPN sera interrompue pendant le changement, puis rétablie automatiquement.';

class _AvailableUpdate extends WindowsUpdateController {
  final _availableRelease = WindowsUpdateRelease(
    version: WindowsUpdateVersion.parse('99.0.0'),
    downloadUrl: Uri.parse('https://example.invalid/update.exe'),
    sha256: '0' * 64,
    releaseNotes: '',
  );

  @override
  WindowsUpdateStatus get status => WindowsUpdateStatus.available;
  @override
  WindowsUpdateRelease get release => _availableRelease;
}

class _UiController extends AppController {
  _UiController({this.sessionPending = false, bool updateAvailable = false})
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
        updates: updateAvailable ? _AvailableUpdate() : null,
      ) {
    isInitialized = true;
    isLoadingLocations = false;
    profile = sessionPending ? null : fixtures.account;
    language = AppLanguage.french;
    locations = const [fixtures.source, fixtures.target];
    selectedLocation = fixtures.source;
  }

  final bool sessionPending;
  int sessionRetries = 0;

  @override
  bool get savedSessionVerificationPending => sessionPending;
  @override
  String? get savedSessionVerificationErrorMessage =>
      sessionPending ? _sessionError : null;
  @override
  Future<void> initialize() async {}
  @override
  Future<void> retrySavedSessionVerification() async => sessionRetries++;
  @override
  Future<void> quickConnect() =>
      throw StateError('A UI regression test cannot operate a VPN.');
  @override
  Future<bool> signIn({required String email, required String password}) async {
    errorMessage = _loginError;
    notifyListeners();
    return false;
  }
}

bool _fontsLoaded = false;

Future<void> _loadFonts(WidgetTester tester) async {
  if (_fontsLoaded) return;
  await tester.runAsync(() async {
    final archivo = File('assets/fonts/Archivo-Variable.ttf');
    expect(await archivo.exists(), isTrue);
    for (final entry in {
      'Archivo': archivo.path,
      'Segoe UI': 'C:/Windows/Fonts/segoeui.ttf',
      'MaterialIcons':
          '.toolchain/flutter/bin/cache/artifacts/material_fonts/MaterialIcons-Regular.otf',
    }.entries) {
      final file = File(entry.value);
      if (!await file.exists()) continue;
      final bytes = ByteData.sublistView(await file.readAsBytes());
      await (FontLoader(entry.key)..addFont(Future.value(bytes))).load();
    }
  });
  _fontsLoaded = true;
}

Future<GlobalKey> _mount(WidgetTester tester, _UiController app) async {
  await _loadFonts(tester);
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = const Size(640, 360);
  tester.platformDispatcher.textScaleFactorTestValue = 2;
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
  final capture = GlobalKey();
  await tester.pumpWidget(
    RepaintBoundary(
      key: capture,
      child: FuzeVpnApp(controller: app),
    ),
  );
  await tester.pumpAndSettle();
  expect(tester.takeException(), isNull);
  return capture;
}

Future<void> _capture(WidgetTester tester, GlobalKey key, String name) async {
  const destination = String.fromEnvironment('UI_AUDIT_CAPTURE_DIR');
  if (destination.isEmpty) return;
  await tester.runAsync(() async {
    final boundary =
        key.currentContext!.findRenderObject()! as RenderRepaintBoundary;
    final image = await boundary.toImage();
    try {
      final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
      final file = File('$destination/$name.png');
      await file.parent.create(recursive: true);
      await file.writeAsBytes(bytes!.buffer.asUint8List());
    } finally {
      image.dispose();
    }
  });
}

Future<void> _close(WidgetTester tester, AppController app) async {
  await tester.pumpWidget(const SizedBox.shrink());
  app.dispose();
  expect(tester.takeException(), isNull);
}

void main() {
  for (final updateAvailable in [false, true]) {
    testWidgets(
      'session recovery and page actions remain reachable at 640x360 text x2 (update $updateAvailable)',
      (tester) async {
        final app = _UiController(
          sessionPending: true,
          updateAvailable: updateAvailable,
        );
        final capture = await _mount(tester, app);
        final notice = find.byKey(
          const ValueKey('saved-session-verification-notice'),
        );
        final retry = find.descendant(
          of: notice,
          matching: find.widgetWithText(OutlinedButton, 'Réessayer'),
        );
        await tester.ensureVisible(retry);
        await tester.pumpAndSettle();
        expect(retry.hitTestable(), findsOneWidget);
        await _capture(
          tester,
          capture,
          'session-retry-update-$updateAvailable',
        );
        await tester.tap(retry);
        expect(app.sessionRetries, 1);

        final primary = find.byKey(const ValueKey('connection-primary-action'));
        await tester.ensureVisible(primary);
        await tester.pumpAndSettle();
        expect(primary.hitTestable(), findsOneWidget);
        await tester.tap(primary);
        expect(app.sessionRetries, 2);
        await _capture(
          tester,
          capture,
          'primary-retry-update-$updateAvailable',
        );
        for (final section in AppSection.values) {
          app.selectSection(section);
          await tester.pumpAndSettle();
          expect(tester.takeException(), isNull, reason: section.name);
        }
        await _close(tester, app);
      },
    );
  }

  testWidgets('server-change warning scrolls completely before confirmation', (
    tester,
  ) async {
    final app = _UiController()
      ..section = AppSection.locations
      ..vpnStatus = VpnStatus.connected
      ..tunnelLocationId = fixtures.source.id;
    final capture = await _mount(tester, app);
    final search = find.byKey(const ValueKey('location-search'));
    await tester.ensureVisible(search);
    await tester.enterText(search, 'Target');
    await tester.pumpAndSettle();
    final row = find.byKey(const ValueKey('location-server-target'));
    await tester.ensureVisible(row);
    await tester.tap(row);
    await tester.pumpAndSettle();
    final message = find.text(_migrationWarning);
    final paragraph = tester.renderObject<RenderParagraph>(message);
    final painter = TextPainter(
      text: paragraph.text,
      textDirection: paragraph.textDirection,
      textScaler: paragraph.textScaler,
    )..layout(maxWidth: paragraph.size.width);
    expect(paragraph.size.height, greaterThanOrEqualTo(painter.height));
    painter.dispose();

    final scrollable = find
        .ancestor(of: message, matching: find.byType(Scrollable))
        .first;
    final scrolling = tester.state<ScrollableState>(scrollable);
    scrolling.position.jumpTo(scrolling.position.maxScrollExtent);
    await tester.pumpAndSettle();
    final lastLine = paragraph
        .getBoxesForSelection(
          const TextSelection(
            baseOffset: _migrationWarning.length - 1,
            extentOffset: _migrationWarning.length,
          ),
        )
        .last;
    final end = paragraph.localToGlobal(
      Offset(lastLine.right, lastLine.bottom),
    );
    expect(end.dy, lessThanOrEqualTo(tester.getRect(scrollable).bottom + 0.01));
    final confirm = find.widgetWithText(FilledButton, 'Changer de serveur');
    expect(confirm.hitTestable(), findsOneWidget);
    await _capture(tester, capture, 'server-change-warning-end');
    await tester.tap(find.widgetWithText(TextButton, 'Annuler'));
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    await _close(tester, app);
  });

  testWidgets('VPN status live region includes its complete explanation', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    final app = _UiController()..vpnStatus = VpnStatus.error;
    try {
      await _mount(tester, app);
      const explanation =
          'La connexion nécessite votre attention. Consultez le diagnostic.';
      final status = find.bySemanticsLabel(
        'État VPN : Connexion impossible\n$explanation',
      );
      expect(status, findsOneWidget);
      expect(
        tester
            .getSemantics(status)
            .getSemanticsData()
            .flagsCollection
            .isLiveRegion,
        isTrue,
      );
      await _close(tester, app);
    } finally {
      semantics.dispose();
    }
  });

  testWidgets('password-login error is an accessible live region', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    final app = _UiController()..profile = null;
    try {
      final capture = await _mount(tester, app);
      final submit = find.widgetWithText(FilledButton, 'Se connecter');
      await tester.ensureVisible(submit);
      await tester.tap(submit);
      await tester.pumpAndSettle();
      final error = find.byKey(const ValueKey('sign-in-submission-error'));
      expect(error, findsOneWidget);
      final data = tester.getSemantics(error).getSemanticsData();
      expect(data.label, _loginError);
      expect(data.flagsCollection.isLiveRegion, isTrue);
      expect(data.flagsCollection.isHidden, isFalse);
      expect(error.hitTestable(), findsOneWidget);
      expect(submit.hitTestable(), findsOneWidget);
      await _capture(tester, capture, 'sign-in-error-visible');
      await _close(tester, app);
    } finally {
      semantics.dispose();
    }
  });
}
