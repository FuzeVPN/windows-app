// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/tray_controller.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

class _Controller extends AppController {
  _Controller() {
    isInitialized = true;
    isLoadingLocations = false;
    apiReachable = true;
    language = AppLanguage.english;
    profile = const UserProfile(
      userId: 'test-user',
      email: 'test@example.invalid',
      firstName: 'Test',
      emailVerified: true,
    );
    locations = const [
      Location(
        id: 'de-1',
        city: 'Frankfurt',
        countryCode: 'DE',
        displayName: 'Frankfurt 1',
      ),
    ];
    selectedLocation = locations.first;
  }
  @override
  Future<void> initialize() async {}
}

class _Window extends WindowBridge {
  final availability = <bool>[];
  @override
  Future<void> setTrayAvailable(bool available) async =>
      availability.add(available);
}

class _OtherSessionController extends _Controller {
  @override
  bool get runtimeOwnedByAnotherUser => true;
}

class _FailingSignInController extends _Controller {
  _FailingSignInController(this.failureMessage);

  final String failureMessage;
  int signInCalls = 0;
  String? submittedEmail;
  String? submittedPassword;

  @override
  Future<bool> signIn({required String email, required String password}) async {
    signInCalls++;
    submittedEmail = email;
    submittedPassword = password;
    errorMessage = failureMessage;
    notifyListeners();
    return false;
  }
}

Future<void> _submitFailingSignIn(
  WidgetTester tester,
  _FailingSignInController controller,
) async {
  final dialog = find.byType(AlertDialog);
  expect(dialog, findsOneWidget);
  final fields = find.descendant(of: dialog, matching: find.byType(TextField));
  expect(fields, findsNWidgets(2));
  await tester.ensureVisible(fields.first);
  await tester.enterText(fields.first, 'test@example.invalid');
  await tester.ensureVisible(fields.last);
  await tester.enterText(fields.last, 'synthetic-password');
  final submit = find.descendant(
    of: dialog,
    matching: find.widgetWithText(
      FilledButton,
      AppStrings.forLanguage(controller.language).text('Se connecter'),
    ),
  );
  await tester.ensureVisible(submit);
  await tester.tap(submit);
  await tester.pumpAndSettle();
  expect(controller.signInCalls, 1);
  expect(controller.submittedEmail, 'test@example.invalid');
  expect(controller.submittedPassword, 'synthetic-password');
}

void main() {
  test(
    'a late successful tray menu cannot revive an invalidated icon',
    () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      const channel = MethodChannel('tray_manager');
      final menuStarted = Completer<void>();
      final menuGate = Completer<void>();
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            if (call.method == 'setContextMenu' && !menuStarted.isCompleted) {
              menuStarted.complete();
              await menuGate.future;
            }
            return true;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      final controller = _Controller();
      final window = _Window();
      final tray = TrayController(controller, window: window);
      final initializing = tray.initialize();
      await menuStarted.future;
      tray.onTrayIconUnavailable();
      menuGate.complete();
      await initializing;
      expect(window.availability, [false]);
      tray.onTrayIconAvailable();
      await Future<void>.delayed(Duration.zero);
      expect(window.availability, [false, true]);
      tray.dispose();
      controller.dispose();
    },
  );

  testWidgets(
    'browser policy failure is visible without an uncaught exception',
    (tester) async {
      tester.view.physicalSize = const Size(1280, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      const channel = MethodChannel('plugins.flutter.io/url_launcher');
      var browserCalls = 0;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (_) async {
            browserCalls++;
            throw PlatformException(code: 'open_error');
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      final controller = _Controller()..section = AppSection.settings;
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pumpAndSettle();
      final strings = AppStrings.forLanguage(AppLanguage.english);
      final account = find.byTooltip(strings.text('Mon compte'));
      await tester.ensureVisible(account);
      await tester.tap(account);
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(find.text('test@example.invalid'), findsOneWidget);
      expect(browserCalls, 0);
      final manage = find.text(strings.text('Gérer mon abonnement sur le Web'));
      await tester.ensureVisible(manage);
      await tester.tap(manage);
      await tester.pumpAndSettle();
      expect(browserCalls, 1);
      expect(
        find.text(
          AppStrings.forLanguage(
            AppLanguage.english,
          ).text('Le navigateur n’a pas pu être ouvert.'),
        ),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    },
  );

  testWidgets(
    'device counters and revocation dialog are translated in every language',
    (tester) async {
      final previousErrorHandler = FlutterError.onError;
      FlutterError.onError = (details) {
        debugPrint(details.toString());
        previousErrorHandler?.call(details);
      };
      addTearDown(() => FlutterError.onError = previousErrorHandler);
      tester.view.physicalSize = const Size(1280, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      for (final language in AppLanguage.values.where(
        (value) => value != AppLanguage.system,
      )) {
        final controller = _Controller()
          ..section = AppSection.devices
          ..language = language;
        controller.devices = [
          VpnDevice(
            deviceId: 'other-device',
            name: 'Laptop test',
            location: controller.selectedLocation,
            createdAt: null,
          ),
        ];
        final strings = AppStrings.forLanguage(language);
        await tester.pumpWidget(
          FuzeVpnApp(key: ValueKey(language), controller: controller),
        );
        await tester.pumpAndSettle();
        final count = strings
            .text('Appareils : {count} / {limit}')
            .replaceAll('{count}', '1')
            .replaceAll('{limit}', '${controller.deviceLimit}');
        expect(find.text(count), findsOneWidget);
        await tester.tap(find.text(strings.text('Retirer l’appareil')));
        await tester.pumpAndSettle();
        const template =
            'L’accès VPN de « {device} » sera retiré. La révocation peut prendre quelques instants à être appliquée par le serveur VPN.';
        final translated = strings.text(template);
        if (language != AppLanguage.french) expect(translated, isNot(template));
        expect(
          find.text(translated.replaceAll('{device}', 'Laptop test')),
          findsOneWidget,
        );
        await tester.tap(find.text(strings.text('Annuler')));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull, reason: language.name);
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      }
    },
  );

  testWidgets('account exit works without a tray and requires confirmation', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final calls = <String>[];
    const channel = MethodChannel('fuzevpn/window');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call.method);
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );
    final controller = _Controller();
    final strings = AppStrings.forLanguage(AppLanguage.english);
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pumpAndSettle();
    Future<void> openExitConfirmation() async {
      final account = find.byTooltip(strings.text('Mon compte'));
      await tester.ensureVisible(account);
      await tester.tap(account);
      await tester.pumpAndSettle();
      await tester.tap(
        find.widgetWithText(TextButton, strings.text('Quitter FuzeVPN')),
      );
      await tester.pumpAndSettle();
      expect(find.text(strings.text('Quitter FuzeVPN ?')), findsOneWidget);
    }

    await openExitConfirmation();
    expect(calls, isNot(contains('quit')));
    await tester.tap(find.text(strings.text('Annuler')));
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(find.byTooltip(strings.text('Mon compte')), findsOneWidget);
    expect(calls, isNot(contains('quit')));

    await openExitConfirmation();
    expect(calls, isNot(contains('quit')));
    await tester.tap(
      find.widgetWithText(FilledButton, strings.text('Quitter FuzeVPN')),
    );
    await tester.pumpAndSettle();
    expect(calls.where((method) => method == 'quit'), hasLength(1));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  test('Explorer tray restore failure invalidates availability', () async {
    TestWidgetsFlutterBinding.ensureInitialized();
    const channel = MethodChannel('tray_manager');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (_) async => true);
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );
    final controller = _Controller();
    final window = _Window();
    final tray = TrayController(controller, window: window);
    await tray.initialize();
    expect(window.availability, [true]);
    tray.onTrayIconUnavailable();
    await Future<void>.delayed(Duration.zero);
    expect(window.availability, [true, false]);
    tray.dispose();
    controller.dispose();
  });

  testWidgets(
    'DNS failure explains retained protection in all languages at large text',
    (tester) async {
      tester.view.physicalSize = const Size(640, 360);
      tester.view.devicePixelRatio = 1;
      tester.platformDispatcher.textScaleFactorTestValue = 2;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      for (final language in AppLanguage.values.where(
        (language) => language != AppLanguage.system,
      )) {
        for (final message in <String>[
          "Le nom du serveur WireGuard n’a pas pu être résolu. Le kill switch bloque toujours le trafic réseau. Réessayez lorsque le réseau est disponible.",
          "Le nom du serveur WireGuard n’a pas pu être résolu. Des protections partielles restent actives, mais le trafic réseau n’est pas entièrement bloqué.",
          "Le nom du serveur WireGuard n’a pas pu être résolu. L’état complet de la protection réseau ne peut pas être confirmé. Déconnectez-vous avant de réessayer.",
        ]) {
          final controller = _Controller()
            ..language = language
            ..vpnStatus = VpnStatus.blocked
            ..errorMessage = message;
          final translated = AppStrings.forLanguage(language).text(message);
          if (language != AppLanguage.french) {
            expect(translated, isNot(message));
          }
          await tester.pumpWidget(FuzeVpnApp(controller: controller));
          await tester.pumpAndSettle();
          expect(find.text(translated), findsOneWidget);
          expect(tester.takeException(), isNull, reason: language.name);
          await tester.pumpWidget(const SizedBox.shrink());
          controller.dispose();
        }
      }
    },
  );
  for (final language in AppLanguage.values.where(
    (language) => language != AppLanguage.system,
  )) {
    testWidgets(
      'API sign-in messages remain localized and readable in ${language.name}',
      (tester) async {
        tester.view.physicalSize = const Size(640, 360);
        tester.view.devicePixelRatio = 1;
        tester.platformDispatcher.textScaleFactorTestValue = 2;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
        for (final message in <String>[
          "Le service de connexion est momentanément indisponible. Réessayez plus tard.",
          "Impossible de joindre le service de connexion. Vérifiez votre connexion Internet puis réessayez.",
          "Votre connexion a été acceptée, mais les informations du compte ne peuvent pas être chargées pour le moment. Réessayez plus tard.",
          "Trop de tentatives de connexion. Réessayez dans quelques instants.",
          "Impossible de finaliser la connexion à ce compte. Réessayez.",
          "Votre session a expiré. Connectez-vous de nouveau.",
        ]) {
          final controller = _FailingSignInController(message)
            ..profile = null
            ..language = language;
          final translated = AppStrings.forLanguage(language).text(message);
          if (language != AppLanguage.french) {
            expect(translated, isNot(message), reason: language.name);
          }
          await tester.pumpWidget(FuzeVpnApp(controller: controller));
          await tester.pumpAndSettle();
          expect(
            find.descendant(
              of: find.byType(AlertDialog),
              matching: find.text(translated),
            ),
            findsNothing,
          );
          await _submitFailingSignIn(tester, controller);
          expect(
            find.descendant(
              of: find.byType(AlertDialog),
              matching: find.text(translated),
            ),
            findsOneWidget,
          );
          expect(
            tester.takeException(),
            isNull,
            reason: '${language.name}: $message',
          );
          await tester.pumpWidget(const SizedBox.shrink());
          controller.dispose();
        }
      },
    );
  }
  testWidgets(
    'another Windows session does not prompt login or offer disconnect',
    (tester) async {
      final controller = _OtherSessionController()..profile = null;
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);
      final connect = tester.widget<FilledButton>(
        find.widgetWithText(FilledButton, 'Quick connect'),
      );
      expect(connect.onPressed, isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    },
  );
  testWidgets('country names, search and refresh use the selected language', (
    tester,
  ) async {
    tester.view.devicePixelRatio = 1;
    tester.view.physicalSize = const Size(1280, 720);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final controller = _Controller()..section = AppSection.locations;
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pump();
    expect(find.text('Germany'), findsOneWidget);
    expect(find.byKey(const ValueKey('location-server-de-1')), findsNothing);
    expect(find.byTooltip('Refresh locations'), findsOneWidget);
    for (final query in ['Germany', 'Deutschland', 'Allemagne', 'DE']) {
      await tester.enterText(
        find.byKey(const ValueKey('location-search')),
        query,
      );
      await tester.pump();
      expect(find.text('Frankfurt 1'), findsOneWidget, reason: query);
      expect(find.text('Frankfurt · Germany'), findsOneWidget, reason: query);
      expect(find.text('No location found'), findsNothing);
    }
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  testWidgets(
    'diagnostic observations wrap at minimum size and 200 percent text',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(640, 360);
      tester.platformDispatcher.textScaleFactorTestValue = 2;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
      final controller = _Controller()..section = AppSection.help;
      controller.diagnosticResults = {
        'checks': [
          {'id': 'api_reachability', 'result': 'passed', 'age_ms': 12345},
          {'id': 'dns', 'result': 'unknown'},
          {'id': 'routing', 'result': 'failed'},
        ],
      };
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pump();
      expect(tester.takeException(), isNull);
      expect(find.text('Verified'), findsNothing);
      final passedChecks = find.byKey(
        const PageStorageKey('diagnostic-checks-passed'),
      );
      await tester.ensureVisible(passedChecks);
      await tester.tap(passedChecks);
      await tester.pumpAndSettle();
      expect(find.text('Verified'), findsOneWidget);
      expect(find.text('Vérifié'), findsNothing);
      expect(find.text('Measurement age : 13 s'), findsOneWidget);
      expect(find.byType(CheckboxListTile), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    },
  );

  testWidgets('device date uses localized label and month', (tester) async {
    tester.view.physicalSize = const Size(1280, 720);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final controller = _Controller()..section = AppSection.devices;
    controller.devices = [
      VpnDevice(
        deviceId: 'device-1',
        name: 'Desktop',
        location: controller.selectedLocation,
        createdAt: DateTime(2026, 9, 11),
      ),
    ];
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pump();
    final context = tester.element(find.byType(Scaffold).first);
    final date = MaterialLocalizations.of(
      context,
    ).formatMediumDate(DateTime(2026, 9, 11));
    expect(find.text('Added on $date'), findsOneWidget);
    expect(find.textContaining('septembre'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  testWidgets('sign-in failure is translated in the actual dialog', (
    tester,
  ) async {
    final controller = _FailingSignInController(
      'La connexion au compte a échoué. Vérifiez votre adresse e-mail et votre mot de passe.',
    )..profile = null;
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pumpAndSettle();
    await _submitFailingSignIn(tester, controller);
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(
          'Sign-in failed. Check your email address and password.',
        ),
      ),
      findsOneWidget,
    );
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  test(
    'tray icon failure informs the native window to keep a return path',
    () async {
      TestWidgetsFlutterBinding.ensureInitialized();
      const channel = MethodChannel('tray_manager');
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(
            channel,
            (_) async => throw PlatformException(code: 'icon_failed'),
          );
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      final controller = _Controller();
      final window = _Window();
      final tray = TrayController(controller, window: window);
      await tray.initialize();
      expect(window.availability, [false]);
      tray.dispose();
      controller.dispose();
    },
  );
}
