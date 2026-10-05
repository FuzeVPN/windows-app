// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

const _firstProfile = UserProfile(
  userId: 'account-one',
  email: 'first@example.invalid',
  firstName: 'Premier',
  emailVerified: true,
);
const _secondProfile = UserProfile(
  userId: 'account-two',
  email: 'second@example.invalid',
  firstName: 'Second',
  emailVerified: true,
);

class _Controller extends AppController {
  _Controller() {
    isInitialized = true;
    isLoadingLocations = false;
    language = AppLanguage.french;
    profile = _firstProfile;
    locations = const [
      Location(
        id: 'fr-1',
        city: 'Paris',
        countryCode: 'FR',
        displayName: 'Paris 1',
      ),
    ];
    selectedLocation = locations.first;
  }

  int signOutCalls = 0;
  @override
  Future<void> initialize() async {}
  @override
  Future<void> signOut() async {
    signOutCalls++;
  }
}

void _size(WidgetTester tester, Size size) {
  tester.view.devicePixelRatio = 1;
  tester.view.physicalSize = size;
  addTearDown(tester.view.resetDevicePixelRatio);
  addTearDown(tester.view.resetPhysicalSize);
}

Future<void> _tap(WidgetTester tester, Finder target) async {
  await tester.ensureVisible(target);
  await tester.tap(target);
  await tester.pumpAndSettle();
}

Future<void> _openAccount(WidgetTester tester) =>
    _tap(tester, find.byTooltip('Mon compte'));

Finder get _signOut =>
    find.widgetWithText(FilledButton, 'Se déconnecter du compte');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('fuzevpn/window');
  late int quitCalls;
  setUp(() {
    quitCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'quit') quitCalls++;
          return null;
        });
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  for (final size in [const Size(1080, 640), const Size(640, 360)]) {
    testWidgets('account sign-out is accessible and cancellable with an active VPN at $size', (tester) async {
      _size(tester, size);
      final controller = _Controller()..vpnStatus = VpnStatus.connected;
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pumpAndSettle();

      await _openAccount(tester);
      expect(find.text(_firstProfile.email), findsOneWidget);
      await _tap(tester, _signOut);
      expect(find.text('Se déconnecter du compte ?'), findsOneWidget);
      expect(
        find.text('Cette action ferme votre session et demande l’arrêt du VPN.'),
        findsOneWidget,
      );
      expect(controller.signOutCalls, 0);
      await _tap(tester, find.text('Annuler'));
      expect(find.byType(AlertDialog), findsNothing);
      expect(controller.signOutCalls, 0);
      expect(controller.profile, same(_firstProfile));
      expect(controller.vpnStatus, VpnStatus.connected);

      await _openAccount(tester);
      await _tap(tester, _signOut);
      await _tap(tester, _signOut);
      expect(controller.signOutCalls, 1);
      expect(quitCalls, 0);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });

    testWidgets('a signed-out blocked VPN can open exit and cancel it at $size', (tester) async {
      _size(tester, size);
      final controller = _Controller()
        ..profile = null
        ..vpnStatus = VpnStatus.blocked;
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);

      await _openAccount(tester);
      expect(find.widgetWithText(FilledButton, 'Se connecter'), findsOneWidget);
      expect(find.text('Annuler'), findsOneWidget);
      await _tap(tester, find.widgetWithText(TextButton, 'Quitter FuzeVPN'));
      expect(find.text('Quitter FuzeVPN ?'), findsOneWidget);
      expect(quitCalls, 0);
      // The sign-in dialog remains underneath the exit confirmation.
      final confirmation = find.widgetWithText(AlertDialog, 'Quitter FuzeVPN ?');
      await _tap(tester, find.descendant(of: confirmation, matching: find.text('Annuler')));
      expect(find.text('Quitter FuzeVPN ?'), findsNothing);
      expect(find.widgetWithText(FilledButton, 'Se connecter'), findsOneWidget);
      expect(quitCalls, 0);
      await _tap(tester, find.text('Annuler'));
      expect(find.byType(AlertDialog), findsNothing);
      expect(controller.vpnStatus, VpnStatus.blocked);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });
  }

  testWidgets('an open account dialog survives losing its profile during resize', (tester) async {
    _size(tester, const Size(1080, 640));
    final controller = _Controller()..vpnStatus = VpnStatus.connected;
    await tester.pumpWidget(FuzeVpnApp(controller: controller));
    await tester.pumpAndSettle();
    await _openAccount(tester);

    // Deliberately avoid notifyListeners: resizing must rebuild the route
    // safely even when the controller has not triggered an application build.
    controller.profile = null;
    tester.view.physicalSize = const Size(640, 360);
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
    expect(find.text(_firstProfile.email), findsOneWidget);
    await _tap(tester, _signOut);
    expect(find.byType(AlertDialog), findsNothing);
    expect(controller.signOutCalls, 0);
    expect(controller.profile, isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  for (final atConfirmation in [false, true]) {
    testWidgets('a stale ${atConfirmation ? 'confirmation' : 'account action'} cannot sign out another account', (tester) async {
      _size(tester, const Size(1080, 640));
      final controller = _Controller()..vpnStatus = VpnStatus.connected;
      await tester.pumpWidget(FuzeVpnApp(controller: controller));
      await tester.pumpAndSettle();
      await _openAccount(tester);
      if (atConfirmation) {
        await _tap(tester, _signOut);
        expect(find.text('Se déconnecter du compte ?'), findsOneWidget);
      }

      controller.profile = _secondProfile;
      await _tap(tester, _signOut);
      expect(controller.signOutCalls, 0);
      expect(controller.profile, same(_secondProfile));
      expect(find.byType(AlertDialog), findsNothing);
      expect(quitCalls, 0);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      controller.dispose();
    });
  }
}
