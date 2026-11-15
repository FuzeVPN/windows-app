// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/app_exit.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/framework_localizations.dart';

const _installedText =
    'FuzeVPN will close. The VPN may remain active if the Windows service is installed.';
const _portableText =
    'FuzeVPN will close. In the portable version, the VPN will stop and its protections will be removed if cleanup succeeds.';
const _killSwitchText =
    'The kill switch prevents leaks. Disconnecting restores Internet access.';
const _stoppingText = 'We are safely stopping the VPN tunnel.';
const _waitText = 'Please wait for the current VPN operation to finish.';
const _stillBlockedText =
    'The kill switch is still blocking network traffic. Try disconnecting again.';
const _interfaceQuit = 'Quit the FuzeVPN interface';

class _Updates extends WindowsUpdateController {
  _Updates(this.portable, {this.known = true});
  bool portable;
  // False models a startup update check whose environment read failed, and a
  // retry from the Quit dialog that fails too.
  bool known;
  int ensureCalls = 0;
  @override
  bool get isPortable => known && portable;
  @override
  bool get canUseInstaller => known && !portable;
  @override
  bool get installationModeKnown => known;
  @override
  Future<void> ensureInstallationMode() async => ensureCalls++;

  /// The installation mode arrives later, while the dialog is open.
  void learn({required bool portable}) {
    this.portable = portable;
    known = true;
    notifyListeners();
  }
}

/// Only what the Quit confirmation reads, set directly by each test. The
/// stop is recorded and held until the test settles it.
class _Controller extends AppController {
  _Controller({bool portable = false, bool modeKnown = true})
    : super(updates: _Updates(portable, known: modeKnown));

  bool busy = false;
  bool cancellable = false;
  bool stopping = false;
  bool retains = false;
  bool requiresDisconnect = false;
  bool unknown = false;
  int stopRequests = 0;
  Completer<void>? _stop;

  @override
  bool get isConnectionBusy => busy || stopping;
  @override
  bool get canCancelConnection => cancellable && !stopping;
  @override
  bool get canDisconnectVpn =>
      canCancelConnection ||
      (!isConnectionBusy && (requiresDisconnect || unknown));
  @override
  bool get isStoppingVpn => stopping;
  @override
  bool get retainsBlockingProtection => retains;
  @override
  bool get requiresExplicitDisconnect => requiresDisconnect;
  @override
  bool get runtimeVerificationPending => unknown;

  void setBusy(bool value) {
    busy = value;
    notifyListeners();
  }

  /// A connection, reconnection or renewal in progress.
  void runOperation({required bool protectionArmed}) {
    busy = true;
    cancellable = true;
    retains = protectionArmed;
    requiresDisconnect = protectionArmed;
    vpnStatus = VpnStatus.preparing;
  }

  /// Internet blocked by a retained kill switch, with nothing running.
  void block() {
    retains = true;
    requiresDisconnect = true;
    vpnStatus = VpnStatus.blocked;
  }

  @override
  Future<void> disconnectVpn() {
    stopRequests++;
    final running = _stop ??= Completer<void>();
    busy = false;
    cancellable = false;
    stopping = true;
    vpnStatus = VpnStatus.disconnecting;
    notifyListeners();
    return running.future;
  }

  /// The stop ends with everything released and confirmed.
  void stopSucceeds() {
    stopping = false;
    retains = false;
    requiresDisconnect = false;
    unknown = false;
    errorMessage = null;
    vpnStatus = VpnStatus.disconnected;
    _settle();
  }

  /// The stop ends with the kill switch still in place.
  void stopFails() {
    stopping = false;
    retains = true;
    requiresDisconnect = true;
    errorMessage =
        'Le kill switch bloque toujours le trafic réseau. Réessayez la déconnexion.';
    vpnStatus = VpnStatus.blocked;
    _settle();
  }

  void _settle() {
    final running = _stop;
    _stop = null;
    notifyListeners();
    running?.complete();
  }
}

Widget _host(_Controller controller, {Locale locale = const Locale('en')}) =>
    MaterialApp(
      locale: locale,
      supportedLocales: AppStrings.supportedLocales,
      localizationsDelegates: [
        AppLocalizations.delegate,
        ...appFrameworkLocalizationsDelegates,
      ],
      home: Scaffold(
        body: Builder(
          builder: (context) => TextButton(
            onPressed: () => requestAppExit(context, controller),
            child: const Text('Open exit confirmation'),
          ),
        ),
      ),
    );

// The busy indicator is intentionally indeterminate: advance the dialog
// transition and the pending work without waiting for it to become idle.
Future<void> _advance(WidgetTester tester) async {
  await tester.pump();
  await tester.pump(const Duration(milliseconds: 350));
}

Future<void> _open(WidgetTester tester, _Controller controller) async {
  await tester.pumpWidget(_host(controller));
  await tester.pumpAndSettle();
  await tester.tap(find.text('Open exit confirmation'));
  await _advance(tester);
  expect(find.byType(AlertDialog), findsOneWidget);
}

Future<void> _close(WidgetTester tester, _Controller controller) async {
  expect(tester.takeException(), isNull);
  await tester.pumpWidget(const SizedBox.shrink());
  controller.dispose();
}

final _quit = find.byKey(const ValueKey('exit-quit'));
final _disconnect = find.byKey(const ValueKey('exit-disconnect'));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('fuzevpn/window');
  late int quitCalls;
  late bool failQuit;

  setUp(() {
    quitCalls = 0;
    failQuit = false;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'quit') {
            quitCalls++;
            if (failQuit) throw PlatformException(code: 'window_quit_failed');
          }
          return null;
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  for (final portable in [true, false]) {
    testWidgets(
      'exit explains ${portable ? 'portable cleanup' : 'possible service persistence'} and cancellation keeps the app open',
      (tester) async {
        final controller = _Controller(portable: portable);
        await tester.pumpWidget(_host(controller));
        await tester.pumpAndSettle();
        await tester.tap(find.text('Open exit confirmation'));
        await tester.pumpAndSettle();
        expect(find.text('Quit FuzeVPN?'), findsOneWidget);
        expect(
          find.text(portable ? _portableText : _installedText),
          findsOneWidget,
        );
        // With nothing engaged, the dialog is the plain confirmation.
        expect(find.widgetWithText(FilledButton, 'Quit FuzeVPN'), findsOne);
        expect(_disconnect, findsNothing);
        expect(find.byType(LinearProgressIndicator), findsNothing);
        expect(quitCalls, 0);
        await tester.tap(find.text('Cancel'));
        await tester.pumpAndSettle();
        expect(find.byType(AlertDialog), findsNothing);
        expect(find.text('Open exit confirmation'), findsOneWidget);
        expect(quitCalls, 0);
        expect(controller.stopRequests, 0);
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      },
    );
  }

  testWidgets('installed: a healthy tunnel keeps the plain confirmation and '
      'quitting leaves it to the service', (tester) async {
    final controller = _Controller()
      ..requiresDisconnect = true
      ..vpnStatus = VpnStatus.connected;
    await _open(tester, controller);
    expect(find.text(_installedText), findsOneWidget);
    expect(_disconnect, findsNothing);
    await tester.tap(find.widgetWithText(FilledButton, 'Quit FuzeVPN'));
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 0);
    await _close(tester, controller);
  });

  for (final protectionArmed in [false, true]) {
    testWidgets('installed: a running operation never disables exit, which '
        'closes the interface at once '
        '(${protectionArmed ? 'kill switch armed' : 'nothing armed'})', (
      tester,
    ) async {
      final controller = _Controller()
        ..runOperation(protectionArmed: protectionArmed);
      await _open(tester, controller);
      expect(
        find.text(protectionArmed ? _killSwitchText : _installedText),
        findsOneWidget,
      );
      expect(find.text(_waitText), findsNothing);
      expect(find.byType(LinearProgressIndicator), findsNothing);
      // Disconnect is offered beside an exit that changes nothing else.
      expect(tester.widget<OutlinedButton>(_disconnect).onPressed, isNotNull);
      expect(find.widgetWithText(FilledButton, _interfaceQuit), findsOne);
      expect(find.widgetWithText(FilledButton, 'Quit FuzeVPN'), findsNothing);
      expect(tester.widget<FilledButton>(_quit).onPressed, isNotNull);

      await tester.tap(_quit);
      await tester.pumpAndSettle();

      // One tap, no wait, and no stop: the service keeps what it holds.
      expect(find.byType(AlertDialog), findsNothing);
      expect(quitCalls, 1);
      expect(controller.stopRequests, 0);
      await _close(tester, controller);
    });
  }

  testWidgets('installed: blocked Internet offers Disconnect, which stops '
      'with progress and then falls back to the plain confirmation', (
    tester,
  ) async {
    final controller = _Controller()..block();
    await _open(tester, controller);
    expect(find.text(_killSwitchText), findsOneWidget);
    expect(find.widgetWithText(FilledButton, _interfaceQuit), findsOne);

    await tester.tap(_disconnect);
    await _advance(tester);

    expect(controller.stopRequests, 1);
    expect(find.text(_stoppingText), findsOneWidget);
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    // The button just pressed stays in place, disabled, while it works.
    expect(tester.widget<OutlinedButton>(_disconnect).onPressed, isNull);
    await tester.tap(_disconnect, warnIfMissed: false);
    await _advance(tester);
    expect(controller.stopRequests, 1);
    // Exit stays available during the stop.
    expect(tester.widget<FilledButton>(_quit).onPressed, isNotNull);
    expect(quitCalls, 0);

    controller.stopSucceeds();
    await tester.pumpAndSettle();

    // Nothing closed the application: the user decides.
    expect(find.byType(AlertDialog), findsOneWidget);
    expect(quitCalls, 0);
    expect(find.text(_installedText), findsOneWidget);
    expect(find.byType(LinearProgressIndicator), findsNothing);
    expect(_disconnect, findsNothing);
    await tester.tap(find.widgetWithText(FilledButton, 'Quit FuzeVPN'));
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 1);
    await _close(tester, controller);
  });

  testWidgets('installed: a failed Disconnect shows its reason, can be '
      'retried and never closes the application', (tester) async {
    final controller = _Controller()..block();
    await _open(tester, controller);
    await tester.tap(_disconnect);
    await _advance(tester);
    controller.stopFails();
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsOneWidget);
    expect(quitCalls, 0);
    expect(find.text(_stillBlockedText), findsOneWidget);
    expect(find.text(_killSwitchText), findsNothing);
    expect(find.byType(LinearProgressIndicator), findsNothing);
    expect(tester.widget<OutlinedButton>(_disconnect).onPressed, isNotNull);
    expect(find.widgetWithText(FilledButton, _interfaceQuit), findsOne);

    await tester.tap(_disconnect);
    await _advance(tester);
    expect(controller.stopRequests, 2);
    controller.stopSucceeds();
    await tester.pumpAndSettle();
    expect(find.text(_installedText), findsOneWidget);
    expect(quitCalls, 0);
    await _close(tester, controller);
  });

  testWidgets('installed: the unknown state offers Disconnect beside an exit '
      'that stays the interface only', (tester) async {
    final controller = _Controller()
      ..unknown = true
      ..vpnStatus = VpnStatus.error;
    await _open(tester, controller);
    expect(find.text(_installedText), findsOneWidget);
    expect(tester.widget<OutlinedButton>(_disconnect).onPressed, isNotNull);
    expect(find.widgetWithText(FilledButton, _interfaceQuit), findsOne);
    await tester.tap(_quit);
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 0);
    await _close(tester, controller);
  });

  for (final state in ['a tunnel', 'a running operation', 'blocked Internet']) {
    testWidgets('portable: Quit with $state stops first and closes only once '
        'the stop is confirmed', (tester) async {
      final controller = _Controller(portable: true);
      switch (state) {
        case 'a tunnel':
          controller
            ..requiresDisconnect = true
            ..vpnStatus = VpnStatus.connected;
        case 'a running operation':
          controller.runOperation(protectionArmed: true);
        default:
          controller.block();
      }
      await _open(tester, controller);
      expect(find.text(_portableText), findsOneWidget);
      // Quit is the stop: no separate Disconnect, no interface-only exit.
      expect(_disconnect, findsNothing);
      expect(find.widgetWithText(FilledButton, 'Quit FuzeVPN'), findsOne);
      expect(find.text(_interfaceQuit), findsNothing);

      await tester.tap(_quit);
      await _advance(tester);

      expect(controller.stopRequests, 1);
      expect(quitCalls, 0);
      expect(find.byType(AlertDialog), findsOneWidget);
      expect(find.text(_stoppingText), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsOneWidget);

      controller.stopSucceeds();
      await tester.pumpAndSettle();

      expect(find.byType(AlertDialog), findsNothing);
      expect(quitCalls, 1);
      expect(controller.stopRequests, 1);
      await _close(tester, controller);
    });
  }

  testWidgets('portable: a failed stop keeps the application open with its '
      'reason; a second Quit closes at once', (tester) async {
    final controller = _Controller(portable: true)..block();
    await _open(tester, controller);
    await tester.tap(_quit);
    await _advance(tester);
    controller.stopFails();
    await tester.pumpAndSettle();

    // No automatic exit over a kill switch that could not be released.
    expect(find.byType(AlertDialog), findsOneWidget);
    expect(quitCalls, 0);
    expect(find.text(_stillBlockedText), findsOneWidget);
    expect(find.text(_portableText), findsNothing);
    expect(tester.widget<OutlinedButton>(_disconnect).onPressed, isNotNull);

    await tester.tap(_quit);
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(quitCalls, 1);
    expect(controller.stopRequests, 1);
    await _close(tester, controller);
  });

  testWidgets('portable: after a failed stop, Disconnect retries without '
      'closing the application', (tester) async {
    final controller = _Controller(portable: true)..block();
    await _open(tester, controller);
    await tester.tap(_quit);
    await _advance(tester);
    controller.stopFails();
    await tester.pumpAndSettle();

    await tester.tap(_disconnect);
    await _advance(tester);
    expect(controller.stopRequests, 2);
    expect(tester.widget<OutlinedButton>(_disconnect).onPressed, isNull);
    controller.stopSucceeds();
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsOneWidget);
    expect(quitCalls, 0);
    expect(find.text(_portableText), findsOneWidget);
    expect(_disconnect, findsNothing);
    await tester.tap(_quit);
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 2);
    await _close(tester, controller);
  });

  testWidgets('portable: pressing Quit again while the stop runs closes at '
      'once', (tester) async {
    final controller = _Controller(portable: true)..block();
    await _open(tester, controller);
    await tester.tap(_quit);
    await _advance(tester);
    expect(quitCalls, 0);

    await tester.tap(_quit);
    await _advance(tester);

    expect(find.byType(AlertDialog), findsNothing);
    expect(quitCalls, 1);
    expect(controller.stopRequests, 1);
    // The stop that was running ends later: nothing quits a second time.
    controller.stopSucceeds();
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    await _close(tester, controller);
  });

  testWidgets('portable: Cancel during the stop keeps the application open '
      'when the stop completes', (tester) async {
    final controller = _Controller(portable: true)..block();
    await _open(tester, controller);
    await tester.tap(_quit);
    await _advance(tester);
    expect(controller.stopRequests, 1);

    await tester.tap(find.text('Cancel'));
    await _advance(tester);
    expect(find.byType(AlertDialog), findsNothing);

    controller.stopSucceeds();
    await tester.pumpAndSettle();
    expect(quitCalls, 0);
    expect(find.text('Open exit confirmation'), findsOneWidget);

    // The next confirmation finds nothing engaged and closes at once.
    await tester.tap(find.text('Open exit confirmation'));
    await tester.pumpAndSettle();
    expect(_disconnect, findsNothing);
    await tester.tap(_quit);
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 1);
    await _close(tester, controller);
  });

  testWidgets('an unknown installation is quit like a portable copy: the '
      'tunnel is stopped first, and the mode is read again', (tester) async {
    final controller = _Controller(modeKnown: false)
      ..requiresDisconnect = true
      ..vpnStatus = VpnStatus.connected;
    await _open(tester, controller);
    expect((controller.updates as _Updates).ensureCalls, 1);
    expect(find.text(_portableText), findsOneWidget);
    expect(find.text(_interfaceQuit), findsNothing);

    await tester.tap(_quit);
    await _advance(tester);
    expect(controller.stopRequests, 1);
    expect(quitCalls, 0);

    controller.stopSucceeds();
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(quitCalls, 1);
    await _close(tester, controller);
  });

  testWidgets('an installed mode read while the dialog is open restores the '
      'installed choices', (tester) async {
    final controller = _Controller(modeKnown: false)..block();
    await _open(tester, controller);
    expect(find.text(_portableText), findsOneWidget);
    expect(find.text(_interfaceQuit), findsNothing);

    (controller.updates as _Updates).learn(portable: false);
    await tester.pumpAndSettle();

    expect(find.text(_killSwitchText), findsOneWidget);
    expect(find.text(_interfaceQuit), findsOneWidget);
    expect(_disconnect, findsOneWidget);
    await tester.tap(_quit);
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 0);
    await _close(tester, controller);
  });

  testWidgets('an unknown installation with nothing engaged closes at once', (
    tester,
  ) async {
    final controller = _Controller(modeKnown: false);
    await _open(tester, controller);
    await tester.tap(_quit);
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(controller.stopRequests, 0);
    await _close(tester, controller);
  });

  testWidgets('portable: a tunnel is stopped before closing even while work '
      'that cannot be cancelled holds the stop back', (tester) async {
    final controller = _Controller(portable: true)
      ..busy = true
      ..requiresDisconnect = true
      ..vpnStatus = VpnStatus.connected;
    await _open(tester, controller);
    expect(find.text(_waitText), findsOneWidget);

    await tester.tap(_quit);
    await _advance(tester);
    expect(controller.stopRequests, 1);
    expect(quitCalls, 0);

    controller.stopSucceeds();
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(quitCalls, 1);
    await _close(tester, controller);
  });

  for (final portable in [false, true]) {
    testWidgets('work that cannot be cancelled shows the wait notice and '
        'still lets the user quit '
        '(${portable ? 'portable' : 'installed'})', (tester) async {
      final controller = _Controller(portable: portable)..busy = true;
      await _open(tester, controller);
      expect(find.text(_waitText), findsOneWidget);
      expect(find.byType(LinearProgressIndicator), findsOneWidget);
      expect(_disconnect, findsNothing);
      expect(tester.widget<FilledButton>(_quit).onPressed, isNotNull);
      expect(
        find.widgetWithText(
          FilledButton,
          portable ? 'Quit FuzeVPN' : _interfaceQuit,
        ),
        findsOne,
      );

      // The notice follows the controller.
      controller.setBusy(false);
      await tester.pumpAndSettle();
      expect(find.text(_waitText), findsNothing);
      expect(find.byType(LinearProgressIndicator), findsNothing);
      controller.setBusy(true);
      await _advance(tester);
      expect(find.text(_waitText), findsOneWidget);

      await tester.tap(_quit);
      await _advance(tester);
      expect(find.byType(AlertDialog), findsNothing);
      expect(quitCalls, 1);
      expect(controller.stopRequests, 0);
      await _close(tester, controller);
    });
  }

  testWidgets('an update whose installer left the window open cannot '
      'disable exit', (tester) async {
    // The real controller: once the installer is launched it stays in the
    // installing state, which used to disable the Quit button for good.
    final controller = AppController(updates: _InstallingUpdates());
    await tester.pumpWidget(
      MaterialApp(
        locale: const Locale('en'),
        supportedLocales: AppStrings.supportedLocales,
        localizationsDelegates: const [AppLocalizations.delegate],
        home: Scaffold(
          body: Builder(
            builder: (context) => TextButton(
              onPressed: () => requestAppExit(context, controller),
              child: const Text('Open exit confirmation'),
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    controller.isInitialized = true;
    failQuit = true;
    await controller.installPreparedUpdate();
    expect(controller.isInstallingUpdate, isTrue);
    expect(controller.isConnectionBusy, isTrue);
    expect(quitCalls, 1);
    failQuit = false;

    await tester.tap(find.text('Open exit confirmation'));
    await _advance(tester);
    expect(find.text(_waitText), findsOneWidget);
    expect(tester.widget<FilledButton>(_quit).onPressed, isNotNull);
    await tester.tap(_quit);
    await _advance(tester);
    expect(find.byType(AlertDialog), findsNothing);
    expect(quitCalls, 2);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  testWidgets('native exit failure stays visible and can be retried', (
    tester,
  ) async {
    final controller = _Controller(portable: true);
    await tester.pumpWidget(_host(controller));
    await tester.pumpAndSettle();
    failQuit = true;
    await tester.tap(find.text('Open exit confirmation'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Quit FuzeVPN'));
    await tester.pumpAndSettle();
    expect(quitCalls, 1);
    expect(find.text('FuzeVPN could not close. Try again.'), findsOneWidget);
    expect(find.text('Open exit confirmation'), findsOneWidget);
    expect(tester.takeException(), isNull);

    failQuit = false;
    await tester.tap(find.text('Open exit confirmation'));
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Quit FuzeVPN'));
    await tester.pumpAndSettle();
    expect(quitCalls, 2);
    expect(find.byType(AlertDialog), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
    controller.dispose();
  });

  testWidgets('the three actions fit narrow windows and large text in every '
      'state', (tester) async {
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.platformDispatcher.clearTextScaleFactorTestValue);
    for (final size in [const Size(360, 520), const Size(1280, 720)]) {
      tester.view.physicalSize = size;
      for (final scale in [1.0, 2.0]) {
        tester.platformDispatcher.textScaleFactorTestValue = scale;
        for (final locale in const [Locale('fr'), Locale('de'), Locale('en')]) {
          for (final portable in [false, true]) {
            final reason = '$size / $scale / $locale / portable=$portable';
            final controller = _Controller(portable: portable)..block();
            await tester.pumpWidget(_host(controller, locale: locale));
            await tester.pumpAndSettle();
            await tester.tap(find.text('Open exit confirmation'));
            await _advance(tester);
            expect(tester.takeException(), isNull, reason: reason);
            // Stopping, then failed: the longest texts and all the buttons.
            await tester.ensureVisible(_quit);
            await tester.tap(portable ? _quit : _disconnect);
            await _advance(tester);
            expect(tester.takeException(), isNull, reason: reason);
            controller.stopFails();
            await tester.pumpAndSettle();
            expect(tester.takeException(), isNull, reason: reason);
            for (final action in [_disconnect, _quit]) {
              await tester.ensureVisible(action);
              await tester.pump();
              expect(action.hitTestable(), findsOneWidget, reason: reason);
              final rect = tester.getRect(action);
              expect(rect.left, greaterThanOrEqualTo(0), reason: reason);
              expect(rect.right, lessThanOrEqualTo(size.width), reason: reason);
            }
            await tester.tap(_quit);
            await tester.pumpAndSettle();
            expect(tester.takeException(), isNull, reason: reason);
            await tester.pumpWidget(const SizedBox.shrink());
            controller.dispose();
          }
        }
      }
    }
  });
}

/// An installer that starts, after which the controller asks the window to
/// close.
class _InstallingUpdates extends WindowsUpdateController {
  // An installed copy: only it updates through the installer.
  @override
  bool get canUseInstaller => true;

  @override
  Future<void> checkForUpdates() async {}

  @override
  Future<bool> installPreparedUpdate({
    Future<void> Function()? beforeInstall,
  }) async => true;
}
