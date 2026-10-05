// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/app_exit.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';

class _Updates extends WindowsUpdateController {
  _Updates(this.portable);
  final bool portable;
  @override
  bool get isPortable => portable;
}

class _Controller extends AppController {
  _Controller({bool portable = false}) : super(updates: _Updates(portable));

  bool busy = false;
  @override
  bool get isConnectionBusy => busy;

  void setBusy(bool value) {
    busy = value;
    notifyListeners();
  }
}

Widget _host(_Controller controller) => MaterialApp(
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
);

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
          find.text(
            portable
                ? 'FuzeVPN will close. In the portable version, the VPN will stop and its protections will be removed if cleanup succeeds.'
                : 'FuzeVPN will close. The VPN may remain active if the Windows service is installed.',
          ),
          findsOneWidget,
        );
        expect(quitCalls, 0);
        await tester.tap(find.text('Cancel'));
        await tester.pumpAndSettle();
        expect(find.byType(AlertDialog), findsNothing);
        expect(find.text('Open exit confirmation'), findsOneWidget);
        expect(quitCalls, 0);
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      },
    );
  }

  testWidgets('a VPN operation disables exit until it finishes', (
    tester,
  ) async {
    final controller = _Controller()..busy = true;
    await tester.pumpWidget(_host(controller));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Open exit confirmation'));
    // The real busy indicator is intentionally indeterminate. Advance the
    // dialog transition without waiting for that animation to become idle.
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 350));
    expect(
      find.text('Please wait for the current VPN operation to finish.'),
      findsOneWidget,
    );
    expect(find.byType(LinearProgressIndicator), findsOneWidget);
    final quit = find.widgetWithText(FilledButton, 'Quit FuzeVPN');
    expect(tester.widget<FilledButton>(quit).onPressed, isNull);
    await tester.tap(quit);
    await tester.pump();
    expect(find.byType(AlertDialog), findsOneWidget);
    expect(quitCalls, 0);

    controller.setBusy(false);
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(quit).onPressed, isNotNull);
    expect(
      find.text('Please wait for the current VPN operation to finish.'),
      findsNothing,
    );
    expect(find.byType(LinearProgressIndicator), findsNothing);
    await tester.tap(quit);
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(quitCalls, 1);
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
}
