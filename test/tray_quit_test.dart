// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/tray_controller.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:tray_manager/tray_manager.dart' as tray;

import 'support/audit_fixtures.dart' as fixtures;

class _Window extends WindowBridge {
  final calls = <String>[];
  @override
  Future<void> show() async => calls.add('show');
  @override
  Future<void> quit() async => calls.add('quit');
  @override
  Future<void> setTrayAvailable(bool available) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'system tray keeps Chinese script and updates with Windows locale',
    (tester) async {
      if (!Platform.isWindows) return;
      final menus = <String>[];
      tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        const MethodChannel('tray_manager'),
        (call) async {
          if (call.method == 'setContextMenu') {
            menus.add(call.arguments.toString());
          }
          return null;
        },
      );
      addTearDown(
        () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
          const MethodChannel('tray_manager'),
          null,
        ),
      );
      addTearDown(tester.platformDispatcher.clearLocaleTestValue);
      final app = fixtures.makeController()
        ..isInitialized = true
        ..language = AppLanguage.system;
      final controller = TrayController(app, window: _Window());
      addTearDown(app.dispose);
      addTearDown(controller.dispose);
      for (final pair in [
        (const Locale('zh', 'TW'), AppLanguage.traditionalChinese),
        (const Locale('zh', 'CN'), AppLanguage.simplifiedChinese),
      ]) {
        tester.platformDispatcher.localeTestValue = pair.$1;
        if (menus.isEmpty) await controller.initialize();
        await tester.pump();
        expect(menus, isNotEmpty);
        expect(
          menus.last,
          contains(AppStrings.forLanguage(pair.$2).text('Ouvrir FuzeVPN')),
        );
      }
    },
  );

  test('tray quit delegates confirmation after restoring the window', () async {
    final app = fixtures.makeController();
    addTearDown(app.dispose);
    final window = _Window();
    final requested = Completer<void>();
    final decision = Completer<void>();
    final controller = TrayController(
      app,
      window: window,
      onQuitRequested: () async {
        window.calls.add('confirm');
        requested.complete();
        await decision.future;
      },
    );
    controller.onTrayMenuItemClick(tray.MenuItem(key: 'quit', label: 'Quit'));
    await requested.future;
    expect(window.calls, ['show', 'confirm']);
    decision
        .complete(); // Dismissing a dialog does not exit or remove the tray.
    await Future<void>.delayed(Duration.zero);
    expect(window.calls, ['show', 'confirm']);
  });
}
