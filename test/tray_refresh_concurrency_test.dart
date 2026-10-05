// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/tray_controller.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';

import 'support/audit_fixtures.dart' as fixture;

class _Window extends WindowBridge {
  @override
  Future<void> setTrayAvailable(bool available) async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('newer tray language cannot be replaced by a slower refresh', (
    tester,
  ) async {
    if (!Platform.isWindows) return;
    final tooltipStarted = Completer<void>();
    final tooltipGate = Completer<void>();
    final menus = <String>[];
    var delayNextTooltip = false;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('tray_manager'),
      (call) async {
        if (call.method == 'setToolTip' && delayNextTooltip) {
          delayNextTooltip = false;
          tooltipStarted.complete();
          await tooltipGate.future;
        }
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
    final app = fixture.makeController()
      ..isInitialized = true
      ..language = AppLanguage.french;
    final controller = TrayController(app, window: _Window());
    addTearDown(app.dispose);
    addTearDown(controller.dispose);
    await controller.initialize();
    delayNextTooltip = true;
    app.language = AppLanguage.arabic;
    app.notifyListeners();
    await tester.pump();
    expect(tooltipStarted.isCompleted, isTrue);
    app.language = AppLanguage.english;
    app.notifyListeners();
    await tester.pump();
    tooltipGate.complete();
    await tester.pump();
    expect(
      menus.last,
      contains(AppStrings.forLanguage(AppLanguage.english).text('Réglages')),
    );
  });

  testWidgets('disposing tray cancels a menu update waiting for its tooltip', (
    tester,
  ) async {
    if (!Platform.isWindows) return;
    final tooltipStarted = Completer<void>();
    final tooltipGate = Completer<void>();
    var menuCalls = 0;
    var delayNextTooltip = false;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('tray_manager'),
      (call) async {
        if (call.method == 'setToolTip' && delayNextTooltip) {
          delayNextTooltip = false;
          tooltipStarted.complete();
          await tooltipGate.future;
        }
        if (call.method == 'setContextMenu') menuCalls++;
        return null;
      },
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        const MethodChannel('tray_manager'),
        null,
      ),
    );
    final app = fixture.makeController()
      ..isInitialized = true
      ..language = AppLanguage.french;
    final controller = TrayController(app, window: _Window());
    addTearDown(app.dispose);
    addTearDown(controller.dispose);
    await controller.initialize();
    final previousMenuCalls = menuCalls;
    delayNextTooltip = true;
    app.language = AppLanguage.english;
    app.notifyListeners();
    await tester.pump();
    expect(tooltipStarted.isCompleted, isTrue);
    controller.dispose();
    tooltipGate.complete();
    await tester.pump();
    expect(menuCalls, previousMenuCalls);
  });
}
