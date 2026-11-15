// SPDX-License-Identifier: MPL-2.0
// Without a notification-area icon the window cannot hide: Windows keeps it
// open and reports the close request, which must open the Quit dialog.
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('fuzevpn/window');
  const codec = StandardMethodCodec();
  const bridge = WindowBridge();

  // What the native window does with NotifyDart(method). Completes once the
  // Dart side has answered that call.
  Future<void> native(String method) {
    final answered = Completer<void>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
          channel.name,
          codec.encodeMethodCall(MethodCall(method)),
          (_) => answered.complete(),
        );
    return answered.future;
  }

  tearDown(() {
    bridge.setCloseRequestHandler(null);
    bridge.stopConnectivityListener();
  });

  test(
    'a close request reaches its handler, and only while registered',
    () async {
      if (!Platform.isWindows) return;
      var requests = 0;
      await native('closeRequested');
      expect(requests, 0);

      bridge.setCloseRequestHandler(() async => requests++);
      await native('closeRequested');
      expect(requests, 1);
      // Nothing else on the channel is taken for a close request.
      await native('networkAvailable');
      await native('systemResumed');
      await native('somethingElse');
      expect(requests, 1);

      bridge.setCloseRequestHandler(null);
      await native('closeRequested');
      expect(requests, 1);
    },
  );

  test('the close handler and the connectivity listener share the channel '
      'without replacing each other', () async {
    if (!Platform.isWindows) return;
    var requests = 0;
    final events = <WindowsConnectivityEvent>[];
    // The order main() and the controller register in, then the reverse.
    for (final closeFirst in [true, false]) {
      requests = 0;
      events.clear();
      void close() => bridge.setCloseRequestHandler(() async => requests++);
      void connectivity() =>
          bridge.startConnectivityListener((event) async => events.add(event));
      closeFirst ? close() : connectivity();
      closeFirst ? connectivity() : close();

      await native('networkAvailable');
      await native('closeRequested');
      await native('systemResumed');
      expect(requests, 1, reason: 'closeFirst=$closeFirst');
      expect(events, [
        WindowsConnectivityEvent.networkAvailable,
        WindowsConnectivityEvent.systemResumed,
      ], reason: 'closeFirst=$closeFirst');

      // A disposed controller stops listening: quitting must stay possible.
      bridge.stopConnectivityListener();
      await native('networkAvailable');
      await native('closeRequested');
      expect(events, hasLength(2));
      expect(requests, 2);

      bridge.setCloseRequestHandler(null);
      await native('closeRequested');
      expect(requests, 2);
    }
  });

  test('the native call never waits for the confirmation, nor fails with '
      'it', () async {
    if (!Platform.isWindows) return;
    final dialogOpen = Completer<void>();
    var opened = 0;
    bridge.setCloseRequestHandler(() {
      opened++;
      return dialogOpen.future;
    });
    // Answered although the dialog is still open.
    await native('closeRequested');
    expect(opened, 1);
    expect(dialogOpen.isCompleted, isFalse);
    dialogOpen.complete();

    bridge.setCloseRequestHandler(() async => throw StateError('no context'));
    await native('closeRequested');
    bridge.setCloseRequestHandler(() => throw StateError('no context'));
    await native('closeRequested');
    await Future<void>.delayed(Duration.zero);
  });

  test('main() answers a close request with the same Quit confirmation as '
      'the notification-area menu', () {
    final source = File('lib/main.dart').readAsStringSync();
    final confirmExit = RegExp(
      r'Future<void> confirmExit\(\) async \{\s*'
      r'final context = navigatorKey\.currentContext;\s*'
      r'if \(context != null\) await requestAppExit\(context, controller\);\s*'
      r'\}',
    );
    expect(confirmExit.hasMatch(source), isTrue);
    expect(
      source,
      contains('const WindowBridge().setCloseRequestHandler(confirmExit);'),
    );
    expect(
      source,
      contains('TrayController(controller, onQuitRequested: confirmExit)'),
    );
    // Registered before the first frame, and before the tray is known.
    expect(
      source.indexOf('setCloseRequestHandler(confirmExit)'),
      lessThan(source.indexOf('runApp(')),
    );
  });
}
