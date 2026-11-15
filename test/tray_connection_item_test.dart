// SPDX-License-Identifier: MPL-2.0
// The notification-area menu can stop a running operation, and its
// connection item acts on the intent it was built with.
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
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
  Future<void> setTrayAvailable(bool available) async {}
}

/// Only what the menu reads, set directly by each test, and a record of the
/// commands a click sends.
class _TrayApp extends AppController {
  _TrayApp()
    : super(
        api: fixtures.ProbeApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: fixtures.ProbeWireGuard(),
        openVpn: fixtures.ProbeOpenVpn(),
      ) {
    language = AppLanguage.french;
    isInitialized = true;
    profile = fixtures.account;
  }

  bool busy = false;
  bool cancellable = false;
  bool requiresDisconnect = false;
  bool unknown = false;
  bool commandRunning = false;
  bool otherSession = false;
  final commands = <String>[];

  @override
  bool get isConnectionBusy => busy;
  @override
  bool get canCancelConnection => cancellable;
  @override
  bool get requiresExplicitDisconnect => requiresDisconnect;
  @override
  bool get runtimeVerificationPending => unknown;
  @override
  bool get isConnectionCommandRunning => commandRunning;
  @override
  bool get runtimeOwnedByAnotherUser => otherSession;
  @override
  bool get canDisconnectVpn =>
      cancellable || (!busy && (requiresDisconnect || unknown));

  @override
  Future<void> quickConnect() async => commands.add('quickConnect');
  @override
  Future<void> disconnectVpn() async => commands.add('disconnectVpn');
  @override
  Future<void> retryRuntimeVerification({bool automatic = false}) async =>
      commands.add('retryRuntimeVerification');

  void changed() => notifyListeners();
}

class _Menu {
  _Menu(this.tooltip, this.items);
  final String tooltip;
  final List<Map<Object?, Object?>> items;

  Map<Object?, Object?>? item(String key) =>
      items.where((item) => item['key'] == key).firstOrNull;
  String? label(String key) => item(key)?['label'] as String?;
  bool? disabled(String key) => item(key)?['disabled'] as bool?;
  // The disabled line under "Open FuzeVPN".
  String get status => items[1]['label']! as String;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late List<_Menu> menus;
  late String tooltip;

  Future<(_TrayApp, TrayController)> start(
    WidgetTester tester, {
    void Function(_TrayApp app)? arrange,
  }) async {
    menus = [];
    tooltip = '';
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      const MethodChannel('tray_manager'),
      (call) async {
        final arguments = call.arguments as Map<Object?, Object?>?;
        if (call.method == 'setToolTip') {
          tooltip = arguments!['toolTip']! as String;
        }
        if (call.method == 'setContextMenu') {
          final menu = arguments!['menu']! as Map<Object?, Object?>;
          menus.add(
            _Menu(tooltip, [
              for (final item in menu['items']! as List<Object?>)
                item! as Map<Object?, Object?>,
            ]),
          );
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
    final app = _TrayApp();
    arrange?.call(app);
    final controller = TrayController(app, window: _Window());
    addTearDown(app.dispose);
    addTearDown(controller.dispose);
    await controller.initialize();
    await tester.pump();
    expect(menus, isNotEmpty);
    return (app, controller);
  }

  Future<void> click(
    WidgetTester tester,
    TrayController controller,
    String key,
  ) async {
    controller.onTrayMenuItemClick(tray.MenuItem(key: key, label: key));
    await tester.pump();
  }

  testWidgets('a running operation can be stopped from the menu', (
    tester,
  ) async {
    if (!Platform.isWindows) return;
    final (app, controller) = await start(
      tester,
      arrange: (app) => app
        ..busy = true
        ..cancellable = true
        ..commandRunning = true
        ..vpnStatus = VpnStatus.preparing,
    );

    // Busy, yet enabled: the item stops what is running.
    expect(menus.last.label('connection'), 'Déconnecter');
    expect(menus.last.disabled('connection'), isFalse);
    expect(menus.last.item('disconnect'), isNull);
    expect(menus.last.status, 'VPN : préparation');
    expect(menus.last.tooltip, 'FuzeVPN — VPN : préparation');
    expect(menus.last.disabled('quit'), isFalse);

    await click(tester, controller, 'connection');
    expect(app.commands, ['disconnectVpn']);
  });

  testWidgets('any other busy cause keeps the connection item off', (
    tester,
  ) async {
    if (!Platform.isWindows) return;
    final (app, _) = await start(
      tester,
      arrange: (app) => app
        ..busy = true
        ..requiresDisconnect = true
        ..vpnStatus = VpnStatus.disconnecting,
    );
    expect(menus.last.label('connection'), 'Déconnecter');
    expect(menus.last.disabled('connection'), isTrue);
    expect(menus.last.status, 'VPN : déconnexion en cours');

    // A VPN owned by another Windows session offers no stop either.
    app
      ..busy = false
      ..cancellable = true
      ..otherSession = true
      ..changed();
    await tester.pump();
    expect(menus.last.disabled('connection'), isTrue);
  });

  testWidgets('the startup attempt shows its live state before the '
      'controller is initialized', (tester) async {
    if (!Platform.isWindows) return;
    final (app, controller) = await start(
      tester,
      arrange: (app) => app
        ..isInitialized = false
        ..vpnStatus = VpnStatus.blocked,
    );
    // Nothing runs yet: the state is still being read.
    expect(menus.last.status, 'VPN : vérification en cours');

    app
      ..busy = true
      ..cancellable = true
      ..commandRunning = true
      ..requiresDisconnect = true
      ..vpnStatus = VpnStatus.preparing
      ..changed();
    await tester.pump();
    expect(menus.last.status, 'VPN : préparation');
    expect(menus.last.label('connection'), 'Déconnecter');
    expect(menus.last.disabled('connection'), isFalse);
    await click(tester, controller, 'connection');
    expect(app.commands, ['disconnectVpn']);
  });

  testWidgets('a menu that offered to connect never disconnects once a '
      'tunnel came up', (tester) async {
    if (!Platform.isWindows) return;
    final (app, controller) = await start(tester);
    expect(menus.last.label('connection'), 'Connexion rapide');
    expect(menus.last.disabled('connection'), isFalse);
    final built = menus.length;

    // The tunnel connects before Windows received a newer menu.
    app
      ..requiresDisconnect = true
      ..vpnStatus = VpnStatus.connected;
    expect(menus.length, built);
    await click(tester, controller, 'connection');
    expect(app.commands, isEmpty);

    // With an up-to-date menu the same item stops it.
    app.changed();
    await tester.pump();
    expect(menus.last.label('connection'), 'Déconnecter');
    await click(tester, controller, 'connection');
    expect(app.commands, ['disconnectVpn']);
  });

  testWidgets('a menu that offered to disconnect never connects once the '
      'tunnel is gone', (tester) async {
    if (!Platform.isWindows) return;
    final (app, controller) = await start(
      tester,
      arrange: (app) => app
        ..requiresDisconnect = true
        ..vpnStatus = VpnStatus.connected,
    );
    expect(menus.last.label('connection'), 'Déconnecter');

    app
      ..requiresDisconnect = false
      ..vpnStatus = VpnStatus.disconnected;
    await click(tester, controller, 'connection');
    // The stop intent is sent, which is a no-op with nothing to stop.
    expect(app.commands, ['disconnectVpn']);

    app.changed();
    await tester.pump();
    expect(menus.last.label('connection'), 'Connexion rapide');
    await click(tester, controller, 'connection');
    expect(app.commands, ['disconnectVpn', 'quickConnect']);
  });

  testWidgets('the unknown state keeps its passive retry and adds an '
      'explicit Disconnect', (tester) async {
    if (!Platform.isWindows) return;
    final (app, controller) = await start(
      tester,
      arrange: (app) => app
        ..unknown = true
        ..vpnStatus = VpnStatus.error,
    );
    expect(menus.last.status, 'État VPN inconnu');
    expect(menus.last.label('connection'), 'Réessayer');
    expect(menus.last.disabled('connection'), isFalse);
    expect(menus.last.label('disconnect'), 'Déconnecter');
    expect(menus.last.disabled('disconnect'), isFalse);
    // Right under the retry, before the navigation items.
    final keys = [for (final item in menus.last.items) item['key']];
    expect(keys.indexOf('disconnect'), keys.indexOf('connection') + 1);

    await click(tester, controller, 'connection');
    expect(app.commands, ['retryRuntimeVerification']);
    await click(tester, controller, 'disconnect');
    expect(app.commands, ['retryRuntimeVerification', 'disconnectVpn']);

    // While the passive verification runs there is nothing to offer.
    app
      ..busy = true
      ..changed();
    await tester.pump();
    expect(menus.last.item('disconnect'), isNull);
    expect(menus.last.disabled('connection'), isTrue);

    // Known again before Windows received a newer menu: the stale retry
    // stays passive and starts nothing.
    app
      ..busy = false
      ..unknown = false
      ..vpnStatus = VpnStatus.disconnected;
    await click(tester, controller, 'connection');
    expect(app.commands, [
      'retryRuntimeVerification',
      'disconnectVpn',
      'retryRuntimeVerification',
    ]);

    app.changed();
    await tester.pump();
    expect(menus.last.item('disconnect'), isNull);
    expect(menus.last.label('connection'), 'Connexion rapide');
  });

  testWidgets('the extra Disconnect item exists in no known state', (
    tester,
  ) async {
    if (!Platform.isWindows) return;
    final (app, _) = await start(tester);
    for (final status in VpnStatus.values) {
      app
        ..vpnStatus = status
        ..requiresDisconnect =
            status == VpnStatus.connected || status == VpnStatus.blocked
        ..changed();
      await tester.pump();
      expect(menus.last.item('disconnect'), isNull, reason: status.name);
      expect(menus.last.item('connection'), isNotNull, reason: status.name);
    }
  });
}
