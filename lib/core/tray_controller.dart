// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/widgets.dart';

import 'package:tray_manager/tray_manager.dart' as tray;

import '../app_controller.dart';
import '../l10n/app_localizations.dart';
import 'models.dart';
import 'vpn_notification_policy.dart';
import 'window_bridge.dart';

/// What the menu's connection item does, as decided when that menu was built.
enum _ConnectionItemIntent { connect, stop, retryVerification }

class TrayController with tray.TrayListener, WidgetsBindingObserver {
  TrayController(
    this._controller, {
    WindowBridge? window,
    this._onQuitRequested,
  }) : _window = window ?? const WindowBridge();

  final AppController _controller;
  final WindowBridge _window;
  final Future<void> Function()? _onQuitRequested;
  bool _isReady = false;
  bool _listening = false;
  int _generation = 0;
  Future<void> _menuRefreshQueue = Future<void>.value();
  VpnStatus _previousStatus = VpnStatus.disconnected;
  // The intent of the connection item in the menu Windows currently holds.
  // A click acts on it, never on a toggle evaluated at click time: a menu
  // that went stale can then neither start nor stop the VPN the wrong way.
  _ConnectionItemIntent _connectionItemIntent = _ConnectionItemIntent.connect;

  Future<void> initialize() async {
    if (!Platform.isWindows) return;
    dispose();
    final generation = _generation;
    _listening = true;
    WidgetsBinding.instance.addObserver(this);
    tray.trayManager.addListener(this);
    _controller.addListener(_onControllerChanged);
    _previousStatus = _controller.vpnStatus;
    try {
      await tray.trayManager.setIcon(_iconPath());
      if (generation != _generation) return;
      await tray.trayManager.setToolTip('FuzeVPN');
      if (generation != _generation) return;
      _isReady = true;
      await _refreshMenu();
      if (generation != _generation || !_isReady) return;
      await _window.setTrayAvailable(true);
    } catch (_) {
      // A missing notification-area icon must never prevent the VPN app from
      // starting. No account or tunnel data is logged here.
      if (generation != _generation) return;
      _generation++;
      _isReady = false;
      await _window.setTrayAvailable(false);
    }
  }

  void dispose() {
    _generation++;
    _isReady = false;
    if (!_listening) return;
    _listening = false;
    WidgetsBinding.instance.removeObserver(this);
    _controller.removeListener(_onControllerChanged);
    tray.trayManager.removeListener(this);
  }

  String _iconPath() =>
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}fuzevpn_tray.ico';

  void _onControllerChanged() {
    _notifyForImportantStatusChange();
    unawaited(_refreshMenuSafely());
  }

  @override
  void didChangeLocales(List<Locale>? locales) {
    if (_controller.language == AppLanguage.system) {
      unawaited(_refreshMenuSafely());
    }
  }

  Future<void> _refreshMenuSafely() async {
    final generation = _generation;
    try {
      await _refreshMenu();
    } catch (_) {
      if (generation != _generation) return;
      _generation++;
      _isReady = false;
      await _window.setTrayAvailable(false);
    }
  }

  void _notifyForImportantStatusChange() {
    final previous = _previousStatus;
    final current = _controller.vpnStatus;
    _previousStatus = current;
    if (!_isReady) return;
    if (_controller.runtimeVerificationPending) return;
    final event = vpnNotificationEventFor(
      previous: previous,
      current: current,
      initialized: _controller.isInitialized,
      enabled: _controller.windowsNotificationsEnabled,
    );
    if (event == null) return;
    final language = _controller.language == AppLanguage.system
        ? AppLanguageLocale.fromLocale(
            WidgetsBinding.instance.platformDispatcher.locale,
          )
        : _controller.language;
    final strings = AppStrings.forLanguage(language);
    if (event == VpnNotificationEvent.connected) {
      final location = _controller.locations
          .where((item) => item.id == _controller.tunnelLocationId)
          .firstOrNull
          ?.displayName;
      unawaited(
        _window.showNotification(
          title: strings.text('VPN connecté'),
          message: location == null
              ? strings.text('Votre connexion VPN est maintenant protégée.')
              : strings
                    .text('Connexion établie sur {location}.')
                    .replaceAll('{location}', location),
        ),
      );
      return;
    }
    if (event == VpnNotificationEvent.unexpectedDisconnection) {
      unawaited(
        _window.showNotification(
          title: strings.text('VPN déconnecté'),
          message: strings.text(
            'La connexion VPN s’est interrompue de manière inattendue.',
          ),
        ),
      );
      return;
    }
    if (event == VpnNotificationEvent.importantError) {
      unawaited(
        _window.showNotification(
          title: strings.text('Connexion VPN impossible'),
          message: strings.text(
            'FuzeVPN n’a pas pu établir ou rétablir la protection.',
          ),
        ),
      );
    }
  }

  Future<void> _refreshMenu() {
    if (!_isReady) return Future<void>.value();
    final generation = _generation;
    // A native tooltip call may finish after a newer controller notification.
    // Keep tooltip/menu pairs ordered and read the latest state at execution.
    final refresh = _menuRefreshQueue.then(
      (_) => _applyMenuRefresh(generation),
    );
    // Preserve each caller's error while allowing recovery to enqueue again.
    _menuRefreshQueue = refresh.then<void>(
      (_) {},
      onError: (Object error, StackTrace stackTrace) {},
    );
    return refresh;
  }

  Future<void> _applyMenuRefresh(int generation) async {
    if (!_isReady || generation != _generation) return;
    final verificationPending = _controller.runtimeVerificationPending;
    // A running connection, reconnection or renewal can be stopped from
    // here too; any other busy cause keeps the item off.
    final canCancel = _controller.canCancelConnection;
    final stops = canCancel || _controller.requiresExplicitDisconnect;
    final intent = verificationPending
        ? _ConnectionItemIntent.retryVerification
        : stops
        ? _ConnectionItemIntent.stop
        : _ConnectionItemIntent.connect;
    // The unknown state keeps its passive retry and adds the explicit stop.
    final offersForcedStop =
        verificationPending && _controller.canDisconnectVpn;
    final isBusy = _controller.isConnectionBusy;
    final signedIn = _controller.profile != null;
    final trayLanguage = _controller.language == AppLanguage.system
        ? AppLanguageLocale.fromLocale(
            WidgetsBinding.instance.platformDispatcher.locale,
          )
        : _controller.language;
    final strings = AppStrings.forLanguage(trayLanguage);
    // The startup resume runs before the controller is initialized: its
    // live state is shown, as in the window.
    final status = verificationPending
        ? strings.text('État VPN inconnu')
        : !(_controller.isInitialized ||
              _controller.isConnectionCommandRunning ||
              _controller.isStoppingVpn)
        ? strings.text('VPN : vérification en cours')
        : switch (_controller.vpnStatus) {
            VpnStatus.connected => strings.text('VPN : protégé'),
            VpnStatus.preparing => strings.text('VPN : préparation'),
            VpnStatus.connecting => strings.text('VPN : connexion en cours'),
            VpnStatus.disconnecting => strings.text(
              'VPN : déconnexion en cours',
            ),
            VpnStatus.blocked => strings.text('VPN : trafic bloqué'),
            VpnStatus.error => strings.text('VPN : connexion impossible'),
            VpnStatus.disconnected => strings.text('VPN : non protégé'),
          };

    await tray.trayManager.setToolTip('FuzeVPN — $status');
    if (!_isReady || generation != _generation) return;

    // Recorded in the same turn as the menu it describes replaces the
    // previous one: clicks are resolved against that menu.
    _connectionItemIntent = intent;
    await tray.trayManager.setContextMenu(
      tray.Menu(
        items: [
          tray.MenuItem(key: 'open', label: strings.text('Ouvrir FuzeVPN')),
          tray.MenuItem(label: status, disabled: true),
          tray.MenuItem.separator(),
          tray.MenuItem(
            key: 'connection',
            label: switch (intent) {
              _ConnectionItemIntent.retryVerification => strings.text(
                'Réessayer',
              ),
              _ConnectionItemIntent.stop => strings.text('Déconnecter'),
              _ConnectionItemIntent.connect =>
                signedIn
                    ? strings.text('Connexion rapide')
                    : strings.text('Se connecter'),
            },
            disabled:
                (isBusy && !canCancel) || _controller.runtimeOwnedByAnotherUser,
          ),
          if (offersForcedStop)
            tray.MenuItem(
              key: 'disconnect',
              label: strings.text('Déconnecter'),
            ),
          tray.MenuItem(
            key: 'locations',
            label: strings.text('Choisir un emplacement'),
          ),
          tray.MenuItem(key: 'settings', label: strings.text('Réglages')),
          tray.MenuItem(key: 'help', label: strings.text('Aide')),
          tray.MenuItem.separator(),
          tray.MenuItem(key: 'quit', label: strings.text('Quitter FuzeVPN')),
        ],
      ),
    );
  }

  @override
  void onTrayIconUnavailable() {
    _generation++;
    _isReady = false;
    unawaited(_window.setTrayAvailable(false));
  }

  @override
  void onTrayIconAvailable() {
    if (!_listening) return;
    unawaited(_restoreTray());
  }

  Future<void> _restoreTray() async {
    final generation = ++_generation;
    _isReady = true;
    await _refreshMenuSafely();
    if (generation == _generation && _isReady) {
      await _window.setTrayAvailable(true);
    }
  }

  @override
  void onTrayIconMouseDown() {
    unawaited(_show(AppSection.connection));
  }

  @override
  void onTrayIconRightMouseDown() {
    unawaited(tray.trayManager.popUpContextMenu());
  }

  @override
  void onTrayMenuItemClick(tray.MenuItem menuItem) {
    switch (menuItem.key) {
      case 'open':
        unawaited(_show(AppSection.connection));
        break;
      case 'connection':
        unawaited(_handleConnection(_connectionItemIntent));
        break;
      case 'disconnect':
        unawaited(_handleConnection(_ConnectionItemIntent.stop));
        break;
      case 'locations':
        unawaited(_show(AppSection.locations));
        break;
      case 'settings':
        unawaited(_show(AppSection.settings));
        break;
      case 'help':
        unawaited(_show(AppSection.help));
        break;
      case 'quit':
        unawaited(_quit());
        break;
    }
  }

  Future<void> _show(AppSection section) async {
    _controller.selectSection(section);
    await _window.show();
  }

  Future<void> _handleConnection(_ConnectionItemIntent intent) async {
    await _show(AppSection.connection);
    switch (intent) {
      case _ConnectionItemIntent.stop:
        await _controller.disconnectVpn();
      case _ConnectionItemIntent.retryVerification:
        // Passive, and a no-op once the state is known again.
        await _controller.retryRuntimeVerification();
      case _ConnectionItemIntent.connect:
        // Meanwhile a tunnel came up or a protection was retained: an item
        // that offered to connect never disconnects.
        if (_controller.requiresExplicitDisconnect) return;
        await _controller.quickConnect();
    }
  }

  Future<void> _quit() async {
    final request = _onQuitRequested;
    if (request != null) {
      await _window.show();
      await request();
      return;
    }
    try {
      await tray.trayManager.destroy();
    } finally {
      await _window.quit();
    }
  }
}
