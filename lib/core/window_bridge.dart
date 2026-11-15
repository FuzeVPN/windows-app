// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

enum WindowsConnectivityEvent { networkAvailable, systemResumed }

class WindowBridge {
  const WindowBridge();

  static const _channel = MethodChannel('fuzevpn/window');
  static const _fallbackDeviceName = 'FuzeVPN 1.0.1 -- Windows';

  Future<String> deviceName() async {
    if (!Platform.isWindows) return _fallbackDeviceName;
    try {
      final value = await _channel.invokeMethod<String>('getDeviceName');
      final name = value?.trim();
      return name == null || name.isEmpty ? _fallbackDeviceName : name;
    } catch (_) {
      return _fallbackDeviceName;
    }
  }

  Future<void> show() async {
    if (!Platform.isWindows) return;
    try {
      await _channel.invokeMethod<void>('show');
    } on PlatformException {
      // The tray remains usable even if Windows cannot restore the window.
    }
  }

  /// Exits after the caller confirms the runtime-specific consequence: an
  /// installed service retains its lifetime, tunnel and kill switch; the
  /// portable engine stops with this window and keeps a kill switch that no
  /// explicit stop released beforehand.
  Future<void> quit() async {
    if (!Platform.isWindows) return;
    await _channel.invokeMethod<void>('quit');
  }

  Future<bool> isLaunchAtStartupEnabled() async {
    if (!Platform.isWindows) return false;
    return await _channel.invokeMethod<bool>('isLaunchAtStartupEnabled') ??
        false;
  }

  Future<void> setTrayAvailable(bool available) async {
    if (!Platform.isWindows) return;
    try {
      await _channel.invokeMethod<void>('setTrayAvailable', {
        'available': available,
      });
    } catch (_) {
      if (!available) await show();
    }
  }

  Future<void> setLaunchAtStartup(bool enabled) async {
    if (!Platform.isWindows) return;
    await _channel.invokeMethod<void>('setLaunchAtStartup', {
      'enabled': enabled,
    });
  }

  Future<void> showNotification({
    required String title,
    required String message,
  }) async {
    if (!Platform.isWindows) return;
    try {
      await _channel.invokeMethod<void>('showNotification', {
        'title': title,
        'message': message,
      });
    } on PlatformException {
      // Notifications are informative and must never affect the VPN state.
    }
  }

  // The channel has a single native-to-Dart handler: both subscriptions
  // share it, and it is removed once neither is registered.
  static Future<void> Function(WindowsConnectivityEvent event)?
  _connectivityHandler;
  static Future<void> Function()? _closeRequestHandler;

  static void _syncNativeEventHandler() {
    _channel.setMethodCallHandler(
      _connectivityHandler == null && _closeRequestHandler == null
          ? null
          : _handleNativeEvent,
    );
  }

  static Future<void> _handleNativeEvent(MethodCall call) async {
    switch (call.method) {
      case 'networkAvailable':
        await _connectivityHandler?.call(
          WindowsConnectivityEvent.networkAvailable,
        );
      case 'systemResumed':
        await _connectivityHandler?.call(
          WindowsConnectivityEvent.systemResumed,
        );
      case 'closeRequested':
        final handler = _closeRequestHandler;
        if (handler == null) return;
        // The confirmation may stay open for a long time: the native call
        // never waits for it, and a failure there never reaches Windows.
        unawaited(Future<void>.sync(handler).catchError((Object _) {}));
    }
  }

  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent event) handler,
  ) {
    if (!Platform.isWindows) return;
    _connectivityHandler = handler;
    _syncNativeEventHandler();
  }

  void stopConnectivityListener() {
    if (!Platform.isWindows) return;
    _connectivityHandler = null;
    _syncNativeEventHandler();
  }

  /// Registers what answers a request to close the window that Windows could
  /// not turn into "hide to the notification area" because no icon exists
  /// there. The window then stays open and is the only place left to quit
  /// from: [handler] opens the Quit confirmation. The request itself changes
  /// nothing in the VPN. Passing null removes the registration.
  void setCloseRequestHandler(Future<void> Function()? handler) {
    if (!Platform.isWindows) return;
    _closeRequestHandler = handler;
    _syncNativeEventHandler();
  }
}
