// SPDX-License-Identifier: MPL-2.0
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
  /// installed service retains its lifetime; the portable broker is cleaned up.
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

  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent event) handler,
  ) {
    if (!Platform.isWindows) return;
    _channel.setMethodCallHandler((call) async {
      final event = switch (call.method) {
        'networkAvailable' => WindowsConnectivityEvent.networkAvailable,
        'systemResumed' => WindowsConnectivityEvent.systemResumed,
        _ => null,
      };
      if (event != null) await handler(event);
    });
  }

  void stopConnectivityListener() {
    if (!Platform.isWindows) return;
    _channel.setMethodCallHandler(null);
  }
}
