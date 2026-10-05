// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';

import 'windows_update_models.dart';

/// The native layer downloads and verifies the package; no path is exposed.
class WindowsUpdateBridge {
  const WindowsUpdateBridge();
  static const _channel = MethodChannel('fuzevpn/update');

  Future<WindowsUpdateEnvironment> getEnvironment() async {
    final value = await _channel.invokeMapMethod<Object?, Object?>(
      'getEnvironment',
    );
    if (value == null) {
      throw const FormatException('Missing Windows update environment.');
    }
    return WindowsUpdateEnvironment.fromMap(value);
  }

  Future<String> prepareUpdate(WindowsUpdateRelease release) async {
    final token = await _channel.invokeMethod<String>('prepareUpdate', {
      'download_url': release.downloadUrl.toString(),
      'sha256': release.sha256,
      'version': release.version.toString(),
      'package': release.package.name,
    });
    if (token == null ||
        token.isEmpty ||
        token.length > 1024 ||
        token.codeUnits.any((unit) => unit <= 32 || unit == 127)) {
      throw const WindowsUpdateFailure('update_not_prepared');
    }
    return token;
  }

  Future<void> installUpdate(String token) =>
      _channel.invokeMethod<void>('installUpdate', {'token': token});
  Future<void> discardUpdate(String token) =>
      _channel.invokeMethod<void>('discardUpdate', {'token': token});
}
