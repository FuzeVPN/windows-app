// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'models.dart';

/// Windows-specific implementation belongs behind this bridge. Private keys
/// stay in the native secure store and are never returned to Dart.
class WireGuardBridge {
  static const _channel = MethodChannel('com.fuzevpn/windows_wireguard');
  bool _killSwitch = true;
  bool _dnsProtection = true;
  bool _webRtcProtection = true;

  void configureNetworkProtection({
    required bool killSwitch,
    required bool dnsProtection,
    required bool webRtcProtection,
  }) {
    _killSwitch = killSwitch;
    _dnsProtection = dnsProtection;
    _webRtcProtection = webRtcProtection;
  }

  /// Ensures the device identity is permanently bound to [accountId]. The
  /// native runner deletes a previous account's identity before making a new
  /// one; no key material crosses this call.
  Future<void> prepareIdentityForAccount(String accountId) => _channel
      .invokeMethod('prepareIdentityForAccount', {'accountId': accountId});

  /// Stops the previous tunnel, erases its identity and creates the
  /// replacement as one privileged native operation. This avoids exposing a
  /// half-reset state to Flutter when a revoked device is enrolled again.
  Future<void> recreateIdentityForAccount(String accountId) => _channel
      .invokeMethod('recreateIdentityForAccount', {'accountId': accountId});

  /// Generates the device identity inside the native WireGuard runtime when
  /// needed. Only the public key crosses the Dart boundary.
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      await _channel.invokeMethod<String>('getOrCreatePublicKey', {
        'accountId': accountId,
      }) ??
      (throw StateError('Clé publique WireGuard indisponible.'));

  Future<bool> isConnected() async =>
      await _channel.invokeMethod<bool>('isConnected') ?? false;

  Future<bool> isNetworkProtectionActive() async =>
      await _channel.invokeMethod<bool>('isNetworkProtectionActive') ?? false;

  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    final value = await _channel.invokeMapMethod<Object?, Object?>(
      'networkProtectionStatus',
    );
    if (value == null) throw const FormatException('État réseau absent.');
    return NetworkProtectionStatus.fromMap(value);
  }

  /// The service resolves only the fixed API hostname with its own bounded
  /// DNS transport; Windows' shared resolver is never granted a WFP bypass.
  /// Empty means the runner confirmed no runtime exists, so normal DNS can
  /// be used before login without starting a service. Unknown state or DNS
  /// failure with a runtime present MUST be an exception, never an empty list.
  Future<List<String>> resolveApiAddresses() async {
    final addresses = await _channel.invokeListMethod<String>(
      'resolveApiAddresses',
    );
    if (addresses == null) {
      throw const FormatException('État du résolveur VPN inconnu.');
    }
    return addresses;
  }

  /// Arms a fail-closed Windows network policy before the native tunnel
  /// service starts. The policy is promoted to the real WireGuard interface by
  /// [connect] once Windows exposes that interface.
  Future<void> prepareNetworkProtection() =>
      _channel.invokeMethod('prepareConnection', {
        'killSwitch': _killSwitch,
        'dnsProtection': _dnsProtection,
        'webRtcProtection': _webRtcProtection,
      });

  /// Reuses the last native configuration without a control-plane request.
  /// False means no configuration is available; failures remain exceptions.
  Future<bool> reconnect() async =>
      await _channel.invokeMethod<bool>('reconnect') ?? false;

  Future<void> connect(DeviceConfiguration configuration) =>
      _channel.invokeMethod('connect', {
        'deviceId': configuration.deviceId,
        'address': configuration.address,
        'addresses': configuration.effectiveAddresses,
        'dns': configuration.dns,
        'serverPublicKey': configuration.serverPublicKey,
        'endpoint': configuration.endpoint,
        'allowedIps': configuration.allowedIps,
        'killSwitch': _killSwitch,
        'dnsProtection': _dnsProtection,
        'webRtcProtection': _webRtcProtection,
      });
  Future<void> disconnect() => _channel.invokeMethod('disconnect');

  /// Stops the adapter without releasing the prepared WFP policy.
  Future<void> suspendForMigration() =>
      _channel.invokeMethod<void>('suspendForMigration');

  /// Stops the local tunnel, removes its restricted configuration, and erases
  /// the native-only WireGuard key pair and its account binding. No key
  /// material crosses into Dart.
  Future<void> resetIdentity() => _channel.invokeMethod('resetIdentity');
}
