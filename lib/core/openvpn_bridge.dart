// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';

import 'models.dart';

/// OpenVPN private material never crosses this boundary. The CSR is public;
/// activation material is passed once to native code for encrypted import and
/// is deliberately not retained by this class.
class OpenVpnBridge {
  static const _channel = MethodChannel('com.fuzevpn/windows_openvpn');
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

  Future<bool> isAvailable() async =>
      await _channel.invokeMethod<bool>('isAvailable') ?? false;

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

  /// Arms the service-owned Windows network policy before any control-plane
  /// request or OpenVPN runtime operation. The native client promotes this
  /// policy to the real DCO interface once OpenVPN reports CONNECTED.
  Future<void> prepareNetworkProtection() =>
      _channel.invokeMethod<void>('prepareConnection', {
        'killSwitch': _killSwitch,
        'dnsProtection': _dnsProtection,
        'webRtcProtection': _webRtcProtection,
      });

  /// Reuses the last native configuration without a control-plane request.
  /// False means no configuration is available; failures remain exceptions.
  Future<bool> reconnect() async =>
      await _channel.invokeMethod<bool>('reconnect') ?? false;

  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async =>
      await _channel.invokeMethod<String>('getOrCreateCsr', {
        'accountId': accountId,
        'deviceId': deviceId,
      }) ??
      (throw StateError('CSR OpenVPN indisponible.'));

  /// Creates a separate pending P-256 identity for certificate renewal. The
  /// native layer swaps it in only after the replacement tunnel is connected.
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async =>
      await _channel.invokeMethod<String>('renewCsr', {
        'accountId': accountId,
        'deviceId': deviceId,
      }) ??
      (throw StateError('CSR OpenVPN indisponible.'));

  Future<void> importAndConnect(OpenVpnActivation activation) =>
      _channel.invokeMethod<void>('importAndConnect', {
        'certificatePem': activation.certificatePem,
        'caCertificatePem': activation.caCertificatePem,
        'tlsCryptV2ClientKey': activation.tlsCryptV2ClientKey,
        'endpoint': activation.endpoint,
        'dns': activation.dns,
        'address': activation.address,
        'addresses': activation.effectiveAddresses,
        'allowedIps': activation.allowedIps,
        'ipv6Enabled': activation.supportsIpv6,
        'serverName': activation.serverName,
        'remoteCertTlsServer': activation.remoteCertTlsServer,
        'ciphers': activation.ciphers,
        'killSwitch': _killSwitch,
        'dnsProtection': _dnsProtection,
        'webRtcProtection': _webRtcProtection,
      });

  Future<void> disconnect() => _channel.invokeMethod<void>('disconnect');

  /// Stops the old OpenVPN tunnel while retaining the prepared WFP policy for
  /// a server migration. Only an explicit Disconnect releases that policy.
  Future<void> suspendForMigration() =>
      _channel.invokeMethod<void>('suspendForMigration');

  /// Stops OpenVPN then deletes its encrypted profile, certificate and key.
  Future<void> deleteProfile() => _channel.invokeMethod<void>('deleteProfile');
}
