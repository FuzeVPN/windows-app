// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';

import 'diagnostic_log.dart';

/// Asks Windows to validate a public certificate from the API chain and return
/// its root. A callback may provide an issuer rather than the server leaf;
/// the caller must retry strict TLS to authenticate the actual server.
class WindowsTlsTrust {
  const WindowsTlsTrust();

  static const _channel = MethodChannel('com.fuzevpn/windows_tls_trust');
  static const _apiHostname = 'api.fuzevpn.com';
  static const _maximumCertificateBytes = 64 * 1024;
  static const _responseKeys = {
    'trusted',
    'anchor_der',
    'trust_status',
    'windows_error',
    'certificate_role',
  };

  Future<Uint8List?> verifyApiCertificate(
    Uint8List certificateDer,
    String hostname,
  ) async {
    if (hostname != _apiHostname ||
        certificateDer.isEmpty ||
        certificateDer.length > _maximumCertificateBytes) {
      throw const FormatException('Invalid Windows TLS verification request.');
    }
    final value = await _channel.invokeMethod<Object?>('verifyApiCertificate', {
      'certificate_der': Uint8List.fromList(certificateDer),
      'hostname': hostname,
    });
    if (value is! Map ||
        value.keys.any((key) => !_responseKeys.contains(key)) ||
        value['trusted'] is! bool) {
      throw const FormatException('Invalid Windows TLS verification response.');
    }
    for (final key in const ['trust_status', 'windows_error']) {
      if (value.containsKey(key)) {
        final number = value[key];
        if (number is! int || number < 0 || number > 0xffffffff) {
          throw const FormatException(
            'Invalid Windows TLS verification status.',
          );
        }
      }
    }
    if (value.containsKey('trust_status') !=
        value.containsKey('windows_error')) {
      throw const FormatException(
        'Incomplete Windows TLS verification status.',
      );
    }
    final certificateRole = value['certificate_role'];
    if (value.containsKey('certificate_role') &&
        certificateRole != 'ca' &&
        certificateRole != 'server') {
      throw const FormatException('Invalid Windows TLS certificate role.');
    }
    final verificationCode = switch (certificateRole) {
      'ca' => 'ca_chain',
      'server' => 'server_certificate',
      _ => null,
    };
    final trusted = value['trusted'] as bool;
    final trustStatus = value['trust_status'] as int?;
    final windowsError = value['windows_error'] as int?;
    if (trusted &&
        (trustStatus != null && trustStatus != 0 ||
            windowsError != null && windowsError != 0)) {
      throw const FormatException(
        'Contradictory Windows TLS verification status.',
      );
    }
    final anchor = value['anchor_der'];
    if (!trusted) {
      if (anchor != null) {
        throw const FormatException('Unexpected Windows TLS trust anchor.');
      }
      await DiagnosticLog.record(
        area: 'tls_trust',
        event: 'rejected',
        code: verificationCode,
        stage: 'windows_certificate_verification',
        trustStatus: trustStatus,
        windowsError: windowsError == 0 ? null : windowsError,
      );
      return null;
    }
    if (anchor is! Uint8List ||
        anchor.isEmpty ||
        anchor.length > _maximumCertificateBytes) {
      throw const FormatException('Invalid Windows TLS trust anchor.');
    }
    await DiagnosticLog.record(
      area: 'tls_trust',
      event: 'trusted',
      code: verificationCode,
      stage: 'windows_certificate_verification',
      trustStatus: trustStatus,
      windowsError: windowsError == 0 ? null : windowsError,
    );
    return Uint8List.fromList(anchor);
  }
}
