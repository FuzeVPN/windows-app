// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/models.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _RecordingDiagnostics extends DiagnosticsController {
  final errors = <DiagnosticError>[];
  @override
  void recordTerminalError(
    DiagnosticError error, {
    String protocol = 'unknown',
    String state = 'error',
    bool terminal = true,
  }) {
    if (terminal) errors.add(error);
  }
}

class _RenewApi extends fixtures.ProbeApi {
  ApiException? renewalError;
  bool recoverRevokedIdentity = false;
  int registrations = 0;

  @override
  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    if (renewalError case final error?) throw error;
    return createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) {
    registrations++;
    if (recoverRevokedIdentity && registrations == 1) {
      throw const ApiException(
        statusCode: 409,
        errorCode: 'device_identity_revoked',
        observedHttpStatus: 409,
      );
    }
    return super.registerDevice(
      token: token,
      name: name,
      publicKey: publicKey,
      locationId: locationId,
      ipFamilies: ipFamilies,
    );
  }
}

class _RenewOpenVpn extends fixtures.ProbeOpenVpn {
  Object? importError;
  Object? csrError;
  @override
  Future<void> prepareNetworkProtection() async => protectionActive = true;
  @override
  Future<void> suspendForMigration() async => connected = false;
  @override
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async {
    if (csrError case final error?) throw error;
    return 'synthetic-renewal-csr';
  }

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    if (importError case final error?) {
      importCalls++;
      throw error;
    }
    await super.importAndConnect(activation);
  }
}

class _RecoveryWireGuard extends fixtures.ProbeWireGuard {
  @override
  Future<void> recreateIdentityForAccount(String accountId) async {}
}

AppController _controller({
  required _RecordingDiagnostics diagnostics,
  _RenewApi? api,
  _RenewOpenVpn? openVpn,
  _RecoveryWireGuard? wireGuard,
}) =>
    AppController(
        api: api ?? _RenewApi(),
        store: fixtures.ProbeStore(),
        window: fixtures.ProbeWindow(),
        wireguard: wireGuard ?? _RecoveryWireGuard(),
        openVpn: openVpn ?? _RenewOpenVpn(),
        diagnostics: diagnostics,
      )
      ..profile = fixtures.account
      ..currentDeviceId = fixtures.device.deviceId
      ..selectedLocation = fixtures.source
      ..realDeviceLocation = fixtures.source
      ..vpnProtocol = VpnProtocol.openVpn
      ..activeProtocol = VpnProtocol.openVpn
      ..openVpnRuntimeAvailable = true
      ..vpnStatus = VpnStatus.connected;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final code in ['openvpn_signer_unavailable', 'node_unavailable']) {
    test(
      'terminal renewal API failure retains renew context ($code)',
      () async {
        final diagnostics = _RecordingDiagnostics();
        final app = _controller(
          diagnostics: diagnostics,
          api: _RenewApi()
            ..renewalError = ApiException(
              statusCode: 503,
              errorCode: code,
              observedHttpStatus: 503,
            ),
        );
        addTearDown(app.dispose);
        await app.renewOpenVpnProfile();
        expect(diagnostics.errors, hasLength(1));
        final error = diagnostics.errors.single;
        expect(error.code, code);
        expect(error.domain, 'api');
        expect(error.operation, 'renew');
        expect(error.stage, 'certificate_renewal');
        expect(error.httpStatus, 503);
      },
    );
  }

  test('unrecovered renewal connection failure is reported once', () async {
    final diagnostics = _RecordingDiagnostics();
    final app = _controller(
      diagnostics: diagnostics,
      openVpn: _RenewOpenVpn()
        ..importError = PlatformException(code: 'openvpn_no_server_response'),
    );
    addTearDown(app.dispose);
    await app.renewOpenVpnProfile();
    expect(diagnostics.errors, hasLength(1));
    expect(diagnostics.errors.single.code, 'openvpn_no_server_response');
    expect(diagnostics.errors.single.operation, 'renew');
    expect(diagnostics.errors.single.stage, 'certificate_renewal');
  });

  test(
    'renewal response loss recovered from native status has no incident',
    () async {
      final diagnostics = _RecordingDiagnostics();
      final app = _controller(
        diagnostics: diagnostics,
        openVpn: _RenewOpenVpn()..loseConnectAcknowledgement = true,
      );
      addTearDown(app.dispose);
      await app.renewOpenVpnProfile();
      expect(app.vpnStatus, VpnStatus.connected);
      expect(diagnostics.errors, isEmpty);
    },
  );

  for (final code in ['operation_cancelled', 'permission_denied']) {
    test('expected renewal interruption is not an incident ($code)', () async {
      final diagnostics = _RecordingDiagnostics();
      final app = _controller(
        diagnostics: diagnostics,
        openVpn: _RenewOpenVpn()..csrError = PlatformException(code: code),
      );
      addTearDown(app.dispose);
      await app.renewOpenVpnProfile();
      expect(diagnostics.errors, isEmpty);
    });
  }

  test('unexpected renewal failure preserves renew context', () async {
    final diagnostics = _RecordingDiagnostics();
    final app = _controller(
      diagnostics: diagnostics,
      openVpn: _RenewOpenVpn()..csrError = StateError('synthetic failure'),
    );
    addTearDown(app.dispose);
    await app.renewOpenVpnProfile();
    expect(diagnostics.errors, hasLength(1));
    expect(diagnostics.errors.single.code, 'unexpected_error');
    expect(diagnostics.errors.single.operation, 'renew');
  });

  test(
    'successful location switch recovery is not a disconnect incident',
    () async {
      final diagnostics = _RecordingDiagnostics();
      final api = _RenewApi()..recoverRevokedIdentity = true;
      final app =
          _controller(
              diagnostics: diagnostics,
              api: api,
              wireGuard: _RecoveryWireGuard()
                ..connected = true
                ..protectionActive = true,
            )
            ..vpnProtocol = VpnProtocol.wireGuard
            ..activeProtocol = VpnProtocol.wireGuard
            ..pendingTargetLocation = fixtures.target;
      addTearDown(app.dispose);
      await app.confirmPreparedLocationChange();
      expect(api.registrations, 2);
      expect(app.vpnStatus, VpnStatus.connected);
      expect(diagnostics.errors, isEmpty);
    },
  );
}
