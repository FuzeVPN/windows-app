// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/diagnostics_support.dart';
import 'package:fuzevpn_windows/core/local_diagnostic_trace.dart';
import 'package:fuzevpn_windows/core/models.dart';

import 'support/audit_fixtures.dart' as fixtures;
import 'support/backend_support_vocabulary.dart';

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

class _EventDiagnostics extends _RecordingDiagnostics {
  final events = <DiagnosticEvent>[];
  @override
  void recordEvent(DiagnosticEvent event) {
    events.add(event);
    super.recordEvent(event);
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

  test(
    'native interruption trace preserves fixed references without exception text',
    () async {
      for (final code in [
        'operation_cancelled',
        'permission_denied',
        'runtime_owned_by_another_user',
        'maintenance_in_progress',
      ]) {
        final before = DiagnosticLog.recentLines.length;
        await DiagnosticLog.recordFailure(
          area: 'openvpn',
          event: 'certificate_renewal_failed',
          stage: 'certificate_renewal',
          error: PlatformException(
            code: code,
            message: 'private-message',
            details: {'private-field': 'private-detail'},
          ),
        );
        final line = DiagnosticLog.recentLines.skip(before).single;
        expect(line, contains('code=$code '));
        expect(line, isNot(contains('native_operation_failed')));
        expect(line, isNot(contains('private')));
      }
      final before = DiagnosticLog.recentLines.length;
      await DiagnosticLog.recordFailure(
        area: 'openvpn',
        event: 'certificate_renewal_failed',
        error: PlatformException(code: 'operation_cancelled_private_secret'),
      );
      final line = DiagnosticLog.recentLines.skip(before).single;
      expect(line, contains('code=native_operation_failed '));
      expect(line, isNot(contains('private_secret')));
    },
  );

  // recentLines is a bounded ring shared by this file: slice after a marker.
  var marks = 0;
  String markTrace() {
    final marker = 'renewal_trace_mark_${marks++}';
    DiagnosticLog.record(area: 'trace_test', event: marker);
    return marker;
  }

  List<String> since(String marker) {
    final lines = DiagnosticLog.recentLines;
    final index = lines.lastIndexWhere(
      (line) => line.endsWith(' event=$marker'),
    );
    expect(index, isNot(-1), reason: 'trace marker $marker was evicted');
    return lines.skip(index + 1).toList();
  }

  Future<Map<String, Object?>> collect(List<String> lines) async {
    final directory = await Directory.systemTemp.createTemp('fuzevpn-renew-');
    addTearDown(() => directory.delete(recursive: true));
    return LocalDiagnosticTrace.collect(
      path: '${directory.path}${Platform.pathSeparator}diagnostic.log',
      currentLines: lines,
    );
  }

  test(
    'the local reader rejects renewal values outside the support vocabulary',
    () async {
      // Values of an earlier draft that the backend's closed lists refuse:
      // one of them would make it reject the whole full report.
      for (final line in [
        '2026-11-10T12:00:00Z area=openvpn event=certificate_renewal_started '
            'count=3',
        '2026-11-10T12:00:00Z area=openvpn event=certificate_renewal_completed '
            'count=90',
        '2026-11-10T12:00:00Z area=openvpn event=started reason=proactive',
        '2026-11-10T12:00:00Z area=openvpn event=native_connect_failed '
            'code=openvpn_client_certificate_rejected',
      ]) {
        final collected = await collect([line]);
        expect(collected['events'], isEmpty, reason: line);
        expect(collected['discarded_lines'], 1, reason: line);
      }
      final accepted = await collect([
        '2026-11-10T12:00:00Z area=openvpn event=started '
            'code=certificate_expired stage=certificate_renewal count=0',
        '2026-11-10T12:00:01Z area=openvpn event=attempt_failed '
            'code=unknown_error stage=certificate_renewal attempt=1',
        '2026-11-10T12:00:02Z area=openvpn event=completed '
            'code=openvpn_certificate_expired stage=certificate_renewal count=90',
      ]);
      expect(accepted['discarded_lines'], 0);
      expect(accepted['events'], hasLength(3));
    },
  );

  test(
    'a refused client certificate keeps its code only outside diagnostics',
    () async {
      const code = 'openvpn_client_certificate_rejected';
      expect(diagnosticCodes, isNot(contains(code)));
      expect(diagnosticCodes, contains('openvpn_certificate_expired'));
      expect(diagnosticCodes.length, 206);
      // Reports keep v1's category, never the server certificate's.
      expect(diagnosticCode(code), 'certificate_invalid');
      expect(DiagnosticError(code: code).code, 'certificate_invalid');
      expect(
        DiagnosticEvent(stage: 'tunnel_start', event: 'error', code: code).code,
        'certificate_invalid',
      );

      // Application traces carry the reportable category at their source.
      final marker = markTrace();
      await DiagnosticLog.recordFailure(
        area: 'openvpn',
        event: 'native_connect_failed',
        error: PlatformException(code: code, message: 'private-detail'),
      );
      await DiagnosticLog.record(
        area: 'openvpn',
        event: 'native_state_recovered',
        code: code,
      );
      final lines = since(marker);
      expect(lines, hasLength(2));
      for (final line in lines) {
        expect(line, contains('code=certificate_invalid'));
        expect(line, isNot(contains(code)));
        expect(line, isNot(contains('private')));
      }
      expect((await collect(lines))['discarded_lines'], 0);

      // A native line written by the service keeps the raw code: the support
      // export maps it, in every field the backend checks.
      final native = DiagnosticSupport.sanitizeNativeEvent({
        'timestamp': '2026-11-10T12:00:00.000Z',
        'area': 'openvpn',
        'event': 'connection_attempt_snapshot',
        'code': code,
        'first_error': code,
        'last_error': 'openvpn_certificate_expired',
        'failure_before_stop': code,
      });
      expect(native, {
        'timestamp': '2026-11-10T12:00:00.000Z',
        'area': 'openvpn',
        'event': 'connection_attempt_snapshot',
        'code': 'certificate_invalid',
        'first_error': 'certificate_invalid',
        'last_error': 'openvpn_certificate_expired',
        'failure_before_stop': 'certificate_invalid',
      });
      expect(
        backendSupportViolations({'source': 'native', ...native!}),
        isEmpty,
      );
    },
  );

  test('renewal steps become certificate_renewal breadcrumbs', () async {
    final diagnostics = _EventDiagnostics();
    final app = _controller(diagnostics: diagnostics);
    addTearDown(app.dispose);
    for (final event in ['started', 'attempt_failed', 'completed']) {
      await DiagnosticLog.record(
        area: 'openvpn',
        event: event,
        code: 'automatic',
        stage: 'certificate_renewal',
      );
    }
    expect(
      diagnostics.events.map((event) => (event.stage, event.event)).toList(),
      [
        ('certificate_renewal', 'begin'),
        ('certificate_renewal', 'retry'),
        ('certificate_renewal', 'end'),
      ],
    );
  });

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
