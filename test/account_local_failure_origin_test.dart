// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_controller.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixtures;

const _location = Location(
  id: 'source',
  city: 'Source',
  countryCode: 'DE',
  displayName: 'Source',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);

class _Api extends fixtures.ProbeApi {
  ApiException? loginFailure;
  ApiException? profileFailure;
  ApiException? enrollmentFailure;
  ApiException? billingFailure;
  @override
  Future<Subscription> subscription(String token) async {
    if (billingFailure case final failure?) throw failure;
    return super.subscription(token);
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    if (loginFailure case final failure?) throw failure;
    return const AuthSession(accessToken: 'synthetic-login-token');
  }

  @override
  Future<UserProfile> me(String token) async {
    if (profileFailure case final failure?) throw failure;
    return fixtures.account;
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    if (enrollmentFailure case final failure?) throw failure;
    return super.registerDevice(
      token: token,
      name: name,
      publicKey: publicKey,
      locationId: locationId,
      ipFamilies: ipFamilies,
    );
  }
}

class _Store extends fixtures.ProbeStore {
  String savedToken = 'synthetic-saved-session';
  int clears = 0;
  @override
  Future<String?> token() async => savedToken;
  @override
  Future<void> saveToken(String token) async {
    savedToken = token;
  }

  @override
  Future<void> clearToken() async {
    clears++;
  }
}

class _WireGuard extends fixtures.ProbeWireGuard {
  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
  }

  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
}

class _OpenVpn extends fixtures.ProbeOpenVpn {
  @override
  Future<void> prepareNetworkProtection() async {}
}

class _Updates extends WindowsUpdateController {
  _Updates() : super(api: fixtures.ProbeApi());
  @override
  Future<void> checkForUpdates() async {}
}

class _Diagnostics extends DiagnosticsController {
  _Diagnostics() : super(api: fixtures.ProbeApi());
  final errors = <DiagnosticError>[];
  @override
  void recordTerminalError(
    DiagnosticError error, {
    String protocol = 'unknown',
    String state = 'error',
    bool terminal = true,
  }) {
    errors.add(error);
  }
}

AppController _controller(_Api api, _Store store, _Diagnostics diagnostics) =>
    AppController(
      api: api,
      store: store,
      wireguard: _WireGuard(),
      openVpn: _OpenVpn(),
      window: fixtures.ProbeWindow(),
      updates: _Updates(),
      diagnostics: diagnostics,
    );

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  setUp(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
          const MethodChannel('fuzevpn/update'),
          (_) async => {
            'version': '1.0.7',
            'windows_build': 26200,
            'arch': 'x64',
            'installation_mode': 'installed',
          },
        );
  });
  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('fuzevpn/update'), null);
  });
  const causes =
      <({String code, String message, String domain, int windowsError})>[
        (
          code: 'broker_unavailable',
          message: 'service VPN local',
          domain: 'system',
          windowsError: 50,
        ),
        (
          code: 'secure_storage_read_failed',
          message: 'stockage protégé',
          domain: 'storage',
          windowsError: 5,
        ),
        (
          code: 'api_bootstrap_unavailable',
          message: 'résoudre l’adresse',
          domain: 'client',
          windowsError: 11001,
        ),
        (
          code: 'runtime_detection_failed',
          message: 'vérifier l’installation',
          domain: 'system',
          windowsError: 1060,
        ),
        (
          code: 'native_bridge_unavailable',
          message: 'composant Windows',
          domain: 'system',
          windowsError: 50,
        ),
      ];
  for (final cause in causes) {
    final failure = ApiException(
      statusCode: 503,
      errorCode: 'api_resolution_unavailable',
      localErrorCode: cause.code,
      windowsError: cause.windowsError,
    );
    test(
      'login preserves local ${cause.code} instead of blaming the API',
      () async {
        final api = _Api()..loginFailure = failure;
        final store = _Store();
        final app = _controller(api, store, _Diagnostics());
        addTearDown(app.dispose);
        final start = DiagnosticLog.recentLines.length;
        expect(
          await app.signIn(
            email: 'synthetic@example.invalid',
            password: 'synthetic',
          ),
          isFalse,
        );
        expect(app.errorMessage, contains(cause.message));
        expect(app.errorMessage, isNot(contains('connexion Internet')));
        expect(store.clears, 0);
        final trace = DiagnosticLog.recentLines.skip(start).join('\n');
        expect(trace, contains('code=${cause.code} '));
        expect(trace, contains('windows_error=${cause.windowsError} '));
        expect(trace, isNot(contains('http_status=503')));
      },
    );
    test(
      'saved session preserves local ${cause.code} and credentials',
      () async {
        final api = _Api()..profileFailure = failure;
        final store = _Store();
        final app = _controller(api, store, _Diagnostics());
        addTearDown(app.dispose);
        await app.initialize();
        expect(app.savedSessionVerificationPending, isTrue);
        expect(
          app.savedSessionVerificationErrorMessage,
          contains(cause.message),
        );
        expect(store.savedToken, 'synthetic-saved-session');
        expect(store.clears, 0);
      },
    );
    test(
      'subscription displays local ${cause.code} without invalidating the account',
      () async {
        final api = _Api()..billingFailure = failure;
        final store = _Store();
        final app = _controller(api, store, _Diagnostics())
          ..profile = fixtures.account;
        addTearDown(app.dispose);
        await app.refreshSubscription();
        expect(app.subscriptionErrorMessage, contains(cause.message));
        expect(app.profile, fixtures.account);
        expect(store.clears, 0);
      },
    );
    for (final protocol in VpnProtocol.values) {
      test(
        '${protocol.name} enrollment preserves ${cause.code} and Windows code',
        () async {
          final api = _Api()..enrollmentFailure = failure;
          final store = _Store();
          final diagnostics = _Diagnostics();
          final app = _controller(api, store, diagnostics)
            ..profile = fixtures.account
            ..locations = [_location]
            ..selectedLocation = _location
            ..vpnProtocol = protocol
            ..protocolPreference = protocol == VpnProtocol.wireGuard
                ? VpnProtocolPreference.wireGuard
                : VpnProtocolPreference.openVpn
            ..openVpnRuntimeAvailable = true
            ..isInitialized = true
            ..isLoadingLocations = false;
          addTearDown(app.dispose);
          final start = DiagnosticLog.recentLines.length;
          await app.quickConnect();
          expect(app.errorMessage, contains(cause.message));
          expect(app.deviceEnrollmentIssue, isNull);
          expect(app.profile, fixtures.account);
          expect(store.clears, 0);
          expect(diagnostics.errors, isNotEmpty);
          final error = diagnostics.errors.last;
          expect(error.code, diagnosticCode(cause.code));
          expect(error.domain, cause.domain);
          expect(error.httpStatus, isNull);
          expect(error.nativeDomain, 'win32');
          expect(error.nativeCode, cause.windowsError);
          final trace = DiagnosticLog.recentLines.skip(start).join('\n');
          expect(trace, contains('code=${cause.code} '));
          expect(trace, contains('windows_error=${cause.windowsError} '));
          expect(trace, isNot(contains('http_status=503')));
        },
      );
    }
  }
  for (final protocol in VpnProtocol.values) {
    test(
      '${protocol.name} real server 503 remains an HTTP API failure',
      () async {
        final failure = ApiException.fromResponse(
          statusCode: HttpStatus.serviceUnavailable,
          body: '{"error":"server_error"}',
        );
        final api = _Api()..enrollmentFailure = failure;
        final diagnostics = _Diagnostics();
        final app = _controller(api, _Store(), diagnostics)
          ..profile = fixtures.account
          ..locations = [_location]
          ..selectedLocation = _location
          ..vpnProtocol = protocol
          ..protocolPreference = protocol == VpnProtocol.wireGuard
              ? VpnProtocolPreference.wireGuard
              : VpnProtocolPreference.openVpn
          ..openVpnRuntimeAvailable = true
          ..isInitialized = true
          ..isLoadingLocations = false;
        addTearDown(app.dispose);
        await app.quickConnect();
        expect(
          app.deviceEnrollmentIssue?.kind,
          DeviceEnrollmentIssueKind.unknown,
        );
        final error = diagnostics.errors.last;
        expect(error.domain, 'api');
        expect(error.code, 'server_error');
        expect(error.httpStatus, 503);
        expect(error.nativeCode, isNull);
      },
    );
  }
}
