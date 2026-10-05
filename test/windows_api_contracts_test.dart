// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';

import 'support/audit_fixtures.dart' as audit;
import 'device_enrollment_error_test.dart' as enrollment;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const authCases = [
    (status: 401, code: 'unauthorized', expires: true),
    (status: 401, code: 'api_error', expires: false),
    (status: 401, code: 'invalid_credentials', expires: false),
    (status: 500, code: 'unauthorized', expires: false),
    (status: 500, code: 'server_error', expires: false),
    (status: 503, code: 'server_error', expires: false),
  ];

  for (final item in authCases) {
    final error = ApiException(statusCode: item.status, errorCode: item.code);
    final label = '${item.status}/${item.code}';

    testWidgets('saved session handles $label and recovers when appropriate', (
      tester,
    ) async {
      final api = _ContractApi()..profileFailure = error;
      final store = _ContractStore();
      final window = audit.ProbeWindow();
      final controller = _controller(api: api, store: store, window: window);
      await controller.initialize();
      expect(controller.profile, isNull);
      expect(store.clearTokenCalls, item.expires ? 1 : 0);
      expect(store.savedToken == null, item.expires);
      api.profileFailure = null;
      await window.listener!(WindowsConnectivityEvent.networkAvailable);
      expect(api.meCalls, item.expires ? 1 : 2);
      expect(controller.profile, item.expires ? isNull : audit.account);
      controller.dispose();
    });

    for (final path in ['enrollment', 'migration', 'openvpn-release']) {
      test(
        '$path expires a session only for 401/unauthorized ($label)',
        () async {
          final api = _ContractApi();
          final store = _ContractStore();
          final controller = _signedInController(api: api, store: store);
          addTearDown(controller.dispose);
          if (path == 'enrollment') {
            api.enrollmentFailure = error;
            await controller.toggleConnection();
            expect(api.registerCalls, 1);
          } else if (path == 'migration') {
            api.migrationFailure = error;
            controller.pendingTargetLocation = audit.target;
            await controller.startPreparedLocationMigration();
            expect(api.migrationCalls, 1);
          } else {
            api.releaseFailure = error;
            await controller.toggleConnection();
            expect(api.releaseCalls, 1);
            expect(api.registerCalls, 1);
          }
          expect(store.clearTokenCalls, item.expires ? 1 : 0);
          expect(controller.profile, item.expires ? isNull : audit.account);
        },
      );
    }
  }

  const loginCases = [
    (status: 401, code: 'invalid_credentials', message: 'mot de passe'),
    (status: 401, code: 'unauthorized', message: 'session a expiré'),
    (status: 401, code: 'api_error', message: 'momentanément indisponible'),
    (status: 500, code: 'unauthorized', message: 'momentanément indisponible'),
    (
      status: 500,
      code: 'invalid_credentials',
      message: 'momentanément indisponible',
    ),
    (status: 500, code: 'server_error', message: 'momentanément indisponible'),
    (status: 503, code: 'server_error', message: 'momentanément indisponible'),
    (status: 429, code: 'rate_limited', message: 'Trop de tentatives'),
    (status: 408, code: 'request_timeout', message: 'connexion Internet'),
    (
      status: 503,
      code: 'api_resolution_unavailable',
      message: 'connexion Internet',
    ),
  ];
  for (final item in loginCases) {
    test(
      'login classifies ${item.status}/${item.code} without retrying',
      () async {
        final api = _ContractApi()
          ..loginFailure = ApiException(
            statusCode: item.status,
            errorCode: item.code,
          );
        final store = _ContractStore();
        final controller = _controller(api: api, store: store);
        addTearDown(controller.dispose);
        expect(await _signIn(controller), isFalse);
        expect(controller.errorMessage, contains(item.message));
        expect(api.loginCalls, 1);
        expect(api.meCalls, 0);
        expect(store.clearTokenCalls, 0);
        expect(store.saveTokenCalls, 0);
      },
    );
  }

  test(
    'login socket failure explains network failure without retrying',
    () async {
      final api = _ContractApi()
        ..loginFailure = const SocketException('Synthetic connection failure');
      final controller = _controller(api: api);
      addTearDown(controller.dispose);
      expect(await _signIn(controller), isFalse);
      expect(controller.errorMessage, contains('connexion Internet'));
      expect(api.loginCalls, 1);
    },
  );

  for (final error in <Object>[
    const ApiException(statusCode: 500, errorCode: 'server_error'),
    const ApiException(statusCode: 500, errorCode: 'unauthorized'),
    const ApiException(statusCode: 401, errorCode: 'invalid_credentials'),
    const SocketException('Synthetic connection failure'),
    const FormatException('Synthetic malformed profile'),
  ]) {
    test(
      'a profile failure after login never blames credentials (${error.runtimeType})',
      () async {
        final api = _ContractApi()..profileFailure = error;
        final store = _ContractStore();
        final controller = _controller(api: api, store: store);
        addTearDown(controller.dispose);
        expect(await _signIn(controller), isFalse);
        expect(controller.errorMessage, contains('connexion a été acceptée'));
        expect(controller.errorMessage, isNot(contains('mot de passe')));
        expect(api.loginCalls, 1);
        expect(api.meCalls, 1);
        expect(store.clearTokenCalls, 0);
        expect(store.saveTokenCalls, 0);
      },
    );
  }

  for (final code in ['device_identity_revoked', 'device_location_locked']) {
    test('500/$code cannot reset an identity or replay enrollment', () async {
      final api = _ContractApi()
        ..enrollmentFailure = ApiException(statusCode: 500, errorCode: code);
      final wg = _ContractWireGuard();
      final controller = _signedInController(api: api, wg: wg);
      addTearDown(controller.dispose);
      await controller.toggleConnection();
      expect(api.registerCalls, 1);
      expect(api.releaseCalls, 0);
      expect(wg.identityResetCalls, 0);
    });
  }

  test(
    '500/openvpn_operation_pending cannot replay profile creation',
    () async {
      final api = _ContractApi()
        ..openVpnFailure = const ApiException(
          statusCode: 500,
          errorCode: 'openvpn_operation_pending',
          retryAfterSeconds: 0,
        );
      final controller = _signedInController(api: api)
        ..vpnProtocol = VpnProtocol.openVpn
        ..selectedLocation = const Location(
          id: 'source',
          city: 'Source',
          countryCode: 'DE',
          displayName: 'Source',
          supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
        )
        ..openVpnRuntimeAvailable = true;
      addTearDown(controller.dispose);
      await controller.toggleConnection();
      expect(api.openVpnCalls, 1);
      expect(controller.profile, audit.account);
    },
  );

  for (final protection in ['full', 'partial', 'unknown']) {
    test(
      'WireGuard DNS failure preserves its cause and $protection protection state',
      () async {
        final api = _ContractApi();
        final wg = _ContractWireGuard()
          ..connectFailureCode = 'endpoint_resolution_failed'
          ..appliedKillSwitch = protection == 'full'
          ..structuredStatusAvailable = protection != 'unknown';
        final controller = _signedInController(api: api, wg: wg);
        addTearDown(controller.dispose);
        await controller.toggleConnection();
        expect(controller.errorMessage, contains('nom du serveur WireGuard'));
        expect(
          controller.errorMessage,
          contains(switch (protection) {
            'full' => 'kill switch bloque toujours',
            'partial' => 'partielles',
            _ => 'ne peut pas être confirmé',
          }),
        );
        if (protection != 'full') {
          expect(
            controller.errorMessage,
            isNot(contains('kill switch bloque')),
          );
        }
        expect(
          controller.vpnStatus,
          protection == 'full' ? VpnStatus.blocked : VpnStatus.error,
        );
        expect(wg.protectionActive, isTrue);
        expect(controller.requiresExplicitDisconnect, isTrue);
        expect(api.registerCalls, 1);
      },
    );
  }

  for (final item in [
    (
      status: 401,
      body:
          '{"error":"unauthorized","message":"Texte public éphémère","request_id":"synthetic-reference","future_field":true}',
      code: 'unauthorized',
    ),
    (status: 401, body: '{"error":"unauthorized"}', code: 'unauthorized'),
    (status: 401, body: '<html>Unauthorized</html>', code: 'api_error'),
    (status: 500, body: '{"error":"unauthorized"}', code: 'unauthorized'),
    (
      status: 500,
      body: '{"error":"server_error","message":null,"request_id":42}',
      code: 'server_error',
    ),
    (status: 502, body: '<html>Gateway unavailable</html>', code: 'api_error'),
  ]) {
    test(
      'HTTP ${item.status}/${item.code} accepts optional fields and non-JSON',
      () async {
        final server = await _serve((request) async {
          request.response.statusCode = item.status;
          request.response.headers.contentType = ContentType.json;
          request.response.write(item.body);
          await request.response.close();
        });
        final api = _localClient(server);
        await expectLater(
          api.me('synthetic-session'),
          throwsA(
            isA<ApiException>()
                .having((e) => e.statusCode, 'status', item.status)
                .having((e) => e.errorCode, 'code', item.code)
                .having(
                  (e) => e.isUnauthorized,
                  'authenticated rejection',
                  item.status == 401 && item.code == 'unauthorized',
                )
                .having(
                  (e) => e.toString(),
                  'safe exception',
                  allOf(
                    isNot(contains('éphémère')),
                    isNot(contains('synthetic-reference')),
                  ),
                ),
          ),
        );
      },
    );
  }

  test(
    '204 DELETE responses are accepted without JSON or a second request',
    () async {
      final methods = <String>[];
      final server = await _serve((request) async {
        methods.add(request.method);
        request.response.statusCode = HttpStatus.noContent;
        await request.response.close();
      });
      final api = _localClient(server);
      await api.revokeDevice(
        token: 'synthetic-session',
        deviceId: 'synthetic-device',
      );
      await api.revokeOpenVpnProfile(
        token: 'synthetic-session',
        deviceId: 'synthetic-device',
      );
      expect(methods, ['DELETE', 'DELETE']);
    },
  );

  test('HTTP login preserves Unicode and whitespace in the password', () async {
    const password = ' é漢字🔐 mot de passe ';
    final received = Completer<Map<String, dynamic>>();
    final server = await _serve((request) async {
      received.complete(
        jsonDecode(await utf8.decoder.bind(request).join())
            as Map<String, dynamic>,
      );
      request.response.headers.contentType = ContentType.json;
      request.response.write('{"access_token":"synthetic-session"}');
      await request.response.close();
    });
    final api = _localClient(server);
    await api.login(email: 'synthetic@example.invalid', password: password);
    expect((await received.future)['password'], password);
    expect(
      UserProfile.fromJson({'first_name': 'Élodie 漢字'}).firstName,
      'Élodie 漢字',
    );
    expect(
      VpnDevice.fromJson({
        'device_id': 'synthetic-device',
        'name': 'Ordinateur 🔐 漢字',
      }).name,
      'Ordinateur 🔐 漢字',
    );
  });

  test(
    'an interrupted successful POST response does not replay enrollment',
    () async {
      var requests = 0;
      final server = await _serve((request) async {
        requests++;
        await request.drain<void>();
        final socket = await request.response.detachSocket(writeHeaders: false);
        socket.write(
          'HTTP/1.1 200 OK\r\n'
          'Content-Type: application/json\r\n'
          'Content-Length: 128\r\n'
          'Connection: close\r\n\r\n'
          '{"device_id":',
        );
        await socket.flush();
        socket.destroy();
      });
      final api = _localClient(server);
      await expectLater(
        api.registerDevice(
          token: 'synthetic-session',
          name: 'Synthetic Windows',
          publicKey: 'synthetic-public-key',
          locationId: 'synthetic-location',
        ),
        throwsA(anything),
      );
      expect(requests, 1);
    },
  );
}

Future<bool> _signIn(AppController controller) => controller.signIn(
  email: 'synthetic@example.invalid',
  password: 'synthetic-password',
);

AppController _controller({
  _ContractApi? api,
  _ContractStore? store,
  audit.ProbeWindow? window,
  _ContractWireGuard? wg,
}) => AppController(
  api: api ?? _ContractApi(),
  store: store ?? _ContractStore(),
  wireguard: wg ?? _ContractWireGuard(),
  openVpn: _ContractOpenVpn(),
  window: window ?? audit.ProbeWindow(),
);

AppController _signedInController({
  required _ContractApi api,
  _ContractStore? store,
  _ContractWireGuard? wg,
}) => _controller(api: api, store: store, wg: wg)
  ..profile = audit.account
  ..currentDeviceId = audit.device.deviceId
  ..devices = [audit.device]
  ..locations = [audit.source, audit.target]
  ..selectedLocation = audit.source
  ..realDeviceLocation = audit.source
  ..vpnProtocol = VpnProtocol.wireGuard
  ..isLoadingLocations = false;

Future<HttpServer> _serve(Future<void> Function(HttpRequest) handler) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  addTearDown(() => server.close(force: true));
  server.listen(handler);
  return server;
}

ApiClient _localClient(HttpServer server) {
  final api = ApiClient(
    // The widget binding replaces HttpClient with a canned 400 response.
    // This client talks exclusively to the loopback server created above.
    client: HttpOverrides.runWithHttpOverrides(
      () => HttpClient(),
      _LoopbackHttpOverrides(),
    ),
    baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
  );
  addTearDown(api.close);
  return api;
}

class _ContractApi extends audit.ProbeApi {
  Object? loginFailure;
  Object? profileFailure;
  ApiException? enrollmentFailure;
  ApiException? migrationFailure;
  ApiException? releaseFailure;
  ApiException? openVpnFailure;
  int loginCalls = 0;
  int registerCalls = 0;
  int migrationCalls = 0;
  int releaseCalls = 0;
  int openVpnCalls = 0;

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    loginCalls++;
    if (loginFailure case final error?) throw error;
    return const AuthSession(accessToken: 'synthetic-session');
  }

  @override
  Future<UserProfile> me(String token) async {
    meCalls++;
    if (profileFailure case final error?) throw error;
    return audit.account;
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registerCalls++;
    if (enrollmentFailure case final error?) throw error;
    if (releaseFailure != null) {
      throw const ApiException(
        statusCode: 409,
        errorCode: 'device_location_locked',
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

  @override
  Future<LocationMigration> startLocationMigration({
    required String token,
    required String deviceId,
    required String locationId,
  }) async {
    migrationCalls++;
    throw migrationFailure!;
  }

  @override
  Future<void> revokeOpenVpnProfile({
    required String token,
    required String deviceId,
  }) async {
    releaseCalls++;
    if (releaseFailure case final error?) throw error;
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    openVpnCalls++;
    if (openVpnFailure case final error?) throw error;
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }
}

class _ContractStore extends audit.ProbeStore {
  String? savedToken = 'synthetic-session';
  int clearTokenCalls = 0;
  int saveTokenCalls = 0;
  @override
  Future<String?> token() async => savedToken;
  @override
  Future<void> clearToken() async {
    clearTokenCalls++;
    savedToken = null;
  }

  @override
  Future<void> saveToken(String value) async {
    saveTokenCalls++;
    savedToken = value;
  }
}

class _ContractWireGuard extends audit.ProbeWireGuard {
  int identityResetCalls = 0;
  String? connectFailureCode;
  bool structuredStatusAvailable = true;
  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async {
    if (!structuredStatusAvailable) throw MissingPluginException();
    return super.networkProtectionStatus();
  }

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    if (connectFailureCode case final code?) {
      throw PlatformException(code: code);
    }
    await super.connect(configuration);
  }

  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
  @override
  Future<void> resetIdentity() async {
    identityResetCalls++;
    await super.resetIdentity();
  }

  @override
  Future<void> recreateIdentityForAccount(String accountId) async {
    identityResetCalls++;
  }
}

class _ContractOpenVpn extends enrollment.FakeOpenVpnBridge {
  @override
  Future<bool> isAvailable() async => false;
}

class _LoopbackHttpOverrides extends HttpOverrides {}
