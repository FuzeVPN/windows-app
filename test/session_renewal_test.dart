// SPDX-License-Identifier: MPL-2.0
// Session renewal contract: synthetic tokens only, a fake API or a loopback
// server, and an in-memory protected store. No network or Windows changes.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/session_renewal.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as f;

const _channel = MethodChannel('com.fuzevpn/windows_secure_store');
const _record = 'renewable_session';

// Synthetic API-shaped values: 43 base64url characters.
String _token(String letter) => letter * 43;
String _refreshToken(int generation) =>
    'fr1.00000000-0000-4000-8000-000000000000.$generation.${'r' * 43}';

final _classic = _token('c');
final _access1 = _token('a');
final _access2 = _token('b');
final _access3 = _token('d');
final _refresh1 = _refreshToken(1);
final _refresh2 = _refreshToken(2);
final _refresh3 = _refreshToken(3);

SessionTokens _pair(String access, String refresh, DateTime expiresAt) =>
    SessionTokens(
      accessToken: access,
      expiresAt: expiresAt,
      refreshToken: refresh,
      refreshExpiresAt: expiresAt.add(const Duration(days: 365)),
    );

ApiException _answer(int status, String code, {int? retryAfter}) =>
    ApiException(
      statusCode: status,
      errorCode: code,
      observedHttpStatus: status,
      retryAfterSeconds: retryAfter,
    );

class _Sent {
  _Sent(this.upgrade, this.token, this.requestId, this.storedBefore);
  final bool upgrade;
  final String token;
  final String requestId;
  // The protected record as it was when the request left.
  final String? storedBefore;
}

mixin _ScriptedSessionRoutes on ApiClient {
  late Map<String, String> disk;
  final sent = <_Sent>[];
  final answers = <Object>[];
  final logouts = <String>[];
  Object? logoutFailure;
  final _requestIdOfRefreshToken = <String, String>{};

  @override
  Future<SessionTokens> rotateSession({
    required bool upgrade,
    required String token,
    required String requestId,
  }) async {
    sent.add(_Sent(upgrade, token, requestId, disk[_record]));
    if (!upgrade) {
      // A refresh token is never presented with a second request ID: that
      // would be a replay, which revokes the session.
      expect(
        _requestIdOfRefreshToken.putIfAbsent(token, () => requestId),
        requestId,
      );
    }
    var answer = answers.removeAt(0);
    if (answer is Future<Object>) answer = await answer;
    if (answer is SessionTokens) return answer;
    throw answer;
  }

  @override
  Future<void> logout(String refreshToken) async {
    logouts.add(refreshToken);
    if (logoutFailure case final failure?) throw failure;
  }
}

class _Api extends ApiClient with _ScriptedSessionRoutes {}

class _ControllerApi extends f.ProbeApi with _ScriptedSessionRoutes {
  final meTokens = <String>[];
  @override
  Future<UserProfile> me(String token) async {
    meTokens.add(token);
    return f.account;
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async => AuthSession(accessToken: _classic);
}

class _WireGuard extends f.ProbeWireGuard {
  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
}

// The fixture's preferences with the real session storage code.
class _ControllerStore extends f.ProbeStore {
  final real = SecureStore();
  @override
  Future<String?> token() => real.token();
  @override
  Future<void> saveToken(String value) => real.saveToken(value);
  @override
  Future<void> clearToken() => real.clearToken();
  @override
  Future<RenewableSession?> renewableSession() => real.renewableSession();
  @override
  Future<void> saveRenewableSession(RenewableSession value) =>
      real.saveRenewableSession(value);
  @override
  Future<void> clearRenewableSession() => real.clearRenewableSession();
}

class _NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

final _requestId = RegExp(r'^[A-Za-z0-9_-]{43}$');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Map<String, String> disk;
  late DateTime now;
  late List<Duration> waits;
  late _Api api;

  SessionRenewal renewal({ApiClient? using}) => SessionRenewal(
    api: using ?? api,
    store: SecureStore(),
    now: () => now,
    wait: (delay) async {
      waits.add(delay);
      now = now.add(delay);
    },
  );

  RenewableSession? stored() {
    final value = disk[_record];
    return value == null ? null : RenewableSession.decode(value);
  }

  void storeRenewable(SessionTokens tokens, {PendingSessionRequest? pending}) =>
      disk[_record] = RenewableSession(
        tokens: tokens,
        pending: pending,
      ).encode();

  setUp(() {
    disk = {};
    now = DateTime.utc(2026, 11, 17, 12);
    waits = [];
    api = _Api()..disk = disk;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, (call) async {
          final key = call.arguments['key'] as String;
          switch (call.method) {
            case 'read':
              return disk[key];
            case 'write':
              disk[key] = call.arguments['value'] as String;
            case 'delete':
              disk.remove(key);
          }
          return null;
        });
  });
  tearDown(
    () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(_channel, null),
  );

  group('storage', () {
    test('one record holds the pair and the pending request', () async {
      final store = SecureStore();
      disk['access_token'] = _classic;
      expect(await store.token(), _classic);
      final session = RenewableSession(
        tokens: _pair(_access1, _refresh1, now),
        pending: PendingSessionRequest(
          upgrade: false,
          token: _refresh1,
          requestId: 'q' * 43,
        ),
      );
      await store.saveRenewableSession(session);
      expect(await store.token(), _access1);
      final read = (await store.renewableSession())!;
      expect(read.tokens!.expiresAt, now);
      expect(read.tokens!.refreshToken, _refresh1);
      expect(read.pending!.requestId, 'q' * 43);
      // A sign-in replaces the renewable session; sign-out removes both.
      await store.saveToken(_token('n'));
      expect(disk.containsKey(_record), isFalse);
      expect(await store.token(), _token('n'));
      await store.saveRenewableSession(session);
      await store.clearToken();
      expect(disk, isEmpty);
    });

    test('an unreadable record never repeats its content', () async {
      disk[_record] = '{"version":1,"access_token":"$_access1"}';
      await expectLater(
        SecureStore().token(),
        throwsA(
          isA<FormatException>().having(
            (error) => '${error.message} ${error.source}',
            'text',
            isNot(contains(_access1)),
          ),
        ),
      );
    });
  });

  group('upgrade', () {
    test('converts a classic session and stores the pair atomically', () async {
      disk['access_token'] = _classic;
      api.answers.add(
        _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
      );
      expect(await renewal().current(_classic, upgrade: true), _access1);
      final request = api.sent.single;
      expect(request.upgrade, isTrue);
      expect(request.token, _classic);
      expect(request.requestId, matches(_requestId));
      expect(base64Url.decode('${request.requestId}=').length, 32);
      // Stored with its route, token and request ID before it was sent.
      final before = RenewableSession.decode(request.storedBefore!);
      expect(before.tokens, isNull);
      expect(before.pending!.upgrade, isTrue);
      expect(before.pending!.token, _classic);
      expect(before.pending!.requestId, request.requestId);
      expect(stored()!.pending, isNull);
      expect(stored()!.tokens!.refreshToken, _refresh1);
      expect(await SecureStore().token(), _access1);
    });

    test('404 keeps the classic session for the rest of the run', () async {
      disk['access_token'] = _classic;
      api.answers.add(_answer(404, 'not_found'));
      final sessions = renewal();
      expect(await sessions.current(_classic, upgrade: true), _classic);
      expect(disk.containsKey(_record), isFalse);
      expect(disk['access_token'], _classic);
      expect(await sessions.current(_classic, upgrade: true), _classic);
      expect(api.sent, hasLength(1));
      expect(waits, isEmpty);
    });

    test(
      'a lost answer is retried identically, also after a restart',
      () async {
        disk['access_token'] = _classic;
        api.answers.addAll([
          TimeoutException('lost'),
          const SocketException('lost'),
          _answer(503, 'server_error'),
        ]);
        expect(await renewal().current(_classic, upgrade: true), _classic);
        expect(api.sent, hasLength(3));
        expect(waits, [const Duration(seconds: 1), const Duration(seconds: 3)]);
        expect(stored()!.pending!.requestId, api.sent.first.requestId);

        // A new process resumes the stored request before anything else.
        now = now.add(const Duration(minutes: 1));
        api.answers.add(
          _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
        );
        expect(await renewal().accessToken(), _access1);
        expect(api.sent, hasLength(4));
        for (final request in api.sent) {
          expect(request.upgrade, isTrue);
          expect(request.token, _classic);
          expect(request.requestId, api.sent.first.requestId);
        }
        expect(stored()!.pending, isNull);
      },
    );

    test(
      '409 session_upgrade_conflict rereads storage, then stays classic',
      () async {
        disk['access_token'] = _classic;
        api.answers.add(_answer(409, 'session_upgrade_conflict'));
        final sessions = renewal();
        expect(await sessions.current(_classic, upgrade: true), _classic);
        expect(disk.containsKey(_record), isFalse);
        expect(disk['access_token'], _classic);
        expect(await sessions.current(_classic, upgrade: true), _classic);
        expect(api.sent, hasLength(1));
        // A later 401 with that token goes to the sign-in-again flow.
        expect(await sessions.retryToken(_classic), isNull);
      },
    );

    test(
      '409 session_upgrade_conflict adopts a pair stored meanwhile',
      () async {
        disk['access_token'] = _classic;
        final elsewhere = _pair(
          _access2,
          _refresh2,
          now.add(const Duration(hours: 1)),
        );
        final answered = Completer<Object>();
        api.answers.add(answered.future);
        final result = renewal().current(_classic, upgrade: true);
        await pumpEventQueue();
        storeRenewable(elsewhere);
        answered.complete(_answer(409, 'session_upgrade_conflict'));
        expect(await result, _access2);
        expect(stored()!.tokens!.refreshToken, _refresh2);
      },
    );

    test(
      '401 rereads storage, then leaves sign-in again to the account call',
      () async {
        disk['access_token'] = _classic;
        api.answers.add(_answer(401, 'unauthorized'));
        final sessions = renewal();
        expect(await sessions.current(_classic, upgrade: true), _classic);
        // The refused request is never sent again in this run.
        expect(await sessions.accessToken(), _classic);
        expect(await sessions.retryToken(_classic), isNull);
        expect(api.sent, hasLength(1));
      },
    );
  });

  group('refresh', () {
    test(
      'renews before a call when access expires within five minutes',
      () async {
        storeRenewable(
          _pair(_access1, _refresh1, now.add(const Duration(minutes: 6))),
        );
        final sessions = renewal();
        expect(await sessions.accessToken(), _access1);
        expect(api.sent, isEmpty);

        now = now.add(const Duration(minutes: 1, seconds: 1));
        api.answers.add(
          _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
        );
        expect(await sessions.accessToken(), _access2);
        final request = api.sent.single;
        expect(request.upgrade, isFalse);
        expect(request.token, _refresh1);
        expect(
          RenewableSession.decode(request.storedBefore!).pending!.token,
          _refresh1,
        );
        expect(stored()!.pending, isNull);
        expect(stored()!.tokens!.refreshToken, _refresh2);
      },
    );

    test('concurrent callers share one renewal', () async {
      storeRenewable(_pair(_access1, _refresh1, now));
      final answered = Completer<Object>();
      api.answers.add(answered.future);
      final sessions = renewal();
      final tokens = Future.wait([
        sessions.accessToken(),
        sessions.accessToken(),
        sessions.current(_access1),
      ]);
      await pumpEventQueue();
      answered.complete(
        _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
      );
      expect(await tokens, [_access2, _access2, _access2]);
      expect(api.sent, hasLength(1));
    });

    test(
      '409 session_transition, 429 and 5xx are retried identically',
      () async {
        storeRenewable(_pair(_access1, _refresh1, now));
        api.answers.addAll([
          _answer(409, 'session_transition'),
          _answer(429, 'rate_limited', retryAfter: 7),
          _pair(_access2, _refresh2, now.add(const Duration(hours: 2))),
        ]);
        expect(await renewal().accessToken(), _access2);
        expect(waits, [const Duration(seconds: 1), const Duration(seconds: 7)]);
        expect(
          api.sent.map((request) => request.requestId).toSet(),
          hasLength(1),
        );
        expect(api.sent.map((request) => request.token).toSet(), {_refresh1});
      },
    );

    test(
      'Retry-After is honoured across calls and the session is kept',
      () async {
        storeRenewable(_pair(_access1, _refresh1, now));
        api.answers.add(_answer(503, 'server_error', retryAfter: 120));
        final sessions = renewal();
        // The expired access is kept: the next account call decides.
        expect(await sessions.accessToken(), _access1);
        expect(waits, isEmpty);
        // Before Retry-After nothing is sent, and a 401 is a temporary failure.
        await expectLater(
          sessions.retryToken(_access1),
          throwsA(
            isA<ApiException>().having((e) => e.statusCode, 'status', 503),
          ),
        );
        expect(api.sent, hasLength(1));
        expect(disk.containsKey(_record), isTrue);

        now = now.add(const Duration(seconds: 120));
        api.answers.add(
          _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
        );
        expect(await sessions.retryToken(_access1), _access2);
        expect(api.sent, hasLength(2));
        expect(api.sent.last.requestId, api.sent.first.requestId);
      },
    );

    test('a restored access already expired is renewed at once', () async {
      final restoredExpiry = now.subtract(const Duration(minutes: 1));
      storeRenewable(
        _pair(_access1, _refresh1, now.subtract(const Duration(hours: 2))),
        pending: PendingSessionRequest(
          upgrade: false,
          token: _refresh1,
          requestId: 'p' * 43,
        ),
      );
      api.answers.addAll([
        _pair(_access2, _refresh2, restoredExpiry),
        _pair(_access3, _refresh3, now.add(const Duration(hours: 1))),
      ]);
      expect(await renewal().accessToken(), _access3);
      expect(api.sent, hasLength(2));
      expect(api.sent[0].token, _refresh1);
      expect(api.sent[0].requestId, 'p' * 43);
      expect(api.sent[1].token, _refresh2);
      expect(api.sent[1].requestId, isNot('p' * 43));
      expect(stored()!.tokens!.refreshToken, _refresh3);
    });

    test('401 adopts a pair another instance stored, else refuses', () async {
      storeRenewable(_pair(_access1, _refresh1, now));
      final answered = Completer<Object>();
      api.answers.add(answered.future);
      final sessions = renewal();
      final result = sessions.accessToken();
      await pumpEventQueue();
      storeRenewable(
        _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
      );
      answered.complete(_answer(401, 'unauthorized'));
      expect(await result, _access2);

      now = now.add(const Duration(hours: 1));
      api.answers.add(_answer(401, 'unauthorized'));
      expect(await sessions.accessToken(), _access2);
      // Refused for good: no new request ID for that refresh token, and the
      // next 401 goes to the sign-in-again flow.
      expect(await sessions.retryToken(_access2), isNull);
      expect(api.sent, hasLength(2));
    });
  });

  group('401 on an account route', () {
    test('retries once with a renewed token, even when the local clock does '
        'not call the access due', () async {
      storeRenewable(
        _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
      );
      final sessions = renewal();
      // A token that is not the stored session's (a sign-in in progress).
      expect(await sessions.retryToken(_access3), isNull);
      expect(api.sent, isEmpty);

      // The server expired the access before the local clock says so (a
      // clock running behind): one renewal, one retry.
      api.answers.add(
        _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
      );
      expect(await sessions.retryToken(_access1), _access2);
      // A call still carrying the replaced token retries with the new one,
      // without another renewal.
      expect(await sessions.retryToken(_access1), _access2);
      expect(api.sent, hasLength(1));

      // A session the server revoked: its renewal is refused, and the 401
      // goes to the sign-in-again flow.
      api.answers.add(_answer(401, 'unauthorized'));
      expect(await sessions.retryToken(_access2), isNull);
      expect(api.sent, hasLength(2));
    });

    test('concurrent 401s for one token share one renewal', () async {
      storeRenewable(
        _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
      );
      api.answers.add(
        _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
      );
      final sessions = renewal();
      final results = await Future.wait([
        sessions.retryToken(_access1),
        sessions.retryToken(_access1),
      ]);
      expect(results, [_access2, _access2]);
      expect(api.sent, hasLength(1));
    });

    test('a restored access already expired is never handed out when its '
        'renewal fails', () async {
      storeRenewable(
        _pair(_access1, _refresh1, now.subtract(const Duration(hours: 2))),
        pending: PendingSessionRequest(
          upgrade: false,
          token: _refresh1,
          requestId: 'p' * 43,
        ),
      );
      api.answers.addAll([
        _pair(_access2, _refresh2, now.subtract(const Duration(minutes: 1))),
        _answer(503, 'server_error'),
        _answer(503, 'server_error'),
        _answer(503, 'server_error'),
      ]);
      await expectLater(
        renewal().retryToken(_access1),
        throwsA(isA<ApiException>()),
      );
      // The restored pair is stored, and its renewal waits as it is.
      expect(stored()!.tokens!.refreshToken, _refresh2);
      expect(stored()!.pending!.token, _refresh2);
    });
  });

  group('clock and storage', () {
    test('a fresh renewal is never followed by another, even when the clock '
        'runs ahead', () async {
      storeRenewable(_pair(_access1, _refresh1, now));
      // Inside the margin by this clock: a clock running ahead of the server.
      api.answers.add(
        _pair(_access2, _refresh2, now.add(const Duration(minutes: 2))),
      );
      expect(await renewal().accessToken(), _access2);
      expect(api.sent, hasLength(1));
      expect(stored()!.pending, isNull);
    });

    test('a request that cannot be stored is not sent, and the session in '
        'use stays', () async {
      disk['access_token'] = _classic;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(_channel, (call) async {
            final key = call.arguments['key'] as String;
            switch (call.method) {
              case 'read':
                return disk[key];
              case 'write':
                if (key == _record) {
                  throw PlatformException(code: 'secure_store_write_failed');
                }
                disk[key] = call.arguments['value'] as String;
              case 'delete':
                disk.remove(key);
            }
            return null;
          });
      expect(await renewal().current(_classic, upgrade: true), _classic);
      expect(api.sent, isEmpty);
      expect(disk.containsKey(_record), isFalse);
      expect(disk['access_token'], _classic);
    });
  });

  group('sign-out', () {
    test(
      'ends the server session with the refresh token, best effort',
      () async {
        disk['access_token'] = _classic;
        storeRenewable(
          _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
        );
        api.logoutFailure = const SocketException('unreachable');
        await renewal().signOut();
        expect(api.logouts, [_refresh1]);
        expect(disk, isEmpty);
      },
    );

    test('a classic session is only removed locally', () async {
      disk['access_token'] = _classic;
      await renewal().signOut();
      expect(api.logouts, isEmpty);
      expect(disk, isEmpty);
    });

    test('waits for a renewal in flight and uses its result', () async {
      storeRenewable(_pair(_access1, _refresh1, now));
      final answered = Completer<Object>();
      api.answers.add(answered.future);
      final sessions = renewal();
      final renewing = sessions.accessToken();
      await pumpEventQueue();
      final signingOut = sessions.signOut();
      await pumpEventQueue();
      expect(api.logouts, isEmpty);
      answered.complete(
        _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
      );
      await renewing;
      await signingOut;
      expect(api.logouts, [_refresh2]);
      expect(disk, isEmpty);
    });
  });

  test(
    'the API client sends the contract and keeps secrets out of traces',
    () async {
      // The test binding answers every HttpClient request with 400; this
      // client talks to the loopback server below.
      final overrides = HttpOverrides.current;
      HttpOverrides.global = null;
      addTearDown(() => HttpOverrides.global = overrides);
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final client = ApiClient(
        baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
      );
      final seen =
          <({String path, String? bearer, String body, HttpHeaders headers})>[];
      var refreshAnswers = 0;
      server.listen((request) async {
        final body = await utf8.decoder.bind(request).join();
        final bearer = request.headers.value(HttpHeaders.authorizationHeader);
        seen.add((
          path: request.uri.path,
          bearer: bearer,
          body: body,
          headers: request.headers,
        ));
        final response = request.response
          ..headers.set(HttpHeaders.cacheControlHeader, 'no-store');
        switch (request.uri.path) {
          case '/v1/me' when bearer == 'Bearer $_access2':
            response.write(jsonEncode({'user_id': 'synthetic-user'}));
          case '/v1/me':
            response.statusCode = 401;
            response.write(jsonEncode({'error': 'unauthorized'}));
          case '/v1/auth/session/refresh' when refreshAnswers++ == 0:
            response.statusCode = 429;
            response.headers.set(HttpHeaders.retryAfterHeader, '2');
            response.write(jsonEncode({'error': 'rate_limited'}));
          case '/v1/auth/session/refresh':
            response.write(
              jsonEncode(
                _pair(
                  _access2,
                  _refresh2,
                  now.add(const Duration(hours: 1)),
                ).toJson(),
              ),
            );
          case '/v1/auth/logout':
            response.statusCode = 204;
        }
        await response.close();
      });
      addTearDown(() async {
        client.close();
        await server.close(force: true);
      });
      storeRenewable(
        _pair(_access1, _refresh1, now.subtract(const Duration(seconds: 1))),
      );
      final sessions = renewal(using: client);
      client.retryTokenAfterUnauthorized = sessions.retryToken;
      final firstLine = DiagnosticLog.recentLines.length;

      expect((await client.me(_access1)).userId, 'synthetic-user');
      await sessions.signOut();

      expect(seen.map((request) => request.path), [
        '/v1/me',
        '/v1/auth/session/refresh',
        '/v1/auth/session/refresh',
        '/v1/me',
        '/v1/auth/logout',
      ]);
      final requestId =
          (jsonDecode(seen[1].body) as Map)['request_id'] as String;
      expect(requestId, matches(_requestId));
      expect(seen[1].bearer, 'Bearer $_refresh1');
      expect(seen[2].bearer, 'Bearer $_refresh1');
      expect(jsonDecode(seen[2].body), {'request_id': requestId});
      expect(waits, [const Duration(seconds: 2)]);
      expect(seen[3].bearer, 'Bearer $_access2');
      expect(seen[4].bearer, 'Bearer $_refresh2');
      expect(seen[4].body, isEmpty);
      seen[4].headers.forEach(
        (name, _) => expect(name, isNot(contains('context'))),
      );
      expect(disk, isEmpty);

      final trace = DiagnosticLog.recentLines.skip(firstLine).join('\n');
      expect(trace, contains('area=api_request'));
      for (final secret in [
        _access1,
        _access2,
        _refresh1,
        _refresh2,
        requestId,
        'r' * 43,
      ]) {
        expect(trace, isNot(contains(secret)));
      }
    },
  );

  group('controller', () {
    late _ControllerApi controllerApi;
    late _ControllerStore store;

    AppController make() {
      final app = AppController(
        api: controllerApi,
        store: store,
        wireguard: _WireGuard(),
        openVpn: f.ProbeOpenVpn(),
        window: f.ProbeWindow(),
        updates: _NoUpdates(),
        now: () => now,
      );
      addTearDown(app.dispose);
      return app;
    }

    setUp(() {
      controllerApi = _ControllerApi()..disk = disk;
      store = _ControllerStore();
    });

    test(
      'startup converts the saved classic session before checking it',
      () async {
        disk['access_token'] = _classic;
        controllerApi.answers.add(
          _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
        );
        final firstLine = DiagnosticLog.recentLines.length;
        final app = make();
        await app.initialize();
        expect(controllerApi.sent.single.upgrade, isTrue);
        expect(controllerApi.sent.single.token, _classic);
        expect(controllerApi.meTokens, [_access1]);
        expect(app.profile, same(f.account));
        expect(stored()!.tokens!.accessToken, _access1);
        final trace = DiagnosticLog.recentLines.skip(firstLine).join('\n');
        for (final secret in [
          _classic,
          _access1,
          _refresh1,
          controllerApi.sent.single.requestId,
        ]) {
          expect(trace, isNot(contains(secret)));
        }
      },
    );

    test('sign-in converts the new session once it is complete', () async {
      controllerApi.answers.add(
        _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
      );
      final app = make()..isInitialized = true;
      expect(
        await app.signIn(email: 'synthetic@example.invalid', password: 'x'),
        isTrue,
      );
      // The sign-in itself used the classic session it stored.
      expect(controllerApi.meTokens, [_classic]);
      await pumpEventQueue();
      expect(controllerApi.sent.single.token, _classic);
      expect(stored()!.tokens!.accessToken, _access1);
    });

    test('an account call and the foreground renew a due session', () async {
      storeRenewable(
        _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
      );
      final app = make()
        ..profile = f.account
        ..isInitialized = true;
      app.renewSessionIfDue();
      await pumpEventQueue();
      expect(controllerApi.sent, isEmpty);

      now = now.add(const Duration(minutes: 56));
      controllerApi.answers.add(
        _pair(_access2, _refresh2, now.add(const Duration(hours: 1))),
      );
      app.renewSessionIfDue();
      await pumpEventQueue();
      expect(controllerApi.sent.single.token, _refresh1);
      expect(stored()!.tokens!.accessToken, _access2);
      // The API client asks the same place after a 401.
      expect(
        await controllerApi.retryTokenAfterUnauthorized!(_access1),
        _access2,
      );
    });

    test(
      'sign-out ends the renewable session even when the server fails',
      () async {
        storeRenewable(
          _pair(_access1, _refresh1, now.add(const Duration(hours: 1))),
        );
        controllerApi.logoutFailure = _answer(503, 'server_error');
        final app = make()
          ..profile = f.account
          ..isInitialized = true;
        await app.signOut();
        expect(controllerApi.logouts, [_refresh1]);
        expect(app.profile, isNull);
        expect(app.errorMessage, isNull);
        expect(disk.containsKey(_record), isFalse);
        expect(disk.containsKey('access_token'), isFalse);
      },
    );
  });
}
