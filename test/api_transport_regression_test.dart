// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';

void main() {
  for (final browser in [false, true]) {
    final method = browser ? 'browser exchange' : 'email login';
    test('$method accepts printable tokens at both size boundaries', () async {
      Object? token;
      final fixture = await _sessionServer(() => token);
      addTearDown(fixture.close);
      for (final value in ['!', '~', List.filled(8192, 't').join()]) {
        token = value;
        expect((await _authenticate(fixture.api, browser)).accessToken, value);
      }
    });
    test('$method rejects malformed and oversized session tokens', () async {
      Object? token;
      final fixture = await _sessionServer(() => token);
      addTearDown(fixture.close);
      for (final value in [
        null,
        42,
        '',
        'synthetic token',
        'synthetic\ntoken',
        'synthetic\rtoken',
        'synthetic\u0000token',
        'synthetic\u007ftoken',
        'synthetic-é',
        List.filled(8193, 't').join(),
      ]) {
        token = value;
        await expectLater(
          _authenticate(fixture.api, browser),
          browser
              ? throwsA(
                  isA<ApiException>().having(
                    (error) => error.errorCode,
                    'code',
                    'browser_auth_invalid_response',
                  ),
                )
              : throwsFormatException,
        );
      }
    });
  }

  for (final stage in _FailureStage.values) {
    test(
      'aborts an opened request after any failure during ${stage.name}',
      () async {
        for (final error in [
          const FormatException('synthetic'),
          StateError('synthetic'),
          const SocketException('synthetic'),
          const ApiException(statusCode: 502, errorCode: 'synthetic_failure'),
        ]) {
          final request = _FailingRequest(stage, error);
          final api = ApiClient(
            client: _FailingClient(request),
            baseUri: Uri.parse('http://127.0.0.1'),
          );
          addTearDown(api.close);
          await expectLater(
            api.login(
              email: 'synthetic@example.invalid',
              password: 'synthetic',
            ),
            throwsA(same(error)),
          );
          expect(request.aborted, isTrue);
        }
      },
    );
  }

  test(
    'invalid bearer closes the TCP transport without sending HTTP',
    () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(server.close);
      final peerClosed = Completer<void>();
      var bytesSeen = 0;
      server.listen((socket) {
        addTearDown(socket.destroy);
        var responded = false;
        socket.listen(
          (data) async {
            bytesSeen += data.length;
            if (responded) return;
            responded = true;
            const body = '{"locations":[]}';
            socket.write(
              'HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n'
              'Connection: close\r\n\r\n$body',
            );
            await socket.close();
          },
          onDone: () {
            if (!peerClosed.isCompleted) peerClosed.complete();
          },
          onError: (Object _) {
            if (!peerClosed.isCompleted) peerClosed.complete();
          },
        );
      });
      final api = ApiClient(
        baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
        requestTimeout: const Duration(seconds: 2),
      );
      addTearDown(api.close);
      await expectLater(api.me('synthetic\ninvalid'), throwsFormatException);
      await peerClosed.future.timeout(const Duration(seconds: 1));
      expect(bytesSeen, 0);
      expect(await api.locations(), isEmpty);
    },
  );
}

Future<AuthSession> _authenticate(ApiClient api, bool browser) => browser
    ? api.exchangeWindowsBrowserCode(
        code: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        redirectUri: Uri.parse('http://127.0.0.1:49152/auth/callback'),
        codeVerifier: 'synthetic-proof-abcdefghijklmnopqrstuvwxyz01',
      )
    : api.login(email: 'synthetic@example.invalid', password: 'synthetic');

Future<({ApiClient api, Future<void> Function() close})> _sessionServer(
  Object? Function() token,
) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((request) async {
    await request.drain<void>();
    request.response
      ..statusCode = request.uri.path == '/v1/auth/desktop/token' ? 201 : 200
      ..headers.contentType = ContentType.json
      ..write(
        jsonEncode({
          'access_token': token(),
          'expires_at': '2030-01-01T00:00:00Z',
        }),
      );
    await request.response.close();
  });
  final api = ApiClient(baseUri: Uri.parse('http://127.0.0.1:${server.port}'));
  return (
    api: api,
    close: () async {
      api.close();
      await server.close(force: true);
    },
  );
}

enum _FailureStage { headers, body, synchronousSend, asynchronousSend }

class _FailingClient implements HttpClient {
  _FailingClient(this.request);
  final HttpClientRequest request;
  @override
  set connectionTimeout(Duration? value) {}
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) async => request;
  @override
  void close({bool force = false}) {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FailingRequest implements HttpClientRequest {
  _FailingRequest(this.stage, this.error);
  final _FailureStage stage;
  final Object error;
  bool aborted = false;
  @override
  final headers = _RequestHeaders();
  @override
  set followRedirects(bool value) {
    if (stage == _FailureStage.headers) throw error;
  }

  @override
  void write(Object? value) {
    if (stage == _FailureStage.body) throw error;
  }

  @override
  Future<HttpClientResponse> close() {
    if (stage == _FailureStage.synchronousSend) throw error;
    return Future.error(error);
  }

  @override
  void abort([Object? exception, StackTrace? stackTrace]) => aborted = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _RequestHeaders implements HttpHeaders {
  @override
  set contentType(ContentType? value) {}
  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
