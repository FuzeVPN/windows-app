// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';

const _code = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const _verifier = 'synthetic-proof-abcdefghijklmnopqrstuvwxyz01';
final _redirect = Uri.parse('http://127.0.0.1:49152/auth/callback');

void main() {
  Future<({ApiClient api, List<Map<String, Object?>> requests})> server({
    int status = 201,
    Object? body = const {
      'access_token': 'synthetic-browser-session',
      'expires_at': '2030-01-01T00:00:00Z',
    },
  }) async {
    final listener = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final requests = <Map<String, Object?>>[];
    listener.listen((request) async {
      requests.add({
        'method': request.method,
        'path': request.uri.path,
        'authorization': request.headers.value(HttpHeaders.authorizationHeader),
        'cookie': request.headers.value(HttpHeaders.cookieHeader),
        'body': jsonDecode(await utf8.decoder.bind(request).join()),
      });
      request.response.statusCode = status;
      request.response.headers.contentType = ContentType.json;
      request.response.write(jsonEncode(body));
      await request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('http://127.0.0.1:${listener.port}'),
    );
    addTearDown(api.close);
    addTearDown(() => listener.close(force: true));
    return (api: api, requests: requests);
  }

  test(
    'desktop exchange has exact public contract and no bearer or cookie',
    () async {
      final fixture = await server();
      final traceStart = DiagnosticLog.recentLines.length;
      final session = await fixture.api.exchangeWindowsBrowserCode(
        code: _code,
        redirectUri: _redirect,
        codeVerifier: _verifier,
      );
      expect(session.accessToken, 'synthetic-browser-session');
      expect(fixture.requests, [
        {
          'method': 'POST',
          'path': '/v1/auth/desktop/token',
          'authorization': null,
          'cookie': null,
          'body': {
            'client_id': 'fuzevpn-windows',
            'code': _code,
            'redirect_uri': _redirect.toString(),
            'code_verifier': _verifier,
          },
        },
      ]);
      final trace = DiagnosticLog.recentLines.skip(traceStart).join('\n');
      expect(trace, contains('code=browser_auth_token'));
      for (final secret in [_code, _verifier, session.accessToken, '49152']) {
        expect(trace, isNot(contains(secret)));
      }
    },
  );

  test(
    'consumed grant remains an explicit API refusal without retry',
    () async {
      final fixture = await server(
        status: 400,
        body: {'error': 'desktop_auth_invalid_grant'},
      );
      await expectLater(
        fixture.api.exchangeWindowsBrowserCode(
          code: _code,
          redirectUri: _redirect,
          codeVerifier: _verifier,
        ),
        throwsA(
          isA<ApiException>()
              .having((e) => e.errorCode, 'code', 'desktop_auth_invalid_grant')
              .having((e) => e.observedHttpStatus, 'HTTP', 400)
              .having(
                (e) => e.diagnosticFailureCode,
                'trace',
                'desktop_auth_invalid_grant',
              ),
        ),
      );
      expect(fixture.requests, hasLength(1));
    },
  );

  for (final status in [200, 202, 204]) {
    test('exchange rejects unexpected successful status $status', () async {
      final fixture = await server(status: status);
      await expectLater(
        fixture.api.exchangeWindowsBrowserCode(
          code: _code,
          redirectUri: _redirect,
          codeVerifier: _verifier,
        ),
        throwsA(
          isA<ApiException>()
              .having(
                (e) => e.errorCode,
                'code',
                'browser_auth_invalid_response',
              )
              .having((e) => e.observedHttpStatus, 'HTTP', status),
        ),
      );
      expect(fixture.requests, hasLength(1));
    });
  }

  final invalidBodies = <Object?>[
    {},
    {'access_token': '', 'expires_at': '2030-01-01T00:00:00Z'},
    {'access_token': 'synthetic\ntoken', 'expires_at': '2030-01-01T00:00:00Z'},
    {'access_token': 'synthetic-token'},
    {'access_token': 'synthetic-token', 'expires_at': 'not-a-date'},
    {'access_token': 42, 'expires_at': '2030-01-01T00:00:00Z'},
    [],
    null,
  ];
  for (var i = 0; i < invalidBodies.length; i++) {
    test('exchange rejects malformed session body $i', () async {
      final fixture = await server(body: invalidBodies[i]);
      await expectLater(
        fixture.api.exchangeWindowsBrowserCode(
          code: _code,
          redirectUri: _redirect,
          codeVerifier: _verifier,
        ),
        throwsA(
          isA<ApiException>().having(
            (e) => e.errorCode,
            'code',
            'browser_auth_invalid_response',
          ),
        ),
      );
    });
  }

  test(
    'invalid proof or loopback destination never starts an HTTP request',
    () async {
      final fixture = await server();
      for (final uri in [
        'http://localhost:49152/auth/callback',
        'http://127.0.0.2:49152/auth/callback',
        'http://127.0.0.1:80/auth/callback',
        'http://127.0.0.1:49152/other',
        'http://127.0.0.1:49152/auth/callback?',
        'http://127.0.0.1:49152/auth/callback#',
        'http://user@127.0.0.1:49152/auth/callback',
      ]) {
        await expectLater(
          fixture.api.exchangeWindowsBrowserCode(
            code: _code,
            redirectUri: Uri.parse(uri),
            codeVerifier: _verifier,
          ),
          throwsA(
            isA<ApiException>().having(
              (e) => e.errorCode,
              'code',
              'desktop_auth_invalid_request',
            ),
          ),
        );
      }
      for (final badCode in [
        '$_code=',
        '${_code}B',
        '${_code.substring(1)}B',
      ]) {
        await expectLater(
          fixture.api.exchangeWindowsBrowserCode(
            code: badCode,
            redirectUri: _redirect,
            codeVerifier: _verifier,
          ),
          throwsA(isA<ApiException>()),
        );
      }
      await expectLater(
        fixture.api.exchangeWindowsBrowserCode(
          code: _code,
          redirectUri: _redirect,
          codeVerifier: '$_verifier\n',
        ),
        throwsA(isA<ApiException>()),
      );
      expect(fixture.requests, isEmpty);
    },
  );
}
