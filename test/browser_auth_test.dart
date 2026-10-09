// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/browser_auth.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';

String _secret(int value) =>
    base64Url.encode(List<int>.filled(32, value)).replaceAll('=', '');

Uri _callback(BrowserAuthAttempt attempt, {String? code, String? state}) =>
    attempt.redirectUri.replace(
      queryParameters: {
        'code': code ?? _secret(7),
        'state': state ?? attempt.state,
      },
    );

class _Reply {
  const _Reply(this.status, this.body, this.headers);

  final int status;
  final String body;
  final Map<String, String?> headers;
}

Future<_Reply> _request(Uri uri, {String method = 'GET', String? host}) async {
  final client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 2)
    ..findProxy = (_) => 'DIRECT';
  try {
    final request = await client.openUrl(method, uri);
    if (host != null) request.headers.set(HttpHeaders.hostHeader, host);
    final response = await request.close();
    final headers = {
      for (final name in [
        'cache-control',
        'referrer-policy',
        'content-security-policy',
        'x-content-type-options',
        'content-type',
        'allow',
      ])
        name: response.headers.value(name),
    };
    return _Reply(
      response.statusCode,
      await response.transform(utf8.decoder).join(),
      headers,
    );
  } finally {
    client.close(force: true);
  }
}

Matcher _failure(String code) =>
    isA<BrowserAuthException>().having((error) => error.code, 'code', code);

Future<void> _closed(BrowserAuthAttempt attempt) async {
  await expectLater(
    Socket.connect(
      InternetAddress.loopbackIPv4,
      attempt.redirectUri.port,
      timeout: const Duration(seconds: 1),
    ),
    throwsA(isA<SocketException>()),
  );
}

void main() {
  test('S256 matches the RFC 7636 ASCII verifier vector', () {
    expect(
      BrowserAuth.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
    for (final invalid in ['short', '${'A' * 43} ', 'é' * 43]) {
      expect(() => BrowserAuth.pkceChallenge(invalid), throwsArgumentError);
    }
  });

  test(
    'starts exclusively on IPv4 loopback with independent secure proofs',
    () async {
      final first = await BrowserAuth().start();
      final second = await BrowserAuth().start();
      addTearDown(first.dispose);
      addTearDown(second.dispose);
      expect(first.redirectUri.scheme, 'http');
      expect(first.redirectUri.host, '127.0.0.1');
      expect(first.redirectUri.port, greaterThan(0));
      expect(first.redirectUri.port, isNot(second.redirectUri.port));
      expect(first.redirectUri.path, BrowserAuth.callbackPath);
      expect(first.redirectUri.query, isEmpty);
      expect(first.state, isNot(second.state));
      expect(first.state, isNot(first.codeVerifier));
      for (final proof in [first.state, first.codeVerifier]) {
        expect(proof.length, 43);
        expect(proof, matches(RegExp(r'^[A-Za-z0-9_-]{43}$')));
        expect(base64Url.decode('$proof=').length, 32);
      }
      expect(
        first.codeChallenge,
        BrowserAuth.pkceChallenge(first.codeVerifier),
      );
      await expectLater(
        ServerSocket.bind(InternetAddress.loopbackIPv4, first.redirectUri.port),
        throwsA(isA<SocketException>()),
      );
    },
  );

  test('authorization URI contains only the public PKCE request', () async {
    final attempt = await BrowserAuth().start();
    addTearDown(attempt.dispose);
    final uri = attempt.authorizationUri(
      Uri.parse('https://app.fuzevpn.com/windows/connect'),
      'fuzevpn-windows',
    );
    expect(uri.scheme, 'https');
    expect(uri.host, 'app.fuzevpn.com');
    expect(uri.path, '/windows/connect');
    expect(uri.queryParameters, {
      'client_id': 'fuzevpn-windows',
      'redirect_uri': attempt.redirectUri.toString(),
      'state': attempt.state,
      'code_challenge': attempt.codeChallenge,
      'code_challenge_method': 'S256',
    });
    expect(uri.toString(), isNot(contains(attempt.codeVerifier)));
    expect(uri.queryParameters.keys, isNot(contains('code')));
    expect(uri.queryParameters.keys, isNot(contains('access_token')));
    for (final endpoint in [
      Uri.parse('/relative'),
      Uri.parse('file:///private'),
      Uri.parse('https://user:password@app.fuzevpn.com/connect'),
      Uri.parse('https://app.fuzevpn.com/connect?unapproved=private-value'),
      Uri.parse('https://app.fuzevpn.com/connect#fragment'),
    ]) {
      expect(
        () => attempt.authorizationUri(endpoint, 'fuzevpn-windows'),
        throwsArgumentError,
      );
    }
  });

  test(
    'valid callback returns one code, static secure page, and closes listener',
    () async {
      final attempt = await BrowserAuth().start();
      addTearDown(attempt.dispose);
      final logPosition = DiagnosticLog.recentLines.length;
      final code = _secret(8);
      final response = await _request(_callback(attempt, code: code));
      expect(response.status, HttpStatus.ok);
      expect(await attempt.callback, code);
      expect(response.body, contains('Autorisation reçue'));
      expect(response.body, contains('terminer la connexion'));
      for (final secret in [code, attempt.state, attempt.codeVerifier]) {
        expect(response.body, isNot(contains(secret)));
        expect(response.headers.values.join(), isNot(contains(secret)));
      }
      expect(response.headers['cache-control'], 'no-store');
      expect(response.headers['referrer-policy'], 'no-referrer');
      expect(response.headers['x-content-type-options'], 'nosniff');
      expect(
        response.headers['content-security-policy'],
        contains("default-src 'none'"),
      );
      expect(
        response.headers['content-security-policy'],
        contains("form-action 'none'"),
      );
      expect(
        response.headers['content-security-policy'],
        contains("frame-ancestors 'none'"),
      );
      expect(DiagnosticLog.recentLines.skip(logPosition), isEmpty);
      await _closed(attempt);
      await expectLater(
        _request(_callback(attempt, code: code)),
        throwsA(anyOf(isA<SocketException>(), isA<HttpException>())),
      );
      expect(await attempt.callback, code);
    },
  );

  final invalidQueries = <String, String Function(BrowserAuthAttempt)>{
    'missing state': (_) => 'code=${_secret(1)}',
    'missing code': (attempt) => 'state=${attempt.state}',
    'different state': (_) => 'code=${_secret(1)}&state=${_secret(2)}',
    'duplicate state': (attempt) =>
        'code=${_secret(1)}&state=${attempt.state}&state=${attempt.state}',
    'duplicate code': (attempt) =>
        'code=${_secret(1)}&code=${_secret(2)}&state=${attempt.state}',
    'padded code': (attempt) => 'code=${_secret(1)}%3D&state=${attempt.state}',
    'noncanonical code': (attempt) =>
        'code=${'A' * 42}B&state=${attempt.state}',
    'noncanonical state': (_) => 'code=${_secret(1)}&state=${'A' * 42}B',
    'extra parameter': (attempt) =>
        'code=${_secret(1)}&state=${attempt.state}&extra=private-secret',
    'unknown error': (attempt) => 'error=server_error&state=${attempt.state}',
    'denial with mismatched state': (_) =>
        'error=access_denied&state=${_secret(2)}',
    'code and error': (attempt) =>
        'code=${_secret(1)}&state=${attempt.state}&error=access_denied',
    'newline in code': (attempt) =>
        'code=${_secret(1)}%0A&state=${attempt.state}',
    'oversized query': (attempt) => 'code=${'A' * 2200}&state=${attempt.state}',
    'empty state': (_) => 'code=${_secret(1)}&state=',
    'invalid escaped state': (_) => 'code=${_secret(1)}&state=%25',
  };

  for (final entry in invalidQueries.entries) {
    test(
      '${entry.key} is rejected without consuming legitimate callback',
      () async {
        final attempt = await BrowserAuth().start();
        addTearDown(attempt.dispose);
        final rejected = await _request(
          attempt.redirectUri.replace(query: entry.value(attempt)),
        );
        expect(rejected.status, HttpStatus.badRequest);
        expect(rejected.body, isNot(contains('private-secret')));
        expect(rejected.body, isNot(contains(attempt.state)));
        final accepted = await _request(_callback(attempt));
        expect(accepted.status, HttpStatus.ok);
        expect(await attempt.callback, _secret(7));
        await _closed(attempt);
      },
    );
  }

  test(
    'POST, unexpected path and foreign Host cannot consume authorization',
    () async {
      final attempt = await BrowserAuth().start();
      addTearDown(attempt.dispose);
      final post = await _request(_callback(attempt), method: 'POST');
      expect(post.status, HttpStatus.methodNotAllowed);
      expect(post.headers['allow'], 'GET');
      final path = await _request(_callback(attempt).replace(path: '/other'));
      expect(path.status, HttpStatus.badRequest);
      final host = await _request(_callback(attempt), host: 'attacker.example');
      expect(host.status, HttpStatus.badRequest);
      final localhost = await _request(
        _callback(attempt),
        host: 'localhost:${attempt.redirectUri.port}',
      );
      expect(localhost.status, HttpStatus.badRequest);
      expect((await _request(_callback(attempt))).status, HttpStatus.ok);
      expect(await attempt.callback, _secret(7));
    },
  );

  test(
    'a second attempt cannot complete the first or exchange its code',
    () async {
      final first = await BrowserAuth().start();
      final second = await BrowserAuth().start();
      addTearDown(first.dispose);
      addTearDown(second.dispose);
      expect(
        (await _request(_callback(first, state: second.state))).status,
        HttpStatus.badRequest,
      );
      expect(
        (await _request(_callback(first, code: _secret(3)))).status,
        HttpStatus.ok,
      );
      expect(await first.callback, _secret(3));
      expect(
        (await _request(_callback(second, code: _secret(4)))).status,
        HttpStatus.ok,
      );
      expect(await second.callback, _secret(4));
    },
  );

  test('concurrent valid callbacks accept exactly one code', () async {
    final attempt = await BrowserAuth().start();
    addTearDown(attempt.dispose);
    Future<int> status(String code) async {
      try {
        return (await _request(_callback(attempt, code: code))).status;
      } on SocketException {
        return HttpStatus.gone;
      } on HttpException {
        return HttpStatus.gone;
      }
    }

    final outcomes = await Future.wait([
      status(_secret(3)),
      status(_secret(4)),
    ]);
    expect(outcomes.where((value) => value == HttpStatus.ok).length, 1);
    expect(outcomes.where((value) => value == HttpStatus.gone).length, 1);
    expect(await attempt.callback, anyOf(_secret(3), _secret(4)));
    await _closed(attempt);
  });

  test(
    'explicit access denial with correct state closes the attempt',
    () async {
      final attempt = await BrowserAuth().start();
      addTearDown(attempt.dispose);
      final callbackState = attempt.state;
      final failed = expectLater(
        attempt.callback,
        throwsA(_failure('browser_auth_denied')),
      );
      final response = await _request(
        attempt.redirectUri.replace(
          queryParameters: {'error': 'access_denied', 'state': attempt.state},
        ),
      );
      expect(response.status, HttpStatus.ok);
      expect(response.body, contains('Autorisation refusée'));
      expect(response.body, isNot(contains(callbackState)));
      await failed;
      await _closed(attempt);
    },
  );

  for (final dispose in [false, true]) {
    test(
      '${dispose ? 'dispose' : 'cancel'} fails callback once and releases port',
      () async {
        final attempt = await BrowserAuth().start();
        final failed = expectLater(
          attempt.callback,
          throwsA(_failure('browser_auth_canceled')),
        );
        if (dispose) {
          await attempt.dispose();
        } else {
          await attempt.cancel();
        }
        await failed;
        await attempt.cancel();
        await attempt.dispose();
        await _closed(attempt);
      },
    );
  }

  test(
    'timeout closes the callback even when no browser request arrives',
    () async {
      final attempt = await BrowserAuth(
        timeout: const Duration(milliseconds: 80),
      ).start();
      await expectLater(
        attempt.callback,
        throwsA(_failure('browser_auth_timeout')),
      );
      await _closed(attempt);
      await attempt.dispose();
    },
  );

  test(
    'invalid callbacks do not extend the global authorization deadline',
    () async {
      final attempt = await BrowserAuth(
        timeout: const Duration(milliseconds: 120),
      ).start();
      final failed = expectLater(
        attempt.callback,
        throwsA(_failure('browser_auth_timeout')),
      );
      expect(
        (await _request(_callback(attempt, state: _secret(3)))).status,
        HttpStatus.badRequest,
      );
      await failed;
      await _closed(attempt);
    },
  );

  test(
    'cancellation is safe before anyone listens to the callback future',
    () async {
      final attempt = await BrowserAuth().start();
      await attempt.cancel();
      await Future<void>.delayed(Duration.zero);
      await expectLater(
        attempt.callback,
        throwsA(_failure('browser_auth_canceled')),
      );
      await _closed(attempt);
    },
  );

  test(
    'proofs remain available for exchange and are discarded on final dispose',
    () async {
      final attempt = await BrowserAuth().start();
      final verifier = attempt.codeVerifier;
      final state = attempt.state;
      expect((await _request(_callback(attempt))).status, HttpStatus.ok);
      expect(await attempt.callback, _secret(7));
      expect(attempt.codeVerifier, verifier);
      expect(attempt.state, state);
      await attempt.dispose();
      expect(
        () => attempt.codeVerifier,
        throwsA(_failure('browser_auth_canceled')),
      );
      expect(() => attempt.state, throwsA(_failure('browser_auth_canceled')));
      expect(
        () => attempt.codeChallenge,
        throwsA(_failure('browser_auth_canceled')),
      );
    },
  );

  test(
    'public failures expose fixed diagnostic references without raw causes',
    () {
      final failures = [
        BrowserAuthException.canceled,
        BrowserAuthException.timeout,
        BrowserAuthException.denied,
        BrowserAuthException.callbackUnavailable,
        BrowserAuthException.launchFailed,
        BrowserAuthException.invalidResponse,
      ];
      expect(failures.map((error) => error.code).toSet().length, 6);
      for (final error in failures) {
        expect(error.diagnosticFailureCode, error.code);
        expect(error.diagnosticWindowsError, isNull);
        expect(error.diagnosticHttpStatus, isNull);
        expect(error.toString(), 'BrowserAuthException(${error.code})');
      }
    },
  );
}
