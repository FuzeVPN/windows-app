// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';

import 'diagnostic_log.dart';

/// Only fixed references are exposed. URLs, authorization codes, PKCE proofs
/// and operating-system messages never enter exception text or diagnostics.
class BrowserAuthException implements Exception, DiagnosticFailureDetails {
  const BrowserAuthException._(this.code);

  static const canceled = BrowserAuthException._('browser_auth_canceled');
  static const timeout = BrowserAuthException._('browser_auth_timeout');
  static const denied = BrowserAuthException._('browser_auth_denied');
  static const callbackUnavailable = BrowserAuthException._(
    'browser_auth_callback_unavailable',
  );
  static const launchFailed = BrowserAuthException._(
    'browser_auth_launch_failed',
  );
  static const invalidResponse = BrowserAuthException._(
    'browser_auth_invalid_response',
  );

  final String code;

  @override
  String get diagnosticFailureCode => code;

  @override
  int? get diagnosticWindowsError => null;

  @override
  int? get diagnosticHttpStatus => null;

  @override
  String toString() => 'BrowserAuthException($code)';
}

/// Reserves the callback before the caller opens the system browser. There is
/// no wildcard interface, fixed port, Windows URL protocol or privileged work.
class BrowserAuth {
  BrowserAuth({this.timeout = const Duration(minutes: 10)}) {
    if (timeout <= Duration.zero) {
      throw ArgumentError('Browser authorization timeout must be positive.');
    }
  }

  final Duration timeout;

  static const callbackPath = '/auth/callback';
  static final _verifierFormat = RegExp(r'^[A-Za-z0-9._~-]{43,128}$');

  /// RFC 7636 S256 hashes the ASCII verifier exactly as supplied.
  static String pkceChallenge(String verifier) {
    if (_verifierFormat.firstMatch(verifier)?.end != verifier.length) {
      throw ArgumentError('Invalid PKCE verifier format.');
    }
    return _base64Url(sha256.convert(ascii.encode(verifier)).bytes);
  }

  Future<BrowserAuthAttempt> start() async {
    final clock = Stopwatch()..start();
    final String state;
    final String verifier;
    try {
      final random = Random.secure();
      state = _randomSecret(random);
      verifier = _randomSecret(random);
    } catch (_) {
      throw const BrowserAuthException._('browser_auth_callback_unavailable');
    }
    var expired = false;
    final binding = HttpServer.bind(
      InternetAddress.loopbackIPv4,
      0,
      shared: false,
      backlog: 8,
    );
    // Future.timeout alone does not close a socket bound after the timeout.
    unawaited(
      binding.then<void>((lateServer) {
        if (expired) unawaited(lateServer.close(force: true));
      }, onError: (Object _, StackTrace _) {}),
    );
    try {
      final server = await binding.timeout(timeout);
      final remaining = timeout - clock.elapsed;
      if (remaining <= Duration.zero) {
        await server.close(force: true);
        throw const BrowserAuthException._('browser_auth_timeout');
      }
      if (server.port < 1024 || server.port > 65535) {
        await server.close(force: true);
        throw const BrowserAuthException._('browser_auth_callback_unavailable');
      }
      return BrowserAuthAttempt._(
        server,
        state,
        verifier,
        pkceChallenge(verifier),
        remaining,
      );
    } on TimeoutException {
      expired = true;
      throw const BrowserAuthException._('browser_auth_timeout');
    } on BrowserAuthException {
      rethrow;
    } catch (_) {
      throw const BrowserAuthException._('browser_auth_callback_unavailable');
    }
  }

  static String _randomSecret(Random random) =>
      _base64Url(List<int>.generate(32, (_) => random.nextInt(256)));

  static String _base64Url(List<int> bytes) =>
      base64Url.encode(bytes).replaceAll('=', '');
}

class BrowserAuthAttempt {
  BrowserAuthAttempt._(
    HttpServer server,
    this._state,
    this._codeVerifier,
    this._codeChallenge,
    Duration timeout,
  ) : _server = server,
      redirectUri = Uri(
        scheme: 'http',
        host: '127.0.0.1',
        port: server.port,
        path: BrowserAuth.callbackPath,
      ) {
    // Cancellation may occur while launchUrl is still pending. Attach an error
    // handler immediately; callers still receive the original failed future.
    unawaited(
      _callback.future.then<void>((_) {}, onError: (Object _, StackTrace _) {}),
    );
    _subscription = _server.listen(
      (request) => unawaited(_handle(request)),
      onError: (Object _, StackTrace _) => unawaited(
        _fail(
          const BrowserAuthException._('browser_auth_callback_unavailable'),
        ),
      ),
      onDone: () {
        if (!_settled) {
          unawaited(
            _fail(
              const BrowserAuthException._('browser_auth_callback_unavailable'),
            ),
          );
        }
      },
    );
    _timer = Timer(
      timeout,
      () => unawaited(
        _fail(const BrowserAuthException._('browser_auth_timeout')),
      ),
    );
  }

  final Uri redirectUri;
  String? _codeVerifier;
  String? _state;
  String? _codeChallenge;
  String get codeVerifier => _availableProof(_codeVerifier);
  String get state => _availableProof(_state);
  String get codeChallenge => _availableProof(_codeChallenge);
  final HttpServer _server;
  final Completer<String> _callback = Completer<String>();
  StreamSubscription<HttpRequest>? _subscription;
  Timer? _timer;
  bool _settled = false;
  Future<void>? _closing;

  Future<String> get callback => _callback.future;

  static String _availableProof(String? value) {
    if (value == null) {
      throw const BrowserAuthException._('browser_auth_canceled');
    }
    return value;
  }

  Uri authorizationUri(Uri endpoint, String clientId) {
    if (!endpoint.isAbsolute ||
        !const {'https', 'http'}.contains(endpoint.scheme) ||
        endpoint.host.isEmpty ||
        endpoint.userInfo.isNotEmpty ||
        endpoint.query.isNotEmpty ||
        endpoint.hasFragment ||
        clientId.isEmpty ||
        clientId.codeUnits.any((unit) => unit <= 32 || unit == 127)) {
      throw ArgumentError('Invalid browser authorization endpoint or client.');
    }
    return endpoint.replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri.toString(),
        'state': state,
        'code_challenge': codeChallenge,
        'code_challenge_method': 'S256',
      },
    );
  }

  Future<void> cancel() =>
      _fail(const BrowserAuthException._('browser_auth_canceled'));

  Future<void> dispose() => cancel();

  Future<void> _handle(HttpRequest request) async {
    if (_settled) {
      await _respond(request, HttpStatus.gone, _invalidPage);
      return;
    }
    try {
      if (request.method != 'GET') {
        request.response.headers.set(HttpHeaders.allowHeader, 'GET');
        await _respond(request, HttpStatus.methodNotAllowed, _invalidPage);
        return;
      }
      final uri = request.uri;
      if (uri.toString().length > 2048 ||
          uri.hasScheme ||
          uri.hasAuthority ||
          uri.hasFragment ||
          uri.path != redirectUri.path ||
          request.headers.value(HttpHeaders.hostHeader) !=
              '127.0.0.1:${redirectUri.port}' ||
          request.connectionInfo?.remoteAddress.address != '127.0.0.1') {
        await _respond(request, HttpStatus.badRequest, _invalidPage);
        return;
      }
      final parameters = uri.queryParametersAll;
      final callbackState = parameters['state'];
      if (parameters.length != 2 ||
          parameters.values.any((values) => values.length != 1) ||
          callbackState == null ||
          !_canonicalSecret(callbackState.single) ||
          !_sameState(callbackState.single)) {
        await _respond(request, HttpStatus.badRequest, _invalidPage);
        return;
      }
      final code = parameters['code']?.single;
      final denied = parameters['error']?.single == 'access_denied';
      if ((code == null || !_canonicalSecret(code)) && !denied) {
        await _respond(request, HttpStatus.badRequest, _invalidPage);
        return;
      }
      // Accept exactly one valid callback. Invalid or unrelated localhost
      // traffic cannot consume the legitimate browser authorization attempt.
      _settled = true;
      _timer?.cancel();
      _timer = null;
      await _respond(
        request,
        HttpStatus.ok,
        denied ? _deniedPage : _receivedPage,
      );
      await _close();
      if (_callback.isCompleted) return;
      if (denied) {
        _discardProofs();
        _callback.completeError(
          const BrowserAuthException._('browser_auth_denied'),
        );
      } else {
        _callback.complete(code!);
      }
    } catch (_) {
      // Malformed HTTP/query input is neither logged nor reflected in HTML.
      if (!_settled) {
        await _respond(request, HttpStatus.badRequest, _invalidPage);
      }
    }
  }

  static final _secretFormat = RegExp(r'^[A-Za-z0-9_-]{43}$');

  static bool _canonicalSecret(String value) {
    if (!_secretFormat.hasMatch(value)) return false;
    try {
      final bytes = base64Url.decode('$value=');
      return bytes.length == 32 && BrowserAuth._base64Url(bytes) == value;
    } on FormatException {
      return false;
    }
  }

  bool _sameState(String value) {
    var difference = value.length ^ state.length;
    for (var index = 0; index < state.length; index++) {
      difference |= state.codeUnitAt(index) ^ value.codeUnitAt(index);
    }
    return difference == 0;
  }

  Future<void> _fail(BrowserAuthException error) async {
    if (_settled) {
      await _close();
      _discardProofs();
      if (!_callback.isCompleted) _callback.completeError(error);
      return;
    }
    _settled = true;
    _timer?.cancel();
    _timer = null;
    await _close();
    _discardProofs();
    if (!_callback.isCompleted) _callback.completeError(error);
  }

  void _discardProofs() {
    _codeVerifier = null;
    _state = null;
    _codeChallenge = null;
  }

  Future<void> _close() => _closing ??= _closeServer();

  Future<void> _closeServer() async {
    try {
      await _server.close(force: true);
    } catch (_) {
      // An already closed socket needs no further action or diagnostics.
    }
    try {
      await _subscription?.cancel();
    } catch (_) {
      // Closing may already have disposed the request stream.
    }
    _subscription = null;
  }

  static Future<void> _respond(
    HttpRequest request,
    int status,
    String page,
  ) async {
    try {
      final response = request.response;
      response.statusCode = status;
      response.persistentConnection = false;
      response.headers
        ..contentType = ContentType.html
        ..set(HttpHeaders.cacheControlHeader, 'no-store')
        ..set(HttpHeaders.pragmaHeader, 'no-cache')
        ..set('Referrer-Policy', 'no-referrer')
        ..set('X-Content-Type-Options', 'nosniff')
        ..set(
          'Content-Security-Policy',
          "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; "
              "form-action 'none'; frame-ancestors 'none'",
        );
      response.write(page);
      await response.close().timeout(const Duration(seconds: 1));
    } catch (_) {
      try {
        final socket = await request.response
            .detachSocket(writeHeaders: false)
            .timeout(const Duration(seconds: 1));
        socket.destroy();
      } catch (_) {
        // A disconnected peer must not interrupt completion or cancellation.
      }
    }
  }

  static const _receivedPage =
      '$_pageStart<h1>Autorisation reçue</h1>'
      '<p>Revenez dans FuzeVPN pour terminer la connexion.</p>$_pageEnd';
  static const _deniedPage =
      '$_pageStart<h1>Autorisation refusée</h1>'
      '<p>Vous pouvez revenir dans FuzeVPN '
      'et recommencer si vous le souhaitez.</p>$_pageEnd';
  static const _invalidPage =
      '$_pageStart<h1>Demande invalide</h1>'
      '<p>Revenez dans FuzeVPN et poursuivez '
      'la demande de connexion ouverte dans votre navigateur.</p>$_pageEnd';
  static const _pageStart =
      '<!doctype html><html lang="fr"><head>'
      '<meta charset="utf-8"><meta name="viewport" '
      'content="width=device-width,initial-scale=1"><title>FuzeVPN</title>'
      '<style>html{color-scheme:light dark}body{margin:0;min-height:100vh;'
      'display:grid;place-items:center;background:#101a22;color:#f4f1e9;'
      'font:17px/1.6 system-ui,sans-serif}main{max-width:540px;margin:24px;'
      'padding:36px;border:1px solid #45505a;border-radius:18px}'
      'strong{color:#f5cb58;letter-spacing:.03em}h1{font-size:28px;'
      'line-height:1.25}p{color:#c9ced1;margin-bottom:0}</style>'
      '</head><body><main><strong>FuzeVPN</strong>';
  static const _pageEnd = '</main></body></html>';
}
