// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/browser_auth.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/local_diagnostic_trace.dart';
import 'package:fuzevpn_windows/core/models.dart';

import 'support/audit_fixtures.dart' as fixtures;

final _code = base64Url.encode(List<int>.filled(32, 17)).replaceAll('=', '');

class _Auth extends BrowserAuth {
  _Auth({super.timeout});
  final started = Completer<BrowserAuthAttempt>();
  BrowserAuthAttempt? attempt;
  int attempts = 0;
  @override
  Future<BrowserAuthAttempt> start() async {
    attempt = await BrowserAuth(
      timeout: ++attempts == 1 ? timeout : const Duration(minutes: 10),
    ).start();
    if (!started.isCompleted) started.complete(attempt);
    return attempt!;
  }
}

class _Api extends fixtures.ProbeApi {
  int exchanges = 0;
  int logins = 0;
  Object? exchangeFailure;
  Object? profileFailure;
  Completer<AuthSession>? exchangeGate;
  final exchangeStarted = Completer<void>();
  String? receivedVerifier;
  Uri? receivedRedirect;
  @override
  Future<AuthSession> exchangeWindowsBrowserCode({
    required String code,
    required Uri redirectUri,
    required String codeVerifier,
  }) async {
    exchanges++;
    if (!exchangeStarted.isCompleted) exchangeStarted.complete();
    expect(code, _code);
    receivedVerifier = codeVerifier;
    receivedRedirect = redirectUri;
    if (exchangeFailure case final failure?) throw failure;
    if (exchangeGate case final gate?) return gate.future;
    return const AuthSession(accessToken: 'synthetic-browser-session');
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    logins++;
    return const AuthSession(accessToken: 'synthetic-password-session');
  }

  @override
  Future<UserProfile> me(String token) async {
    if (profileFailure case final failure?) throw failure;
    return super.me(token);
  }
}

class _Store extends fixtures.ProbeStore {
  String? savedToken;
  int writes = 0;
  final writeStarted = Completer<void>();
  Completer<void>? writeGate;
  final events = <String>[];
  @override
  Future<String?> token() async => savedToken;
  @override
  Future<void> saveToken(String token) async {
    writes++;
    if (!writeStarted.isCompleted) writeStarted.complete();
    await writeGate?.future;
    savedToken = token;
    events.add('write');
  }

  @override
  Future<void> clearToken() async {
    savedToken = null;
    events.add('clear');
  }
}

class _WireGuard extends fixtures.ProbeWireGuard {
  int identityCalls = 0;
  @override
  Future<void> prepareIdentityForAccount(String accountId) async {
    identityCalls++;
  }
}

class _Window extends fixtures.ProbeWindow {
  int showCalls = 0;
  @override
  Future<void> show() async => showCalls++;
}

class _Fixture {
  _Fixture({Future<bool> Function(Uri)? launcher, Duration? timeout}) {
    auth = _Auth(timeout: timeout ?? const Duration(minutes: 10));
    controller = AppController(
      api: api,
      store: store,
      wireguard: wireguard,
      openVpn: fixtures.ProbeOpenVpn(),
      window: window,
      browserAuth: auth,
      browserLauncher:
          launcher ??
          (url) async {
            openedUrl = url;
            return true;
          },
    );
  }
  final api = _Api();
  final store = _Store();
  final wireguard = _WireGuard();
  final window = _Window();
  late final _Auth auth;
  late final AppController controller;
  Uri? openedUrl;

  Future<BrowserAuthAttempt> waiting() async {
    await auth.started.future;
    await _waitForState(controller, BrowserSignInStatus.waitingForBrowser);
    expect(
      controller.browserSignInStatus,
      BrowserSignInStatus.waitingForBrowser,
    );
    return auth.attempt!;
  }
}

Future<void> _waitForState(
  AppController controller,
  BrowserSignInStatus state,
) {
  if (controller.browserSignInStatus == state) return Future<void>.value();
  final ready = Completer<void>();
  void observe() {
    if (controller.browserSignInStatus == state && !ready.isCompleted) {
      ready.complete();
    }
  }

  controller.addListener(observe);
  return ready.future
      .timeout(const Duration(seconds: 5))
      .whenComplete(() => controller.removeListener(observe));
}

Future<void> _authorize(
  BrowserAuthAttempt attempt, {
  bool denied = false,
}) async {
  final client = HttpClient();
  try {
    final request = await client.getUrl(
      attempt.redirectUri.replace(
        queryParameters: {
          if (denied) 'error': 'access_denied' else 'code': _code,
          'state': attempt.state,
        },
      ),
    );
    final response = await request.close();
    expect(response.statusCode, HttpStatus.ok);
    await response.drain<void>();
  } finally {
    client.close(force: true);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // These controller tests drive a real loopback listener, not a widget HTTP
  // stub. All remote account operations remain injected synthetic fixtures.
  final overrides = HttpOverrides.current;
  setUp(() => HttpOverrides.global = null);
  tearDown(() => HttpOverrides.global = overrides);

  test(
    'browser sign-in uses the normal secure session and restores the window',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.controller.dispose);
      final phases = <BrowserSignInStatus>[];
      fixture.controller.addListener(
        () => phases.add(fixture.controller.browserSignInStatus),
      );
      final before = DiagnosticLog.recentLines.length;
      final operation = fixture.controller.signInWithBrowser();
      final attempt = await fixture.waiting();
      final verifier = attempt.codeVerifier;
      final state = attempt.state;
      final redirect = attempt.redirectUri;
      expect(fixture.openedUrl?.origin, 'https://app.fuzevpn.com');
      expect(fixture.openedUrl?.path, '/desktop/connect');
      expect(
        fixture.openedUrl?.queryParameters['client_id'],
        'fuzevpn-windows',
      );
      await _authorize(attempt);
      expect(await operation, isTrue);
      expect(fixture.api.exchanges, 1);
      expect(fixture.api.logins, 0);
      expect(fixture.api.receivedVerifier, verifier);
      expect(fixture.api.receivedRedirect, redirect);
      expect(fixture.store.savedToken, 'synthetic-browser-session');
      expect(fixture.controller.profile, fixtures.account);
      expect(fixture.wireguard.identityCalls, 1);
      expect(fixture.wireguard.prepareCalls, 0);
      expect(fixture.window.showCalls, 1);
      expect(
        phases,
        containsAll([
          BrowserSignInStatus.openingBrowser,
          BrowserSignInStatus.waitingForBrowser,
          BrowserSignInStatus.completingSignIn,
          BrowserSignInStatus.idle,
        ]),
      );
      final trace = DiagnosticLog.recentLines.skip(before).join('\n');
      for (final stage in ['listener', 'open', 'callback', 'exchange']) {
        expect(trace, contains('stage=browser_auth_$stage'));
      }
      for (final secret in [
        _code,
        verifier,
        state,
        'synthetic-browser-session',
      ]) {
        expect(trace, isNot(contains(secret)));
      }
      final safe = await LocalDiagnosticTrace.collect(
        path: 'absent-synthetic-browser-trace.log',
        currentLines: DiagnosticLog.recentLines.skip(before),
      );
      expect(safe.toString(), contains('browser_auth_callback'));
    },
  );

  test('browser and password attempts cannot run concurrently', () async {
    final fixture = _Fixture();
    addTearDown(fixture.controller.dispose);
    final operation = fixture.controller.signInWithBrowser();
    await fixture.waiting();
    expect(await fixture.controller.signInWithBrowser(), isFalse);
    expect(
      await fixture.controller.signIn(
        email: 'test@example.invalid',
        password: 'synthetic',
      ),
      isFalse,
    );
    expect(fixture.api.logins, 0);
    fixture.controller.cancelBrowserSignIn();
    expect(await operation, isFalse);
    expect(fixture.store.writes, 0);
    expect(fixture.controller.browserSignInErrorMessage, isNull);
    expect(fixture.controller.errorMessage, isNull);
    expect(fixture.controller.browserSignInBusy, isFalse);
  });

  test(
    'failed browser opening is local and closes the reserved listener',
    () async {
      final fixture = _Fixture(launcher: (_) async => false);
      addTearDown(fixture.controller.dispose);
      expect(await fixture.controller.signInWithBrowser(), isFalse);
      expect(fixture.api.exchanges, 0);
      expect(fixture.store.writes, 0);
      expect(
        fixture.controller.browserSignInErrorMessage,
        contains('navigateur par défaut'),
      );
      expect(
        fixture.controller.browserSignInErrorMessage,
        isNot(contains('API')),
      );
      expect(fixture.controller.browserSignInBusy, isFalse);
    },
  );

  test('browser launch exceptions cannot leak the authorization URL', () async {
    final fixture = _Fixture(
      launcher: (url) async =>
          throw PlatformException(code: 'shell_error', message: url.toString()),
    );
    addTearDown(fixture.controller.dispose);
    final before = DiagnosticLog.recentLines.length;
    expect(await fixture.controller.signInWithBrowser(), isFalse);
    final trace = DiagnosticLog.recentLines.skip(before).join('\n');
    expect(trace, contains('browser_auth_launch_failed'));
    expect(trace, isNot(contains('code_challenge')));
    expect(trace, isNot(contains('redirect_uri')));
    expect(fixture.controller.errorMessage, isNot(contains('https:')));
  });

  test('explicit web denial never exchanges or persists a session', () async {
    final fixture = _Fixture();
    addTearDown(fixture.controller.dispose);
    final operation = fixture.controller.signInWithBrowser();
    final attempt = await fixture.waiting();
    await _authorize(attempt, denied: true);
    expect(await operation, isFalse);
    expect(fixture.api.exchanges, 0);
    expect(fixture.store.writes, 0);
    expect(
      fixture.controller.browserSignInErrorMessage,
      contains('annulée dans le navigateur'),
    );
  });

  test('timeout explains the expired request without an API outage', () async {
    final fixture = _Fixture(timeout: const Duration(milliseconds: 100));
    addTearDown(fixture.controller.dispose);
    expect(await fixture.controller.signInWithBrowser(), isFalse);
    expect(fixture.api.exchanges, 0);
    expect(fixture.controller.browserSignInErrorMessage, contains('a expiré'));
    expect(fixture.controller.browserSignInBusy, isFalse);
  });

  for (final denied in [false, true]) {
    test(
      'late reopen after ${denied ? 'denial' : 'expiry'} cannot alter a new attempt',
      () async {
        final oldReopen = Completer<bool>();
        var launches = 0;
        final fixture = _Fixture(
          timeout: const Duration(milliseconds: 300),
          launcher: (_) async => switch (++launches) {
            2 => oldReopen.future,
            4 => false,
            _ => true,
          },
        );
        addTearDown(fixture.controller.dispose);
        final first = fixture.controller.signInWithBrowser();
        final firstAttempt = await fixture.waiting();
        final reopening = fixture.controller.reopenBrowserSignIn();
        if (denied) await _authorize(firstAttempt, denied: true);
        expect(await first, isFalse);

        final second = fixture.controller.signInWithBrowser();
        await fixture.waiting();
        expect(await fixture.controller.reopenBrowserSignIn(), isFalse);
        final newError = fixture.controller.browserSignInErrorMessage;
        expect(newError, contains('navigateur par défaut'));
        oldReopen.complete(true);
        expect(await reopening, isFalse);
        expect(fixture.controller.browserSignInErrorMessage, newError);
        expect(fixture.controller.browserSignInBusy, isTrue);
        fixture.controller.cancelBrowserSignIn();
        expect(await second, isFalse);
        expect(fixture.api.exchanges, 0);
        expect(fixture.store.writes, 0);
      },
    );
  }

  test('authorization deadline also covers the token exchange', () async {
    final fixture = _Fixture(timeout: const Duration(milliseconds: 300));
    addTearDown(fixture.controller.dispose);
    fixture.api.exchangeGate = Completer<AuthSession>();
    final operation = fixture.controller.signInWithBrowser();
    final attempt = await fixture.waiting();
    await _authorize(attempt);
    await fixture.api.exchangeStarted.future;
    expect(await operation, isFalse);
    expect(fixture.controller.browserSignInErrorMessage, contains('a expiré'));
    fixture.api.exchangeGate!.complete(
      const AuthSession(accessToken: 'synthetic-late-session'),
    );
    await Future<void>.delayed(Duration.zero);
    expect(fixture.api.exchanges, 1);
    expect(fixture.store.writes, 0);
    expect(fixture.controller.profile, isNull);
  });

  test(
    'accepted token finishes secure storage past the flow deadline',
    () async {
      final fixture = _Fixture(timeout: const Duration(milliseconds: 300));
      addTearDown(fixture.controller.dispose);
      fixture.store.writeGate = Completer<void>();
      final operation = fixture.controller.signInWithBrowser();
      final attempt = await fixture.waiting();
      await _authorize(attempt);
      await fixture.store.writeStarted.future;
      await Future<void>.delayed(const Duration(milliseconds: 350));
      expect(fixture.controller.browserSignInBusy, isTrue);
      fixture.store.writeGate!.complete();
      expect(await operation, isTrue);
      expect(fixture.store.savedToken, 'synthetic-browser-session');
      expect(fixture.controller.profile, fixtures.account);
    },
  );

  for (final code in [
    'desktop_auth_invalid_grant',
    'desktop_auth_unavailable',
    'account_login_required',
  ]) {
    test(
      'browser API refusal $code preserves its cause and cannot save a token',
      () async {
        final fixture = _Fixture();
        addTearDown(fixture.controller.dispose);
        fixture.api.exchangeFailure = ApiException(
          statusCode: code == 'desktop_auth_unavailable' ? 503 : 400,
          observedHttpStatus: code == 'desktop_auth_unavailable' ? 503 : 400,
          errorCode: code,
        );
        final operation = fixture.controller.signInWithBrowser();
        final attempt = await fixture.waiting();
        await _authorize(attempt);
        expect(await operation, isFalse);
        expect(fixture.api.exchanges, 1);
        expect(fixture.store.writes, 0);
        expect(fixture.controller.profile, isNull);
        expect(fixture.controller.browserSignInErrorMessage, isNotNull);
        expect(
          fixture.controller.browserSignInErrorMessage,
          isNot(contains('API')),
        );
      },
    );
  }

  test(
    'profile rejection after exchange preserves normal session errors',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.controller.dispose);
      fixture.api.profileFailure = const ApiException(
        statusCode: 401,
        errorCode: 'unauthorized',
      );
      final operation = fixture.controller.signInWithBrowser();
      final attempt = await fixture.waiting();
      await _authorize(attempt);
      expect(await operation, isFalse);
      expect(fixture.api.exchanges, 1);
      expect(fixture.store.writes, 0);
      expect(fixture.controller.profile, isNull);
      expect(
        fixture.controller.errorMessage,
        'Votre session a expiré. Connectez-vous de nouveau.',
      );
      expect(
        fixture.controller.browserSignInErrorMessage,
        'Votre session a expiré. Connectez-vous de nouveau.',
      );
    },
  );

  test('sign-out during token exchange rejects its late response', () async {
    final fixture = _Fixture();
    addTearDown(fixture.controller.dispose);
    fixture.api.exchangeGate = Completer<AuthSession>();
    final operation = fixture.controller.signInWithBrowser();
    final attempt = await fixture.waiting();
    await _authorize(attempt);
    await fixture.api.exchangeStarted.future;
    expect(fixture.api.exchanges, 1);
    await fixture.controller.signOut();
    expect(await operation, isFalse);
    fixture.api.exchangeGate!.complete(
      const AuthSession(accessToken: 'synthetic-late-session'),
    );
    await Future<void>.delayed(Duration.zero);
    expect(fixture.store.savedToken, isNull);
    expect(fixture.store.writes, 0);
    expect(fixture.controller.profile, isNull);
  });

  test(
    'sign-out clears a token after any already-started secure write',
    () async {
      final fixture = _Fixture();
      addTearDown(fixture.controller.dispose);
      fixture.store.writeGate = Completer<void>();
      final operation = fixture.controller.signInWithBrowser();
      final attempt = await fixture.waiting();
      await _authorize(attempt);
      await fixture.store.writeStarted.future;
      final logout = fixture.controller.signOut();
      await Future<void>.delayed(Duration.zero);
      fixture.store.writeGate!.complete();
      await logout;
      expect(await operation, isFalse);
      expect(fixture.store.events, ['write', 'clear']);
      expect(fixture.store.savedToken, isNull);
      expect(fixture.controller.profile, isNull);
    },
  );

  test(
    'dispose while waiting closes the flow with no late session work',
    () async {
      final fixture = _Fixture();
      final operation = fixture.controller.signInWithBrowser();
      await fixture.waiting();
      fixture.controller.dispose();
      expect(await operation, isFalse);
      expect(fixture.api.exchanges, 0);
      expect(fixture.store.writes, 0);
    },
  );
}
