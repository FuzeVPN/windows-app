// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'subscription_models_test.dart' show subscriptionJson;
import 'support/audit_fixtures.dart' as fixtures;

class _Api extends fixtures.ProbeApi {
  final requests = <String>[];
  final responses = <Future<Subscription>>[];
  @override
  Future<Subscription> subscription(String token) {
    requests.add(token);
    return responses.isEmpty
        ? Future.value(Subscription.fromJson(subscriptionJson()))
        : responses.removeAt(0);
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async => const AuthSession(accessToken: 'new-synthetic-token');
}

class _Store extends fixtures.ProbeStore {
  String? savedToken = 'synthetic-token';
  Completer<void>? tokenGate;
  int clearCalls = 0;
  bool automaticReconnectEnabled = true;

  @override
  Future<SecuritySettings> securitySettings() async => SecuritySettings(
    killSwitch: true,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: automaticReconnectEnabled,
  );
  @override
  Future<String?> token() async {
    await tokenGate?.future;
    return savedToken;
  }

  @override
  Future<void> saveToken(String value) async => savedToken = value;
  @override
  Future<void> clearToken() async {
    clearCalls++;
    savedToken = null;
  }
}

class _WireGuard extends fixtures.ProbeWireGuard {
  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
}

class _UnknownWireGuard extends _WireGuard {
  _UnknownWireGuard({this.connectionFailureCode = 'broker_unavailable'});
  final String connectionFailureCode;

  @override
  Future<bool> isConnected() async =>
      throw PlatformException(code: connectionFailureCode);
  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() async =>
      throw PlatformException(code: 'runtime_status_unavailable');
  @override
  Future<bool> isNetworkProtectionActive() async =>
      throw PlatformException(code: 'broker_unavailable');
}

class _NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

AppController _controller(_Api api, _Store store, {_WireGuard? wireguard}) =>
    AppController(
      api: api,
      store: store,
      wireguard: wireguard ?? _WireGuard(),
      openVpn: fixtures.ProbeOpenVpn(),
      window: fixtures.ProbeWindow(),
      updates: _NoUpdates(),
    )..profile = fixtures.account;

Future<void> _flush() => Future<void>.delayed(Duration.zero);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test(
    'startup never fetches billing; opening refreshes and coalesces requests',
    () async {
      final api = _Api();
      final app = _controller(api, _Store());
      addTearDown(app.dispose);
      await app.initialize();
      expect(api.requests, isEmpty);
      final reply = Completer<Subscription>();
      api.responses.add(reply.future);
      final first = app.refreshSubscription();
      final second = app.refreshSubscription();
      expect(app.isLoadingSubscription, isTrue);
      await _flush();
      expect(api.requests, hasLength(1));
      final result = Subscription.fromJson(subscriptionJson());
      reply.complete(result);
      await Future.wait([first, second]);
      expect(app.subscription, same(result));
      expect(app.isLoadingSubscription, isFalse);
      expect(app.subscriptionErrorMessage, isNull);
      await app.refreshSubscription();
      expect(api.requests, hasLength(2));
    },
  );

  test(
    'absence of an account or stored token never sends a billing request',
    () async {
      final api = _Api();
      final store = _Store();
      final app = _controller(api, store);
      addTearDown(app.dispose);
      await app.refreshSubscription();
      app.profile = null;
      expect(app.subscription, isNull);
      await app.refreshSubscription();
      expect(api.requests, hasLength(1));
      app.profile = fixtures.account;
      store.savedToken = null;
      await app.refreshSubscription();
      expect(api.requests, hasLength(1));
      expect(app.subscription, isNull);
      expect(app.isLoadingSubscription, isFalse);
    },
  );

  test(
    'a refresh requested synchronously by a loading listener is coalesced',
    () async {
      final api = _Api();
      final app = _controller(api, _Store());
      addTearDown(app.dispose);
      Future<void>? nested;
      app.addListener(() {
        if (app.isLoadingSubscription && nested == null) {
          nested = app.refreshSubscription();
        }
      });
      final first = app.refreshSubscription();
      expect(nested, same(first));
      await first;
      expect(api.requests, hasLength(1));
    },
  );

  test(
    'failed refresh preserves same-account cache and isolates its error from the tunnel',
    () async {
      final api = _Api();
      final app = _controller(api, _Store());
      addTearDown(app.dispose);
      await app.refreshSubscription();
      final previous = app.subscription;
      app.errorMessage = 'synthetic tunnel failure';
      final reply = Completer<Subscription>();
      api.responses.add(reply.future);
      final refreshing = app.refreshSubscription();
      expect(app.subscription, same(previous));
      await _flush();
      reply.completeError(
        const ApiException(statusCode: 503, errorCode: 'server_error'),
      );
      await refreshing;
      expect(app.subscription, same(previous));
      expect(app.subscriptionErrorMessage, isNotNull);
      expect(app.errorMessage, 'synthetic tunnel failure');
      expect(app.isLoadingSubscription, isFalse);
      await app.refreshSubscription();
      expect(app.subscriptionErrorMessage, isNull);
    },
  );

  test(
    'account switches clear immediately and obsolete A to B to A response is ignored',
    () async {
      final api = _Api();
      final app = _controller(api, _Store());
      addTearDown(app.dispose);
      await app.refreshSubscription();
      final reply = Completer<Subscription>();
      api.responses.add(reply.future);
      final old = app.refreshSubscription();
      await _flush();
      app.profile = const UserProfile(
        userId: 'other',
        email: 'other@example.invalid',
        firstName: 'Other',
        emailVerified: true,
      );
      expect(app.subscription, isNull);
      expect(app.isLoadingSubscription, isFalse);
      app.profile = fixtures.account;
      reply.complete(Subscription.fromJson(subscriptionJson(status: 'active')));
      await old;
      expect(app.subscription, isNull);
      await app.refreshSubscription();
      expect(app.subscription, isNotNull);
    },
  );

  test(
    'sign-out clears billing and old unauthorized reply cannot expire a new account',
    () async {
      final api = _Api();
      final store = _Store();
      final app = _controller(api, store);
      addTearDown(app.dispose);
      await app.refreshSubscription();
      final reply = Completer<Subscription>();
      api.responses.add(reply.future);
      final old = app.refreshSubscription();
      await _flush();
      await app.signOut();
      expect(app.subscription, isNull);
      app.profile = fixtures.account;
      store.savedToken = 'other-synthetic-token';
      reply.completeError(
        const ApiException(statusCode: 401, errorCode: 'unauthorized'),
      );
      await old;
      expect(app.profile, fixtures.account);
      expect(store.savedToken, 'other-synthetic-token');
      expect(app.subscription, isNull);
    },
  );

  test(
    'new sign-in token invalidates in-flight billing even for the same user',
    () async {
      final api = _Api();
      final store = _Store();
      final app = _controller(api, store);
      addTearDown(app.dispose);
      final reply = Completer<Subscription>();
      api.responses.add(reply.future);
      final old = app.refreshSubscription();
      await _flush();
      expect(
        await app.signIn(
          email: 'synthetic@example.invalid',
          password: 'synthetic',
        ),
        isTrue,
      );
      reply.complete(Subscription.fromJson(subscriptionJson()));
      await old;
      expect(app.subscription, isNull);
      await app.refreshSubscription();
      expect(api.requests.last, 'new-synthetic-token');
    },
  );

  for (final error in [
    const ApiException(statusCode: 401, errorCode: 'unauthorized'),
    const ApiException(statusCode: 401, errorCode: 'api_error'),
    const ApiException(statusCode: 503, errorCode: 'unauthorized'),
  ]) {
    test(
      'billing expires only the strict ${error.statusCode}/${error.errorCode} session',
      () async {
        final api = _Api();
        final store = _Store();
        final app = _controller(api, store);
        addTearDown(app.dispose);
        await app.refreshSubscription();
        app.errorMessage = 'synthetic tunnel failure';
        final reply = Completer<Subscription>();
        api.responses.add(reply.future);
        final pending = app.refreshSubscription();
        await _flush();
        reply.completeError(error);
        await pending;
        expect(app.profile == null, error.isUnauthorized);
        expect(store.clearCalls, error.isUnauthorized ? 1 : 0);
        expect(app.subscription == null, error.isUnauthorized);
        expect(app.errorMessage, 'synthetic tunnel failure');
        expect(app.isLoadingSubscription, isFalse);
      },
    );
  }

  test(
    'blocked and native-unknown states do not issue billing requests',
    () async {
      final api = _Api();
      final wireGuard = _UnknownWireGuard();
      final app = _controller(api, _Store(), wireguard: wireGuard);
      addTearDown(app.dispose);
      await app.initialize();
      expect(app.vpnStatus, VpnStatus.error);
      expect(app.runtimeVerificationPending, isTrue);
      expect(app.requiresExplicitDisconnect, isFalse);
      app.profile = fixtures.account;
      await app.refreshSubscription();
      expect(api.requests, isEmpty);
      expect(app.subscriptionErrorMessage, isNotNull);
      expect(wireGuard.prepareCalls, 0);
      expect(wireGuard.connectCalls, 0);
      expect(wireGuard.reconnectCalls, 0);
      expect(wireGuard.disconnectCalls, 0);
      app.vpnStatus = VpnStatus.blocked;
      await app.refreshSubscription();
      expect(api.requests, isEmpty);
    },
  );

  test(
    'subscription explains an unknown installation state without requesting a disconnect',
    () async {
      final api = _Api();
      final wireGuard = _UnknownWireGuard(
        connectionFailureCode: 'runtime_detection_failed',
      );
      final app = _controller(api, _Store(), wireguard: wireGuard);
      addTearDown(app.dispose);
      await app.initialize();
      app.profile = fixtures.account;

      await app.refreshSubscription();

      expect(app.runtimeVerificationPending, isTrue);
      expect(app.requiresExplicitDisconnect, isFalse);
      expect(
        app.subscriptionErrorMessage,
        'Windows n’a pas permis de vérifier l’installation de FuzeVPN.',
      );
      expect(api.requests, isEmpty);
      expect(wireGuard.prepareCalls, 0);
      expect(wireGuard.connectCalls, 0);
      expect(wireGuard.disconnectCalls, 0);
    },
  );

  test(
    'a known blocked state after the token read still permits billing',
    () async {
      final api = _Api();
      final store = _Store()..tokenGate = Completer<void>();
      final app = _controller(api, store);
      addTearDown(app.dispose);
      final pending = app.refreshSubscription();
      app.vpnStatus = VpnStatus.blocked;
      store.tokenGate!.complete();
      await pending;
      expect(api.requests, hasLength(1));
      expect(app.subscription, isNotNull);
      expect(app.vpnStatus, VpnStatus.blocked);
      expect(app.isLoadingSubscription, isFalse);
    },
  );

  test(
    'billing while native protection is retained never changes WFP',
    () async {
      final api = _Api();
      final wireguard = _WireGuard()..protectionActive = true;
      final store = _Store()..automaticReconnectEnabled = false;
      final app = _controller(api, store, wireguard: wireguard);
      addTearDown(app.dispose);
      await app.initialize();
      app.profile = fixtures.account;
      expect(app.vpnStatus, VpnStatus.blocked);
      expect(app.runtimeVerificationPending, isFalse);
      expect(app.requiresExplicitDisconnect, isTrue);

      await app.refreshSubscription();

      expect(api.requests, hasLength(1));
      expect(app.subscription, isNotNull);
      expect(app.subscriptionErrorMessage, isNull);
      expect(app.vpnStatus, VpnStatus.blocked);
      expect(app.requiresExplicitDisconnect, isTrue);
      expect(wireguard.protectionActive, isTrue);
      expect(wireguard.prepareCalls, 0);
      expect(wireguard.connectCalls, 0);
      expect(wireguard.reconnectCalls, 0);
      expect(wireguard.disconnectCalls, 0);
    },
  );

  test('response after disposal cannot publish or notify', () async {
    final api = _Api();
    final app = _controller(api, _Store());
    final reply = Completer<Subscription>();
    api.responses.add(reply.future);
    var notifications = 0;
    app.addListener(() => notifications++);
    final pending = app.refreshSubscription();
    await _flush();
    final before = notifications;
    app.dispose();
    reply.complete(Subscription.fromJson(subscriptionJson()));
    await pending;
    expect(notifications, before);
    expect(app.subscription, isNull);
  });
}
