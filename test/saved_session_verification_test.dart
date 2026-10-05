// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixture;

const _bootstrapFailure = ApiException(
  statusCode: 503,
  errorCode: 'api_resolution_unavailable',
  localErrorCode: 'api_bootstrap_unavailable',
);

class _Api extends fixture.ProbeApi {
  Object? profileFailure;
  Completer<UserProfile>? profileGate;
  int loginCalls = 0;
  int deviceCalls = 0;
  int bootstrapInvalidations = 0;

  @override
  Future<UserProfile> me(String token) async {
    meCalls++;
    if (profileFailure case final failure?) throw failure;
    return await profileGate?.future ?? fixture.account;
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async {
    loginCalls++;
    throw StateError('Passive verification must not log in.');
  }

  @override
  Future<DeviceList> devices(String token) async {
    deviceCalls++;
    return super.devices(token);
  }

  @override
  void invalidateBootstrapCache() {
    bootstrapInvalidations++;
    super.invalidateBootstrapCache();
  }
}

class _Store extends fixture.ProbeStore {
  String? savedToken = 'synthetic-saved-session';
  Object? readFailure;
  int clearTokenCalls = 0;
  int saveTokenCalls = 0;
  int clearDeviceCalls = 0;

  @override
  Future<String?> token() async {
    if (readFailure case final failure?) throw failure;
    return savedToken;
  }

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

  @override
  Future<void> clearCurrentDeviceId() async {
    clearDeviceCalls++;
  }
}

class _WireGuard extends fixture.ProbeWireGuard {
  final mutations = <String>[];

  Never _mutation(String name) {
    mutations.add(name);
    throw StateError('Passive verification attempted a VPN mutation.');
  }

  @override
  Future<void> prepareIdentityForAccount(String accountId) async =>
      _mutation('prepareIdentity');
  @override
  Future<void> recreateIdentityForAccount(String accountId) async =>
      _mutation('recreateIdentity');
  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      _mutation('getOrCreatePublicKey');
  @override
  Future<void> resetIdentity() async => _mutation('resetIdentity');
  @override
  Future<void> prepareNetworkProtection() async =>
      _mutation('prepareProtection');
  @override
  Future<bool> reconnect() async => _mutation('reconnect');
  @override
  Future<void> connect(DeviceConfiguration configuration) async =>
      _mutation('connect');
  @override
  Future<void> disconnect() async => _mutation('disconnect');
  @override
  Future<void> suspendForMigration() async => _mutation('suspend');
}

class _OpenVpn extends fixture.ProbeOpenVpn {
  final mutations = <String>[];

  Never _mutation(String name) {
    mutations.add(name);
    throw StateError('Passive verification attempted a VPN mutation.');
  }

  @override
  Future<void> deleteProfile() async => _mutation('deleteProfile');
  @override
  Future<void> prepareNetworkProtection() async =>
      _mutation('prepareProtection');
  @override
  Future<bool> reconnect() async => _mutation('reconnect');
  @override
  Future<void> disconnect() async => _mutation('disconnect');
  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async =>
      _mutation('importAndConnect');
  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async => _mutation('getOrCreateCsr');
}

class _NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

AppController _controller({
  required _Api api,
  required _Store store,
  _WireGuard? wireguard,
  _OpenVpn? openVpn,
}) => AppController(
  api: api,
  store: store,
  wireguard: wireguard ?? _WireGuard(),
  openVpn: openVpn ?? _OpenVpn(),
  window: fixture.ProbeWindow(),
  updates: _NoUpdates(),
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final failure in <Object>[
    _bootstrapFailure,
    const ApiException(statusCode: 503, errorCode: 'server_error'),
    const ApiException(statusCode: 401, errorCode: 'api_error'),
    const SocketException('Synthetic private transport details'),
  ]) {
    test(
      'saved session survives ${failure.runtimeType} and passive retry',
      () async {
        final api = _Api()..profileFailure = failure;
        final store = _Store()..autoConnect = true;
        final wg = _WireGuard();
        final ov = _OpenVpn();
        final app = _controller(
          api: api,
          store: store,
          wireguard: wg,
          openVpn: ov,
        );
        addTearDown(app.dispose);
        await app.initialize();
        expect(app.profile, isNull);
        expect(app.savedSessionVerificationPending, isTrue);
        expect(app.sessionStorageUnavailable, isFalse);
        expect(app.savedSessionVerificationErrorMessage, isNotNull);
        expect(store.savedToken, 'synthetic-saved-session');
        expect(store.clearTokenCalls, 0);
        expect(store.clearDeviceCalls, 0);
        if (failure == _bootstrapFailure) {
          expect(
            app.savedSessionVerificationErrorMessage,
            'FuzeVPN ne peut pas résoudre l’adresse du service de connexion.',
          );
        }
        api.profileFailure = null;
        await app.retrySavedSessionVerification();
        expect(app.profile, fixture.account);
        expect(app.savedSessionVerificationPending, isFalse);
        expect(app.savedSessionVerificationErrorMessage, isNull);
        expect(app.isVerifyingSavedSession, isFalse);
        expect(store.savedToken, 'synthetic-saved-session');
        expect(store.clearTokenCalls, 0);
        expect(store.saveTokenCalls, 0);
        expect(api.loginCalls, 0);
        expect(api.deviceCalls, 1);
        expect(api.bootstrapInvalidations, greaterThan(0));
        expect(wg.mutations, isEmpty);
        expect(ov.mutations, isEmpty);
        expect(app.vpnStatus, VpnStatus.disconnected);
      },
    );
  }

  for (final code in [
    'storage_access_denied',
    'storage_corrupt',
    'storage_decryption_failed',
    'storage_io_error',
  ]) {
    test('protected token $code is unavailable, not absent', () async {
      final api = _Api();
      final store = _Store()
        ..readFailure = PlatformException(
          code: code,
          message: 'Private synthetic value must not be logged.',
          details: {'secret': 'synthetic-secret'},
        );
      final app = _controller(api: api, store: store);
      addTearDown(app.dispose);
      await app.initialize();
      expect(app.profile, isNull);
      expect(app.savedSessionVerificationPending, isTrue);
      expect(app.sessionStorageUnavailable, isTrue);
      expect(
        app.savedSessionVerificationErrorMessage,
        'Votre session enregistrée ne peut pas être lue. Réessayez la vérification.',
      );
      expect(api.meCalls, 0);
      expect(store.savedToken, 'synthetic-saved-session');
      expect(store.clearTokenCalls, 0);
      store.readFailure = null;
      await app.retrySavedSessionVerification();
      expect(app.profile, fixture.account);
      expect(app.savedSessionVerificationPending, isFalse);
      expect(app.sessionStorageUnavailable, isFalse);
      expect(store.clearTokenCalls, 0);
      expect(store.saveTokenCalls, 0);
      expect(api.loginCalls, 0);
    });
  }

  test('confirmed token absence has no pending verification', () async {
    final api = _Api();
    final app = _controller(api: api, store: _Store()..savedToken = null);
    addTearDown(app.dispose);
    await app.initialize();
    expect(app.savedSessionVerificationPending, isFalse);
    expect(app.sessionStorageUnavailable, isFalse);
    expect(app.savedSessionVerificationErrorMessage, isNull);
    expect(api.meCalls, 0);
    await app.retrySavedSessionVerification();
    expect(api.meCalls, 0);
  });

  test(
    'strict server rejection permits login and removes the rejected token',
    () async {
      final api = _Api()
        ..profileFailure = const ApiException(
          statusCode: 401,
          errorCode: 'unauthorized',
          observedHttpStatus: 401,
        );
      final store = _Store();
      final app = _controller(api: api, store: store);
      addTearDown(app.dispose);
      await app.initialize();
      expect(app.savedSessionVerificationPending, isFalse);
      expect(app.sessionStorageUnavailable, isFalse);
      expect(store.clearTokenCalls, 1);
      expect(store.savedToken, isNull);
      expect(app.profile, isNull);
    },
  );

  test('parallel retry requests reserve one profile validation', () async {
    final api = _Api()..profileFailure = _bootstrapFailure;
    final app = _controller(api: api, store: _Store());
    addTearDown(app.dispose);
    await app.initialize();
    api.profileFailure = null;
    final gate = Completer<UserProfile>();
    api.profileGate = gate;
    final first = app.retrySavedSessionVerification();
    final second = app.retrySavedSessionVerification();
    await Future<void>.delayed(Duration.zero);
    expect(app.isVerifyingSavedSession, isTrue);
    expect(api.meCalls, 2);
    gate.complete(fixture.account);
    await Future.wait([first, second]);
    expect(app.isVerifyingSavedSession, isFalse);
    expect(app.savedSessionVerificationPending, isFalse);
  });

  testWidgets(
    'automatic bootstrap retry is passive and stops after three retries',
    (tester) async {
      final api = _Api()..profileFailure = _bootstrapFailure;
      final store = _Store()..autoConnect = true;
      final wg = _WireGuard();
      final ov = _OpenVpn();
      final app = _controller(
        api: api,
        store: store,
        wireguard: wg,
        openVpn: ov,
      );
      await app.initialize();
      expect(api.meCalls, 1);
      for (final milliseconds in [500, 1500, 3000]) {
        await tester.pump(Duration(milliseconds: milliseconds));
        await tester.pump();
      }
      expect(api.meCalls, 4);
      await tester.pump(const Duration(seconds: 30));
      expect(api.meCalls, 4);
      expect(app.savedSessionVerificationPending, isTrue);
      expect(store.clearTokenCalls, 0);
      expect(api.loginCalls, 0);
      expect(wg.mutations, isEmpty);
      expect(ov.mutations, isEmpty);
      app.dispose();
    },
  );

  testWidgets('automatic retry recovers without invoking launch auto-connect', (
    tester,
  ) async {
    final api = _Api()..profileFailure = _bootstrapFailure;
    final store = _Store()..autoConnect = true;
    final wg = _WireGuard();
    final ov = _OpenVpn();
    final app = _controller(api: api, store: store, wireguard: wg, openVpn: ov);
    await app.initialize();
    api.profileFailure = null;
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pump();
    expect(app.profile, fixture.account);
    expect(app.savedSessionVerificationPending, isFalse);
    expect(wg.mutations, isEmpty);
    expect(ov.mutations, isEmpty);
    await tester.pump(const Duration(seconds: 10));
    expect(api.meCalls, 2);
    app.dispose();
  });

  test('verification logs only stable stages and safe failure codes', () async {
    final trace = <({String area, String event, String? code})>[];
    final stop = DiagnosticLog.observe((area, event, code) {
      if (area == 'account') trace.add((area: area, event: event, code: code));
    });
    addTearDown(stop);
    final api = _Api()..profileFailure = _bootstrapFailure;
    final app = _controller(api: api, store: _Store());
    addTearDown(app.dispose);
    await app.initialize();
    expect(
      trace,
      contains((
        area: 'account',
        event: 'saved_session_verification_pending',
        code: 'api_bootstrap_unavailable',
      )),
    );
    expect(trace.toString(), isNot(contains('synthetic-saved-session')));
    expect(trace.toString(), isNot(contains('audit@example')));
    expect(trace.toString(), isNot(contains('private')));
    api.profileFailure = null;
    await app.retrySavedSessionVerification();
    expect(
      trace,
      contains((
        area: 'account',
        event: 'saved_session_verification_succeeded',
        code: null,
      )),
    );
  });
}
