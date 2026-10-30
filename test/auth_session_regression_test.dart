// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as f;

class Store extends f.ProbeStore {
  String? storedToken = 'synthetic-account-a';
  bool failTokenDelete = false;
  bool failDeviceDelete = false;
  int tokenDeletes = 0;
  int deviceDeletes = 0;
  int deviceWrites = 0;
  Completer<void>? tokenDeleteGate;
  final tokenDeleteStarted = Completer<void>();
  final tokenRead = Completer<void>();
  @override
  Future<String?> token() async {
    if (!tokenRead.isCompleted) tokenRead.complete();
    return storedToken;
  }

  @override
  Future<void> saveToken(String value) async => storedToken = value;
  @override
  Future<void> clearToken() async {
    tokenDeletes++;
    if (!tokenDeleteStarted.isCompleted) tokenDeleteStarted.complete();
    await tokenDeleteGate?.future;
    if (failTokenDelete) throw PlatformException(code: 'storage_error');
    storedToken = null;
  }

  @override
  Future<void> clearCurrentDeviceId() async {
    deviceDeletes++;
    if (failDeviceDelete) throw PlatformException(code: 'storage_error');
  }

  @override
  Future<void> saveCurrentDeviceId(String value) async => deviceWrites++;
}

const accountB = UserProfile(
  userId: 'synthetic-b',
  email: 'b@example.invalid',
  firstName: 'B',
  emailVerified: true,
);
const dualSource = Location(
  id: 'source',
  city: 'Source',
  countryCode: 'DE',
  displayName: 'Source',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);

class Api extends f.ProbeApi {
  bool rejectSubscription = false;
  bool rejectSavedProfile = false;
  Completer<void>? registerGate;
  final registerStarted = Completer<void>();
  Completer<void>? profileGate;
  final profileStarted = Completer<void>();
  final meTokens = <String>[];
  @override
  Future<UserProfile> me(String token) async {
    meTokens.add(token);
    if (rejectSavedProfile && token == 'synthetic-account-a') {
      throw const ApiException(
        statusCode: 401,
        observedHttpStatus: 401,
        errorCode: 'unauthorized',
      );
    }
    return token == 'synthetic-account-a' ? f.account : accountB;
  }

  @override
  Future<AuthSession> login({
    required String email,
    required String password,
  }) async => const AuthSession(accessToken: 'synthetic-account-b');
  @override
  Future<Subscription> subscription(String token) {
    if (rejectSubscription) {
      throw const ApiException(
        statusCode: 401,
        observedHttpStatus: 401,
        errorCode: 'unauthorized',
      );
    }
    return super.subscription(token);
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    if (!registerStarted.isCompleted) registerStarted.complete();
    await registerGate?.future;
    return super.registerDevice(
      token: token,
      name: name,
      publicKey: publicKey,
      locationId: locationId,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    if (!profileStarted.isCompleted) profileStarted.complete();
    await profileGate?.future;
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }
}

class WireGuard extends f.ProbeWireGuard {
  final connectStarted = Completer<void>();
  Completer<bool>? connectedReadGate;
  final connectedReadStarted = Completer<void>();
  @override
  Future<bool> isConnected() {
    final gate = connectedReadGate;
    connectedReadGate = null;
    if (gate != null) {
      if (!connectedReadStarted.isCompleted) connectedReadStarted.complete();
      return gate.future;
    }
    return super.isConnected();
  }

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    if (!connectStarted.isCompleted) connectStarted.complete();
    await super.connect(configuration);
  }

  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
}

class OpenVpn extends f.ProbeOpenVpn {
  final availabilityStarted = Completer<void>();
  Completer<bool>? availabilityGate;
  @override
  Future<bool> isAvailable() async {
    if (!availabilityStarted.isCompleted) availabilityStarted.complete();
    return availabilityGate == null ? false : availabilityGate!.future;
  }

  @override
  Future<void> prepareNetworkProtection() async => protectionActive = true;
}

class NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

AppController make(
  Api api,
  Store store, {
  OpenVpn? openVpn,
  WireGuard? wireguard,
}) => AppController(
  api: api,
  store: store,
  wireguard: wireguard ?? WireGuard(),
  openVpn: openVpn ?? OpenVpn(),
  window: f.ProbeWindow(),
  updates: NoUpdates(),
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final failingTokenDelete in [true, false]) {
    test(
      'confirmed 401 invalidates memory despite ${failingTokenDelete ? 'token' : 'device'} deletion failure',
      () async {
        final api = Api()..rejectSubscription = true;
        final store = Store()
          ..failTokenDelete = failingTokenDelete
          ..failDeviceDelete = !failingTokenDelete;
        final app = make(api, store)
          ..profile = f.account
          ..isInitialized = true
          ..currentDeviceId = f.device.deviceId
          ..devices = [f.device];
        addTearDown(app.dispose);
        await app.refreshSubscription();
        expect(app.profile, null);
        expect(app.devices, isEmpty);
        expect(app.currentDeviceId, null);
        expect(app.savedSessionVerificationPending, false);
        expect(app.takeSignInPrompt(), true);
        expect(app.errorMessage, contains('n’a pas pu être effacée'));
        expect(app.subscriptionErrorMessage, null);
        expect(store.storedToken == null, !failingTokenDelete);
        expect(store.tokenDeletes, 1);
        expect(store.deviceDeletes, 1);
      },
    );
  }

  test(
    'startup retained token cannot overwrite a completed newer login profile',
    () async {
      final api = Api();
      final store = Store();
      final openVpn = OpenVpn()..availabilityGate = Completer<bool>();
      final app = make(api, store, openVpn: openVpn);
      addTearDown(app.dispose);
      final initialization = app.initialize();
      await openVpn.availabilityStarted.future;
      expect(
        await app.signIn(email: 'b@example.invalid', password: 'synthetic'),
        true,
      );
      expect(app.profile, same(accountB));
      expect(store.storedToken, 'synthetic-account-b');
      openVpn.availabilityGate!.complete(false);
      await initialization;
      expect(app.profile, same(accountB));
      expect(store.storedToken, 'synthetic-account-b');
      expect(api.meTokens, ['synthetic-account-b']);
    },
  );

  test(
    'confirmed session expiry stops pending WireGuard enrollment from connecting',
    () async {
      final api = Api()..registerGate = Completer<void>();
      final store = Store();
      final wg = WireGuard();
      final app = make(api, store, wireguard: wg)
        ..profile = f.account
        ..isInitialized = true
        ..selectedLocation = f.source
        ..locations = [f.source];
      addTearDown(app.dispose);
      final connection = app.quickConnect();
      await api.registerStarted.future;
      api.rejectSubscription = true;
      await app.refreshSubscription();
      expect(app.profile, null);
      expect(store.storedToken, null);
      expect(app.takeSignInPrompt(), true);
      expect(wg.connectCalls, 0);
      api.registerGate!.complete();
      await connection;
      expect(wg.connectCalls, 0);
      expect(app.vpnStatus, isNot(VpnStatus.connected));
      expect(app.profile, null);
      expect(app.currentDeviceId, null);
      await Future<void>.delayed(Duration.zero);
      expect(store.deviceWrites, 0);
      expect(wg.protectionActive, true);
      expect(wg.disconnectCalls, 0);
      expect(app.vpnStatus, VpnStatus.blocked);
      expect(app.requiresExplicitDisconnect, true);
    },
  );

  test(
    'confirmed session expiry stops pending OpenVPN profile from connecting',
    () async {
      final api = Api()..profileGate = Completer<void>();
      final store = Store();
      final ovpn = OpenVpn();
      final app = make(api, store, openVpn: ovpn)
        ..profile = f.account
        ..isInitialized = true
        ..selectedLocation = dualSource
        ..locations = [dualSource]
        ..currentDeviceId = f.device.deviceId
        ..devices = [f.device]
        ..protocolPreference = VpnProtocolPreference.openVpn
        ..vpnProtocol = VpnProtocol.openVpn
        ..openVpnRuntimeAvailable = true;
      addTearDown(app.dispose);
      final connection = app.quickConnect();
      await api.profileStarted.future.timeout(const Duration(seconds: 5));
      api.rejectSubscription = true;
      await app.refreshSubscription();
      expect(app.profile, null);
      expect(store.storedToken, null);
      expect(ovpn.importCalls, 0);
      api.profileGate!.complete();
      await connection;
      expect(ovpn.importCalls, 0);
      expect(app.vpnStatus, isNot(VpnStatus.connected));
      expect(app.profile, null);
      await Future<void>.delayed(Duration.zero);
      expect(ovpn.protectionActive, true);
      expect(ovpn.disconnectCalls, 0);
      expect(app.vpnStatus, VpnStatus.blocked);
      expect(app.requiresExplicitDisconnect, true);
    },
  );

  test(
    'account is invalidated while persistent cleanup is still waiting',
    () async {
      final api = Api()..rejectSubscription = true;
      final store = Store()..tokenDeleteGate = Completer<void>();
      final app = make(api, store)
        ..profile = f.account
        ..isInitialized = true;
      addTearDown(app.dispose);
      final expiration = app.refreshSubscription();
      await store.tokenDeleteStarted.future;
      expect(app.profile, null);
      expect(app.takeSignInPrompt(), true);
      expect(
        await app.signIn(email: 'b@example.invalid', password: 'synthetic'),
        false,
      );
      expect(api.meTokens, isEmpty);
      store.tokenDeleteGate!.complete();
      await expiration;
    },
  );

  test(
    'expiry observes a native connection already sent without releasing protection',
    () async {
      final api = Api();
      final store = Store();
      final wg = WireGuard()..connectGate = Completer<void>();
      final app = make(api, store, wireguard: wg)
        ..profile = f.account
        ..isInitialized = true
        ..selectedLocation = f.source
        ..locations = [f.source];
      addTearDown(app.dispose);
      final connection = app.quickConnect();
      await wg.connectStarted.future;
      api.rejectSubscription = true;
      await app.refreshSubscription();
      expect(app.profile, null);
      expect(app.requiresExplicitDisconnect, true);
      wg.connectGate!.complete();
      await connection;
      await Future<void>.delayed(Duration.zero);
      expect(wg.connectCalls, 1);
      expect(wg.disconnectCalls, 0);
      expect(wg.connected, true);
      expect(wg.protectionActive, true);
      expect(app.vpnStatus, VpnStatus.connected);
      expect(app.requiresExplicitDisconnect, true);
    },
  );

  test(
    'expired OpenVPN logical device response cannot repopulate a binding',
    () async {
      final api = Api()..registerGate = Completer<void>();
      final store = Store();
      final ovpn = OpenVpn();
      final app = make(api, store, openVpn: ovpn)
        ..profile = f.account
        ..isInitialized = true
        ..selectedLocation = dualSource
        ..locations = [dualSource]
        ..protocolPreference = VpnProtocolPreference.openVpn
        ..vpnProtocol = VpnProtocol.openVpn
        ..openVpnRuntimeAvailable = true;
      addTearDown(app.dispose);
      final connection = app.quickConnect();
      await api.registerStarted.future;
      api.rejectSubscription = true;
      await app.refreshSubscription();
      api.registerGate!.complete();
      await connection;
      await Future<void>.delayed(Duration.zero);
      expect(app.currentDeviceId, null);
      expect(store.deviceWrites, 0);
      expect(ovpn.importCalls, 0);
      expect(ovpn.protectionActive, true);
      expect(app.vpnStatus, VpnStatus.blocked);
    },
  );

  test(
    'expiry during configuration trace cannot persist a stale device',
    () async {
      final api = Api();
      final store = Store();
      final wg = WireGuard();
      final app = make(api, store, wireguard: wg)
        ..profile = f.account
        ..isInitialized = true
        ..selectedLocation = f.source
        ..locations = [f.source];
      addTearDown(app.dispose);
      Future<void>? expiration;
      final stopObserving = DiagnosticLog.observe((area, event, code) {
        if (area == 'wireguard' && event == 'api_configuration_received') {
          api.rejectSubscription = true;
          expiration = app.refreshSubscription();
        }
      });
      addTearDown(stopObserving);
      await app.quickConnect();
      expect(expiration, isNotNull);
      await expiration;
      expect(app.profile, null);
      expect(app.currentDeviceId, null);
      expect(store.deviceWrites, 0);
      expect(wg.connectCalls, 0);
    },
  );

  test(
    'rejected saved-token cleanup excludes a newer login until it finishes',
    () async {
      final api = Api()..rejectSavedProfile = true;
      final store = Store()..tokenDeleteGate = Completer<void>();
      final app = make(api, store);
      addTearDown(app.dispose);
      final initialization = app.initialize();
      await store.tokenDeleteStarted.future;
      expect(
        await app.signIn(email: 'b@example.invalid', password: 'synthetic'),
        false,
      );
      expect(app.profile, null);
      store.tokenDeleteGate!.complete();
      await initialization;
      expect(
        await app.signIn(email: 'b@example.invalid', password: 'synthetic'),
        true,
      );
      expect(app.profile, same(accountB));
      expect(store.storedToken, 'synthetic-account-b');
    },
  );

  test(
    'an old expiry observation cannot restore a tunnel after logout and login B',
    () async {
      final api = Api()..registerGate = Completer<void>();
      final store = Store();
      final wg = WireGuard();
      final app = make(api, store, wireguard: wg)
        ..profile = f.account
        ..isInitialized = true
        ..selectedLocation = f.source
        ..locations = [f.source];
      addTearDown(app.dispose);
      final connection = app.quickConnect();
      await api.registerStarted.future;
      api.rejectSubscription = true;
      await app.refreshSubscription();
      final staleRead = Completer<bool>();
      wg.connectedReadGate = staleRead;
      api.registerGate!.complete();
      await connection;
      await wg.connectedReadStarted.future;
      await app.signOut();
      api.rejectSubscription = false;
      expect(
        await app.signIn(email: 'b@example.invalid', password: 'synthetic'),
        true,
      );
      staleRead.complete(true);
      await staleRead.future;
      expect(app.profile, same(accountB));
      expect(store.storedToken, 'synthetic-account-b');
      expect(app.activeProtocol, null);
      expect(app.vpnStatus, VpnStatus.disconnected);
      expect(app.requiresExplicitDisconnect, false);
      expect(wg.connectCalls, 0);
    },
  );

  test(
    'a rejected-profile trace cannot erase a login that already superseded it',
    () async {
      final api = Api()..rejectSavedProfile = true;
      final store = Store();
      final app = make(api, store);
      addTearDown(app.dispose);
      Future<bool>? login;
      final stopObserving = DiagnosticLog.observe((area, event, code) {
        if (area == 'account' &&
            event == 'saved_session_verification_rejected') {
          login = app.signIn(email: 'b@example.invalid', password: 'synthetic');
        }
      });
      addTearDown(stopObserving);
      await app.initialize();
      expect(login, isNotNull);
      expect(await login, true);
      expect(app.profile, same(accountB));
      expect(store.storedToken, 'synthetic-account-b');
      expect(store.tokenDeletes, 0);
    },
  );

  test('sign-in traces the local identity step with its duration', () async {
    final app = make(Api(), Store());
    addTearDown(app.dispose);
    final start = DiagnosticLog.recentLines.length;
    expect(
      await app.signIn(email: 'b@example.invalid', password: 'synthetic'),
      true,
    );
    final lines = DiagnosticLog.recentLines.skip(start).toList();
    int indexOf(String fields) =>
        lines.indexWhere((line) => line.contains(fields));
    final begin = indexOf('area=account event=begin stage=local_identity');
    final completed = indexOf(
      'area=account event=completed stage=local_identity duration_ms=',
    );
    expect(begin, isNonNegative);
    expect(completed, greaterThan(begin));
  });
}
