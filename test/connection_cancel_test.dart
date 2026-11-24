// SPDX-License-Identifier: MPL-2.0
// An explicit stop is always available: it cancels a running connection,
// reconnection or renewal, then disconnects, and only that releases the
// protections. Synthetic fixtures only: no network, no Windows change.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/split_tunnel.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';
import 'package:fuzevpn_windows/main.dart';

import 'device_enrollment_error_test.dart' as enrollment;

const _location = Location(
  id: 'frankfurt-01',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const _otherLocation = Location(
  id: 'paris-01',
  city: 'Paris',
  countryCode: 'FR',
  displayName: 'Paris 1',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);
const _profile = UserProfile(
  userId: 'user-cancel',
  email: 'cancel@example.invalid',
  firstName: 'Test',
  emailVerified: true,
);
const _device = VpnDevice(
  deviceId: 'device-cancel',
  name: 'FuzeVPN — Windows',
  location: _location,
  createdAt: null,
);
const _configuration = DeviceConfiguration(
  deviceId: 'device-cancel',
  address: 'address-not-logged',
  dns: [],
  serverPublicKey: 'public-material-not-logged',
  endpoint: 'endpoint-not-logged',
  allowedIps: [],
);
final _activation = OpenVpnActivation(
  deviceId: 'device-cancel',
  protocol: 'openvpn',
  certificatePem: 'certificate-not-logged',
  caCertificatePem: 'ca-not-logged',
  tlsCryptV2ClientKey: 'secret-not-logged',
  endpoint: '198.51.100.10',
  dns: const ['1.1.1.1'],
  address: '10.20.0.2/24',
  serverName: 'frankfurt-01.openvpn.internal',
  remoteCertTlsServer: true,
  ciphers: const ['AES-256-GCM'],
  // Far from expiry, whatever the real date: no renewal unless a test asks.
  notAfter: DateTime.utc(2099),
);
const _profilePending = ApiException(
  statusCode: 409,
  errorCode: 'openvpn_operation_pending',
  observedHttpStatus: 409,
  retryAfterSeconds: 10,
);

const _progressMessage =
    'La préparation OpenVPN continue. Le kill switch bloque le trafic jusqu’à la connexion ou une déconnexion explicite.';
const _interruptedMessage =
    'La connexion VPN s’est interrompue. Le kill switch bloque toujours le trafic réseau.';
const _stillBlockedMessage =
    'Le kill switch bloque toujours le trafic réseau. Réessayez la déconnexion.';
const _stillConnectedMessage =
    'Le tunnel VPN est toujours actif. Réessayez la déconnexion.';
const _unconfirmedMessage =
    'La déconnexion VPN n’a pas pu être confirmée. Réessayez la déconnexion.';

/// Holds a call until the test releases it, and tells when it began.
class _Gate {
  Completer<void> _reached = Completer<void>();
  Completer<void>? _release;
  bool _once = false;

  /// With [once], only the first call that arrives is held.
  void arm({bool once = false}) {
    _reached = Completer<void>();
    _release = Completer<void>();
    _once = once;
  }

  /// Completes once a call is waiting here.
  Future<void> get reached => _reached.future;
  bool get holding => _release != null && _reached.isCompleted;

  Future<void> pass() async {
    final release = _release;
    if (release == null) return;
    if (_once) {
      if (_reached.isCompleted) return;
      _held = release;
      _release = null;
    }
    if (!_reached.isCompleted) _reached.complete();
    await release.future;
  }

  Completer<void>? _held;

  void open() {
    final release = _release ?? _held;
    _release = null;
    _held = null;
    release?.complete();
  }
}

class _Clock {
  DateTime value = DateTime.utc(2026, 11, 12, 8);
  DateTime call() => value;
  void advance(Duration duration) => value = value.add(duration);
}

/// Every command, stop and automatic attempt ends in a state the next
/// command can begin from: checked at every notification that finds nothing
/// running, so that a wedge fails the test that produced it.
class _RestingGuard {
  _RestingGuard(this.controller) {
    controller.addListener(_check);
  }

  final AppController controller;
  final violations = <VpnStatus>[];
  static const _resting = {
    VpnStatus.disconnected,
    VpnStatus.connected,
    VpnStatus.blocked,
    VpnStatus.error,
  };

  void _check() {
    if (!controller.isConnectionBusy &&
        !_resting.contains(controller.vpnStatus)) {
      violations.add(controller.vpnStatus);
    }
  }

  void expectResting([WidgetTester? tester]) {
    if (tester != null) expect(tester.takeException(), isNull);
    expect(violations, isEmpty);
    expect(controller.isConnectionBusy, isFalse);
    expect(_resting, contains(controller.vpnStatus));
  }
}

class _CancelApi extends ApiClient {
  _CancelApi(this.log) : super(baseUri: Uri.parse('http://localhost/'));

  final List<String> log;
  final subscriptionGate = _Gate();
  final devicesGate = _Gate();
  final registerGate = _Gate();
  final createGate = _Gate();
  final revokeGate = _Gate();
  final releaseGate = _Gate();
  // Answers of the profile creation, in order; the last one repeats.
  List<Object> createResults = [_activation];
  // Answers of the device registration, in order; the last one repeats.
  List<Object> registerResults = const [_configuration];
  int createCalls = 0;
  int registerCalls = 0;
  int meCalls = 0;
  bool offline = false;
  bool unauthorized = false;

  void _reach() {
    if (offline) throw const SocketException('Simulated offline');
    if (unauthorized) {
      throw const ApiException(
        statusCode: 401,
        errorCode: 'unauthorized',
        observedHttpStatus: 401,
      );
    }
  }

  @override
  Future<Subscription> subscription(String token) async {
    log.add('api.subscription');
    await subscriptionGate.pass();
    _reach();
    return const Subscription(
      status: SubscriptionStatus.active,
      hasAccess: true,
      renewsAutomatically: false,
      cancelAtPeriodEnd: false,
    );
  }

  @override
  Future<List<Location>> locations() async {
    log.add('api.locations');
    _reach();
    return const [_location, _otherLocation];
  }

  @override
  Future<UserProfile> me(String token) async {
    log.add('api.me');
    meCalls++;
    _reach();
    return _profile;
  }

  @override
  Future<DeviceList> devices(String token) async {
    log.add('api.devices');
    await devicesGate.pass();
    _reach();
    return const DeviceList(limit: 2, devices: [_device]);
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    log.add('api.register');
    registerCalls++;
    final result = registerCalls <= registerResults.length
        ? registerResults[registerCalls - 1]
        : registerResults.last;
    await registerGate.pass();
    _reach();
    if (result is DeviceConfiguration) return result;
    throw result;
  }

  @override
  Future<void> revokeOpenVpnProfile({
    required String token,
    required String deviceId,
  }) async {
    log.add('api.release');
    await releaseGate.pass();
    _reach();
  }

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    log.add('api.create');
    createCalls++;
    final result = createCalls <= createResults.length
        ? createResults[createCalls - 1]
        : createResults.last;
    await createGate.pass();
    _reach();
    if (result is OpenVpnActivation) return result;
    throw result;
  }

  @override
  Future<void> revokeDevice({
    required String token,
    required String deviceId,
  }) async {
    log.add('api.revoke');
    await revokeGate.pass();
    _reach();
  }
}

class _CancelStore extends SecureStore {
  _CancelStore({
    required this.protocol,
    required this.killSwitchSetting,
    required this.autoConnect,
  });

  final String protocol;
  final bool killSwitchSetting;
  bool autoConnect;
  String? savedToken = 'session-not-logged';

  @override
  Future<String?> openVpnRenewalDeviceId() async => null;
  @override
  Future<String?> openVpnRenewalCsrSha256() async => null;
  @override
  Future<void> saveOpenVpnRenewalDeviceId(
    String deviceId, {
    String? csrSha256,
  }) async {}
  @override
  Future<void> clearOpenVpnRenewalDeviceId() async {}
  @override
  Future<void> saveSelectedLocation(String value) async {}
  @override
  Future<void> saveLocationMigration(StoredLocationMigration value) async {}
  @override
  Future<void> clearLocationMigration() async {}
  @override
  Future<void> clearToken() async => savedToken = null;
  @override
  Future<SecuritySettings> securitySettings() async => SecuritySettings(
    killSwitch: killSwitchSetting,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: true,
  );
  @override
  Future<SplitTunnelSettings> splitTunnelSettings() async =>
      SplitTunnelSettings.disabled;
  // Holds the write of the theme until the test releases it.
  final themeGate = _Gate();
  @override
  Future<void> saveThemeMode(String value) => themeGate.pass();
  // Holds the write of a security preference until the test releases it.
  final settingsGate = _Gate();
  @override
  Future<void> saveSecuritySettings(SecuritySettings value) =>
      settingsGate.pass();
  @override
  Future<String?> token() async => savedToken;
  @override
  Future<String?> selectedLocation() async => _location.id;
  @override
  Future<String?> currentDeviceId() async => _device.deviceId;
  @override
  Future<String?> vpnProtocol() async => protocol;
  @override
  Future<String?> themeMode() async => 'light';
  @override
  Future<String?> appLanguage() async => 'fr';
  @override
  Future<String?> autoConnectOnLaunch() async => autoConnect ? 'true' : 'false';
  @override
  Future<String?> windowsNotifications() async => 'false';
  @override
  Future<List<String>> favoriteLocationIds() async => const [];
  @override
  Future<List<String>> recentLocationIds() async => const [];
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async {}
  @override
  Future<StoredLocationMigration?> locationMigration() async => null;
  @override
  Future<void> saveCurrentDeviceId(String value) async {}
  @override
  Future<void> clearCurrentDeviceId() async {}
  @override
  Future<void> saveVpnProtocol(String value) async {}
}

class _CancelWindow extends WindowBridge {
  Future<void> Function(WindowsConnectivityEvent event)? listener;
  int quits = 0;

  @override
  Future<String> deviceName() async => 'FuzeVPN 0.1.0 -- Windows';
  @override
  Future<bool> isLaunchAtStartupEnabled() async => false;
  @override
  Future<void> quit() async => quits++;
  @override
  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent event) handler,
  ) {
    listener = handler;
  }

  @override
  void stopConnectivityListener() => listener = null;

  Future<void> emit(WindowsConnectivityEvent event) async {
    await listener?.call(event);
  }
}

/// The update check is skipped; an installation runs the VPN cleanup the
/// controller hands it and then reports that nothing was launched.
class _Updates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}

  @override
  Future<bool> installPreparedUpdate({
    Future<void> Function()? beforeInstall,
  }) async {
    await beforeInstall?.call();
    return false;
  }
}

/// The state both native fakes keep: a tunnel, a WFP policy and, when no
/// runtime process exists, the persisted policy the interface reads itself.
mixin _NativeState {
  List<String> get log;
  String get tag;
  bool connected = false;
  bool protectionActive = false;
  // What the applied policy does, whatever the saved preference says.
  bool appliedKillSwitch = true;
  bool ownedByAnotherUser = false;
  // No privileged runtime process exists (see runtime_absent_policy.h).
  bool runtimeAbsent = false;
  // Every status read fails.
  bool statusUnavailable = false;
  // Windows does not let the persisted policy be read: the tunnel reads
  // still answer, the protection reads do not.
  bool protectionUnreadable = false;
  bool cacheAvailable = true;
  bool failReconnect = false;
  bool failDisconnect = false;
  // The disconnect is acknowledged, but the policy stays.
  bool keepProtectionOnDisconnect = false;
  int prepareCalls = 0;
  int reconnectCalls = 0;
  int disconnectCalls = 0;
  int suspendCalls = 0;
  // Reads of the tunnel or of the policy, whether they answer or not.
  int statusReads = 0;
  final reconnectGate = _Gate();
  final disconnectGate = _Gate();
  final suspendGate = _Gate();
  // Holds a read of the tunnel state, as a slow broker would.
  final connectedReadGate = _Gate();

  void _readable() {
    statusReads++;
    if (statusUnavailable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
  }

  Future<void> nativePrepare() async {
    prepareCalls++;
    log.add('$tag.prepare');
    // Like a connection, this starts the runtime that does not exist.
    runtimeAbsent = false;
    protectionActive = true;
  }

  Future<bool> nativeReconnect() async {
    reconnectCalls++;
    log.add('$tag.reconnect');
    await reconnectGate.pass();
    // No runtime process: nothing to reconnect, and nothing is started.
    if (runtimeAbsent || !cacheAvailable) return false;
    if (failReconnect) {
      connected = false;
      throw PlatformException(code: 'broker_response_timeout');
    }
    connected = true;
    log.add('$tag.reconnect:done');
    return true;
  }

  Future<bool> nativeIsConnected() async {
    _readable();
    // Like the broker, the answer is the state when the read began.
    final answer = connected;
    await connectedReadGate.pass();
    return answer;
  }

  Future<bool> nativeIsProtectionActive() async {
    _readable();
    if (protectionUnreadable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return protectionActive;
  }

  Future<NetworkProtectionStatus> nativeProtectionStatus() async {
    _readable();
    if (protectionUnreadable) {
      throw PlatformException(code: 'runtime_status_unavailable');
    }
    return NetworkProtectionStatus.fromMap({
      'active': protectionActive,
      'killSwitch': appliedKillSwitch,
      'phase': !protectionActive
          ? 'inactive'
          : connected
          ? 'tunnel'
          : 'prepared',
      'ownedByAnotherUser': ownedByAnotherUser,
      // Only the interface's own answer ever carries this key.
      if (runtimeAbsent) 'runtimeAbsent': true,
    });
  }

  Future<void> nativeDisconnect() async {
    disconnectCalls++;
    log.add('$tag.disconnect');
    await disconnectGate.pass();
    if (failDisconnect) {
      throw PlatformException(code: 'broker_response_timeout');
    }
    // The explicit stop is forwarded to a runtime started for it.
    runtimeAbsent = false;
    connected = false;
    if (!keepProtectionOnDisconnect) protectionActive = false;
  }

  Future<void> nativeSuspend() async {
    suspendCalls++;
    log.add('$tag.suspend');
    await suspendGate.pass();
    connected = false;
  }
}

class _CancelWireGuard extends WireGuardBridge with _NativeState {
  _CancelWireGuard(this.log);

  @override
  final List<String> log;
  @override
  String get tag => 'wg';
  bool failConnect = false;
  int connectCalls = 0;
  final connectGate = _Gate();

  @override
  Future<void> prepareNetworkProtection() => nativePrepare();
  @override
  Future<bool> reconnect() => nativeReconnect();
  @override
  Future<bool> isConnected() => nativeIsConnected();
  @override
  Future<bool> isNetworkProtectionActive() => nativeIsProtectionActive();
  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() =>
      nativeProtectionStatus();
  @override
  Future<void> disconnect() => nativeDisconnect();
  @override
  Future<void> suspendForMigration() => nativeSuspend();
  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      'public-key-not-logged';
  @override
  Future<void> prepareIdentityForAccount(String accountId) async {}
  @override
  Future<void> resetIdentity() async {
    connected = false;
    protectionActive = false;
  }

  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectCalls++;
    log.add('wg.connect');
    await connectGate.pass();
    if (failConnect) {
      connected = false;
      throw PlatformException(code: 'wireguard_start_failed');
    }
    runtimeAbsent = false;
    connected = true;
    protectionActive = true;
    log.add('wg.connect:done');
  }
}

class _CancelOpenVpn extends OpenVpnBridge with _NativeState {
  _CancelOpenVpn(this.log);

  @override
  final List<String> log;
  @override
  String get tag => 'ovpn';
  String? importFailure;
  int importCalls = 0;
  final importGate = _Gate();

  @override
  Future<bool> isAvailable() async => true;
  @override
  Future<void> prepareNetworkProtection() => nativePrepare();
  @override
  Future<bool> reconnect() => nativeReconnect();
  @override
  Future<bool> isConnected() => nativeIsConnected();
  @override
  Future<bool> isNetworkProtectionActive() => nativeIsProtectionActive();
  @override
  Future<NetworkProtectionStatus> networkProtectionStatus() =>
      nativeProtectionStatus();
  @override
  Future<void> disconnect() => nativeDisconnect();
  @override
  Future<void> suspendForMigration() => nativeSuspend();
  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async => 'csr-not-logged';
  @override
  Future<void> deleteProfile() async {}

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importCalls++;
    log.add('ovpn.import');
    await importGate.pass();
    if (importFailure case final code?) {
      connected = false;
      throw PlatformException(code: code);
    }
    runtimeAbsent = false;
    connected = true;
    protectionActive = true;
    log.add('ovpn.import:done');
  }
}

class _Harness {
  _Harness({
    required bool killSwitch,
    String protocol = 'wireguard',
    bool autoConnect = false,
  }) : store = _CancelStore(
         protocol: protocol,
         killSwitchSetting: killSwitch,
         autoConnect: autoConnect,
       ) {
    api = _CancelApi(log);
    wireGuard = _CancelWireGuard(log)..appliedKillSwitch = killSwitch;
    openVpn = _CancelOpenVpn(log)..appliedKillSwitch = killSwitch;
    controller = AppController(
      api: api,
      store: store,
      wireguard: wireGuard,
      openVpn: openVpn,
      window: window,
      updates: _Updates(),
      now: clock.call,
    );
    controller.addListener(() => statuses.add(controller.vpnStatus));
    guard = _RestingGuard(controller);
  }

  final log = <String>[];
  final statuses = <VpnStatus>[];
  final clock = _Clock();
  final window = _CancelWindow();
  final _CancelStore store;
  late final _CancelApi api;
  late final _CancelWireGuard wireGuard;
  late final _CancelOpenVpn openVpn;
  late final AppController controller;
  late final _RestingGuard guard;

  Iterable<String> get apiCalls => log.where((call) => call.startsWith('api.'));

  /// What reached the API or changed a tunnel or a policy since [mark].
  List<String> since(int mark) => log.skip(mark).toList();

  Future<void> start() => controller.initialize();

  /// A tunnel connected before this window opened.
  void attachTunnel(VpnProtocol protocol, {required bool killSwitch}) {
    final _NativeState native = protocol == VpnProtocol.wireGuard
        ? wireGuard
        : openVpn;
    native
      ..connected = true
      ..protectionActive = killSwitch;
  }

  /// The tunnel monitor finds the tunnel down twice, as its timer would.
  Future<void> dropTunnel(VpnProtocol protocol) async {
    final _NativeState native = protocol == VpnProtocol.wireGuard
        ? wireGuard
        : openVpn;
    native.connected = false;
    await controller.checkTunnelHealthNow();
    await controller.checkTunnelHealthNow();
  }

  void expectReleased() {
    expect(controller.vpnStatus, VpnStatus.disconnected);
    expect(controller.requiresExplicitDisconnect, isFalse);
    expect(controller.activeProtocol, isNull);
    expect(wireGuard.connected, isFalse);
    expect(openVpn.connected, isFalse);
    expect(wireGuard.protectionActive, isFalse);
    expect(openVpn.protectionActive, isFalse);
  }
}

/// Lets a command, a stop or a native recovery run to its end in fake time.
Future<void> _settle(WidgetTester tester, AppController controller) async {
  for (var tick = 0; tick < 80 && controller.isConnectionBusy; tick++) {
    await tester.pump(const Duration(milliseconds: 200));
  }
  await tester.pump();
}

String _label(bool killSwitch) =>
    killSwitch ? 'kill switch actif' : 'kill switch inactif';

void main() {
  group('NetworkProtectionStatus.runtimeAbsent', () {
    test('est absent par défaut et lu seulement comme booléen', () {
      final ordinary = NetworkProtectionStatus.fromMap(const {
        'active': true,
        'killSwitch': true,
        'phase': 'prepared',
      });
      expect(ordinary.runtimeAbsent, isFalse);
      final persisted = NetworkProtectionStatus.fromMap(const {
        'active': true,
        'killSwitch': true,
        'phase': 'prepared',
        'ownedByAnotherUser': false,
        'runtimeAbsent': true,
      });
      expect(persisted.runtimeAbsent, isTrue);
      expect(persisted.blocksTraffic, isTrue);
      expect(
        () => NetworkProtectionStatus.fromMap(const {
          'active': true,
          'killSwitch': true,
          'phase': 'prepared',
          'runtimeAbsent': 'true',
        }),
        throwsFormatException,
      );
    });
  });

  for (final killSwitch in [true, false]) {
    final mode = _label(killSwitch);

    testWidgets('T1 annuler pendant la vérification de l’abonnement arrête '
        'sans rien préparer ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch);
      await h.start();
      h.api.subscriptionGate.arm();
      final connecting = h.controller.quickConnect();
      await h.api.subscriptionGate.reached;
      expect(h.controller.vpnStatus, VpnStatus.preparing);
      expect(h.controller.canCancelConnection, isTrue);
      expect(h.controller.canDisconnectVpn, isTrue);
      // Nothing is armed yet: the window offers Cancel, not Disconnect.
      expect(h.controller.requiresExplicitDisconnect, isFalse);
      final mark = h.log.length;

      final stopping = h.controller.disconnectVpn();
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);
      expect(h.controller.canCancelConnection, isFalse);
      expect(h.controller.canDisconnectVpn, isFalse);
      expect(h.controller.isStoppingVpn, isTrue);
      // The request in flight is waited for: nothing is sent meanwhile.
      await tester.pump(const Duration(seconds: 5));
      expect(h.since(mark), isEmpty);
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);

      h.api.subscriptionGate.open();
      await stopping;
      await connecting;

      // Both protocols are asked to stop, and nothing else happened.
      expect(h.since(mark), ['wg.disconnect', 'ovpn.disconnect']);
      expect(h.wireGuard.prepareCalls, 0);
      expect(h.wireGuard.connectCalls, 0);
      expect(h.openVpn.importCalls, 0);
      expect(h.controller.isStoppingVpn, isFalse);
      expect(h.controller.errorMessage, isNull);
      h.expectReleased();
      h.guard.expectResting(tester);
      expect(h.statuses, isNot(contains(VpnStatus.connected)));
      h.controller.dispose();
    });

    for (final step in ['la liste des appareils', 'la création du profil']) {
      testWidgets('T2 annuler OpenVPN pendant $step libère les protections '
          'sans autre requête ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch, protocol: 'openvpn');
        await h.start();
        final gate = step == 'la liste des appareils'
            ? h.api.devicesGate
            : h.api.createGate;
        gate.arm();
        final connecting = h.controller.quickConnect();
        await gate.reached;
        // The kill switch is armed before any enrollment request.
        expect(h.openVpn.protectionActive, killSwitch);
        expect(h.controller.requiresExplicitDisconnect, killSwitch);
        expect(h.controller.canCancelConnection, isTrue);
        final mark = h.log.length;

        final stopping = h.controller.disconnectVpn();
        expect(h.controller.vpnStatus, VpnStatus.disconnecting);
        gate.open();
        await stopping;
        await connecting;

        expect(h.since(mark), ['wg.disconnect', 'ovpn.disconnect']);
        expect(h.openVpn.importCalls, 0);
        h.expectReleased();
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    for (final late in ['réussit', 'échoue']) {
      testWidgets('T3/T4 annuler pendant un import OpenVPN qui $late ensuite '
          'finit déconnecté ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch, protocol: 'openvpn');
        await h.start();
        if (late == 'échoue') {
          h.openVpn.importFailure = 'openvpn_connection_timeout';
        }
        h.openVpn.importGate.arm();
        final connecting = h.controller.quickConnect();
        await h.openVpn.importGate.reached;
        expect(h.controller.vpnStatus, VpnStatus.connecting);
        expect(h.controller.canCancelConnection, isTrue);
        final mark = h.log.length;

        final stopping = h.controller.disconnectVpn();
        // The native call cannot be aborted: the stop waits behind it.
        await tester.pump(const Duration(seconds: 20));
        expect(h.since(mark), isEmpty);
        expect(h.controller.vpnStatus, VpnStatus.disconnecting);
        h.openVpn.importGate.open();
        await stopping;
        await connecting;

        // The disconnect runs after the import, so that a tunnel that came
        // up late is stopped and its policy released.
        expect(h.since(mark), [
          if (late == 'réussit') 'ovpn.import:done',
          'wg.disconnect',
          'ovpn.disconnect',
        ]);
        expect(h.statuses, isNot(contains(VpnStatus.connected)));
        expect(h.statuses, isNot(contains(VpnStatus.blocked)));
        h.expectReleased();
        // Nothing was scheduled by the cancelled attempt.
        final settled = h.log.length;
        await tester.pump(const Duration(seconds: 120));
        expect(h.since(settled), isEmpty);
        h.expectReleased();
        h.guard.expectResting(tester);
        h.controller.dispose();
      });

      testWidgets('T5 annuler pendant une connexion WireGuard qui $late '
          'ensuite finit déconnecté ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch);
        await h.start();
        h.wireGuard.failConnect = late == 'échoue';
        h.wireGuard.connectGate.arm();
        final connecting = h.controller.quickConnect();
        await h.wireGuard.connectGate.reached;
        expect(h.controller.vpnStatus, VpnStatus.connecting);
        final mark = h.log.length;

        final stopping = h.controller.disconnectVpn();
        await tester.pump(const Duration(seconds: 20));
        expect(h.since(mark), isEmpty);
        h.wireGuard.connectGate.open();
        await stopping;
        await connecting;

        expect(h.since(mark), [
          if (late == 'réussit') 'wg.connect:done',
          'wg.disconnect',
          'ovpn.disconnect',
        ]);
        expect(h.statuses, isNot(contains(VpnStatus.connected)));
        expect(h.statuses, isNot(contains(VpnStatus.blocked)));
        h.expectReleased();
        final settled = h.log.length;
        await tester.pump(const Duration(seconds: 120));
        expect(h.since(settled), isEmpty);
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    testWidgets('T6 annuler pendant l’attente du profil en préparation met '
        'fin à la commande sans nouvelle création ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch, protocol: 'openvpn');
      await h.start();
      h.api.createResults = [_profilePending, _activation];
      final connecting = h.controller.quickConnect();
      await tester.pump();
      expect(h.api.createCalls, 1);
      expect(h.controller.isConnectionBusy, isTrue);
      // Under the kill switch, the wait says that the preparation continues.
      expect(h.controller.errorMessage, killSwitch ? _progressMessage : isNull);
      expect(h.controller.canCancelConnection, isTrue);
      final mark = h.log.length;

      final stopping = h.controller.disconnectVpn();
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);
      // The pause in flight (Retry-After: 10 s) is the only wait left.
      await tester.pump(const Duration(seconds: 9));
      expect(h.controller.isConnectionBusy, isTrue);
      await tester.pump(const Duration(seconds: 1));
      await stopping;
      await connecting;

      expect(h.api.createCalls, 1);
      expect(h.since(mark), ['wg.disconnect', 'ovpn.disconnect']);
      expect(h.controller.errorMessage, isNull);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T7 annuler une reconnexion automatique en cours l’arrête '
        'pour de bon, même si elle aboutit ensuite ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      expect(h.controller.vpnStatus, VpnStatus.connected);
      await h.dropTunnel(VpnProtocol.wireGuard);
      expect(
        h.controller.vpnStatus,
        killSwitch ? VpnStatus.blocked : VpnStatus.disconnected,
      );
      h.wireGuard.reconnectGate.arm();
      await tester.pump(const Duration(seconds: 3));
      await h.wireGuard.reconnectGate.reached;
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.controller.vpnStatus, VpnStatus.connecting);
      expect(h.controller.canCancelConnection, isTrue);
      final mark = h.log.length;
      final from = h.statuses.length;

      final stopping = h.controller.disconnectVpn();
      // The native replay succeeds after the cancellation.
      h.wireGuard.reconnectGate.open();
      await stopping;

      expect(h.since(mark), [
        'wg.reconnect:done',
        'wg.disconnect',
        'ovpn.disconnect',
      ]);
      expect(h.statuses.skip(from), isNot(contains(VpnStatus.connected)));
      h.expectReleased();
      // No further attempt, whatever the network reports.
      h.clock.advance(const Duration(seconds: 60));
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 120));
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.wireGuard.connectCalls, 0);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    for (final entry in ['disconnectVpn', 'toggleConnection']) {
      testWidgets('T8 arrêter ($entry) entre deux tentatives automatiques '
          'sous kill switch annule la suivante (préférence : $mode)', (
        tester,
      ) async {
        final h = _Harness(killSwitch: killSwitch)
          ..attachTunnel(VpnProtocol.wireGuard, killSwitch: true);
        h.wireGuard.appliedKillSwitch = true;
        await h.start();
        await h.dropTunnel(VpnProtocol.wireGuard);
        h.wireGuard.failReconnect = true;
        await tester.pump(const Duration(seconds: 3));
        await _settle(tester, h.controller);
        expect(h.wireGuard.reconnectCalls, 1);
        // The next attempt is armed, six seconds away.
        expect(h.controller.vpnStatus, VpnStatus.blocked);
        expect(h.controller.isConnectionBusy, isFalse);
        expect(h.controller.canCancelConnection, isFalse);
        expect(h.controller.canDisconnectVpn, isTrue);

        await (entry == 'disconnectVpn'
            ? h.controller.disconnectVpn()
            : h.controller.toggleConnection());
        h.expectReleased();
        // The tunnel could be replayed again: nothing tries to.
        h.wireGuard.failReconnect = false;
        await tester.pump(const Duration(seconds: 120));
        expect(h.wireGuard.reconnectCalls, 1);
        expect(h.wireGuard.connectCalls, 0);
        h.expectReleased();
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    testWidgets('T8 arrêter entre deux tentatives automatiques annule la '
        'suivante ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      await h.dropTunnel(VpnProtocol.wireGuard);
      h.wireGuard.failReconnect = true;
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.controller.isConnectionBusy, isFalse);

      if (killSwitch) {
        // Between attempts the retained kill switch offers Disconnect.
        expect(h.controller.vpnStatus, VpnStatus.blocked);
        expect(h.controller.canCancelConnection, isFalse);
        expect(h.controller.canDisconnectVpn, isTrue);
        await h.controller.disconnectVpn();
        h.expectReleased();
      } else {
        // Nothing is retained between attempts: there is nothing to stop
        // until the next one runs, which can then be cancelled.
        expect(h.controller.requiresExplicitDisconnect, isFalse);
        expect(h.controller.canDisconnectVpn, isFalse);
        await h.controller.disconnectVpn();
        expect(h.wireGuard.disconnectCalls, 0);
        h.wireGuard.reconnectGate.arm();
        await tester.pump(const Duration(seconds: 6));
        await h.wireGuard.reconnectGate.reached;
        expect(h.wireGuard.reconnectCalls, 2);
        expect(h.controller.canCancelConnection, isTrue);
        final stopping = h.controller.disconnectVpn();
        h.wireGuard.reconnectGate.open();
        await stopping;
        await _settle(tester, h.controller);
        h.expectReleased();
      }
      final attempts = h.wireGuard.reconnectCalls;
      await tester.pump(const Duration(seconds: 120));
      expect(h.wireGuard.reconnectCalls, attempts);
      expect(h.wireGuard.connectCalls, 0);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T9 au démarrage sous un kill switch conservé, Déconnecter '
        'interrompt la reprise et rien ne se connecte ensuite '
        '(préférence : $mode)', (tester) async {
      // The applied policy blocks traffic whatever the saved preference.
      final h = _Harness(killSwitch: killSwitch, autoConnect: true);
      h.wireGuard
        ..protectionActive = true
        ..appliedKillSwitch = true;
      h.wireGuard.reconnectGate.arm();
      final starting = h.start();
      await h.wireGuard.reconnectGate.reached;

      // The first automatic attempt runs before the window is initialized.
      expect(h.controller.isInitialized, isFalse);
      expect(h.controller.isConnectionCommandRunning, isTrue);
      expect(h.controller.canCancelConnection, isTrue);
      expect(h.controller.canDisconnectVpn, isTrue);
      expect(h.controller.requiresExplicitDisconnect, isTrue);
      expect(h.apiCalls, isEmpty);
      // The first answer, if any, must not validate the session yet.
      h.api.offline = true;

      final stopping = h.controller.disconnectVpn();
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);
      h.wireGuard.reconnectGate.open();
      await stopping;
      await starting;

      expect(h.controller.isInitialized, isTrue);
      h.expectReleased();
      // No request left this window before the protection was released.
      final released = h.log.indexOf('wg.disconnect');
      expect(released, isNot(-1));
      expect(
        h.log.take(released).where((call) => call.startsWith('api.')),
        isEmpty,
      );
      await tester.pump();
      expect(h.controller.profile, isNull);
      expect(h.controller.savedSessionVerificationPending, isTrue);

      // The network comes back: the saved session is validated, but the
      // launch connection the user interrupted is not started.
      h.api.offline = false;
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await _settle(tester, h.controller);
      expect(h.controller.profile, isNotNull);
      expect(h.controller.autoConnectOnLaunch, isTrue);
      await tester.pump(const Duration(seconds: 120));
      expect(h.wireGuard.connectCalls, 0);
      expect(h.wireGuard.reconnectCalls, 1);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T9 dans la fenêtre, la reprise au démarrage montre son '
        'état et un Déconnecter actif qui rétablit Internet '
        '(préférence : $mode)', (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(1080, 640);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.view.resetPhysicalSize);
      final h = _Harness(killSwitch: killSwitch);
      h.wireGuard
        ..protectionActive = true
        ..appliedKillSwitch = true;
      h.wireGuard.reconnectGate.arm();
      // The application starts the controller itself.
      await tester.pumpWidget(FuzeVpnApp(controller: h.controller));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 100));
      final primary = find.byKey(const ValueKey('connection-primary-action'));

      // Not the disabled "checking protection" notice: the attempt itself.
      expect(h.controller.isInitialized, isFalse);
      expect(h.wireGuard.reconnectGate.holding, isTrue);
      expect(find.text('Vérification de la protection…'), findsNothing);
      expect(find.text('Connexion en cours'), findsOneWidget);
      expect(
        find.descendant(of: primary, matching: find.text('Déconnecter')),
        findsOneWidget,
      );
      expect(tester.widget<FilledButton>(primary).onPressed, isNotNull);

      await tester.tap(primary);
      await tester.pump();
      expect(find.text('Déconnexion en cours'), findsOneWidget);
      expect(tester.widget<FilledButton>(primary).onPressed, isNull);
      expect(h.wireGuard.protectionActive, isTrue);

      // The native call in flight returns; only then is the stop sent.
      h.wireGuard.reconnectGate.open();
      await tester.pump();
      await _settle(tester, h.controller);
      await tester.pump(const Duration(milliseconds: 500));

      expect(find.text('Non protégé'), findsOneWidget);
      expect(find.text('Trafic bloqué'), findsNothing);
      h.expectReleased();
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.wireGuard.connectCalls, 0);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
      h.controller.dispose();
    });

    testWidgets('T12 un arrêt qui échoue garde le tunnel et sa protection, '
        'sans reconnexion, puis réussit au second essai ($mode)', (
      tester,
    ) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      h.wireGuard.failDisconnect = true;

      final failing = h.controller.disconnectVpn();
      await _settle(tester, h.controller);
      await failing;

      // No release is claimed: the native truth is shown.
      expect(h.controller.vpnStatus, VpnStatus.connected);
      expect(h.controller.errorMessage, _stillConnectedMessage);
      expect(h.controller.requiresExplicitDisconnect, isTrue);
      expect(h.controller.canDisconnectVpn, isTrue);
      expect(h.wireGuard.connected, isTrue);
      expect(h.wireGuard.protectionActive, killSwitch);
      h.guard.expectResting(tester);

      // The user asked to stop: the tunnel that then drops is not
      // reconnected on its own, and its kill switch stays.
      await h.dropTunnel(VpnProtocol.wireGuard);
      h.clock.advance(const Duration(seconds: 60));
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 120));
      expect(h.wireGuard.reconnectCalls, 0);
      expect(h.wireGuard.connectCalls, 0);
      expect(h.wireGuard.protectionActive, killSwitch);
      if (killSwitch) {
        expect(h.controller.vpnStatus, VpnStatus.blocked);
        expect(h.controller.errorMessage, _interruptedMessage);

        // A second failure under the kill switch names it.
        final again = h.controller.disconnectVpn();
        await _settle(tester, h.controller);
        await again;
        expect(h.controller.vpnStatus, VpnStatus.blocked);
        expect(h.controller.errorMessage, _stillBlockedMessage);
        expect(h.wireGuard.protectionActive, isTrue);

        h.wireGuard.failDisconnect = false;
        await h.controller.disconnectVpn();
      }
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T13 après une annulation, un arrêt acquitté qui laisse la '
        'protection en place n’est jamais annoncé déconnecté ($mode)', (
      tester,
    ) async {
      final h = _Harness(killSwitch: killSwitch);
      await h.start();
      h.wireGuard
        ..keepProtectionOnDisconnect = true
        ..appliedKillSwitch = true;
      h.wireGuard.connectGate.arm();
      final connecting = h.controller.quickConnect();
      await h.wireGuard.connectGate.reached;
      final from = h.statuses.length;

      final stopping = h.controller.disconnectVpn();
      // The tunnel comes up late, with its policy.
      h.wireGuard.connectGate.open();
      await stopping;
      await connecting;

      expect(h.wireGuard.disconnectCalls, greaterThanOrEqualTo(1));
      expect(h.wireGuard.protectionActive, isTrue);
      expect(h.statuses.skip(from), isNot(contains(VpnStatus.disconnected)));
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      expect(h.controller.errorMessage, _stillBlockedMessage);
      expect(h.controller.requiresExplicitDisconnect, isTrue);
      h.guard.expectResting(tester);

      // Once the policy really goes, the same button releases it.
      h.wireGuard.keepProtectionOnDisconnect = false;
      await h.controller.disconnectVpn();
      h.expectReleased();
      h.controller.dispose();
    });

    testWidgets('T14 les demandes d’arrêt sont à vol unique et rien d’autre '
        'ne démarre pendant un arrêt ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      h.wireGuard.disconnectGate.arm();
      final first = h.controller.disconnectVpn();
      final second = h.controller.disconnectVpn();
      expect(identical(first, second), isTrue);
      await h.wireGuard.disconnectGate.reached;
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);
      expect(h.controller.isStoppingVpn, isTrue);
      expect(h.controller.canCancelConnection, isFalse);

      // Every other command joins the stop instead of starting.
      final others = [
        h.controller.quickConnect(),
        h.controller.toggleConnection(),
        h.controller.retryConnection(),
        h.controller.renewOpenVpnProfile(),
      ];
      await tester.pump(const Duration(seconds: 5));
      expect(h.log.where((call) => call.endsWith('.disconnect')), [
        'wg.disconnect',
      ]);

      h.wireGuard.disconnectGate.open();
      await first;
      await Future.wait(others);
      await _settle(tester, h.controller);

      // One disconnect sequence, and no connection.
      expect(h.wireGuard.disconnectCalls, 1);
      expect(h.wireGuard.connectCalls, 0);
      expect(h.wireGuard.prepareCalls, 0);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T14 une commande demandée à l’instant où la commande '
        'annulée se termine rejoint l’arrêt ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch);
      await h.start();
      h.wireGuard.connectGate.arm();
      final connecting = h.controller.quickConnect();
      await h.wireGuard.connectGate.reached;
      // Registered before the stop, like the startup that awaits its own
      // attempt: it resumes first, when no command runs any more and the
      // disconnect of the stop has not begun.
      Future<void>? joined;
      var busyThen = false;
      var stoppingThen = false;
      unawaited(
        connecting.then((_) {
          busyThen = h.controller.isConnectionCommandRunning;
          stoppingThen = h.controller.isStoppingVpn;
          joined = h.controller.quickConnect();
        }),
      );
      final stopping = h.controller.disconnectVpn();
      h.wireGuard.connectGate.open();
      await stopping;
      await connecting;
      await joined;
      await _settle(tester, h.controller);

      expect(busyThen, isFalse);
      expect(stoppingThen, isTrue);
      // It joined the stop: it neither connected nor broke the state.
      expect(identical(joined, stopping), isTrue);
      expect(h.wireGuard.connectCalls, 1);
      expect(h.api.registerCalls, 1);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    for (final entry in ['toggleConnection', 'quickConnect']) {
      testWidgets('T14 un arrêt demandé pendant une déconnexion ordinaire '
          '($entry) la rejoint ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch)
          ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
        await h.start();
        h.wireGuard.disconnectGate.arm();
        final disconnecting = entry == 'toggleConnection'
            ? h.controller.toggleConnection()
            : h.controller.quickConnect();
        await h.wireGuard.disconnectGate.reached;
        // A command that only disconnects is not cancellable.
        expect(h.controller.isConnectionCommandRunning, isTrue);
        expect(h.controller.canCancelConnection, isFalse);
        expect(h.controller.canDisconnectVpn, isFalse);

        final stop = h.controller.disconnectVpn();
        expect(identical(stop, disconnecting), isTrue);
        expect(h.controller.isStoppingVpn, isFalse);

        h.wireGuard.disconnectGate.open();
        await disconnecting;
        expect(h.wireGuard.disconnectCalls, 1);
        h.expectReleased();
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    for (final recovers in [true, false]) {
      testWidgets('T15 dans un état inconnu, Déconnecter arrête les deux '
          'protocoles puis ${recovers ? 'confirme' : 'ne peut pas confirmer'} '
          'l’arrêt ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch);
        h.wireGuard.statusUnavailable = true;
        h.openVpn.statusUnavailable = true;
        await h.start();
        expect(h.controller.runtimeVerificationPending, isTrue);
        // Let the passive retries end: they never disconnect anything.
        await tester.pump(const Duration(seconds: 10));
        await _settle(tester, h.controller);
        expect(h.log.where((call) => call.endsWith('.disconnect')), isEmpty);
        expect(h.controller.runtimeVerificationPending, isTrue);
        expect(h.controller.canCancelConnection, isFalse);
        expect(h.controller.canDisconnectVpn, isTrue);

        // A passive retry stays passive.
        await h.controller.quickConnect();
        expect(h.log.where((call) => call.endsWith('.disconnect')), isEmpty);

        if (recovers) {
          h.wireGuard.statusUnavailable = false;
          h.openVpn.statusUnavailable = false;
        }
        final mark = h.log.length;
        final stopping = h.controller.disconnectVpn();
        await _settle(tester, h.controller);
        await stopping;

        // Both protocols are asked to stop before anything else happens.
        expect(h.since(mark).take(2), ['wg.disconnect', 'ovpn.disconnect']);
        expect(h.controller.runtimeVerificationPending, isFalse);
        if (recovers) {
          h.expectReleased();
          expect(h.controller.errorMessage, isNull);
          // The session left unverified under the unknown state is
          // validated once the release is confirmed, and only then.
          await _settle(tester, h.controller);
          expect(h.since(mark).skip(2), everyElement(startsWith('api.')));
          expect(h.controller.profile, isNotNull);
          expect(h.wireGuard.connectCalls, 0);
        } else {
          expect(h.since(mark), hasLength(2));
          expect(h.controller.vpnStatus, VpnStatus.error);
          expect(h.controller.errorMessage, _unconfirmedMessage);
          expect(h.controller.requiresExplicitDisconnect, isTrue);
          expect(h.controller.canDisconnectVpn, isTrue);
        }
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    testWidgets('T15 aucune vérification passive ne s’intercale dans un '
        'arrêt demandé depuis un état inconnu ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch);
      h.wireGuard.statusUnavailable = true;
      h.openVpn.statusUnavailable = true;
      await h.start();
      expect(h.controller.runtimeVerificationPending, isTrue);
      h.wireGuard.disconnectGate.arm();
      final stopping = h.controller.disconnectVpn();
      await h.wireGuard.disconnectGate.reached;
      expect(h.controller.runtimeVerificationPending, isTrue);
      final reads = h.wireGuard.statusReads + h.openVpn.statusReads;

      // The automatic retries (250 ms, 1 s and 2 s) fall inside the stop,
      // and so does a retry asked for from a stale menu.
      await tester.pump(const Duration(seconds: 5));
      await h.controller.retryRuntimeVerification();
      final joined = h.controller.quickConnect();
      await tester.pump();
      expect(h.wireGuard.statusReads + h.openVpn.statusReads, reads);
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);

      h.wireGuard.statusUnavailable = false;
      h.openVpn.statusUnavailable = false;
      h.wireGuard.disconnectGate.open();
      await stopping;
      await joined;
      h.expectReleased();
      expect(h.controller.runtimeVerificationPending, isFalse);
      await _settle(tester, h.controller);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T16 les événements réseau relancent le cycle de reprise au '
        'plus cinq fois par épisode ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      await h.dropTunnel(VpnProtocol.wireGuard);
      h.wireGuard.failReconnect = true;

      // Each event restarts the cycle: one attempt three seconds later.
      for (var restart = 1; restart <= 5; restart++) {
        await h.window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await _settle(tester, h.controller);
        expect(h.wireGuard.reconnectCalls, restart);
      }
      // A sixth event restarts nothing: the cycle in progress runs its four
      // remaining attempts (6, 12, 24 and 48 s apart) and then stops.
      for (var extra = 0; extra < 3; extra++) {
        await h.window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 2));
        await _settle(tester, h.controller);
      }
      await tester.pump(const Duration(seconds: 200));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 9);
      for (var extra = 0; extra < 3; extra++) {
        await h.window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 200));
        await _settle(tester, h.controller);
      }
      expect(h.wireGuard.reconnectCalls, 9);
      expect(h.controller.isConnectionBusy, isFalse);
      // The retained state still offers its stop.
      expect(h.controller.canDisconnectVpn, killSwitch);
      expect(h.wireGuard.protectionActive, killSwitch);
      h.guard.expectResting(tester);

      // A system resume opens a new episode.
      await h.window.emit(WindowsConnectivityEvent.systemResumed);
      await tester.pump(const Duration(seconds: 2));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 10);
      for (var restart = 1; restart <= 5; restart++) {
        await h.window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await _settle(tester, h.controller);
        expect(h.wireGuard.reconnectCalls, 10 + restart);
      }
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 15);

      // So does a successful connection: every later event is followed by
      // its check, well beyond five of them.
      h.wireGuard.failReconnect = false;
      await tester.pump(const Duration(seconds: 200));
      await _settle(tester, h.controller);
      expect(h.controller.vpnStatus, VpnStatus.connected);
      final connectedAfter = h.wireGuard.reconnectCalls;
      for (var event = 1; event <= 7; event++) {
        h.clock.advance(const Duration(seconds: 13));
        await h.window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 3));
        await _settle(tester, h.controller);
        expect(h.wireGuard.reconnectCalls, connectedAfter + event);
        expect(h.controller.vpnStatus, VpnStatus.connected);
      }
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T17 ce qui arrête déjà le VPN ne s’annule pas, un '
        'changement de serveur si ($mode)', (tester) async {
      // The update cleanup is itself a stop.
      final updating = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await updating.start();
      updating.wireGuard.disconnectGate.arm();
      final installing = updating.controller.installPreparedUpdate();
      await updating.wireGuard.disconnectGate.reached;
      expect(updating.controller.isInstallingUpdate, isTrue);
      expect(updating.controller.isConnectionCommandRunning, isTrue);
      expect(updating.controller.canCancelConnection, isFalse);
      expect(updating.controller.canDisconnectVpn, isFalse);
      await updating.controller.disconnectVpn();
      expect(updating.controller.isStoppingVpn, isFalse);
      expect(updating.wireGuard.disconnectCalls, 1);
      updating.wireGuard.disconnectGate.open();
      await installing;
      updating.expectReleased();
      updating.controller.dispose();

      // So is the removal of this device.
      final revoking = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await revoking.start();
      revoking.api.revokeGate.arm();
      final removal = revoking.controller.revokeDevice(_device);
      await revoking.api.revokeGate.reached;
      expect(revoking.controller.canCancelConnection, isFalse);
      expect(revoking.controller.canDisconnectVpn, isFalse);
      await revoking.controller.disconnectVpn();
      expect(revoking.controller.isStoppingVpn, isFalse);
      expect(revoking.wireGuard.disconnectCalls, 0);
      revoking.api.revokeGate.open();
      expect(await removal, DeviceRevocationResult.revoked);
      revoking.expectReleased();
      revoking.controller.dispose();

      // A runtime owned by another Windows session offers no stop.
      final foreign = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: true);
      foreign.wireGuard.ownedByAnotherUser = true;
      await foreign.start();
      expect(foreign.controller.runtimeOwnedByAnotherUser, isTrue);
      expect(foreign.controller.canCancelConnection, isFalse);
      expect(foreign.controller.canDisconnectVpn, isFalse);
      await foreign.controller.disconnectVpn();
      expect(foreign.wireGuard.disconnectCalls, 0);
      expect(foreign.wireGuard.connected, isTrue);
      foreign.controller.dispose();

      // A location change begins by disconnecting, and then reconnects: it
      // is cancellable although its first state is `disconnecting`.
      final moving = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await moving.start();
      expect(
        await moving.controller.prepareLocationChange(_otherLocation),
        LocationChangePreparation.confirmationRequired,
      );
      final gate = killSwitch
          ? moving.wireGuard.suspendGate
          : moving.wireGuard.disconnectGate;
      gate.arm();
      final change = moving.controller.confirmPreparedLocationChange();
      await gate.reached;
      expect(moving.controller.vpnStatus, VpnStatus.disconnecting);
      expect(moving.controller.canCancelConnection, isTrue);
      final mark = moving.log.length;
      final stopping = moving.controller.disconnectVpn();
      gate.open();
      await stopping;
      await change;
      // The destination is never registered nor connected.
      expect(moving.since(mark), ['wg.disconnect', 'ovpn.disconnect']);
      expect(moving.wireGuard.connectCalls, 0);
      moving.expectReleased();
      moving.guard.expectResting(tester);
      moving.controller.dispose();
    });

    testWidgets('T17 un arrêt demandé pendant l’enregistrement d’un réglage '
        'attend cette écriture au lieu d’être refusé ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      h.store.settingsGate.arm();
      final saving = h.controller.setAutomaticReconnect(false);
      await h.store.settingsGate.reached;
      // A preference being written refuses every command meanwhile.
      expect(h.controller.isConnectionBusy, isTrue);
      expect(h.controller.canCancelConnection, isFalse);

      final stopping = h.controller.disconnectVpn();
      expect(h.controller.isStoppingVpn, isTrue);
      await tester.pump(const Duration(seconds: 2));
      expect(h.wireGuard.disconnectCalls, 0);
      expect(h.wireGuard.connected, isTrue);

      h.store.settingsGate.open();
      await saving;
      await stopping;
      expect(h.wireGuard.disconnectCalls, 1);
      expect(h.controller.automaticReconnectEnabled, isFalse);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T17 un arrêt dont la déconnexion ne peut pas démarrer '
        'rend l’état natif, jamais un état transitoire ($mode)', (
      tester,
    ) async {
      final h = _Harness(killSwitch: killSwitch);
      await h.start();
      h.wireGuard.connectGate.arm();
      final connecting = h.controller.quickConnect();
      await h.wireGuard.connectGate.reached;
      // A first preference is being written when the stop is requested.
      h.store.themeGate.arm();
      final theming = h.controller.setTheme(ThemeMode.dark);
      await h.store.themeGate.reached;

      final stopping = h.controller.disconnectVpn();
      expect(h.controller.vpnStatus, VpnStatus.disconnecting);
      // The tunnel comes up late; the stop now waits for that write.
      h.wireGuard.connectGate.open();
      await connecting;
      await tester.pump();
      expect(h.wireGuard.connected, isTrue);
      expect(h.controller.isStoppingVpn, isTrue);
      // A second preference starts being written meanwhile: when the first
      // one ends, every command is still refused.
      h.store.settingsGate.arm();
      final saving = h.controller.setAutomaticReconnect(false);
      await h.store.settingsGate.reached;
      h.store.themeGate.open();
      await theming;
      await stopping;

      // Nothing was released and nothing claims it: the tunnel that came
      // up is shown, with the stop offered again.
      expect(h.wireGuard.disconnectCalls, 0);
      expect(h.controller.isStoppingVpn, isFalse);
      expect(h.controller.vpnStatus, VpnStatus.connected);
      expect(h.controller.errorMessage, _stillConnectedMessage);
      expect(h.controller.requiresExplicitDisconnect, isTrue);
      h.store.settingsGate.open();
      await saving;
      h.guard.expectResting(tester);
      expect(h.controller.canDisconnectVpn, isTrue);

      await h.controller.disconnectVpn();
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T18 l’application reste occupée pendant tout l’arrêt '
        '($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch);
      await h.start();
      expect(h.controller.canInstallUpdate, isTrue);
      final busy = <bool>[];
      var watching = false;
      h.controller.addListener(() {
        if (watching) busy.add(h.controller.isConnectionBusy);
      });
      h.wireGuard.connectGate.arm();
      h.wireGuard.disconnectGate.arm();
      final connecting = h.controller.quickConnect();
      await h.wireGuard.connectGate.reached;

      watching = true;
      final stopping = h.controller.disconnectVpn();
      expect(h.controller.isConnectionBusy, isTrue);
      expect(h.controller.canInstallUpdate, isFalse);
      // Between the cancelled command and the disconnect of the stop.
      h.wireGuard.connectGate.open();
      await h.wireGuard.disconnectGate.reached;
      expect(h.controller.isConnectionBusy, isTrue);
      expect(h.controller.canInstallUpdate, isFalse);
      await h.controller.installPreparedUpdate();
      expect(h.controller.isInstallingUpdate, isFalse);
      h.wireGuard.disconnectGate.open();
      await stopping;
      await connecting;
      watching = false;

      // Busy at every notification of the stop except the one that ends it.
      expect(busy, isNotEmpty);
      expect(busy.last, isFalse);
      expect(busy.take(busy.length - 1), everyElement(isTrue));
      expect(h.controller.canInstallUpdate, isTrue);
      h.expectReleased();
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('T19 une déconnexion du compte pendant un arrêt se termine '
        'sans blocage ($mode)', (tester) async {
      for (final phase in ['commande annulée', 'déconnexion de l’arrêt']) {
        final h = _Harness(killSwitch: killSwitch);
        await h.start();
        h.wireGuard.connectGate.arm();
        h.wireGuard.disconnectGate.arm();
        final connecting = h.controller.quickConnect();
        await h.wireGuard.connectGate.reached;
        final stopping = h.controller.disconnectVpn();
        if (phase == 'déconnexion de l’arrêt') {
          h.wireGuard.connectGate.open();
          await h.wireGuard.disconnectGate.reached;
        }
        final signingOut = h.controller.signOut();
        h.wireGuard.connectGate.open();
        h.wireGuard.disconnectGate.open();
        await _settle(tester, h.controller);
        await stopping;
        await connecting;
        await signingOut;

        expect(h.controller.isStoppingVpn, isFalse, reason: phase);
        expect(h.controller.isConnectionBusy, isFalse, reason: phase);
        expect(h.controller.profile, isNull, reason: phase);
        expect(h.store.savedToken, isNull, reason: phase);
        h.expectReleased();
        expect(tester.takeException(), isNull, reason: phase);
        h.controller.dispose();
      }
    });

    for (final late in ['aboutit', 'échoue']) {
      testWidgets('T19 une session qui expire pendant un arrêt laisse l’état '
          'natif, même si la connexion annulée $late ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch);
        await h.start();
        // The node still holds this device's OpenVPN profile: the WireGuard
        // registration is refused once, the profile is released, and the
        // registration is sent again.
        h.api.registerResults = const [
          ApiException(
            statusCode: 409,
            errorCode: 'device_location_locked',
            observedHttpStatus: 409,
          ),
          _configuration,
        ];
        h.api.releaseGate.arm();
        final connecting = h.controller.quickConnect();
        await h.api.releaseGate.reached;
        expect(h.controller.canCancelConnection, isTrue);

        final stopping = h.controller.disconnectVpn();
        expect(h.controller.vpnStatus, VpnStatus.disconnecting);
        // The one request the cancelled command still waits for is refused:
        // the session expired. That expiry observes the native state once
        // the command it interrupted has returned.
        h.api.unauthorized = true;
        if (late == 'aboutit') {
          // Meanwhile a tunnel came up natively, as after a lost answer.
          h.wireGuard
            ..connected = true
            ..protectionActive = true;
        }
        // The next read of the OpenVPN tunnel state is slow: the stop is
        // held at its own confirmation.
        h.openVpn.connectedReadGate.arm(once: true);
        h.api.releaseGate.open();
        await connecting;
        await tester.pump();
        await tester.pump(const Duration(seconds: 1));
        // Until that confirmation arrives nothing may announce a release:
        // the observation the expiry asked for waits for the stop.
        expect(h.controller.isStoppingVpn, isTrue);
        expect(h.controller.vpnStatus, VpnStatus.disconnecting);
        h.openVpn.connectedReadGate.open();
        await stopping;
        await _settle(tester, h.controller);
        await tester.pump(const Duration(seconds: 5));

        // Signed out, and the stop the user asked for was carried out: the
        // observation never published a state from the middle of it.
        expect(h.controller.profile, isNull);
        expect(h.controller.isStoppingVpn, isFalse);
        expect(h.controller.isConnectionBusy, isFalse);
        expect(h.api.registerCalls, 1);
        expect(h.wireGuard.connectCalls, 0);
        expect(h.wireGuard.disconnectCalls, 1);
        h.expectReleased();
        expect(h.controller.errorMessage, isNull);
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    for (final removed in [false, true]) {
      testWidgets('T19 la suppression de cet appareil demandée pendant un '
          'arrêt, qui ${removed ? 'aboutit' : 'échoue'}, ne laisse pas '
          'l’arrêt en suspens ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch);
        await h.start();
        h.wireGuard.connectGate.arm();
        final connecting = h.controller.quickConnect();
        await h.wireGuard.connectGate.reached;
        final stopping = h.controller.disconnectVpn();
        // Meanwhile this device is being removed from the account.
        h.api.revokeGate.arm();
        final removal = h.controller.revokeDevice(_device);
        await h.api.revokeGate.reached;
        // The tunnel comes up late.
        h.wireGuard.connectGate.open();
        await connecting;
        await tester.pump();

        // A removal the server accepts stops the VPN itself: the stop waits
        // for its outcome instead of racing it or giving up.
        expect(h.controller.isStoppingVpn, isTrue);
        expect(h.wireGuard.connected, isTrue);
        expect(h.wireGuard.disconnectCalls, 0);

        h.api.offline = !removed;
        h.api.revokeGate.open();
        expect(
          await removal,
          removed
              ? DeviceRevocationResult.revoked
              : DeviceRevocationResult.failed,
        );
        await stopping;
        await _settle(tester, h.controller);

        // Either way the tunnel is stopped and nothing is left in between.
        expect(h.controller.isStoppingVpn, isFalse);
        expect(h.wireGuard.disconnectCalls, greaterThanOrEqualTo(1));
        expect(
          h.controller.currentDeviceId,
          removed ? isNull : _device.deviceId,
        );
        h.expectReleased();
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    for (final stop in ['disconnectVpn', 'toggleConnection']) {
      testWidgets('D5 après un arrêt explicite ($stop), une déconnexion qui '
          'échoue ensuite ne déclenche aucune reprise ($mode)', (tester) async {
        final h = _Harness(killSwitch: killSwitch)
          ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
        await h.start();
        h.wireGuard.failDisconnect = true;
        final failing = stop == 'disconnectVpn'
            ? h.controller.disconnectVpn()
            : h.controller.toggleConnection();
        await _settle(tester, h.controller);
        await failing;
        expect(h.controller.vpnStatus, VpnStatus.connected);

        // The tunnel the user asked to stop drops by itself afterwards.
        await h.dropTunnel(VpnProtocol.wireGuard);
        await tester.pump(const Duration(seconds: 120));
        expect(h.wireGuard.reconnectCalls, 0);
        expect(h.wireGuard.connectCalls, 0);
        h.guard.expectResting(tester);
        h.controller.dispose();
      });
    }

    testWidgets('D5 après un arrêt explicite, plus rien ne se connecte seul '
        'jusqu’à la prochaine connexion demandée ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch, autoConnect: true)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: killSwitch);
      await h.start();
      expect(h.controller.vpnStatus, VpnStatus.connected);
      await h.controller.disconnectVpn();
      h.expectReleased();

      // The network changes, the machine resumes: nothing reconnects.
      for (final event in WindowsConnectivityEvent.values) {
        h.clock.advance(const Duration(seconds: 60));
        await h.window.emit(event);
        await tester.pump(const Duration(seconds: 120));
      }
      expect(h.wireGuard.connectCalls, 0);
      expect(h.wireGuard.reconnectCalls, 0);
      h.expectReleased();

      // The user connects again: a tunnel that drops is resumed as before.
      await h.controller.quickConnect();
      expect(h.controller.vpnStatus, VpnStatus.connected);
      expect(h.wireGuard.connectCalls, 1);
      await h.dropTunnel(VpnProtocol.wireGuard);
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.controller.vpnStatus, VpnStatus.connected);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('sans moteur privilégié, la protection persistante est '
        'signalée, rien ne démarre le moteur et Déconnecter la retire '
        '(préférence : $mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch, autoConnect: true);
      // After a reboot before the service runs, or a portable relaunch.
      h.wireGuard
        ..protectionActive = true
        ..appliedKillSwitch = true
        ..runtimeAbsent = true;
      h.openVpn.runtimeAbsent = true;
      await h.start();

      expect(h.controller.isInitialized, isTrue);
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      expect(h.controller.errorMessage, _interruptedMessage);
      expect(h.controller.requiresExplicitDisconnect, isTrue);
      expect(h.controller.retainsBlockingProtection, isTrue);
      expect(h.controller.canDisconnectVpn, isTrue);
      expect(h.controller.isConnectionBusy, isFalse);
      // The startup resume did not even begin.
      expect(h.statuses, isNot(contains(VpnStatus.preparing)));
      // Nothing automatic runs, however long it lasts and whatever the
      // network reports: each of these calls would start a runtime.
      for (final event in WindowsConnectivityEvent.values) {
        h.clock.advance(const Duration(seconds: 60));
        await h.window.emit(event);
        await tester.pump(const Duration(seconds: 120));
      }
      expect(h.log, isEmpty);
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      expect(h.statuses, isNot(contains(VpnStatus.preparing)));
      expect(h.wireGuard.runtimeAbsent, isTrue);

      // The explicit stop is forwarded, which starts the runtime for it.
      await h.controller.disconnectVpn();
      expect(h.log.first, 'wg.disconnect');
      expect(h.wireGuard.reconnectCalls, 0);
      expect(h.wireGuard.prepareCalls, 0);
      h.expectReleased();
      // Released by the user: no launch connection follows.
      await _settle(tester, h.controller);
      await tester.pump(const Duration(seconds: 120));
      expect(h.wireGuard.connectCalls, 0);
      expect(h.controller.profile, isNotNull);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('sans moteur privilégié, la reprise attend que le service '
        'soit observé puis reconnecte (préférence : $mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch);
      h.wireGuard
        ..protectionActive = true
        ..appliedKillSwitch = true
        ..runtimeAbsent = true;
      h.openVpn.runtimeAbsent = true;
      await h.start();
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      await tester.pump(const Duration(seconds: 60));
      expect(h.log, isEmpty);

      // For a while Windows does not let the persisted policy be read.
      // That proves no runtime: still nothing automatic, and the stop stays.
      h.wireGuard.protectionUnreadable = true;
      h.openVpn.protectionUnreadable = true;
      await tester.pump(const Duration(seconds: 60));
      h.clock.advance(const Duration(seconds: 60));
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 60));
      expect(h.log, isEmpty);
      expect(h.controller.vpnStatus, isNot(VpnStatus.disconnected));
      expect(h.controller.requiresExplicitDisconnect, isTrue);
      expect(h.controller.canDisconnectVpn, isTrue);
      h.wireGuard.protectionUnreadable = false;
      h.openVpn.protectionUnreadable = false;
      await tester.pump(const Duration(seconds: 8));
      expect(h.log, isEmpty);
      expect(h.controller.vpnStatus, VpnStatus.blocked);

      // Windows starts the delayed service, which restores the policy.
      h.wireGuard.runtimeAbsent = false;
      h.openVpn.runtimeAbsent = false;
      // The tunnel monitor observes it within its four-second period, and
      // the first attempt follows three seconds later.
      await tester.pump(const Duration(seconds: 4));
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);

      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.controller.vpnStatus, VpnStatus.connected);
      expect(h.controller.activeProtocol, VpnProtocol.wireGuard);
      expect(h.controller.profile, isNotNull);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('un service qui s’arrête entre deux tentatives n’est pas '
        'redémarré par la suivante (préférence : $mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: true);
      h.wireGuard.appliedKillSwitch = true;
      await h.start();
      await h.dropTunnel(VpnProtocol.wireGuard);
      h.wireGuard.failReconnect = true;
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      final mark = h.log.length;

      // The second attempt is due in six seconds. The service stops first,
      // which this window has no way to know yet.
      h.wireGuard.runtimeAbsent = true;
      h.openVpn.runtimeAbsent = true;
      await tester.pump(const Duration(seconds: 6));
      await _settle(tester, h.controller);
      // The attempt read the state and gave up before preparing anything.
      expect(h.since(mark), isEmpty);
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      expect(h.controller.errorMessage, _interruptedMessage);
      expect(h.controller.canDisconnectVpn, isTrue);
      // Network hints while no runtime exists use up nothing.
      for (var hint = 0; hint < 6; hint++) {
        h.clock.advance(const Duration(seconds: 20));
        await h.window.emit(WindowsConnectivityEvent.networkAvailable);
        await tester.pump(const Duration(seconds: 20));
      }
      expect(h.since(mark), isEmpty);
      h.guard.expectResting(tester);

      // The service returns: the attempt that waited runs, and fails.
      h.wireGuard.runtimeAbsent = false;
      h.openVpn.runtimeAbsent = false;
      await tester.pump(const Duration(seconds: 4));
      await tester.pump(const Duration(seconds: 12));
      await _settle(tester, h.controller);
      final attempts = h.wireGuard.reconnectCalls;
      expect(attempts, greaterThan(1));
      // A network hint still restarts the cycle: three seconds, not the
      // longer delay the cycle had reached.
      h.wireGuard.failReconnect = false;
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, attempts + 1);
      expect(h.controller.vpnStatus, VpnStatus.connected);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });

    testWidgets('un service arrêté en cours de session bloque le trafic sans '
        'tentative jusqu’à son retour ($mode)', (tester) async {
      final h = _Harness(killSwitch: killSwitch)
        ..attachTunnel(VpnProtocol.wireGuard, killSwitch: true);
      // The applied policy blocks traffic whatever the saved preference.
      h.wireGuard.appliedKillSwitch = true;
      await h.start();
      expect(h.controller.vpnStatus, VpnStatus.connected);
      final mark = h.log.length;

      // The service stops: its tunnel goes, its persisted policy stays.
      h.wireGuard
        ..connected = false
        ..runtimeAbsent = true;
      h.openVpn.runtimeAbsent = true;
      await tester.pump(const Duration(seconds: 8));
      await _settle(tester, h.controller);
      expect(h.controller.vpnStatus, VpnStatus.blocked);
      expect(h.controller.errorMessage, _interruptedMessage);
      h.clock.advance(const Duration(seconds: 60));
      await h.window.emit(WindowsConnectivityEvent.networkAvailable);
      await tester.pump(const Duration(seconds: 120));
      expect(h.since(mark), isEmpty);
      expect(h.controller.canDisconnectVpn, isTrue);

      h.wireGuard.runtimeAbsent = false;
      h.openVpn.runtimeAbsent = false;
      await tester.pump(const Duration(seconds: 4));
      await tester.pump(const Duration(seconds: 3));
      await _settle(tester, h.controller);
      expect(h.wireGuard.reconnectCalls, 1);
      expect(h.controller.vpnStatus, VpnStatus.connected);
      h.guard.expectResting(tester);
      h.controller.dispose();
    });
  }

  group('renouvellement OpenVPN et arrêt', () {
    for (final killSwitch in [true, false]) {
      final mode = _label(killSwitch);

      test('T10 annuler un renouvellement à la connexion avant sa réponse '
          'garde le marqueur ; la connexion suivante rejoue le même CSR, '
          'sans renouvellement compté ($mode)', () async {
        final current = _activationUntil(_renewalNow.add(_tenDays));
        final renewed = _activationUntil(
          _renewalNow.add(const Duration(days: 365)),
        );
        final store = _MarkerStore();
        final api = _RenewalApi()
          ..openVpnResults = [current]
          ..renewResults = [renewed, renewed];
        final openVpn = _RenewalOpenVpn();
        final controller = _renewalController(
          api,
          openVpn,
          killSwitch: killSwitch,
          store: store,
        );
        addTearDown(controller.dispose);
        final guard = _RestingGuard(controller);

        // Within the renewal window: the request leaves before any import
        // and gets no answer yet.
        final answer = Completer<void>();
        api.renewGate = answer;
        final connecting = controller.toggleConnection();
        await api.renewStarted.future;
        expect(api.renewCalls, 1);
        expect(store.renewalDevice, 'device-existing');
        expect(store.renewalCsrSha256, _sha256('pending-csr'));
        expect(controller.canCancelConnection, isTrue);

        final stopping = controller.disconnectVpn();
        expect(controller.vpnStatus, VpnStatus.disconnecting);
        // The answer arrives after the cancellation and is discarded.
        answer.complete();
        await stopping;
        await connecting;
        await _settleRenewal(controller);

        guard.expectResting();
        expect(controller.vpnStatus, VpnStatus.disconnected);
        expect(openVpn.connected, isFalse);
        expect(openVpn.protectionActive, isFalse);
        expect(openVpn.importedNotAfter, isEmpty);
        // The stop left the renewal exactly as it was: the marker and its
        // fingerprint are still stored, never cleared.
        expect(store.renewalWrites, ['device-existing']);
        expect(store.renewalDevice, 'device-existing');
        expect(store.renewalCsrSha256, _sha256('pending-csr'));
        expect(openVpn.deleteProfileCalls, 0);

        // The next connection replays the same pending CSR before anything
        // else: the server answers it for free with what it already issued.
        await controller.quickConnect();

        expect(controller.vpnStatus, VpnStatus.connected);
        expect(api.renewedCsrs, ['pending-csr', 'pending-csr']);
        expect(api.createOpenVpnCalls, 1);
        expect(openVpn.importedNotAfter, [renewed.notAfter]);
        // Connected with the renewed certificate: the marker is settled.
        expect(store.renewalDevice, isNull);
        guard.expectResting();
      });

      test('T11 annuler pendant l’import du certificat renouvelé, qui '
          'aboutit ensuite : la connexion suivante ne paie aucun '
          'renouvellement ($mode)', () async {
        final renewed = _activationUntil(
          _renewalNow.add(const Duration(days: 365)),
        );
        final store = _MarkerStore();
        final api = _RenewalApi()
          ..openVpnResults = [_activationUntil(_renewalNow.add(_tenDays))]
          ..renewResults = [renewed];
        final importing = Completer<void>();
        final openVpn = _RenewalOpenVpn()..importGate = importing;
        final controller = _renewalController(
          api,
          openVpn,
          killSwitch: killSwitch,
          store: store,
        );
        addTearDown(controller.dispose);
        final guard = _RestingGuard(controller);
        final statuses = <VpnStatus>[];
        controller.addListener(() => statuses.add(controller.vpnStatus));

        final connecting = controller.toggleConnection();
        await openVpn.importStarted.future;
        expect(api.renewCalls, 1);
        expect(store.renewalDevice, 'device-existing');
        expect(controller.canCancelConnection, isTrue);

        final stopping = controller.disconnectVpn();
        // The renewed certificate connects natively after the cancellation,
        // which promotes the pending key.
        importing.complete();
        await stopping;
        await connecting;

        guard.expectResting();
        expect(statuses, isNot(contains(VpnStatus.connected)));
        expect(controller.vpnStatus, VpnStatus.disconnected);
        expect(openVpn.connected, isFalse);
        expect(openVpn.protectionActive, isFalse);
        expect(openVpn.importedNotAfter, [renewed.notAfter]);
        // The cancellation dropped nothing.
        expect(store.renewalWrites, ['device-existing']);
        expect(store.renewalCsrSha256, _sha256('pending-csr'));

        // The marked key is the active one now: nothing is left to replay,
        // and the renewed certificate is created again for free.
        await controller.quickConnect();

        expect(controller.vpnStatus, VpnStatus.connected);
        expect(api.renewCalls, 1);
        expect(api.renewedCsrs, ['pending-csr']);
        expect(api.receivedCsrs.last, 'pending-csr');
        expect(openVpn.importedNotAfter, [renewed.notAfter, renewed.notAfter]);
        expect(store.renewalDevice, isNull);
        expect(controller.deviceEnrollmentIssue, isNull);
        guard.expectResting();
      });

      test('après un renouvellement refusé, un arrêt garde le marqueur et le '
          'CSR en attente comme une simple nouvelle tentative '
          '($mode)', () async {
        // What reaches the server and the tunnel from the refusal to the
        // connection that follows, with or without an explicit stop between.
        Future<
          ({
            List<String> renewedCsrs,
            int creations,
            List<DateTime> imported,
            VpnStatus status,
          })
        >
        after(bool stop) async {
          // Expired: a certificate still valid would carry the tunnel itself
          // while its renewal is refused.
          final current = _activationUntil(
            _renewalNow.subtract(const Duration(days: 1)),
          );
          final renewed = _activationUntil(
            _renewalNow.add(const Duration(days: 365)),
          );
          const refused = ApiException(
            statusCode: 503,
            errorCode: 'openvpn_signer_unavailable',
            observedHttpStatus: 503,
          );
          final store = _MarkerStore();
          final api = _RenewalApi()
            ..openVpnResults = [current]
            ..renewResults = [refused, renewed];
          final openVpn = _RenewalOpenVpn();
          final controller = _renewalController(
            api,
            openVpn,
            killSwitch: killSwitch,
            store: store,
          );
          addTearDown(controller.dispose);
          final guard = _RestingGuard(controller);
          await controller.toggleConnection();
          expect(api.renewCalls, 1);
          expect(controller.vpnStatus, isNot(VpnStatus.connected));
          expect(store.renewalCsrSha256, _sha256('pending-csr'));

          if (stop) {
            // Without the kill switch nothing is left to stop: the state
            // stays as the failure left it.
            await controller.disconnectVpn();
            expect(
              controller.vpnStatus,
              killSwitch ? VpnStatus.disconnected : VpnStatus.error,
            );
            expect(store.renewalCsrSha256, _sha256('pending-csr'));
            await controller.quickConnect();
          } else {
            await controller.retryConnection();
          }
          guard.expectResting();
          return (
            renewedCsrs: api.renewedCsrs,
            creations: api.createOpenVpnCalls,
            imported: openVpn.importedNotAfter,
            status: controller.vpnStatus,
          );
        }

        final retried = await after(false);
        expect(retried.renewedCsrs, ['pending-csr', 'pending-csr']);
        expect(retried.status, VpnStatus.connected);
        final stopped = await after(true);
        // No request more, none less.
        expect(stopped.renewedCsrs, retried.renewedCsrs);
        expect(stopped.creations, retried.creations);
        expect(stopped.imported, retried.imported);
        expect(stopped.status, retried.status);
      });

      // Once is enough: this reads the source.
      if (killSwitch) {
        test('le code de l’arrêt ne touche à aucun état de '
            'renouvellement', () {
          final source = File('lib/app_controller.dart').readAsStringSync();
          String body(String signature, String next) {
            final from = source.indexOf(signature);
            final to = source.indexOf(next, from);
            expect(from, isNot(-1), reason: signature);
            expect(to, greaterThan(from), reason: next);
            return source.substring(from, to);
          }

          final stop =
              body(
                'Future<void> _explicitDisconnect(',
                'Future<void> disconnectVpn()',
              ) +
              body('Future<void> disconnectVpn()', 'Future<bool> _stopVpn(') +
              body('Future<bool> _stopVpn(', 'Future<void> quickConnect()');
          for (final forbidden in [
            '_forgetOpenVpnCertificate',
            '_forgetOpenVpnRenewalRequest',
            '_openVpnRenewalRequestedDeviceId',
            '_openVpnRenewalCsrSha256',
            '_openVpnCertificate',
            '_openVpnRequestsBlocked',
            'clearOpenVpnRenewalDeviceId',
            'deleteProfile',
          ]) {
            expect(stop, isNot(contains(forbidden)), reason: forbidden);
          }
        });
      }

      test('après un arrêt qui échoue, le tunnel resté actif n’est jamais '
          'renouvelé de lui-même : seule une connexion renouvelle '
          '($mode)', () async {
        final clock = _RenewalClock();
        final current = _activationUntil(
          _renewalNow.add(const Duration(days: 20)),
        );
        final api = _RenewalApi()..openVpnResults = [current];
        final openVpn = _RenewalOpenVpn();
        final controller = _renewalController(
          api,
          openVpn,
          killSwitch: killSwitch,
          clock: clock,
        );
        addTearDown(controller.dispose);
        await controller.toggleConnection();
        expect(controller.vpnStatus, VpnStatus.connected);

        openVpn.failDisconnect = true;
        await controller.disconnectVpn();
        expect(controller.vpnStatus, VpnStatus.connected);
        expect(controller.errorMessage, _stillConnectedMessage);

        // The last day of the certificate: the tunnel monitor sends nothing.
        clock.value = _renewalNow.add(const Duration(days: 19, hours: 12));
        await controller.checkTunnelHealthNow();
        await _settleRenewal(controller);
        expect(api.renewCalls, 0);
        expect(api.createOpenVpnCalls, 1);
        expect(openVpn.connected, isTrue);
        expect(controller.vpnStatus, VpnStatus.connected);
      });
    }
  });
}

// The renewal fixtures follow test/openvpn_certificate_renewal_test.dart,
// with gates on the renewal request and on the native import.

final _renewalNow = DateTime.utc(2026, 11, 10, 12);
const _tenDays = Duration(days: 10);

String _sha256(String csrPem) => sha256.convert(utf8.encode(csrPem)).toString();

OpenVpnActivation _activationUntil(DateTime notAfter) => OpenVpnActivation(
  deviceId: 'device-existing',
  protocol: 'openvpn',
  certificatePem: 'certificate-not-displayed',
  caCertificatePem: 'ca-not-displayed',
  tlsCryptV2ClientKey: 'tls-key-not-displayed',
  endpoint: '198.51.100.10',
  dns: const ['1.1.1.1'],
  address: '10.20.0.2/24',
  serverName: 'frankfurt-01.openvpn.internal',
  remoteCertTlsServer: true,
  ciphers: const ['AES-256-GCM'],
  notAfter: notAfter,
);

class _RenewalClock {
  DateTime value = _renewalNow;
  DateTime call() => value;
}

class _RenewalApi extends enrollment.FakeApiClient {
  List<Object> renewResults = const [];
  int renewCalls = 0;
  final renewedCsrs = <String>[];
  // Holds the next renewal answer until the test releases it.
  Completer<void>? renewGate;
  final renewStarted = Completer<void>();

  @override
  Future<UserProfile> me(String token) async => const UserProfile(
    userId: 'user-client',
    email: 'client@example.com',
    firstName: 'Client',
    emailVerified: true,
  );

  @override
  Future<OpenVpnActivation> createOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    // Once a renewal was issued for the pending key, creating the profile
    // with that key replays its certificate for free.
    final issued = renewResults.take(renewCalls).whereType<OpenVpnActivation>();
    if (csrPem == 'pending-csr' && issued.isNotEmpty) {
      createOpenVpnCalls++;
      receivedCsrs.add(csrPem);
      return issued.first;
    }
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }

  @override
  Future<OpenVpnActivation> renewOpenVpnProfile({
    required String token,
    required String deviceId,
    required String csrPem,
    List<IpFamily>? ipFamilies,
  }) async {
    renewCalls++;
    renewedCsrs.add(csrPem);
    final result = renewResults[renewCalls - 1];
    final gate = renewGate;
    renewGate = null;
    if (gate != null) {
      if (!renewStarted.isCompleted) renewStarted.complete();
      await gate.future;
    }
    if (result is OpenVpnActivation) return result;
    throw result;
  }
}

class _RenewalOpenVpn extends enrollment.FakeOpenVpnBridge {
  // The native identity: renewCsr returns the pending key's CSR until a
  // tunnel connects with its certificate, which promotes it.
  String? activeCsr;
  String pendingCsr = 'pending-csr';
  bool _pendingSent = false;
  final importedNotAfter = <DateTime>[];
  bool failDisconnect = false;
  // Holds the next native import until the test releases it.
  Completer<void>? importGate;
  final importStarted = Completer<void>();

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async {
    csrCalls++;
    return activeCsr ??= 'csr-1';
  }

  @override
  Future<String> renewCsr({
    required String accountId,
    required String deviceId,
  }) async {
    _pendingSent = true;
    return pendingCsr;
  }

  @override
  Future<void> suspendForMigration() async => connected = false;

  @override
  Future<void> importAndConnect(OpenVpnActivation activation) async {
    importedNotAfter.add(activation.notAfter);
    final gate = importGate;
    importGate = null;
    if (gate != null) {
      if (!importStarted.isCompleted) importStarted.complete();
      await gate.future;
    }
    await super.importAndConnect(activation);
    // Only a renewed certificate (beyond the window) belongs to that key.
    if (_pendingSent &&
        activation.notAfter.isAfter(_renewalNow.add(_tenDays))) {
      activeCsr = pendingCsr;
      pendingCsr = '$pendingCsr-next';
      _pendingSent = false;
    }
  }

  @override
  Future<void> disconnect() async {
    if (failDisconnect) {
      disconnectCalls++;
      throw PlatformException(code: 'broker_response_timeout');
    }
    await super.disconnect();
  }
}

/// Persists the renewal marker like the protected store does.
class _MarkerStore extends enrollment.FakeSecureStore {
  String? renewalDevice;
  String? renewalCsrSha256;
  // Every write of the marker, a clear being recorded as null.
  final renewalWrites = <String?>[];

  @override
  Future<String?> openVpnRenewalDeviceId() async => renewalDevice;

  @override
  Future<String?> openVpnRenewalCsrSha256() async =>
      renewalDevice == null ? null : renewalCsrSha256;

  @override
  Future<void> saveOpenVpnRenewalDeviceId(
    String deviceId, {
    String? csrSha256,
  }) async {
    renewalDevice = deviceId;
    renewalCsrSha256 = csrSha256;
    renewalWrites.add(deviceId);
  }

  @override
  Future<void> clearOpenVpnRenewalDeviceId() async {
    renewalDevice = null;
    renewalCsrSha256 = null;
    renewalWrites.add(null);
  }

  @override
  Future<StoredLocationMigration?> locationMigration() async => null;
}

AppController _renewalController(
  _RenewalApi api,
  _RenewalOpenVpn openVpn, {
  required bool killSwitch,
  enrollment.FakeSecureStore? store,
  _RenewalClock? clock,
}) {
  api.deviceList = const DeviceList(
    limit: 2,
    devices: [
      VpnDevice(
        deviceId: 'device-existing',
        name: 'Cet ordinateur',
        location: _location,
        createdAt: null,
      ),
    ],
  );
  return AppController(
      api: api,
      store: store ?? enrollment.FakeSecureStore(),
      wireguard: enrollment.FakeWireGuardBridge(),
      openVpn: openVpn,
      now: clock?.call ?? () => _renewalNow,
    )
    ..profile = const UserProfile(
      userId: 'user-client',
      email: 'client@example.com',
      firstName: 'Client',
      emailVerified: true,
    )
    ..locations = const [_location]
    ..selectedLocation = _location
    ..isLoadingLocations = false
    ..currentDeviceId = 'device-existing'
    ..vpnProtocol = VpnProtocol.openVpn
    ..openVpnRuntimeAvailable = true
    ..killSwitchEnabled = killSwitch;
}

Future<void> _settleRenewal(AppController controller) async {
  for (var turn = 0; turn < 200 && controller.isConnectionBusy; turn++) {
    await Future<void>.delayed(Duration.zero);
  }
  expect(controller.isConnectionBusy, isFalse);
}
