// SPDX-License-Identifier: MPL-2.0
import 'native_protection_status_fixture.dart';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

const _location1 = Location(
  id: 'frankfurt-01',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 1',
  supportedProtocols: {VpnProtocol.wireGuard},
);
const _location2 = Location(
  id: 'frankfurt-02',
  city: 'Frankfurt',
  countryCode: 'DE',
  displayName: 'Frankfurt 2',
  supportedProtocols: {VpnProtocol.wireGuard},
);
const _profile = UserProfile(
  userId: 'user-1',
  email: 'client@example.invalid',
  firstName: 'Client',
  emailVerified: true,
);

void main() {
  test('restaure et ordonne favoris puis emplacements récents', () async {
    final store = _ExperienceStore(
      favorites: const ['frankfurt-02'],
      recents: const ['frankfurt-01'],
    );
    final controller = _controller(store: store);
    addTearDown(controller.dispose);

    await controller.initialize();

    expect(controller.isFavoriteLocation(_location2), isTrue);
    expect(controller.isRecentLocation(_location1), isTrue);
    expect(controller.orderedLocations.map((location) => location.id), [
      'frankfurt-02',
      'frankfurt-01',
    ]);
  });

  test('mémorise un favori sans changer le serveur sélectionné', () async {
    final store = _ExperienceStore();
    final controller = _controller(store: store);
    addTearDown(controller.dispose);
    await controller.initialize();

    await controller.toggleFavoriteLocation(_location2);

    expect(controller.selectedLocation, _location1);
    expect(controller.isFavoriteLocation(_location2), isTrue);
    expect(store.savedFavorites, contains('frankfurt-02'));
  });

  test(
    'connexion optionnelle au démarrage utilise le dernier serveur',
    () async {
      final store = _ExperienceStore(autoConnect: true);
      final wireGuard = _ExperienceWireGuard();
      final controller = _controller(store: store, wireGuard: wireGuard);
      addTearDown(controller.dispose);

      await controller.initialize();

      expect(wireGuard.connectCalls, 1);
      expect(controller.vpnStatus, VpnStatus.connected);
      expect(controller.selectedLocation, _location1);
      expect(controller.connectedAt, isNotNull);
      expect(store.savedRecents.first, 'frankfurt-01');
    },
  );

  test('enregistre les préférences Windows et de notification', () async {
    final store = _ExperienceStore();
    final window = _ExperienceWindow();
    final controller = _controller(store: store, window: window);
    addTearDown(controller.dispose);
    await controller.initialize();

    await controller.setLaunchWithWindows(true);
    await controller.setAutoConnectOnLaunch(true);
    await controller.setWindowsNotifications(false);

    expect(window.launchAtStartup, isTrue);
    expect(store.savedAutoConnect, isTrue);
    expect(store.savedNotifications, isFalse);
  });
}

AppController _controller({
  required _ExperienceStore store,
  _ExperienceWireGuard? wireGuard,
  _ExperienceWindow? window,
}) => AppController(
  api: _ExperienceApi(),
  store: store,
  wireguard: wireGuard ?? _ExperienceWireGuard(),
  openVpn: _ExperienceOpenVpn(),
  window: window ?? _ExperienceWindow(),
);

class _ExperienceStore extends SecureStore {
  _ExperienceStore({
    this.autoConnect = false,
    this.favorites = const [],
    this.recents = const [],
  });

  final bool autoConnect;
  final List<String> favorites;
  final List<String> recents;
  List<String> savedFavorites = [];
  List<String> savedRecents = [];
  bool? savedAutoConnect;
  bool? savedNotifications;

  @override
  Future<String?> token() async => 'session-not-logged';
  @override
  Future<String?> selectedLocation() async => _location1.id;
  @override
  Future<String?> currentDeviceId() async => null;
  @override
  Future<String?> themeMode() async => 'light';
  @override
  Future<String?> vpnProtocol() async => 'wireguard';
  @override
  Future<String?> appLanguage() async => 'fr';
  @override
  Future<SecuritySettings> securitySettings() async =>
      SecuritySettings.secureDefaults;
  @override
  Future<StoredLocationMigration?> locationMigration() async => null;
  @override
  Future<String?> autoConnectOnLaunch() async => autoConnect ? 'true' : 'false';
  @override
  Future<String?> windowsNotifications() async => 'true';
  @override
  Future<List<String>> favoriteLocationIds() async => favorites;
  @override
  Future<List<String>> recentLocationIds() async => recents;
  @override
  Future<void> saveSelectedLocation(String value) async {}
  @override
  Future<void> saveCurrentDeviceId(String value) async {}
  @override
  Future<void> saveFavoriteLocationIds(Iterable<String> values) async =>
      savedFavorites = values.toList(growable: false);
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async =>
      savedRecents = values.toList(growable: false);
  @override
  Future<void> saveAutoConnectOnLaunch(bool value) async =>
      savedAutoConnect = value;
  @override
  Future<void> saveWindowsNotifications(bool value) async =>
      savedNotifications = value;
}

class _ExperienceWindow extends WindowBridge {
  bool launchAtStartup = false;

  @override
  Future<String> deviceName() async => 'FuzeVPN 0.1.0 -- Windows';

  @override
  Future<bool> isLaunchAtStartupEnabled() async => launchAtStartup;
  @override
  Future<void> setLaunchAtStartup(bool enabled) async =>
      launchAtStartup = enabled;
  @override
  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent event) handler,
  ) {}
  @override
  void stopConnectivityListener() {}
}

class _ExperienceApi extends ApiClient {
  @override
  Future<Subscription> subscription(String token) async => const Subscription(
    status: SubscriptionStatus.active,
    hasAccess: true,
    renewsAutomatically: false,
    cancelAtPeriodEnd: false,
  );

  @override
  Future<List<Location>> locations() async => const [_location1, _location2];
  @override
  Future<UserProfile> me(String token) async => _profile;
  @override
  Future<DeviceList> devices(String token) async =>
      const DeviceList(limit: 2, devices: []);
  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async => const DeviceConfiguration(
    deviceId: 'device-1',
    address: '10.10.0.2/24',
    dns: ['10.10.0.1'],
    serverPublicKey: 'public-key-not-logged',
    endpoint: '198.51.100.10:51820',
    allowedIps: ['0.0.0.0/0'],
  );
}

class _ExperienceWireGuard extends WireGuardBridge
    with NativeProtectionStatusFixture {
  bool connected = false;
  int connectCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async {}

  @override
  Future<bool> isConnected() async => connected;
  @override
  Future<bool> isNetworkProtectionActive() async => connected;
  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async =>
      'public-key-not-logged';
  @override
  Future<void> connect(DeviceConfiguration configuration) async {
    connectCalls++;
    connected = true;
  }

  @override
  Future<void> disconnect() async => connected = false;
}

class _ExperienceOpenVpn extends OpenVpnBridge
    with NativeProtectionStatusFixture {
  @override
  Future<void> prepareNetworkProtection() async {}

  @override
  Future<bool> isAvailable() async => false;
  @override
  Future<bool> isConnected() async => false;
  @override
  Future<bool> isNetworkProtectionActive() async => false;
}
