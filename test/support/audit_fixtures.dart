// SPDX-License-Identifier: MPL-2.0
// Shared synthetic fixtures for regression tests.
// No production credentials, network calls or Windows changes.
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';

import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/window_bridge.dart';

import '../automatic_protocol_test.dart' as fixtures;

const source = Location(
  id: 'source',
  city: 'Source',
  countryCode: 'DE',
  displayName: 'Source',
);
const target = Location(
  id: 'target',
  city: 'Target',
  countryCode: 'DE',
  displayName: 'Target',
);
const account = UserProfile(
  userId: 'audit-user',
  email: 'audit@example.invalid',
  firstName: 'Audit',
  emailVerified: true,
);
const device = VpnDevice(
  deviceId: 'device-test',
  name: 'Audit',
  location: source,
  createdAt: null,
);

AppController makeController({
  ProbeApi? api,
  ProbeStore? store,
  ProbeWindow? window,
  ProbeWireGuard? wg,
}) => AppController(
  api: api ?? ProbeApi(),
  store: store ?? ProbeStore(),
  window: window ?? ProbeWindow(),
  wireguard: wg ?? ProbeWireGuard(),
  openVpn: ProbeOpenVpn(),
);

class ProbeApi extends fixtures.AutomaticApi {
  bool offline = false;
  bool revoked = false;
  int meCalls = 0;
  @override
  Future<List<Location>> locations() async {
    if (offline) throw const SocketException('Simulated offline');
    return [source, target];
  }

  @override
  Future<UserProfile> me(String token) async {
    meCalls++;
    if (offline) throw const SocketException('Simulated offline');
    return account;
  }

  @override
  Future<DeviceList> devices(String token) async =>
      const DeviceList(limit: 2, devices: [device]);
  @override
  Future<void> revokeDevice({
    required String token,
    required String deviceId,
  }) async {
    revoked = true;
  }
}

class ProbeStore extends SecureStore {
  bool autoConnect = false;
  bool killSwitchSetting = true;
  bool failClearDevice = false;
  bool selectionWriteStarted = false;
  Completer<void>? selectionGate;
  @override
  Future<String?> token() async => 'audit-synthetic-token';
  @override
  Future<void> clearToken() async {}
  @override
  Future<String?> themeMode() async => 'light';
  @override
  Future<String?> vpnProtocol() async => 'wireguard';
  @override
  Future<String?> appLanguage() async => 'fr';
  @override
  Future<SecuritySettings> securitySettings() async => SecuritySettings(
    killSwitch: killSwitchSetting,
    dnsProtection: true,
    webRtcProtection: true,
    automaticReconnect: true,
  );
  @override
  Future<String?> autoConnectOnLaunch() async => autoConnect ? 'true' : 'false';
  @override
  Future<String?> windowsNotifications() async => 'false';
  @override
  Future<List<String>> favoriteLocationIds() async => [];
  @override
  Future<List<String>> recentLocationIds() async => [];
  @override
  Future<void> saveRecentLocationIds(Iterable<String> values) async {}
  @override
  Future<String?> selectedLocation() async => source.id;
  @override
  Future<void> saveSelectedLocation(String value) async {
    selectionWriteStarted = true;
    await selectionGate?.future;
  }

  @override
  Future<String?> currentDeviceId() async => device.deviceId;
  @override
  Future<void> saveCurrentDeviceId(String value) async {}
  @override
  Future<void> clearCurrentDeviceId() async {
    if (failClearDevice) throw PlatformException(code: 'secure_store_error');
  }

  @override
  Future<StoredLocationMigration?> locationMigration() async => null;
  @override
  Future<void> clearLocationMigration() async {}
}

class ProbeWindow extends WindowBridge {
  Future<void> Function(WindowsConnectivityEvent event)? listener;
  @override
  Future<String> deviceName() async => 'Audit Windows';
  @override
  Future<bool> isLaunchAtStartupEnabled() async => false;
  @override
  void startConnectivityListener(
    Future<void> Function(WindowsConnectivityEvent event) handler,
  ) {
    listener = handler;
  }

  @override
  void stopConnectivityListener() {
    listener = null;
  }
}

class ProbeWireGuard extends fixtures.AutomaticWireGuard {
  int prepareCalls = 0;
  int reconnectCalls = 0;
  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    protectionActive = true;
  }

  @override
  Future<bool> reconnect() async {
    reconnectCalls++;
    connected = true;
    return true;
  }

  @override
  Future<void> resetIdentity() async {
    connected = false;
    protectionActive = false;
  }
}

class ProbeOpenVpn extends fixtures.AutomaticOpenVpn {
  @override
  Future<bool> isAvailable() async => false;
  @override
  Future<void> deleteProfile() async {
    connected = false;
    protectionActive = false;
  }
}
