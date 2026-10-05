// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixtures;

const _location = Location(
  id: 'source',
  city: 'Source',
  countryCode: 'DE',
  displayName: 'Source',
  supportedProtocols: {VpnProtocol.wireGuard, VpnProtocol.openVpn},
);

PlatformException _brokerFailure() => PlatformException(
  code: 'broker_unavailable',
  message: 'private-native-error-message',
  details: {
    'stage': 'broker_connection',
    'win32_error': 50,
    'private': 'private-native-error-detail',
  },
);

class _Api extends fixtures.ProbeApi {
  int deviceCalls = 0;
  int registrationCalls = 0;
  int openVpnActivationCalls = 0;

  @override
  Future<DeviceList> devices(String token) async {
    deviceCalls++;
    return super.devices(token);
  }

  @override
  Future<DeviceConfiguration> registerDevice({
    required String token,
    required String name,
    required String publicKey,
    required String locationId,
    List<IpFamily>? ipFamilies,
  }) async {
    registrationCalls++;
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
    openVpnActivationCalls++;
    return super.createOpenVpnProfile(
      token: token,
      deviceId: deviceId,
      csrPem: csrPem,
      ipFamilies: ipFamilies,
    );
  }
}

class _WireGuard extends fixtures.ProbeWireGuard {
  int publicKeyCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    throw _brokerFailure();
  }

  @override
  Future<String> getOrCreatePublicKey({required String accountId}) async {
    publicKeyCalls++;
    return super.getOrCreatePublicKey(accountId: accountId);
  }
}

class _OpenVpn extends fixtures.ProbeOpenVpn {
  int prepareCalls = 0;
  int csrCalls = 0;

  @override
  Future<void> prepareNetworkProtection() async {
    prepareCalls++;
    throw _brokerFailure();
  }

  @override
  Future<String> getOrCreateCsr({
    required String accountId,
    required String deviceId,
  }) async {
    csrCalls++;
    return super.getOrCreateCsr(accountId: accountId, deviceId: deviceId);
  }
}

class _QuietUpdates extends WindowsUpdateController {
  _QuietUpdates() : super(api: fixtures.ProbeApi());

  @override
  Future<void> checkForUpdates() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  for (final protocol in VpnProtocol.values) {
    test(
      '${protocol.name} preserves broker failure origin before enrollment',
      () async {
        final api = _Api();
        final wireguard = _WireGuard();
        final openVpn = _OpenVpn();
        final updates = _QuietUpdates();
        addTearDown(updates.dispose);
        final controller =
            AppController(
                api: api,
                store: fixtures.ProbeStore(),
                wireguard: wireguard,
                openVpn: openVpn,
                window: fixtures.ProbeWindow(),
                updates: updates,
              )
              ..profile = fixtures.account
              ..locations = [_location]
              ..selectedLocation = _location
              ..currentDeviceId = fixtures.device.deviceId
              ..devices = [fixtures.device]
              ..realDeviceLocation = _location
              ..vpnProtocol = protocol
              ..protocolPreference = protocol == VpnProtocol.wireGuard
                  ? VpnProtocolPreference.wireGuard
                  : VpnProtocolPreference.openVpn
              ..openVpnRuntimeAvailable = true
              ..killSwitchEnabled = true
              ..isInitialized = true
              ..isLoadingLocations = false;
        addTearDown(controller.dispose);
        final firstLine = DiagnosticLog.recentLines.length;

        await controller.quickConnect();

        expect(controller.vpnStatus, VpnStatus.error);
        expect(controller.errorMessage, isNotNull);
        expect(controller.profile, fixtures.account);
        expect(api.deviceCalls, 0);
        expect(api.registrationCalls, 0);
        expect(api.openVpnActivationCalls, 0);
        expect(wireguard.publicKeyCalls, 0);
        expect(openVpn.csrCalls, 0);
        expect(wireguard.connectCalls, 0);
        expect(openVpn.importCalls, 0);
        expect(wireguard.connected, isFalse);
        expect(openVpn.connected, isFalse);
        expect(wireguard.protectionActive, isFalse);
        expect(openVpn.protectionActive, isFalse);
        expect(
          wireguard.prepareCalls,
          protocol == VpnProtocol.wireGuard ? 1 : 0,
        );
        expect(openVpn.prepareCalls, protocol == VpnProtocol.openVpn ? 1 : 0);

        final lines = DiagnosticLog.recentLines.skip(firstLine).toList();
        final failures = lines.where(
          (line) => line.contains('event=network_protection_prepare_failed '),
        );
        expect(failures, hasLength(1));
        final failure = failures.single;
        expect(
          failure,
          contains(
            'area=${protocol == VpnProtocol.wireGuard ? 'wireguard' : 'openvpn'} ',
          ),
        );
        expect(failure, contains('code=broker_unavailable '));
        expect(failure, contains('windows_error=50 '));
        expect(failure, contains('stage=broker_connection '));
        expect(
          lines.join('\n'),
          isNot(contains('private-native-error-message')),
        );
        expect(
          lines.join('\n'),
          isNot(contains('private-native-error-detail')),
        );
        expect(lines.join('\n'), isNot(contains('audit-synthetic-token')));
      },
    );
  }
}
