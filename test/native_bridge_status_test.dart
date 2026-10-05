// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const wireGuardChannel = MethodChannel('com.fuzevpn/windows_wireguard');
  const openVpnChannel = MethodChannel('com.fuzevpn/windows_openvpn');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() {
    messenger.setMockMethodCallHandler(wireGuardChannel, null);
    messenger.setMockMethodCallHandler(openVpnChannel, null);
  });

  test(
    'only an explicit native empty address list authorizes pre-runtime DNS',
    () async {
      messenger.setMockMethodCallHandler(wireGuardChannel, (_) async => null);
      await expectLater(
        WireGuardBridge().resolveApiAddresses(),
        throwsFormatException,
      );
      messenger.setMockMethodCallHandler(
        wireGuardChannel,
        (_) async => <String>[],
      );
      expect(await WireGuardBridge().resolveApiAddresses(), isEmpty);
    },
  );

  test(
    'both bridges preserve actual partial-policy and Windows ownership flags',
    () async {
      Future<Object?> status(MethodCall call) async => {
        'active': true,
        'killSwitch': false,
        'phase': 'tunnel',
        'ownedByAnotherUser': true,
      };
      messenger.setMockMethodCallHandler(wireGuardChannel, status);
      messenger.setMockMethodCallHandler(openVpnChannel, status);
      for (final state in [
        await WireGuardBridge().networkProtectionStatus(),
        await OpenVpnBridge().networkProtectionStatus(),
      ]) {
        expect(state.active, isTrue);
        expect(state.blocksTraffic, isFalse);
        expect(state.ownedByAnotherUser, isTrue);
      }
    },
  );

  test(
    'malformed or absent native state cannot become a full-block claim',
    () async {
      for (final value in [
        null,
        {'active': true, 'killSwitch': true, 'phase': 'inactive'},
      ]) {
        messenger.setMockMethodCallHandler(
          wireGuardChannel,
          (_) async => value,
        );
        await expectLater(
          WireGuardBridge().networkProtectionStatus(),
          throwsFormatException,
        );
      }
    },
  );
}
