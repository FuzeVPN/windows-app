// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

Map<String, dynamic> configurationJson(List<Object?> dns) => {
  'device_id': 'validation-fixture',
  'address': '10.20.0.2/32',
  'dns': dns,
  'server_public_key': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  'endpoint': '192.0.2.1:51820',
  'allowed_ips': ['0.0.0.0/0'],
};

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('com.fuzevpn/windows_wireguard');
  var nativeCalls = 0;

  setUp(() {
    nativeCalls = 0;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          nativeCalls++;
          return null;
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  for (final dns in [
    ['1.1.1.1'],
    ['2001:db8::53'],
    ['192.0.2.53', 'FD00:ABCD::53', '::ffff:192.0.2.53'],
    List.filled(8, '1.1.1.1'),
  ]) {
    test('numeric DNS servers are preserved: $dns', () async {
      final configuration = DeviceConfiguration.fromJson(
        configurationJson(dns),
      );
      expect(configuration.dns, dns);
      await WireGuardBridge().connect(configuration);
      expect(nativeCalls, 1);
    });
  }

  for (final dns in <List<Object?>>[
    [],
    [null],
    [53],
    ['face'],
    ['deadbeef'],
    ['dns.example'],
    ['999.999.999.999'],
    ['1.1.1'],
    ['1.1.1.1/32'],
    ['1.1.1.1:53'],
    ['[2001:db8::53]'],
    ['fd00::1:'],
    ['fe80::1%2'],
    [' 1.1.1.1'],
    ['1.1.1.1 '],
    ['1.1.1.1\u0000suffix'],
    ['1.1.1.1\nPostUp = bad'],
    ['1.1.1.1', 'face'],
    List.filled(9, '1.1.1.1'),
  ]) {
    test('invalid DNS cannot reach the native channel: $dns', () async {
      await expectLater(
        () async => WireGuardBridge().connect(
          DeviceConfiguration.fromJson(configurationJson(dns)),
        ),
        throwsFormatException,
      );
      expect(nativeCalls, 0);
    });
  }

  test('malformed ULA cannot reach the native channel', () async {
    final json = configurationJson(['1.1.1.1'])
      ..['addresses'] = ['10.20.0.2/32', 'fd00::1:/128']
      ..['ip_families'] = ['ipv4', 'ipv6']
      ..['allowed_ips'] = ['0.0.0.0/0', '::/0'];
    await expectLater(
      () async => WireGuardBridge().connect(DeviceConfiguration.fromJson(json)),
      throwsFormatException,
    );
    expect(nativeCalls, 0);
  });

  test(
    'native validation returns before protection, SCM or configuration writes',
    () {
      final source = File(
        'windows/runner/wireguard_tunnel.cpp',
      ).readAsStringSync();
      final start = source.indexOf('bool ConnectTunnel(');
      final end = source.indexOf('bool DisconnectTunnel(', start);
      final connect = source.substring(start, end);
      final validation = connect.indexOf('if (!IsValidConfiguration(');
      final rejection = connect.indexOf('return false;', validation);
      expect(validation, greaterThanOrEqualTo(0));
      expect(rejection, greaterThan(validation));
      for (final mutation in [
        'PrepareNetworkProtection(',
        'StopServiceForReuse(',
        'WriteWireGuardConfiguration(',
        'StartServiceForConfig(',
      ]) {
        expect(
          connect.indexOf(mutation),
          greaterThan(rejection),
          reason: mutation,
        );
      }
      final validatorStart = source.indexOf('bool IsValidConfiguration(');
      final validatorEnd = source.indexOf(
        'std::string ToWgQuickConfiguration(',
        validatorStart,
      );
      final validator = source.substring(validatorStart, validatorEnd);
      expect(validator, contains('fuzevpn::IsWireGuardDnsAddress(dns)'));
      expect(
        validator,
        contains('fuzevpn::IsWireGuardUlaHostCidr(configuration.addresses[1])'),
      );
    },
  );
}
