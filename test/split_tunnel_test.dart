// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/split_tunnel.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

SplitTunnelRange _range(String text) => SplitTunnelRange.tryParse(text)!;

String? _error(String text) {
  String? error;
  SplitTunnelRange.tryParse(text, error: (value) => error = value);
  return error;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('plages', () {
    test('normalise IPv4, IPv6 et les adresses seules', () {
      expect(_range('192.168.1.5/24').toString(), '192.168.1.0/24');
      expect(_range(' 8.8.8.8 ').toString(), '8.8.8.8');
      expect(_range('8.8.8.8').cidr, '8.8.8.8/32');
      expect(_range('2001:DB8:0:0:0:0:0:1/32').cidr, '2001:db8::/32');
      expect(_range('2001:db8::1').cidr, '2001:db8::1/128');
      expect(_range('1:0:1:1:1:1:1:1').toString(), '1:0:1:1:1:1:1:1');
      expect(_range('1:0:0:1:0:0:0:1').toString(), '1:0:0:1::1');
      expect(_range('10.0.0.0/8'), _range('10.1.2.3/8'));
    });

    test('refuse les saisies invalides', () {
      for (final text in [
        '',
        'nas.local',
        '10.0.0.0/33',
        '10.0.0/8',
        '256.1.1.1',
        '10.0.0.0/-1',
        '10.0.0.0/ 8',
        '2001:db8::/129',
        'fe80::1%2',
        '1::2::3',
      ]) {
        expect(_error(text), SplitTunnelRange.invalidError, reason: text);
      }
    });

    test('refuse les plages réservées et la route par défaut', () {
      for (final text in [
        '0.0.0.0/0',
        '0.0.0.0/1',
        '127.0.0.1',
        '224.0.0.251',
        '255.255.255.255',
        '::/0',
        '::1',
        'ff02::1',
        '::ffff:192.0.2.1',
      ]) {
        expect(_error(text), SplitTunnelRange.reservedError, reason: text);
      }
      expect(_error('192.168.0.0/16'), isNull);
      expect(_error('fd00::/8'), isNull);
    });
  });

  group('réglages', () {
    test('restent désactivés par défaut et sans argument natif', () {
      const settings = SplitTunnelSettings.disabled;
      expect(settings.isActive, isFalse);
      expect(settings.effectiveMode, 'off');
      expect(settings.channelArguments, isEmpty);
    });

    test('ne transmettent que la liste du mode choisi', () {
      final settings = SplitTunnelSettings.disabled.copyWith(
        enabled: true,
        excludedRanges: [_range('203.0.113.0/24')],
        includedRanges: [_range('198.51.100.0/24')],
        allowLocalNetwork: true,
      );
      expect(settings.channelArguments, {
        'splitTunnelMode': 'exclude',
        'splitTunnelRoutes': ['203.0.113.0/24'],
        'splitTunnelLan': true,
      });
      final include = settings.copyWith(mode: SplitTunnelMode.include);
      expect(include.channelArguments, {
        'splitTunnelMode': 'include',
        'splitTunnelRoutes': ['198.51.100.0/24'],
        'splitTunnelLan': false,
      });
      expect(
        settings.copyWith(enabled: false).channelArguments,
        isEmpty,
        reason: 'désactivé : tout passe par le VPN',
      );
    });

    test('un mode sans effet reste inactif', () {
      final empty = SplitTunnelSettings.disabled.copyWith(enabled: true);
      expect(empty.effectiveMode, 'off');
      expect(empty.copyWith(allowLocalNetwork: true).effectiveMode, 'exclude');
      expect(
        empty
            .copyWith(mode: SplitTunnelMode.include, allowLocalNetwork: true)
            .effectiveMode,
        'off',
      );
    });

    test('ajoute, refuse les doublons, limite et retire des plages', () {
      String? error;
      var settings = SplitTunnelSettings.disabled.copyWith(enabled: true);
      settings = settings.withAddedRange(
        '192.168.1.0/24',
        error: (value) => error = value,
      )!;
      expect(settings.excludedRanges, [_range('192.168.1.0/24')]);
      expect(
        settings.withAddedRange(
          '192.168.1.9/24',
          error: (value) => error = value,
        ),
        isNull,
      );
      expect(error, SplitTunnelRange.duplicateError);
      for (var index = 1; index < SplitTunnelRange.maximumCount; index++) {
        settings = settings.withAddedRange(
          '10.0.$index.0/24',
          error: (value) => error = value,
        )!;
      }
      expect(
        settings.withAddedRange('10.9.9.0/24', error: (value) => error = value),
        isNull,
      );
      expect(error, SplitTunnelRange.limitError);
      settings = settings.withoutRange(_range('192.168.1.0/24'));
      expect(settings.excludedRanges, hasLength(15));
      final include = settings
          .copyWith(mode: SplitTunnelMode.include)
          .withAddedRange('2001:db8::/32', error: (value) => error = value)!;
      expect(include.includedRanges, [_range('2001:db8::/32')]);
      expect(include.excludedRanges, hasLength(15));
    });

    test('survivent à un aller-retour de stockage', () {
      final settings = SplitTunnelSettings.disabled.copyWith(
        enabled: true,
        mode: SplitTunnelMode.include,
        excludedRanges: [_range('203.0.113.0/24')],
        includedRanges: [_range('2001:db8::/32'), _range('198.51.100.7')],
        allowLocalNetwork: true,
      );
      final restored = SplitTunnelSettings.tryParse(settings.toStorageValue())!;
      expect(restored.enabled, isTrue);
      expect(restored.mode, SplitTunnelMode.include);
      expect(restored.excludedRanges, settings.excludedRanges);
      expect(restored.includedRanges, settings.includedRanges);
      expect(restored.allowLocalNetwork, isTrue);
    });

    test('rejettent un enregistrement illisible et écartent les plages '
        'invalides', () {
      expect(SplitTunnelSettings.tryParse('{'), isNull);
      expect(SplitTunnelSettings.tryParse('{"v":2}'), isNull);
      expect(
        SplitTunnelSettings.tryParse(
          '{"v":1,"enabled":true,"mode":"everything","exclude":[],'
          '"include":[],"lan":false}',
        ),
        isNull,
      );
      final cleaned = SplitTunnelSettings.tryParse(
        '{"v":1,"enabled":true,"mode":"exclude","exclude":["127.0.0.1",'
        '"bad",42,"203.0.113.0/24","203.0.113.0/24"],"include":[],'
        '"lan":false}',
      )!;
      expect(cleaned.excludedRanges, [_range('203.0.113.0/24')]);
    });
  });

  group('stockage sécurisé', () {
    const channel = MethodChannel('com.fuzevpn/windows_secure_store');
    late Map<String, String> disk;
    setUp(() {
      disk = {};
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            final key = call.arguments['key'] as String;
            if (call.method == 'read') return disk[key];
            if (call.method == 'write') {
              disk[key] = call.arguments['value'] as String;
            }
            return null;
          });
    });
    tearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    test('absent signifie désactivé', () async {
      final settings = await SecureStore().splitTunnelSettings();
      expect(settings.isActive, isFalse);
    });

    test('enregistre sous sa propre clé et relit la valeur', () async {
      final value = SplitTunnelSettings.disabled.copyWith(
        enabled: true,
        excludedRanges: [_range('203.0.113.0/24')],
      );
      await SecureStore().saveSplitTunnelSettings(value);
      expect(disk.keys, ['split_tunnel_settings']);
      final restored = await SecureStore().splitTunnelSettings();
      expect(restored.excludedRanges, value.excludedRanges);
    });

    test('un enregistrement corrompu est une erreur', () async {
      disk['split_tunnel_settings'] = 'not json';
      expect(SecureStore().splitTunnelSettings(), throwsFormatException);
    });
  });

  group('moteurs', () {
    final settings = SplitTunnelSettings.disabled.copyWith(
      enabled: true,
      excludedRanges: [_range('203.0.113.0/24'), _range('2001:db8::/32')],
      allowLocalNetwork: true,
    );
    const expected = {
      'splitTunnelMode': 'exclude',
      'splitTunnelRoutes': ['203.0.113.0/24', '2001:db8::/32'],
      'splitTunnelLan': true,
    };

    List<MethodCall> capture(String name) {
      final channel = MethodChannel(name);
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      return calls;
    }

    test('WireGuard reçoit la même politique à la préparation et à la '
        'connexion', () async {
      final calls = capture('com.fuzevpn/windows_wireguard');
      final bridge = WireGuardBridge()..configureSplitTunnel(settings);
      await bridge.prepareNetworkProtection();
      await bridge.connect(
        const DeviceConfiguration(
          deviceId: 'device-1',
          address: '10.10.0.2/32',
          dns: ['10.10.0.1'],
          serverPublicKey: 'public-key-not-displayed',
          endpoint: '198.51.100.10:51820',
          allowedIps: ['0.0.0.0/0'],
        ),
      );
      for (final call in calls) {
        final arguments = call.arguments as Map<Object?, Object?>;
        for (final entry in expected.entries) {
          expect(arguments[entry.key], entry.value, reason: call.method);
        }
      }
      expect(calls.map((call) => call.method), [
        'prepareConnection',
        'connect',
      ]);
    });

    test(
      'OpenVPN reçoit la politique et rien quand elle est inactive',
      () async {
        final calls = capture('com.fuzevpn/windows_openvpn');
        final bridge = OpenVpnBridge()..configureSplitTunnel(settings);
        await bridge.prepareNetworkProtection();
        bridge.configureSplitTunnel(SplitTunnelSettings.disabled);
        await bridge.prepareNetworkProtection();
        final active = calls.first.arguments as Map<Object?, Object?>;
        for (final entry in expected.entries) {
          expect(active[entry.key], entry.value);
        }
        final inactive = calls.last.arguments as Map<Object?, Object?>;
        expect(
          inactive.keys.where((key) => '$key'.startsWith('split')),
          isEmpty,
        );
      },
    );
  });

  group('contrôleur', () {
    test('enregistre puis configure les deux moteurs', () async {
      final store = _SplitStore();
      final wireguardCalls = <MethodCall>[];
      const channel = MethodChannel('com.fuzevpn/windows_wireguard');
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            wireguardCalls.add(call);
            return null;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      final wireguard = WireGuardBridge();
      final controller = AppController(store: store, wireguard: wireguard);
      final value = SplitTunnelSettings.disabled.copyWith(
        enabled: true,
        mode: SplitTunnelMode.include,
        includedRanges: [_range('198.51.100.0/24')],
      );

      await controller.setSplitTunnel(value);
      await wireguard.prepareNetworkProtection();

      expect(store.saved.single.toStorageValue(), value.toStorageValue());
      expect(controller.splitTunnel.effectiveMode, 'include');
      expect(controller.splitTunnelSettingsError, isNull);
      final arguments =
          wireguardCalls.single.arguments as Map<Object?, Object?>;
      expect(arguments['splitTunnelMode'], 'include');
      expect(arguments['splitTunnelRoutes'], ['198.51.100.0/24']);
    });

    test('garde la valeur précédente si l’enregistrement échoue', () async {
      final controller = AppController(store: _SplitStore(fail: true));

      await controller.setSplitTunnel(
        SplitTunnelSettings.disabled.copyWith(
          enabled: true,
          allowLocalNetwork: true,
        ),
      );

      expect(controller.splitTunnel.isActive, isFalse);
      expect(controller.splitTunnelSettingsError, isNotNull);
    });
  });
}

class _SplitStore extends SecureStore {
  _SplitStore({this.fail = false});

  final bool fail;
  final List<SplitTunnelSettings> saved = [];

  @override
  Future<void> saveSplitTunnelSettings(SplitTunnelSettings value) async {
    if (fail) throw StateError('unavailable');
    saved.add(value);
  }

  // Like every store call the controller makes, the renewal marker stays
  // in this fake: an unmocked channel would never answer in a widget test.
  @override
  Future<String?> openVpnRenewalDeviceId() async => null;
  @override
  Future<void> saveOpenVpnRenewalDeviceId(
    String deviceId, {
    String? csrSha256,
  }) async {}
  @override
  Future<void> clearOpenVpnRenewalDeviceId() async {}
  @override
  Future<String?> openVpnRenewalCsrSha256() async => null;
}
