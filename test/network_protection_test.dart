// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('transmet les protections choisies au moteur WireGuard', () async {
    const channel = MethodChannel('com.fuzevpn/windows_wireguard');
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final bridge = WireGuardBridge()
      ..configureNetworkProtection(
        killSwitch: false,
        dnsProtection: true,
        webRtcProtection: true,
      );
    await bridge.connect(
      const DeviceConfiguration(
        deviceId: 'device-1',
        address: '10.10.0.2/24',
        dns: ['10.10.0.1'],
        serverPublicKey: 'public-key-not-displayed',
        endpoint: '198.51.100.10:51820',
        allowedIps: ['0.0.0.0/0', '::/0'],
        addresses: ['10.10.0.2/24', 'fd00::2/128'],
        ipFamilies: dualStackIpFamilies,
      ),
    );

    expect(received?.method, 'connect');
    final arguments = received?.arguments as Map<Object?, Object?>;
    expect(arguments['killSwitch'], isFalse);
    expect(arguments['dnsProtection'], isTrue);
    expect(arguments.containsKey('ipv6Protection'), isFalse);
    expect(arguments['addresses'], ['10.10.0.2/24', 'fd00::2/128']);
    expect(arguments['webRtcProtection'], isTrue);
  });

  test('prépare WireGuard avec uniquement les trois protections', () async {
    const channel = MethodChannel('com.fuzevpn/windows_wireguard');
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final bridge = WireGuardBridge()
      ..configureNetworkProtection(
        killSwitch: true,
        dnsProtection: false,
        webRtcProtection: true,
      );
    await bridge.prepareNetworkProtection();

    expect(received?.method, 'prepareConnection');
    expect(received?.arguments, {
      'killSwitch': true,
      'dnsProtection': false,
      'webRtcProtection': true,
    });
  });

  test('demande une recréation WireGuard atomique au moteur natif', () async {
    const channel = MethodChannel('com.fuzevpn/windows_wireguard');
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    await WireGuardBridge().recreateIdentityForAccount('account-1');

    expect(received?.method, 'recreateIdentityForAccount');
    expect(received?.arguments, {'accountId': 'account-1'});
  });

  test('transmet les protections choisies au moteur OpenVPN', () async {
    const channel = MethodChannel('com.fuzevpn/windows_openvpn');
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final bridge = OpenVpnBridge()
      ..configureNetworkProtection(
        killSwitch: true,
        dnsProtection: false,
        webRtcProtection: false,
      );
    await bridge.importAndConnect(
      OpenVpnActivation(
        deviceId: 'device-1',
        protocol: 'openvpn',
        certificatePem: 'certificate-not-displayed',
        caCertificatePem: 'ca-not-displayed',
        tlsCryptV2ClientKey: 'tls-key-not-displayed',
        endpoint: '198.51.100.10',
        dns: const ['10.10.0.1'],
        address: '10.10.0.2/24',
        serverName: 'frankfurt-01.openvpn.fuzevpn.internal',
        remoteCertTlsServer: true,
        ciphers: const ['AES-256-GCM'],
        notAfter: DateTime.utc(2027),
        addresses: const ['10.10.0.2/24', 'fd00::2/128'],
        allowedIps: const ['0.0.0.0/0', '::/0'],
        ipFamilies: dualStackIpFamilies,
      ),
    );

    expect(received?.method, 'importAndConnect');
    final arguments = received?.arguments as Map<Object?, Object?>;
    expect(arguments['killSwitch'], isTrue);
    expect(arguments['dnsProtection'], isFalse);
    expect(arguments.containsKey('ipv6Protection'), isFalse);
    expect(arguments['ipv6Enabled'], isTrue);
    expect(arguments['addresses'], ['10.10.0.2/24', 'fd00::2/128']);
    expect(arguments['webRtcProtection'], isFalse);
  });

  test('prépare OpenVPN avec uniquement les trois protections', () async {
    const channel = MethodChannel('com.fuzevpn/windows_openvpn');
    MethodCall? received;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          received = call;
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final bridge = OpenVpnBridge()
      ..configureNetworkProtection(
        killSwitch: true,
        dnsProtection: true,
        webRtcProtection: false,
      );
    await bridge.prepareNetworkProtection();

    expect(received?.method, 'prepareConnection');
    expect(received?.arguments, {
      'killSwitch': true,
      'dnsProtection': true,
      'webRtcProtection': false,
    });
  });

  test('les moteurs natifs conservent les protections par défaut', () {
    final openVpn = File(
      'windows/runner/openvpn_tunnel.cpp',
    ).readAsStringSync();
    final wireGuard = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();
    final options = File(
      'windows/runner/network_protection.h',
    ).readAsStringSync();

    expect(openVpn, contains('FlagOrDefault(args, "killSwitch", true)'));
    expect(openVpn, contains('FlagOrDefault(args, "dnsProtection", true)'));
    expect(openVpn, contains('FlagOrDefault(args, "ipv6Enabled", false)'));
    expect(openVpn, contains('FlagOrDefault(args, "webRtcProtection", true)'));
    expect(
      wireGuard,
      contains('BoolArgument(*arguments, "webRtcProtection", true)'),
    );
    expect(options, contains('bool web_rtc_protection = true;'));
    expect(options, isNot(contains('ipv6_protection')));
  });

  test('mémorise ensemble les quatre préférences de sécurité', () async {
    final store = _ProtectionStore();
    final controller = AppController(store: store);

    await controller.setKillSwitch(false);
    await controller.setDnsProtection(false);
    await controller.setWebRtcProtection(false);
    await controller.setAutomaticReconnect(false);

    expect(store.killSwitchValue, isFalse);
    expect(store.dnsProtectionValue, isFalse);
    expect(store.webRtcProtectionValue, isFalse);
    expect(store.automaticReconnectValue, isFalse);
  });

  test('migre le stockage v2 sans conserver la préférence IPv6', () async {
    const channel = MethodChannel('com.fuzevpn/windows_secure_store');
    String? committedValue;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          if (call.method == 'read' &&
              call.arguments['key'] == 'security_settings') {
            return 'v2|0|1|0|0|1';
          }
          if (call.method == 'write' &&
              call.arguments['key'] == 'security_settings') {
            committedValue = call.arguments['value'] as String;
          }
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final settings = await SecureStore().securitySettings();

    expect(settings.killSwitch, isFalse);
    expect(settings.dnsProtection, isTrue);
    expect(settings.webRtcProtection, isFalse);
    expect(settings.automaticReconnect, isTrue);
    expect(committedValue, 'v3|0|1|0|1');
  });

  test('migre le stockage v1 en activant la protection WebRTC', () async {
    const channel = MethodChannel('com.fuzevpn/windows_secure_store');
    String? committedValue;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          final key = call.arguments['key'];
          if (call.method == 'read' && key == 'security_settings') {
            return 'v1|0|1|0|1';
          }
          if (call.method == 'write' && key == 'security_settings') {
            committedValue = call.arguments['value'] as String;
          }
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final settings = await SecureStore().securitySettings();

    expect(settings.killSwitch, isFalse);
    expect(settings.dnsProtection, isTrue);
    expect(settings.webRtcProtection, isTrue);
    expect(settings.automaticReconnect, isTrue);
    expect(committedValue, 'v3|0|1|1|1');
  });

  test('migre les anciennes préférences vers une écriture unique', () async {
    const channel = MethodChannel('com.fuzevpn/windows_secure_store');
    String? committedValue;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          final key = call.arguments['key'];
          if (call.method == 'read') {
            return switch (key) {
              'kill_switch' => 'false',
              'dns_protection' => 'true',
              'ipv6_protection' => 'false',
              'automatic_reconnect' => 'true',
              _ => null,
            };
          }
          if (call.method == 'write' && key == 'security_settings') {
            committedValue = call.arguments['value'] as String;
          }
          return null;
        });
    addTearDown(
      () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null),
    );

    final settings = await SecureStore().securitySettings();

    expect(settings.webRtcProtection, isTrue);
    expect(settings.toStorageValue(), 'v3|0|1|1|1');
    expect(committedValue, 'v3|0|1|1|1');
  });

  test('rétablit la valeur précédente si la persistance échoue', () async {
    final controller = AppController(store: _FailingProtectionStore());

    await controller.setKillSwitch(false);

    expect(controller.killSwitchEnabled, isTrue);
    expect(controller.securitySettingsError, isNotNull);
  });

  test(
    'sérialise les changements rapides sans perdre une préférence',
    () async {
      final store = _ProtectionStore();
      final controller = AppController(store: store);

      await Future.wait([
        controller.setKillSwitch(false),
        controller.setDnsProtection(false),
        controller.setWebRtcProtection(false),
        controller.setAutomaticReconnect(false),
      ]);

      expect(store.savedValues.last, 'v3|0|0|0|0');
    },
  );

  test(
    'le moteur natif installe des filtres dynamiques sans journal secret',
    () {
      final source = File(
        'windows/runner/network_protection.cpp',
      ).readAsStringSync();
      final policy = File(
        'windows/runner/network_protection_lifecycle.h',
      ).readAsStringSync();
      expect(source, contains('FWPM_SESSION_FLAG_DYNAMIC'));
      expect(source, contains('FWPM_LAYER_ALE_AUTH_CONNECT_V4'));
      expect(source, contains('FWPM_LAYER_ALE_AUTH_CONNECT_V6'));
      expect(source, contains('FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4'));
      expect(source, contains('FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6'));
      expect(source, contains('FWPM_CONDITION_IP_PROTOCOL'));
      expect(source, contains('IPPROTO_UDP'));
      expect(policy, contains('options.web_rtc_protection'));
      expect(
        policy,
        contains('options.web_rtc_protection && !options.kill_switch'),
      );
      expect(policy, isNot(contains('options.ipv6_protection')));
      expect(source, contains('protection IPv6 obligatoire'));
      expect(source, contains('protection WebRTC UDP IPv4'));
      expect(source, isNot(contains('protection WebRTC UDP IPv6')));
      expect(source, isNot(contains('certificatePem')));
      expect(source, isNot(contains('tlsCryptV2ClientKey')));
      expect(
        policy,
        isNot(contains('options.kill_switch || options.ipv6_protection')),
      );
    },
  );

  test('WireGuard génère une interface avec les deux adresses', () {
    final source = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();

    expect(source, contains('configuration.addresses[index]'));
    expect(source, contains('configuration.allowed_ips[1] != "::/0"'));
    expect(source, contains('IsUlaIPv6HostCidr(configuration.addresses[1])'));
    expect(source, contains('StringListArgument(*arguments, "addresses"'));
  });

  test('remplace la session WFP seulement après le commit candidat', () {
    final source = File(
      'windows/runner/network_protection.cpp',
    ).readAsStringSync();

    final commit = source.indexOf('FwpmTransactionCommit0(candidate_engine)');
    final swap = source.indexOf('HANDLE previous_engine = engine_handle;');
    final closePrevious = source.indexOf('CloseEngine(&previous_engine);');
    expect(commit, greaterThanOrEqualTo(0));
    expect(swap, greaterThan(commit));
    expect(closePrevious, greaterThan(swap));
    expect(source, contains('CloseEngine(&candidate_engine);'));
    expect(source, isNot(contains('AdapterIndexForAddress')));
    expect(source, contains('ConvertInterfaceLuidToIndex'));
    expect(source, contains('interface_luid.Value == 0'));
  });

  test(
    'la phase préparée autorise le service et la GUI attendus seulement',
    () {
      final source = File(
        'windows/runner/network_protection.cpp',
      ).readAsStringSync();

      expect(source, contains('kUiExecutableName[] = L"fuzevpn_windows.exe"'));
      expect(
        source,
        contains('kServiceExecutableName[] = L"fuzevpn-service.exe"'),
      );
      expect(source, contains('WinVerifyTrust'));
      expect(source, contains('current.filename().wstring()'));
      expect(source, contains('if (prepared)'));
      expect(source, contains('FuzeVPN — moteur VPN'));
      expect(source, contains('FuzeVPN — préparation de l’application'));
      expect(source, isNot(contains('résolution DNS de préparation')));
      expect(source, contains('FuzeVPN — interface VPN'));
      expect(source, contains('FWP_CONDITION_FLAG_IS_LOOPBACK'));
      expect(source, contains('FuzeVPN — kill switch IPv4'));
      expect(source, contains('FuzeVPN — protection IPv6 obligatoire'));
    },
  );

  test('la promotion refuse un propriétaire ou des options différents', () {
    final source = File(
      'windows/runner/network_protection_lifecycle.h',
    ).readAsStringSync();

    expect(source, contains('phase_ == NetworkProtectionPhase::prepared'));
    expect(source, contains('owner_ == owner'));
    expect(source, contains('SameNetworkProtectionOptions(options_, options)'));
    expect(source, contains('NetworkProtectionPhase::tunnel'));
    expect(source, contains('NetworkProtectionPhase::inactive'));
  });

  // DNS filtering is exercised by the native filter-capture regression,
  // including ordinary application port-53 traffic during preparation.

  test('les échecs de connexion ne désactivent plus la protection WFP', () {
    final wireGuard = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();
    final openVpn = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();

    final connectStart = wireGuard.indexOf('bool ConnectTunnel(');
    final disconnectStart = wireGuard.indexOf(
      'bool DisconnectTunnel(',
      connectStart,
    );
    expect(connectStart, greaterThanOrEqualTo(0));
    expect(disconnectStart, greaterThan(connectStart));
    expect(
      wireGuard.substring(connectStart, disconnectStart),
      isNot(contains('DisableNetworkProtection')),
    );
    expect(
      RegExp('DisableNetworkProtection').allMatches(openVpn),
      hasLength(1),
    );
    expect(wireGuard, contains('isNetworkProtectionActive'));
    expect(openVpn, contains('OpenVpnCoreDisconnect()'));
    final suspendStart = openVpn.indexOf(
      'bool OpenVpnCoreSuspendForMigration()',
    );
    final explicitDisconnectStart = openVpn.indexOf(
      'bool OpenVpnCoreDisconnect()',
      suspendStart,
    );
    expect(suspendStart, greaterThanOrEqualTo(0));
    expect(explicitDisconnectStart, greaterThan(suspendStart));
    expect(
      openVpn.substring(suspendStart, explicitDisconnectStart),
      isNot(contains('DisableNetworkProtection')),
    );
    final deleteIdentityStart = openVpn.indexOf(
      'bool OpenVpnCoreDeleteIdentity()',
      explicitDisconnectStart,
    );
    expect(deleteIdentityStart, greaterThan(explicitDisconnectStart));
    expect(
      openVpn.substring(deleteIdentityStart),
      isNot(contains('DisableNetworkProtection')),
    );
  });

  test('prépare avant le moteur et promeut seulement avec le LUID', () {
    final wireGuard = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();
    final openVpn = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();

    final wireGuardPrepare = wireGuard.indexOf(
      'fuzevpn::PrepareWireGuardEndpoints(configuration.endpoint',
    );
    expect(wireGuardPrepare, greaterThanOrEqualTo(0));
    final wireGuardServiceStart = wireGuard.indexOf(
      'StartServiceForConfig(*path, failure, attempt_deadline)',
      wireGuardPrepare,
    );
    expect(wireGuardServiceStart, greaterThan(wireGuardPrepare));
    final wireGuardPromote = wireGuard.indexOf(
      '!PromoteNetworkProtection(NetworkProtectionOwner::wire_guard',
      wireGuardServiceStart,
    );
    final openVpnPrepare = openVpn.indexOf(
      '!PrepareNetworkProtection(NetworkProtectionOwner::open_vpn',
    );
    final openVpnDriver = openVpn.indexOf(
      'EnsureBundledOpenVpnDcoDriver()',
      openVpnPrepare,
    );
    final openVpnConnect = openVpn.indexOf(
      'connecting_client->connect()',
      openVpnDriver,
    );
    final openVpnPromote = openVpn.indexOf(
      'PromoteNetworkProtection(NetworkProtectionOwner::open_vpn',
    );

    expect(wireGuardPrepare, greaterThanOrEqualTo(0));
    expect(wireGuardServiceStart, greaterThan(wireGuardPrepare));
    expect(wireGuardPromote, greaterThan(wireGuardServiceStart));
    expect(openVpnPrepare, greaterThanOrEqualTo(0));
    expect(openVpnDriver, greaterThan(openVpnPrepare));
    expect(openVpnConnect, greaterThan(openVpnDriver));
    expect(openVpnPromote, greaterThanOrEqualTo(0));
    expect(openVpn, contains('event.name == "CONNECTED"'));
    expect(openVpn, contains('stop();'));
  });

  test('les moteurs utilisent l’identité de leur véritable adaptateur', () {
    final wireGuard = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();
    final openVpn = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();
    expect(wireGuard, contains('WireGuardGetAdapterLUID'));
    expect(wireGuard, contains('WireGuardOpenAdapter'));
    expect(openVpn, contains('connected->vpn_interface_index'));
    expect(openVpn, contains('ConvertInterfaceIndexToLuid'));
    expect(openVpn, isNot(contains('AdapterIndexForAddress')));
  });

  test('un résultat Flutter obsolète ne déclenche pas de déconnexion', () {
    final controller = File('lib/app_controller.dart').readAsStringSync();

    expect(controller, isNot(contains('_safe<void>(_wireguard.disconnect())')));
    expect(controller, isNot(contains('_safe<void>(_openVpn.disconnect())')));
  });

  test('le stockage Windows remplace atomiquement les préférences', () {
    final source = File(
      'windows/runner/secure_store_channel.cpp',
    ).readAsStringSync();
    expect(source, contains('MOVEFILE_REPLACE_EXISTING'));
    expect(source, contains('MOVEFILE_WRITE_THROUGH'));
    expect(source, contains('security_settings'));
  });

  test('supprime complètement le service WireGuard à la sortie du broker', () {
    final source = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();
    expect(source, contains('WaitForServiceDeletion'));
    expect(source, contains('ERROR_SERVICE_MARKED_FOR_DELETE'));
    expect(source, contains('service.reset()'));
    expect(source, contains('void RemoveWireGuardTunnelService()'));
  });

  test('réutilise le service WireGuard entre deux connexions', () {
    final wireGuard = File(
      'windows/runner/wireguard_tunnel.cpp',
    ).readAsStringSync();

    expect(wireGuard, isNot(contains('ShutdownPrivilegedBroker();')));
    expect(wireGuard, contains('StopServiceForReuse(failure)'));
    expect(
      wireGuard,
      contains('StopServiceForReuse(&stop_failure, connection_deadline)'),
    );
    expect(wireGuard, contains('ChangeServiceConfigW('));
    expect(wireGuard, contains('OpenServiceW('));
  });

  test('termine uniquement le moteur OpenVPN de façon déterministe', () {
    final openVpn = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();

    expect(openVpn, contains('bool Stop()'));
    expect(openVpn, contains('WaitForCompletion(std::chrono::seconds(20))'));
    expect(openVpn, contains('if (!Stop()) return false;'));
    expect(openVpn, contains('OpenVpnCoreDisconnect()'));
    expect(openVpn, contains('Client* const connecting_client = client.get()'));
    expect(openVpn, isNot(contains('retiring_thread')));
    expect(openVpn, isNot(contains('std::async')));
    expect(openVpn, isNot(contains('StopBrokerTunnels')));
    expect(openVpn, isNot(contains('ShutdownPrivilegedBroker')));
  });
}

class _ProtectionStore extends SecureStore {
  bool? killSwitchValue;
  bool? dnsProtectionValue;
  bool? webRtcProtectionValue;
  bool? automaticReconnectValue;
  final List<String> savedValues = [];

  @override
  Future<void> saveSecuritySettings(SecuritySettings value) async {
    killSwitchValue = value.killSwitch;
    dnsProtectionValue = value.dnsProtection;
    webRtcProtectionValue = value.webRtcProtection;
    automaticReconnectValue = value.automaticReconnect;
    savedValues.add(value.toStorageValue());
  }

  @override
  Future<void> saveKillSwitch(bool value) async => killSwitchValue = value;

  @override
  Future<void> saveDnsProtection(bool value) async =>
      dnsProtectionValue = value;

  @override
  Future<void> saveAutomaticReconnect(bool value) async =>
      automaticReconnectValue = value;
}

class _FailingProtectionStore extends SecureStore {
  @override
  Future<void> saveSecuritySettings(SecuritySettings value) =>
      Future.error(StateError('storage unavailable'));
}
