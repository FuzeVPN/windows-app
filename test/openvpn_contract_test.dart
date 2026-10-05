// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/models.dart';

const certificatePem = '''-----BEGIN CERTIFICATE-----
QUJD
-----END CERTIFICATE-----''';
const tlsCryptV2ClientKey = '''-----BEGIN OpenVPN tls-crypt-v2 client key-----
QUJD
-----END OpenVPN tls-crypt-v2 client key-----''';

Map<String, dynamic> activation({
  String endpoint = '198.51.100.10',
  Object? remoteCertTlsServer = true,
  Object? dns = const ['10.10.0.1'],
  Object? ciphers = const ['AES-256-GCM'],
  String certificate = certificatePem,
  String caCertificate = certificatePem,
  String tlsCryptV2 = tlsCryptV2ClientKey,
  bool dualStack = false,
}) => {
  'device_id': 'device-123',
  'protocol': 'openvpn',
  'certificate_pem': certificate,
  'ca_certificate_pem': caCertificate,
  'tls_crypt_v2_client_key': tlsCryptV2,
  'endpoint': endpoint,
  'dns': dns,
  'address': '10.10.0.2/24',
  'server_name': 'frankfurt-01.openvpn.fuzevpn.internal',
  'remote_cert_tls_server': remoteCertTlsServer,
  'ciphers': ciphers,
  'not_after': '2027-01-01T12:00:00Z',
  if (dualStack) ...{
    'addresses': ['10.10.0.2/24', 'fd42::2/128'],
    'allowed_ips': ['0.0.0.0/0', '::/0'],
    'ip_families': ['ipv4', 'ipv6'],
  },
};

void main() {
  test('lit les protocoles réellement proposés par un emplacement', () {
    final location = Location.fromJson({
      'id': 'frankfurt-01',
      'display_name': 'Frankfurt 1',
      'city': 'Frankfurt',
      'country_code': 'DE',
      'supported_protocols': ['wireguard', 'openvpn'],
      'supported_ip_families': ['ipv4', 'ipv6'],
    });

    expect(location.supportedProtocols, {
      VpnProtocol.wireGuard,
      VpnProtocol.openVpn,
    });
    expect(location.supportedIpFamilies, {IpFamily.ipv4, IpFamily.ipv6});
    expect(location.supportsIpv6, isTrue);
  });

  test('conserve IPv4 pour une réponse historique sans nouveaux champs', () {
    final profile = OpenVpnActivation.fromJson(
      activation(),
      expectedDeviceId: 'device-123',
    );

    expect(profile.effectiveAddresses, ['10.10.0.2/24']);
    expect(profile.allowedIps, isEmpty);
    expect(profile.ipFamilies, [IpFamily.ipv4]);
    expect(profile.supportsIpv6, isFalse);
  });

  test('valide une activation OpenVPN double pile complète', () {
    final profile = OpenVpnActivation.fromJson(
      activation(dualStack: true),
      expectedDeviceId: 'device-123',
    );

    expect(profile.effectiveAddresses, ['10.10.0.2/24', 'fd42::2/128']);
    expect(profile.allowedIps, ['0.0.0.0/0', '::/0']);
    expect(profile.ipFamilies, dualStackIpFamilies);
    expect(profile.supportsIpv6, isTrue);
  });

  test('valide une configuration WireGuard double pile complète', () {
    final payload = <String, dynamic>{
      'device_id': 'device-123',
      'address': '10.10.0.2/24',
      'addresses': ['10.10.0.2/24', 'fd42::2/128'],
      'dns': ['10.10.0.1'],
      'server_public_key': 'public-key',
      'endpoint': '198.51.100.10:51820',
      'allowed_ips': ['0.0.0.0/0', '::/0'],
      'ip_families': ['ipv4', 'ipv6'],
    };
    final configuration = DeviceConfiguration.fromJson(payload);

    expect(configuration.effectiveAddresses, ['10.10.0.2/24', 'fd42::2/128']);
    expect(configuration.supportsIpv6, isTrue);

    for (final invalid in [
      {
        ...payload,
        'ip_families': ['ipv6', 'ipv4'],
      },
      {
        ...payload,
        'addresses': ['10.10.0.2/24', '2001:db8::2/128'],
      },
      {
        ...payload,
        'allowed_ips': ['::/0', '0.0.0.0/0'],
      },
      {...payload}..remove('ip_families'),
    ]) {
      expect(
        () => DeviceConfiguration.fromJson(invalid),
        throwsFormatException,
      );
    }
  });

  test('refuse les combinaisons double pile incohérentes', () {
    final valid = activation(dualStack: true);
    for (final invalid in [
      {
        ...valid,
        'ip_families': ['ipv6', 'ipv4'],
      },
      {
        ...valid,
        'addresses': ['10.10.0.2/24'],
      },
      {
        ...valid,
        'addresses': ['10.10.0.2/24', '2001:db8::2/128'],
      },
      {
        ...valid,
        'addresses': ['10.10.0.2/24', 'fd42::2/64'],
      },
      {
        ...valid,
        'allowed_ips': ['0.0.0.0/0'],
      },
      {...valid}..remove('addresses'),
    ]) {
      expect(
        () =>
            OpenVpnActivation.fromJson(invalid, expectedDeviceId: 'device-123'),
        throwsFormatException,
      );
    }
  });

  test(
    'valide une activation complète sans rendre ses secrets affichables',
    () {
      final profile = OpenVpnActivation.fromJson(
        activation(),
        expectedDeviceId: 'device-123',
      );

      expect(profile.endpoint, '198.51.100.10');
      expect(profile.address, '10.10.0.2/24');
      expect(profile.dns, ['10.10.0.1']);
      expect(profile.notAfter, DateTime.utc(2027, 1, 1, 12));
      expect(profile.toString(), isNot(contains(tlsCryptV2ClientKey)));
      expect(profile.toString(), isNot(contains(certificatePem)));
    },
  );

  test('accepte CRLF et une chaîne de certificats CA', () {
    final crlfCertificate = certificatePem.replaceAll('\n', '\r\n');
    final profile = OpenVpnActivation.fromJson(
      activation(
        certificate: crlfCertificate,
        caCertificate: '$crlfCertificate\r\n$crlfCertificate',
        tlsCryptV2: tlsCryptV2ClientKey.replaceAll('\n', '\r\n'),
      ),
      expectedDeviceId: 'device-123',
    );

    expect(profile.certificatePem, crlfCertificate);
    expect(profile.caCertificatePem, contains('\r\n'));
  });

  test('refuse les détails d’activation incomplets ou incohérents', () {
    for (final invalid in [
      activation(remoteCertTlsServer: false),
      activation(endpoint: 'vpn.example.com'),
      activation(endpoint: '198.51.100.10\u0000\nscript-security 2'),
      activation(dns: const ['2001:db8::1']),
      activation(dns: const ['1.1.1.1\u0000\nscript-security 2']),
      activation(ciphers: const []),
      {...activation(), 'protocol': 'wireguard'},
      {...activation(), 'device_id': 'other-device'},
      {...activation(), 'address': '10.10.0.2/33'},
      {...activation(), 'not_after': 'not-a-date'},
      activation(certificate: '$certificatePem\n</cert>\nscript-security 2'),
      activation(caCertificate: '$certificatePem\n</ca>\nplugin malicious.dll'),
      activation(
        tlsCryptV2: '$tlsCryptV2ClientKey\n</tls-crypt-v2>\nup malicious.cmd',
      ),
      activation(certificate: '$certificatePem\u0000'),
      activation(certificate: certificatePem.replaceFirst('\n', '\r')),
      activation(certificate: '$certificatePem\n$certificatePem'),
      activation(
        tlsCryptV2: tlsCryptV2ClientKey.replaceFirst(
          'OpenVPN tls-crypt-v2 client key',
          'OpenVPN Static key V1',
        ),
      ),
      activation(
        caCertificate:
            '-----BEGIN CERTIFICATE-----\n${'A' * (64 * 1024)}\n-----END CERTIFICATE-----',
      ),
    ]) {
      expect(
        () =>
            OpenVpnActivation.fromJson(invalid, expectedDeviceId: 'device-123'),
        throwsFormatException,
      );
    }
  });

  test('le serveur pousse la topologie et l adresse OpenVPN', () {
    final nativeSource = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();
    final profileLiteralStart = nativeSource.indexOf(
      'std::string profile = "client',
    );
    final profileLiteralEnd = nativeSource.indexOf(
      'for (const auto& dns',
      profileLiteralStart,
    );
    final profileBuilder = nativeSource.substring(
      profileLiteralStart,
      profileLiteralEnd,
    );

    expect(profileBuilder, isNot(contains(r'\ntopology subnet\n')));
    expect(profileBuilder, isNot(contains(r'\nifconfig ')));
  });

  test('OpenVPN accepte IPv6 seulement pour un profil double pile', () {
    final nativeSource = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();

    expect(nativeSource, contains('proto udp4'));
    expect(nativeSource, contains('config.protoVersionOverride = 4'));
    expect(nativeSource, contains('if (!a.ipv6_enabled)'));
    expect(nativeSource, contains('pull-filter ignore \\"route-ipv6\\"'));
    expect(nativeSource, contains('pull-filter ignore \\"ifconfig-ipv6\\"'));
  });

  test('le natif canonise les secrets avant de construire le profil', () {
    final nativeSource = File(
      'windows/runner/openvpn_core_module.cpp',
    ).readAsStringSync();
    final connect = nativeSource.indexOf('static bool ConnectLocked');
    final validation = nativeSource.indexOf(
      'CanonicalizeCertificates(a.certificate_pem',
      connect,
    );
    final driver = nativeSource.indexOf(
      'EnsureBundledOpenVpnDcoDriver()',
      connect,
    );
    final profileStart = nativeSource.indexOf('profile += "\\n<ca>');
    final profileEnd = nativeSource.indexOf(
      'erase_remote_material();',
      profileStart,
    );
    final inlineMaterial = nativeSource.substring(profileStart, profileEnd);

    expect(validation, greaterThanOrEqualTo(0));
    expect(driver, greaterThan(validation));
    expect(
      nativeSource.substring(validation, driver),
      contains('SetFailure("openvpn_profile_rejected")'),
    );
    expect(nativeSource, contains('NormalizeTlsCryptV2Key('));
    expect(nativeSource, contains('PEM_read_bio_X509('));
    expect(inlineMaterial, isNot(contains('a.certificate_pem')));
    expect(inlineMaterial, isNot(contains('a.ca_certificate_pem')));
    expect(inlineMaterial, isNot(contains('a.tls_crypt_v2_client_key')));
  });
}
