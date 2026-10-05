// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('verrouille le graphe natif et OpenSSL 3.6.5', () {
    final manifest =
        jsonDecode(
              File('third_party/openvpn3-core/vcpkg.json').readAsStringSync(),
            )
            as Map<String, dynamic>;
    expect(
      manifest['builtin-baseline'],
      '7e43e0768a5af180a9cf75d87d692dce1b9da34f',
    );

    final overrides = {
      for (final dependency in manifest['overrides'] as List<dynamic>)
        (dependency as Map<String, dynamic>)['name'] as String: dependency,
    };
    expect(overrides['openssl']?['version'], '3.6.5');
    expect(overrides['asio']?['version'], '1.36.0');
    expect(
      overrides.keys,
      containsAll(<String>[
        'asio',
        'fmt',
        'gtest',
        'jsoncpp',
        'lz4',
        'openssl',
        'tap-windows6',
        'xxhash',
      ]),
    );

    final opensslOverlay =
        jsonDecode(
              File(
                'third_party/openvpn3-core/fuzevpn-vcpkg-overlays/openssl/vcpkg.json',
              ).readAsStringSync(),
            )
            as Map<String, dynamic>;
    expect(opensslOverlay['version'], '3.6.5');
    final opensslPort = File(
      'third_party/openvpn3-core/fuzevpn-vcpkg-overlays/openssl/portfile.cmake',
    ).readAsStringSync();
    expect(opensslPort, contains('openssl-3.6.5.tar.gz'));
    expect(opensslPort, contains('SHA512 1243d8ef75be54d3'));

    final overlay = File(
      'third_party/openvpn3-core/fuzevpn-vcpkg-overlays/asio/portfile.cmake',
    ).readAsStringSync();
    expect(overlay, contains('REF "asio-1-36-0"'));
    expect(overlay, contains('SHA512 d44b35d9'));
  });

  final nativeRoot = Directory(
    'third_party/openvpn3-core/vcpkg_installed/x64-windows',
  );
  test(
    'vérifie les versions des dépendances natives compilées',
    () {
      final opensslVersion = File(
        '${nativeRoot.path}/share/openssl/OpenSSLConfigVersion.cmake',
      ).readAsStringSync();
      expect(opensslVersion, contains('set(PACKAGE_VERSION 3.6.5)'));
      final asioVersion = File(
        '${nativeRoot.path}/include/asio/version.hpp',
      ).readAsStringSync();
      expect(asioVersion, contains('#define ASIO_VERSION 103600'));
    },
    skip: nativeRoot.existsSync()
        ? false
        : 'Run the native dependency bootstrap to check built artifacts.',
  );

  test('verrouille les dépendances et le SDK Flutter', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    expect(pubspec, contains("sdk: '>=3.12.2 <3.13.0'"));
    expect(pubspec, contains("flutter: '>=3.44.7 <3.45.0'"));
    expect(pubspec, contains('tray_manager: 0.5.3'));
    expect(pubspec, contains('url_launcher: 6.3.2'));
    expect(pubspec, contains('flutter_lints: 5.0.0'));
    expect(File('pubspec.lock').existsSync(), isTrue);
  });
}
