// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/windows_update_bridge.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/windows_update_models.dart';

Map<String, dynamic> manifest({String version = '1.2.3'}) => {
  'version': version,
  'download_url': 'https://downloads.example.test/FuzeVPN.exe',
  'sha256': 'a' * 64,
  'release_notes': 'Correctifs et améliorations.',
};

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  test('TLS reasons are allowlisted and survive update-stage propagation', () {
    for (final reason in DiagnosticLog.tlsFailureReasons) {
      final failure = WindowsUpdateFailure('tls_handshake_failed', tlsReason: reason);
      final staged = failure.withStage('update_check');
      expect(staged.tlsReason, reason);
      expect(staged.stage, 'update_check');
      expect(staged.windowsError, isNull);
      expect(staged.toString(), contains('TLS: $reason'));
    }
    const unsafe = WindowsUpdateFailure(
      'tls_handshake_failed',
      tlsReason: 'private/path certificate=secret',
    );
    expect(unsafe.tlsReason, isNull);
    expect(unsafe.withStage('update_check').tlsReason, isNull);
    expect(unsafe.toString(), isNot(contains('secret')));
  });
  test('native updater diagnostics retain only bounded documented fields', () {
    final failure =
        WindowsUpdateFailure.fromNative('update_unsigned_application', {
          'stage': 'application_signature',
          'http_status': 403,
          'windows_error': 5,
          'trust_status': -2146762496,
          'url': 'https://example.test/private?token=secret',
          'path': r'C:\Users\private\update.exe',
          'message': 'secret diagnostic message',
        });
    expect(failure.stage, 'application_signature');
    expect(failure.statusCode, 403);
    expect(failure.windowsError, 5);
    expect(failure.trustStatus, 0x800b0100);
    expect(failure.toString(), isNot(contains('secret')));
    expect(failure.toString(), isNot(contains('private')));

    for (final details in <Object?>[
      null,
      'secret',
      ['download_http', 403],
      {
        'stage': 'https://example.test/?token=secret',
        'http_status': '403',
        'windows_error': -1,
        'trust_status': 0x100000000,
      },
      {
        'stage': 1,
        'http_status': 600,
        'windows_error': 0x100000000,
        'trust_status': -0x80000001,
      },
      {'stage': '', 'http_status': 99, 'windows_error': 0, 'trust_status': 0},
    ]) {
      final rejected = WindowsUpdateFailure.fromNative(
        'update_download_failed',
        details,
        fallbackStage: 'prepare_update',
      );
      expect(rejected.stage, 'prepare_update');
      expect(rejected.statusCode, isNull);
      expect(rejected.windowsError, isNull);
      expect(rejected.trustStatus, isNull);
      expect(rejected.toString(), isNot(contains('secret')));
    }
  });

  test('MSI versions compare numerically and reject Flutter revisions', () {
    final ten = WindowsUpdateVersion.parse('1.10.0');
    expect(
      ten.compareTo(WindowsUpdateVersion.parse('1.9.65535')),
      greaterThan(0),
    );
    expect(WindowsUpdateVersion.parse('001.02.00003').toString(), '1.2.3');
    expect(WindowsUpdateVersion.parse('255.255.65535').components, [
      255,
      255,
      65535,
    ]);
    expect(
      WindowsUpdateVersion.parse(
        '0.0.0',
      ).compareTo(WindowsUpdateVersion.parse('0.0.0')),
      0,
    );
    for (final invalid in [
      '',
      '1',
      '1.2',
      '1.2.3.0',
      '1.2.3+1',
      'v1.2.3',
      '256.1.1',
      '1.256.1',
      '1.2.65536',
      '1.2.-1',
      '1.2.+1',
      '1.2.3 ',
      ' 1.2.3',
      '1.2.3\n',
      '1.2.٣',
      '1..3',
      '000001.2.3',
    ]) {
      expect(
        () => WindowsUpdateVersion.parse(invalid),
        throwsFormatException,
        reason: invalid,
      );
    }
  });

  test('release metadata validates all security and compatibility fields', () {
    final valid = WindowsUpdateRelease.fromJson({
      ...manifest(),
      'sha256': 'A' * 64,
      'min_windows_build': 19045,
    });
    expect(valid.sha256, 'a' * 64);
    expect(valid.minWindowsBuild, 19045);
    expect(
      valid.sameArtifact(
        WindowsUpdateRelease.fromJson({
          ...manifest(),
          'min_windows_build': 19045,
          'release_notes': 'Reworded notes',
        }),
      ),
      isTrue,
    );
    for (final invalid in <Map<String, dynamic>>[
      {},
      {...manifest(), 'version': 123},
      {...manifest(), 'sha256': 'g' * 64},
      {...manifest(), 'sha256': '${'a' * 64}\n'},
      {...manifest(), 'release_notes': null},
      {...manifest(), 'release_notes': 'x' * 16385},
      {...manifest(), 'release_notes': '\u0000'},
      {...manifest(), 'min_windows_build': 19045.0},
      {...manifest(), 'min_windows_build': -1},
      {...manifest(), 'min_windows_build': null},
      {...manifest(), 'min_windows_build': true},
    ]) {
      expect(
        () => WindowsUpdateRelease.fromJson(invalid),
        throwsFormatException,
      );
    }
    for (final url in [
      'http://example.test/a.exe',
      'https://user@example.test/a.exe',
      'https://@example.test/a.exe',
      'https://example.test/a.exe#fragment',
      'file:///a.exe',
      '//example.test/a.exe',
      'https://example.test:0/a.exe',
      'https://example.test:65536/a.exe',
      'https://example.test/a\n.exe',
    ]) {
      expect(
        () =>
            WindowsUpdateRelease.fromJson({...manifest(), 'download_url': url}),
        throwsFormatException,
        reason: url,
      );
    }
  });

  test('native environment has three public version components', () {
    final environment = WindowsUpdateEnvironment.fromMap({
      'version': '1.2.3',
      'windows_build': 19045,
      'arch': 'x64',
      'installation_mode': 'installed',
    });
    expect(environment.version.toString(), '1.2.3');
    expect(
      () => WindowsUpdateEnvironment.fromMap({
        'version': '1.2.3.1',
        'windows_build': 19045,
        'arch': 'x64',
        'installation_mode': 'installed',
      }),
      throwsFormatException,
    );
    expect(
      () => WindowsUpdateEnvironment.fromMap({
        'version': '1.2.3',
        'windows_build': '19045',
        'arch': 'x64',
        'installation_mode': 'installed',
      }),
      throwsFormatException,
    );
  });

  test('distribution mode is explicit and never defaults to installed', () {
    final valid = <Object?, Object?>{
      'version': '1.2.3',
      'windows_build': 19045,
      'arch': 'x64',
    };
    for (final mode in WindowsInstallationMode.values) {
      expect(
        WindowsUpdateEnvironment.fromMap({
          ...valid,
          'installation_mode': mode.name,
        }).installationMode,
        mode,
      );
    }
    for (final mode in [null, true, 1, '', 'Installed', 'unknown']) {
      expect(
        () => WindowsUpdateEnvironment.fromMap({
          ...valid,
          if (mode != null) 'installation_mode': mode,
        }),
        throwsFormatException,
      );
    }
  });

  test(
    'bridge uses the opaque native token and the agreed channel payload',
    () async {
      const channel = MethodChannel('fuzevpn/update');
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return switch (call.method) {
              'getEnvironment' => {
                'version': '1.0.0',
                'windows_build': 19045,
                'arch': 'x64',
                'installation_mode': 'installed',
              },
              'prepareUpdate' => 'opaque-preparation-token',
              _ => null,
            };
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      const bridge = WindowsUpdateBridge();
      expect((await bridge.getEnvironment()).version.toString(), '1.0.0');
      final token = await bridge.prepareUpdate(
        WindowsUpdateRelease.fromJson(manifest()),
      );
      await bridge.installUpdate(token);
      await bridge.discardUpdate(token);
      expect(calls[1].arguments, {
        'download_url': manifest()['download_url'],
        'sha256': 'a' * 64,
        'version': '1.2.3',
        'package': 'installer',
      });
      expect(calls[2].arguments, {'token': token});
      expect(calls[3].arguments, {'token': token});
      final portable = WindowsUpdateRelease.fromJson({
        ...manifest(),
        'download_url': 'https://downloads.example.test/FuzeVPN.zip',
      }, package: WindowsUpdatePackage.portable);
      await bridge.prepareUpdate(portable);
      expect(calls[4].arguments, {
        'download_url': portable.downloadUrl.toString(),
        'sha256': portable.sha256,
        'version': portable.version.toString(),
        'package': 'portable',
      });
    },
  );

  test(
    'portable manifests require ZIP and installed metadata accepts EXE or MSI',
    () {
      for (final package in WindowsUpdatePackage.values) {
        final extension = package == WindowsUpdatePackage.portable
            ? 'zip'
            : 'exe';
        final release = WindowsUpdateRelease.fromJson({
          ...manifest(),
          'download_url':
              'https://downloads.example.test/FuzeVPN.$extension?download=1',
        }, package: package);
        expect(release.package, package);
        expect(release.supportsAutomaticUpdate, isTrue);
        expect(release.requiresManualInstallation, isFalse);
        for (final invalid in [
          if (package == WindowsUpdatePackage.portable) 'msi',
          package == WindowsUpdatePackage.portable ? 'exe' : 'zip',
          'zip.exe/other',
          'zip%2fexe',
        ]) {
          expect(
            () => WindowsUpdateRelease.fromJson({
              ...manifest(),
              'download_url': 'https://downloads.example.test/FuzeVPN.$invalid',
            }, package: package),
            throwsFormatException,
          );
        }
      }
    },
  );

  test('MSI metadata is valid but always requires manual installation', () {
    for (final path in ['FuzeVPN.msi', 'FuzeVPN.MSI?download=1']) {
      final release = WindowsUpdateRelease.fromJson({
        ...manifest(),
        'download_url': 'https://downloads.example.test/$path',
      });
      expect(release.package, WindowsUpdatePackage.installer);
      expect(release.supportsAutomaticUpdate, isFalse);
      expect(release.requiresManualInstallation, isTrue);
    }
  });

  test('MSI discovery preserves HTTPS, hash and public version validation', () {
    final valid = {
      ...manifest(),
      'download_url': 'https://downloads.example.test/FuzeVPN.msi',
    };
    for (final invalid in <Map<String, dynamic>>[
      {...valid, 'download_url': 'http://downloads.example.test/FuzeVPN.msi'},
      {
        ...valid,
        'download_url': 'https://user@downloads.example.test/FuzeVPN.msi',
      },
      {
        ...valid,
        'download_url': 'https://downloads.example.test/FuzeVPN.msi#x',
      },
      {
        ...valid,
        'download_url': 'https://downloads.example.test/FuzeVPN.msi.exe/other',
      },
      {...valid, 'download_url': 'https://downloads.example.test/FuzeVPN.msix'},
      {...valid, 'sha256': 'g' * 64},
      {...valid, 'sha256': 'a' * 63},
      {...valid, 'version': '1.2.3+4'},
      {...valid, 'min_windows_build': -1},
    ]) {
      expect(
        () => WindowsUpdateRelease.fromJson(invalid),
        throwsFormatException,
      );
    }
  });
}
