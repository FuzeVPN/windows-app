// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/windows_update_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'windows_update_models_test.dart' show manifest;
import 'support/audit_fixtures.dart';

void main() {
  test(
    'application and update failure traces retain native trust status',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final updates = WindowsUpdateController(api: api, bridge: bridge);
      final app = AppController(
        api: ProbeApi(),
        store: ProbeStore(),
        wireguard: ProbeWireGuard(),
        openVpn: ProbeOpenVpn(),
        window: ProbeWindow(),
        updates: updates,
      );
      addTearDown(() {
        app.dispose();
        api.close();
      });
      await updates.checkForUpdates();
      const trustStatus = 0x800b0101;
      bridge.failure = PlatformException(
        code: 'update_signature_invalid',
        message: 'private signature message',
        details: {
          'stage': 'package_signature',
          'trust_status': trustStatus - 0x100000000,
          'url': 'https://private.example.invalid/?token=secret',
        },
      );
      final start = DiagnosticLog.recentLines.length;
      await updates.prepareUpdate();
      expect(app.updates.error?.trustStatus, trustStatus);
      final traces = DiagnosticLog.recentLines
          .skip(start)
          .where(
            (line) =>
                line.contains(' area=update ') &&
                line.contains(' code=update_signature_invalid '),
          )
          .toList();
      expect(traces, hasLength(3));
      for (final event in [
        'download_prepare_failed',
        'operation_failed',
        'failed',
      ]) {
        expect(
          traces.where((line) => line.contains(' event=$event ')),
          hasLength(1),
        );
      }
      for (final line in traces) {
        expect(line, matches(RegExp(r'\bstage=package_signature(?:\s|$)')));
        expect(line, matches(RegExp(r'\btrust_status=2148204801(?:\s|$)')));
        expect(line, isNot(contains('private')));
        expect(line, isNot(contains('secret')));
      }
    },
  );

  for (final phase in ['prepare', 'install']) {
    test(
      '$phase failure traces retain normalized native trust status',
      () async {
        final api = _Api();
        final bridge = _Bridge();
        final controller = WindowsUpdateController(api: api, bridge: bridge);
        addTearDown(() {
          controller.dispose();
          api.close();
        });
        await controller.checkForUpdates();
        if (phase == 'install') await controller.prepareUpdate();
        const trustStatus = 0x800b0101;
        bridge.failure = PlatformException(
          code: 'update_signature_invalid',
          message: 'private signature message',
          details: {
            'stage': 'package_signature',
            // Native HRESULT values can arrive as signed 32-bit integers.
            'trust_status': trustStatus - 0x100000000,
            'url': 'https://private.example.invalid/?token=secret',
          },
        );
        final start = DiagnosticLog.recentLines.length;
        if (phase == 'prepare') {
          await controller.prepareUpdate();
        } else {
          expect(await controller.installPreparedUpdate(), isFalse);
        }
        expect(controller.error?.trustStatus, trustStatus);
        final traces = DiagnosticLog.recentLines
            .skip(start)
            .where((line) => line.contains(' code=update_signature_invalid '))
            .toList();
        expect(traces, hasLength(2));
        expect(
          traces.any((line) => line.contains(' event=operation_failed ')),
          isTrue,
        );
        for (final line in traces) {
          expect(line, contains(' stage=package_signature '));
          expect(line, contains(' trust_status=$trustStatus '));
          expect(line, isNot(contains('private')));
          expect(line, isNot(contains('secret')));
        }
      },
    );
  }

  test('failure traces reject invalid native trust status values', () async {
    final api = _Api();
    final bridge = _Bridge();
    final controller = WindowsUpdateController(api: api, bridge: bridge);
    addTearDown(() {
      controller.dispose();
      api.close();
    });
    await controller.checkForUpdates();
    for (final trustStatus in [0, -0x80000001, 0x100000000, 'secret']) {
      bridge.failure = PlatformException(
        code: 'update_signature_invalid',
        details: {'trust_status': trustStatus},
      );
      final start = DiagnosticLog.recentLines.length;
      await controller.prepareUpdate();
      expect(controller.error?.trustStatus, isNull);
      final traces = DiagnosticLog.recentLines
          .skip(start)
          .where((line) => line.contains(' code=update_signature_invalid '))
          .toList();
      expect(traces, hasLength(2));
      expect(traces.join('\n'), isNot(contains('trust_status=')));
      expect(traces.join('\n'), isNot(contains('secret')));
    }
  });
}

class _Api extends ApiClient {
  _Api() : super(baseUri: Uri.parse('http://localhost/'));

  @override
  Future<WindowsUpdateRelease?> latestWindowsUpdate({
    String arch = 'x64',
    String channel = 'stable',
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
    bool revalidate = false,
  }) async => WindowsUpdateRelease.fromJson(manifest());
}

class _Bridge extends WindowsUpdateBridge {
  PlatformException? failure;

  @override
  Future<WindowsUpdateEnvironment> getEnvironment() async =>
      WindowsUpdateEnvironment(
        version: WindowsUpdateVersion.parse('1.0.0'),
        windowsBuild: 22631,
        arch: 'x64',
        installationMode: WindowsInstallationMode.installed,
      );

  @override
  Future<String> prepareUpdate(WindowsUpdateRelease release) async {
    if (failure case final error?) throw error;
    return 'opaque-token';
  }

  @override
  Future<void> installUpdate(String token) async {
    if (failure case final error?) throw error;
  }

  @override
  Future<void> discardUpdate(String token) async {}
}
