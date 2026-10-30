// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/local_diagnostic_trace.dart';
import 'package:fuzevpn_windows/core/windows_update_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/core/windows_update_trace_codes.dart';

import 'windows_update_models_test.dart' show manifest;

void main() {
  for (final mode in [
    WindowsInstallationMode.installed,
    WindowsInstallationMode.portable,
  ]) {
    test(
      'complete exports retain all normal ${mode.name} update operations',
      () async {
        final api = _Api(mode);
        final bridge = _Bridge(mode);
        final controller = WindowsUpdateController(api: api, bridge: bridge);
        addTearDown(() {
          controller.dispose();
          api.close();
        });
        final start = DiagnosticLog.recentLines.length;
        await controller.checkForUpdates();
        expect(controller.status, WindowsUpdateStatus.noUpdate);
        api.release = WindowsUpdateRelease.fromJson(
          {
            ...manifest(),
            if (mode == WindowsInstallationMode.portable)
              'download_url': 'https://downloads.example.test/FuzeVPN.zip',
          },
          package: mode == WindowsInstallationMode.portable
              ? WindowsUpdatePackage.portable
              : WindowsUpdatePackage.installer,
        );
        await controller.checkForUpdates();
        await controller.prepareUpdate();
        expect(controller.status, WindowsUpdateStatus.ready);
        await controller.discardPreparedUpdate();
        await controller.prepareUpdate();
        expect(await controller.installPreparedUpdate(), true);
        final lines = DiagnosticLog.recentLines.skip(start).toList();
        final directory = await Directory.systemTemp.createTemp(
          'update-trace-',
        );
        addTearDown(() => directory.delete(recursive: true));
        final source = File('${directory.path}/diagnostic.log');
        await source.writeAsString('${lines.join('\n')}\n');
        final collected = await LocalDiagnosticTrace.collect(path: source.path);
        expect(collected['status'], 'ok');
        expect(collected['discarded_lines'], 0);
        final events = (collected['events'] as List).cast<Map>();
        for (final operation in ['check', 'prepare', 'discard', 'install']) {
          expect(
            events,
            contains(
              allOf(
                containsPair('event', 'operation_started'),
                containsPair('code', operation),
              ),
            ),
          );
        }
        for (final result in ['no_update', 'available', 'ready', 'launched']) {
          expect(
            events,
            contains(
              allOf(
                containsPair('event', 'operation_completed'),
                containsPair('code', result),
              ),
            ),
          );
        }
        expect(
          events,
          contains(
            allOf(
              containsPair('event', 'environment_distribution'),
              containsPair('code', mode.name),
            ),
          ),
        );
        await DiagnosticLog.flush();
      },
    );
  }

  test('persisted outcomes from earlier update traces remain readable', () async {
    final directory = await Directory.systemTemp.createTemp(
      'update-trace-legacy-',
    );
    addTearDown(() => directory.delete(recursive: true));
    final source = File('${directory.path}/diagnostic.log');
    await source.writeAsString(
      '2026-10-19T12:00:00Z area=update event=operation_completed code=noupdate\n'
      '2026-10-19T12:00:01Z area=update event=operation_completed code=disabledfortesting\n',
    );
    final collected = await LocalDiagnosticTrace.collect(path: source.path);
    expect(collected['status'], 'ok');
    expect(collected['discarded_lines'], 0);
    expect(collected['events'], hasLength(2));
  });

  test(
    'shared catalogue remains closed to unknown identifier-shaped values',
    () async {
      const unknown = 'synthetic_private_reference';
      expect(WindowsUpdateTraceCodes.operation(unknown), 'unknown');
      expect(WindowsUpdateTraceCodes.status(unknown), 'unknown');
      expect(WindowsUpdateTraceCodes.installationMode(unknown), 'unknown');
      expect(WindowsUpdateTraceCodes.values, isNot(contains(unknown)));
      final directory = await Directory.systemTemp.createTemp(
        'update-trace-reject-',
      );
      addTearDown(() => directory.delete(recursive: true));
      final collected = await LocalDiagnosticTrace.collect(
        path: '${directory.path}/absent',
        currentLines: [
          '2026-10-19T12:00:00Z area=update event=operation_started code=$unknown',
        ],
      );
      expect(collected['events'], isEmpty);
      expect(collected['discarded_lines'], 1);
      expect(collected['status'], 'rejected');
    },
  );
}

class _Api extends ApiClient {
  _Api(this.mode) : super(baseUri: Uri.parse('http://127.0.0.1'));
  final WindowsInstallationMode mode;
  WindowsUpdateRelease? release;
  @override
  Future<WindowsUpdateRelease?> latestWindowsUpdate({
    String arch = 'x64',
    String channel = 'stable',
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
    bool revalidate = false,
  }) async => release;
}

class _Bridge extends WindowsUpdateBridge {
  _Bridge(this.mode);
  final WindowsInstallationMode mode;
  @override
  Future<WindowsUpdateEnvironment> getEnvironment() async =>
      WindowsUpdateEnvironment(
        version: WindowsUpdateVersion.parse('1.0.11'),
        windowsBuild: 22631,
        arch: 'x64',
        installationMode: mode,
      );
  @override
  Future<String> prepareUpdate(WindowsUpdateRelease release) async =>
      'synthetic-token';
  @override
  Future<void> installUpdate(String token) async {}
  @override
  Future<void> discardUpdate(String token) async {}
}
