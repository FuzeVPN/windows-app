// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/windows_update_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'windows_update_models_test.dart' show manifest;

WindowsUpdateRelease _release([
  String version = '1.2.3',
  WindowsUpdatePackage package = WindowsUpdatePackage.installer,
]) => WindowsUpdateRelease.fromJson({
  ...manifest(version: version),
  if (package == WindowsUpdatePackage.portable)
    'download_url': 'https://downloads.example.test/FuzeVPN.zip',
}, package: package);

WindowsUpdateRelease _msiRelease(String version, {int? minWindowsBuild}) =>
    WindowsUpdateRelease.fromJson({
      ...manifest(version: version),
      'download_url': 'https://downloads.example.test/FuzeVPN.msi',
      if (minWindowsBuild != null) 'min_windows_build': minWindowsBuild,
    });

void main() {
  test('successful MSI checks expose fixed local acceptance codes', () async {
    final trace = <({String area, String event, String? code})>[];
    final stop = DiagnosticLog.observe((area, event, code) {
      if (area == 'update') trace.add((area: area, event: event, code: code));
    });
    addTearDown(stop);
    final api = _Api()..candidate = _msiRelease('1.0.3');
    final bridge = _Bridge()..currentVersion = '1.0.5';
    final controller = WindowsUpdateController(api: api, bridge: bridge);
    addTearDown(controller.dispose);
    await controller.checkForUpdates();
    expect(
      trace,
      contains((area: 'update', event: 'check_succeeded', code: 'no_update')),
    );
    api.candidate = _msiRelease('1.0.6');
    await controller.checkForUpdates();
    expect(
      trace,
      contains((
        area: 'update',
        event: 'check_succeeded',
        code: 'manual_installation',
      )),
    );
    expect(trace.toString(), isNot(contains('downloads.example')));
    expect(trace.toString(), isNot(contains('1.0.3')));
    expect(trace.toString(), isNot(contains('1.0.6')));
    expect(trace.toString(), isNot(contains('Correctifs')));
  });

  for (final version in ['1.0.3', '1.0.5']) {
    test(
      'installed 1.0.5 ignores valid MSI $version without preparation',
      () async {
        final api = _Api()
          ..candidate = _msiRelease(version, minWindowsBuild: 99999);
        final bridge = _Bridge()..currentVersion = '1.0.5';
        final controller = WindowsUpdateController(api: api, bridge: bridge);
        addTearDown(controller.dispose);
        await controller.checkForUpdates();
        expect(controller.status, WindowsUpdateStatus.noUpdate);
        expect(controller.error, isNull);
        expect(controller.requiresManualInstallation, isFalse);
        await controller.prepareUpdate();
        expect(controller.status, WindowsUpdateStatus.noUpdate);
        expect(bridge.preparations, 0);
        expect(bridge.installs, 0);
      },
    );
  }

  test('newer MSI is discoverable but preparation stays manual', () async {
    final api = _Api()..candidate = _msiRelease('1.0.6');
    final bridge = _Bridge()..currentVersion = '1.0.5';
    final controller = WindowsUpdateController(api: api, bridge: bridge);
    addTearDown(controller.dispose);
    await controller.checkForUpdates();
    expect(controller.release?.version.toString(), '1.0.6');
    expect(controller.status, WindowsUpdateStatus.unsupported);
    expect(controller.requiresManualInstallation, isTrue);
    expect(controller.canAutomaticallyUpdate, isFalse);
    expect(controller.error?.code, 'update_installer_manual');
    await controller.prepareUpdate();
    expect(controller.status, WindowsUpdateStatus.unsupported);
    expect(controller.requiresManualInstallation, isTrue);
    expect(bridge.preparations, 0);
    var stopCalls = 0;
    expect(
      await controller.installPreparedUpdate(
        beforeInstall: () async => stopCalls++,
      ),
      isFalse,
    );
    expect(stopCalls, 0);
    expect(bridge.installs, 0);
    expect(controller.status, WindowsUpdateStatus.unsupported);
    expect(controller.error?.code, 'update_installer_manual');
  });

  test(
    'EXE display replaced by MSI never reaches native preparation',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      api.candidate = _msiRelease('1.2.3');
      await controller.prepareUpdate();
      expect(controller.status, WindowsUpdateStatus.unsupported);
      expect(controller.requiresManualInstallation, isTrue);
      expect(bridge.preparations, 0);
    },
  );

  test(
    'prepared EXE replaced by MSI is discarded before stopping the VPN',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      expect(controller.hasPreparedUpdate, isTrue);
      api.candidate = _msiRelease('1.2.3');
      var stopCalls = 0;
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async => stopCalls++,
        ),
        isFalse,
      );
      expect(controller.hasPreparedUpdate, isFalse);
      expect(controller.status, WindowsUpdateStatus.unsupported);
      expect(controller.error?.code, 'update_installer_manual');
      expect(bridge.discarded, ['token-1']);
      expect(bridge.preparations, 1);
      expect(bridge.installs, 0);
      expect(stopCalls, 0);
      await controller.discardPreparedUpdate();
      expect(controller.status, WindowsUpdateStatus.unsupported);
      expect(controller.requiresManualInstallation, isTrue);
    },
  );

  test(
    'newer MSI still respects installation mode and Windows build',
    () async {
      final api = _Api()
        ..candidate = _msiRelease('1.2.3', minWindowsBuild: 99999);
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.unsupported);
      expect(controller.error?.code, 'update_unsupported');
      await controller.prepareUpdate();
      expect(bridge.preparations, 0);
      bridge.installationMode = WindowsInstallationMode.unavailable;
      await controller.prepareUpdate();
      expect(controller.error?.code, 'update_environment_unavailable');
      expect(bridge.preparations, 0);
    },
  );

  for (final mode in [WindowsInstallationMode.unavailable]) {
    test(
      '$mode may check releases but cannot download or stop the VPN',
      () async {
        final api = _Api();
        final bridge = _Bridge()..installationMode = mode;
        final controller = WindowsUpdateController(api: api, bridge: bridge);
        addTearDown(controller.dispose);
        await controller.checkForUpdates();
        expect(controller.status, WindowsUpdateStatus.available);
        expect(controller.canUseInstaller, isFalse);
        expect(controller.release?.version.toString(), '1.2.3');
        await controller.prepareUpdate();
        const code = 'update_environment_unavailable';
        expect(controller.error?.code, code);
        var stopped = false;
        expect(
          await controller.installPreparedUpdate(
            beforeInstall: () async {
              stopped = true;
            },
          ),
          isFalse,
        );
        expect(controller.error?.code, code);
        expect(stopped, isFalse);
        expect(bridge.preparations, 0);
        expect(bridge.installs, 0);
        expect(api.revalidations, [false]);
      },
    );
  }

  for (final arch in ['x64', 'arm64']) {
    test('portable $arch checks ZIP package through launch', () async {
      final api = _Api()
        ..candidate = _release('1.2.3', WindowsUpdatePackage.portable);
      final bridge = _Bridge()
        ..arch = arch
        ..installationMode = WindowsInstallationMode.portable;
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      expect(controller.canUpdate, isTrue);
      expect(controller.canUseInstaller, isFalse);
      await controller.prepareUpdate();
      expect(controller.status, WindowsUpdateStatus.ready);
      var stops = 0;
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async {
            stops++;
          },
        ),
        isTrue,
      );
      expect(stops, 1);
      expect(bridge.installs, 1);
      expect(controller.status, WindowsUpdateStatus.launched);
      expect(api.architectures, [arch, arch, arch]);
      expect(api.packages, List.filled(3, WindowsUpdatePackage.portable));
      expect(api.revalidations, [false, true, true]);
    });
  }

  test(
    'distribution is rechecked before downloading a displayed release',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      bridge.installationMode = WindowsInstallationMode.portable;
      api.candidate = _release('1.2.3', WindowsUpdatePackage.portable);
      await controller.prepareUpdate();
      expect(controller.error?.code, 'update_changed');
      expect(bridge.preparations, 0);
      expect(api.revalidations, [false, true]);
      expect(api.packages, [
        WindowsUpdatePackage.installer,
        WindowsUpdatePackage.portable,
      ]);
    },
  );

  test(
    'distribution changed during revalidation never stops the VPN',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      final gate = Completer<void>();
      api.gate = gate.future;
      var stopped = false;
      final installing = controller.installPreparedUpdate(
        beforeInstall: () async {
          stopped = true;
        },
      );
      await _until(() => api.revalidations.length == 3);
      bridge.installationMode = WindowsInstallationMode.portable;
      gate.complete();
      expect(await installing, isFalse);
      expect(stopped, isFalse);
      expect(bridge.installs, 0);
      expect(controller.error?.code, 'update_changed');
    },
  );

  test(
    'native preparation failures retain their actionable error codes',
    () async {
      for (final code in [
        'update_environment_unavailable',
        'update_portable_manual',
        'update_version_invalid',
        'update_storage_failed',
        'update_installation_unprotected',
        'maintenance_in_progress',
        'update_unsupported',
        'update_unsigned_application',
        'update_application_signature_invalid',
        'update_application_open_failed',
        'update_application_architecture_mismatch',
        'update_download_http_error',
        'update_download_redirect_rejected',
        'update_download_network_error',
        'update_download_timeout',
        'update_download_url_invalid',
        'update_download_too_large',
        'update_download_empty',
        'update_prepare_failed',
        'update_hash_mismatch',
        'update_signature_invalid',
        'update_publisher_mismatch',
        'update_package_architecture_mismatch',
        'update_package_version_mismatch',
        'update_package_mode_mismatch',
        'update_archive_invalid',
        'update_archive_unsafe',
        'update_archive_too_large',
        'update_archive_extract_failed',
        'update_portable_manifest_invalid',
        'update_portable_target_invalid',
        'update_portable_replace_failed',
      ]) {
        final bridge = _Bridge();
        final controller = WindowsUpdateController(api: _Api(), bridge: bridge);
        await controller.checkForUpdates();
        bridge.prepareFailure = PlatformException(code: code);
        await controller.prepareUpdate();
        expect(controller.status, WindowsUpdateStatus.error);
        expect(controller.error?.code, code);
        expect(controller.hasPreparedUpdate, isFalse);
        expect(bridge.installs, 0);
        controller.dispose();
      }
    },
  );

  test(
    'preparation retains safe native stage and HTTP codes without raw messages',
    () async {
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: _Api(), bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      bridge.prepareFailure = PlatformException(
        code: 'update_download_http_error',
        message: 'download https://example.test?token=secret',
        details: {
          'stage': 'download_http',
          'http_status': 403,
          'url': 'https://example.test?token=secret',
        },
      );
      await controller.prepareUpdate();
      expect(controller.error?.code, 'update_download_http_error');
      expect(controller.error?.stage, 'download_http');
      expect(controller.error?.statusCode, 403);
      expect(controller.error.toString(), isNot(contains('secret')));
      expect(controller.hasPreparedUpdate, isFalse);
      expect(bridge.installs, 0);

      bridge.prepareFailure = PlatformException(
        code: 'https://example.test?token=secret',
        message: 'private message',
        details: {'stage': 'private message', 'http_status': '403'},
      );
      await controller.prepareUpdate();
      expect(controller.error?.code, 'update_prepare_failed');
      expect(controller.error?.stage, 'prepare_update');
      expect(controller.error?.statusCode, isNull);
      expect(controller.error.toString(), isNot(contains('secret')));
    },
  );

  test(
    'portable archive rejection retains its code and safe extraction stage',
    () async {
      final api = _Api()
        ..candidate = _release('1.2.3', WindowsUpdatePackage.portable);
      final bridge = _Bridge()
        ..installationMode = WindowsInstallationMode.portable;
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      bridge.prepareFailure = PlatformException(
        code: 'update_archive_unsafe',
        message: 'private file path',
        details: {
          'stage': 'portable_archive',
          'windows_error': 5,
          'path': 'secret',
        },
      );
      await controller.prepareUpdate();
      expect(controller.error?.code, 'update_archive_unsafe');
      expect(controller.error?.stage, 'portable_archive');
      expect(controller.error?.windowsError, 5);
      expect(controller.error.toString(), isNot(contains('private')));
      expect(controller.hasPreparedUpdate, isFalse);
      expect(bridge.installs, 0);
    },
  );

  test(
    'API timeouts identify discovery rather than installer download',
    () async {
      final api = _Api()..failure = TimeoutException('private endpoint');
      final controller = WindowsUpdateController(api: api, bridge: _Bridge());
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_network_timeout');
      expect(controller.error?.stage, 'update_check');
      expect(controller.error.toString(), isNot(contains('private endpoint')));
    },
  );

  test(
    'locally synthesized API failures never pretend to be HTTP replies',
    () async {
      final api = _Api();
      final controller = WindowsUpdateController(api: api, bridge: _Bridge());
      addTearDown(controller.dispose);
      api.failure = const ApiException(
        statusCode: 408,
        errorCode: 'request_timeout',
      );
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_network_timeout');
      expect(controller.error?.stage, 'update_check');
      expect(controller.error?.statusCode, isNull);
      api.failure = const ApiException(
        statusCode: 502,
        errorCode: 'response_too_large',
      );
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_manifest_invalid');
      expect(controller.error?.statusCode, isNull);
      api.failure = const ApiException(
        statusCode: 408,
        errorCode: 'request_timeout',
        observedHttpStatus: 408,
      );
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_request_failed');
      expect(controller.error?.statusCode, 408);
    },
  );

  test(
    'newer release requires separate preparation and explicit installation',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.available);
      expect(bridge.preparations, 0);
      expect(bridge.installs, 0);
      await controller.prepareUpdate();
      expect(controller.status, WindowsUpdateStatus.ready);
      expect(controller.preparedVersion.toString(), '1.2.3');
      expect(bridge.installs, 0);
      var stopped = false;
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async {
            stopped = true;
          },
        ),
        isTrue,
      );
      expect(stopped, isTrue);
      expect(bridge.installs, 1);
      expect(controller.status, WindowsUpdateStatus.launched);
      expect(controller.hasPreparedUpdate, isFalse);
      expect(api.revalidations, [false, true, true]);
    },
  );

  test('same or older versions and absent releases never download', () async {
    for (final candidate in [
      null,
      _release('1.0.0'),
      _release('0.255.65535'),
    ]) {
      final api = _Api()..candidate = candidate;
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.noUpdate);
      await controller.prepareUpdate();
      expect(bridge.preparations, 0);
      controller.dispose();
    }
  });

  test(
    'unsupported architecture or Windows build is blocked before preparation',
    () async {
      final api = _Api();
      final bridge = _Bridge()..arch = 'x86';
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.unsupported);
      expect(api.revalidations, isEmpty);
      controller.dispose();
      final minBuildApi = _Api()
        ..candidate = WindowsUpdateRelease.fromJson({
          ...manifest(),
          'min_windows_build': 99999,
        });
      final other = WindowsUpdateController(
        api: minBuildApi,
        bridge: _Bridge(),
      );
      await other.checkForUpdates();
      expect(other.status, WindowsUpdateStatus.unsupported);
      await other.prepareUpdate();
      expect(other.status, WindowsUpdateStatus.unsupported);
      other.dispose();
    },
  );

  test(
    'ARM64 discovery and safety revalidation use the ARM64 endpoint',
    () async {
      final api = _Api();
      final bridge = _Bridge()..arch = 'arm64';
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.available);
      await controller.prepareUpdate();
      expect(controller.status, WindowsUpdateStatus.ready);
      expect(api.architectures, ['arm64', 'arm64']);
      expect(api.revalidations, [false, true]);
      controller.dispose();
    },
  );

  test(
    'withdrawal between display and preparation prevents downloading',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      api.candidate = null;
      await controller.prepareUpdate();
      expect(controller.status, WindowsUpdateStatus.noUpdate);
      expect(bridge.preparations, 0);
    },
  );

  test('changed metadata requires a new explicit preparation', () async {
    final api = _Api();
    final bridge = _Bridge();
    final controller = WindowsUpdateController(api: api, bridge: bridge);
    addTearDown(controller.dispose);
    await controller.checkForUpdates();
    api.candidate = _release('1.2.4');
    await controller.prepareUpdate();
    expect(controller.status, WindowsUpdateStatus.available);
    expect(controller.error?.code, 'update_changed');
    expect(bridge.preparations, 0);
    await controller.prepareUpdate();
    expect(bridge.preparations, 1);
    expect(controller.status, WindowsUpdateStatus.ready);
  });

  test(
    'withdrawal before installation discards artifact without stopping VPN',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      api.candidate = null;
      var stopped = false;
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async {
            stopped = true;
          },
        ),
        isFalse,
      );
      expect(stopped, isFalse);
      expect(bridge.installs, 0);
      expect(bridge.discarded, ['token-1']);
      expect(controller.status, WindowsUpdateStatus.noUpdate);
    },
  );

  for (final change in ['sha256', 'download_url', 'min_windows_build']) {
    test('changed $change before install invalidates prepared token', () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      api.candidate = WindowsUpdateRelease.fromJson({
        ...manifest(),
        change: switch (change) {
          'sha256' => 'b' * 64,
          'download_url' => 'https://downloads.example.test/replaced.exe',
          _ => 19000,
        },
      });
      var stopped = false;
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async {
            stopped = true;
          },
        ),
        isFalse,
      );
      expect(stopped, isFalse);
      expect(bridge.installs, 0);
      expect(controller.hasPreparedUpdate, isFalse);
      expect(controller.error?.code, 'update_changed');
    });
  }

  test(
    'network failure at revalidation retains staged artifact but cannot install it',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      api.failure = const SocketException('offline');
      var stopped = false;
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async {
            stopped = true;
          },
        ),
        isFalse,
      );
      expect(controller.status, WindowsUpdateStatus.error);
      expect(controller.error?.code, 'update_network_failed');
      expect(controller.hasPreparedUpdate, isTrue);
      expect(stopped, isFalse);
      expect(bridge.installs, 0);
      api.failure = null;
      expect(await controller.installPreparedUpdate(), isTrue);
    },
  );

  test(
    'VPN cleanup failure and cancelled UAC preserve retry without claiming launch',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      expect(
        await controller.installPreparedUpdate(
          beforeInstall: () async {
            throw PlatformException(code: 'update_vpn_cleanup_failed');
          },
        ),
        isFalse,
      );
      expect(controller.error?.code, 'update_vpn_cleanup_failed');
      expect(bridge.installs, 0);
      bridge.installFailure = PlatformException(code: 'update_cancelled');
      expect(await controller.installPreparedUpdate(), isFalse);
      expect(controller.error?.code, 'update_cancelled');
      expect(controller.hasPreparedUpdate, isTrue);
      bridge.installFailure = null;
      expect(await controller.installPreparedUpdate(), isTrue);
    },
  );

  test(
    'concurrent checks and preparations serialize native operations',
    () async {
      final gate = Completer<void>();
      final api = _Api()..gate = gate.future;
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      final first = controller.checkForUpdates();
      final second = controller.checkForUpdates();
      expect(identical(first, second), isTrue);
      await controller.prepareUpdate();
      expect(bridge.preparations, 0);
      gate.complete();
      await first;
      api.gate = null;
      final prepareGate = Completer<String>();
      bridge.prepareGate = prepareGate.future;
      final prepare = controller.prepareUpdate();
      final duplicate = controller.prepareUpdate();
      expect(identical(prepare, duplicate), isTrue);
      await _until(() => bridge.preparations == 1);
      expect(await controller.installPreparedUpdate(), isFalse);
      prepareGate.complete('token-delayed');
      await prepare;
      expect(controller.status, WindowsUpdateStatus.ready);
    },
  );

  test(
    'double installation invokes the VPN callback and native launch once',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(controller.dispose);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      final gate = Completer<void>();
      var callbacks = 0;
      final first = controller.installPreparedUpdate(
        beforeInstall: () async {
          callbacks++;
          await gate.future;
        },
      );
      final second = controller.installPreparedUpdate(
        beforeInstall: () async {
          callbacks++;
        },
      );
      expect(identical(first, second), isTrue);
      gate.complete();
      expect(await first, isTrue);
      expect(callbacks, 1);
      expect(bridge.installs, 1);
    },
  );

  test(
    'dispose during download discards a late token and never closes an injected API',
    () async {
      final api = _Api();
      final gate = Completer<String>();
      final bridge = _Bridge()..prepareGate = gate.future;
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      var notifications = 0;
      controller.addListener(() {
        notifications++;
      });
      await controller.checkForUpdates();
      final pending = controller.prepareUpdate();
      await _until(() => bridge.preparations == 1);
      controller.dispose();
      final afterDispose = notifications;
      gate.complete('late-token');
      await pending;
      expect(bridge.discarded, ['late-token']);
      expect(notifications, afterDispose);
      expect(api.closed, isFalse);
    },
  );

  test(
    'dispose during VPN callback cancels the launch and cleans prepared artifact',
    () async {
      final api = _Api();
      final bridge = _Bridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      await controller.checkForUpdates();
      await controller.prepareUpdate();
      final gate = Completer<void>();
      var callbackEntered = false;
      final pending = controller.installPreparedUpdate(
        beforeInstall: () async {
          callbackEntered = true;
          await gate.future;
        },
      );
      await _until(() => callbackEntered);
      controller.dispose();
      gate.complete();
      expect(await pending, isFalse);
      expect(bridge.installs, 0);
      expect(bridge.discarded, ['token-1']);
    },
  );

  test(
    '401 and malformed manifests stay isolated in updater failure state',
    () async {
      final api = _Api();
      final controller = WindowsUpdateController(api: api, bridge: _Bridge());
      addTearDown(controller.dispose);
      api.failure = const ApiException(
        statusCode: 401,
        errorCode: 'unauthorized',
        observedHttpStatus: 401,
      );
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_request_failed');
      expect(controller.error?.statusCode, 401);
      api.failure = const FormatException('invalid response');
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_manifest_invalid');
    },
  );
}

Future<void> _until(bool Function() predicate) async {
  for (var attempt = 0; attempt < 40 && !predicate(); attempt++) {
    await Future<void>.delayed(Duration.zero);
  }
  expect(predicate(), isTrue);
}

class _Api extends ApiClient {
  _Api() : super(baseUri: Uri.parse('http://localhost/'));
  WindowsUpdateRelease? candidate = _release();
  Object? failure;
  Future<void>? gate;
  bool closed = false;
  final revalidations = <bool>[];
  final architectures = <String>[];
  final packages = <WindowsUpdatePackage>[];
  @override
  Future<WindowsUpdateRelease?> latestWindowsUpdate({
    String arch = 'x64',
    String channel = 'stable',
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
    bool revalidate = false,
  }) async {
    architectures.add(arch);
    packages.add(package);
    revalidations.add(revalidate);
    await gate;
    final error = failure;
    if (error != null) throw error;
    return candidate;
  }

  @override
  void close() {
    closed = true;
    super.close();
  }
}

class _Bridge extends WindowsUpdateBridge {
  String arch = 'x64';
  String currentVersion = '1.0.0';
  WindowsInstallationMode installationMode = WindowsInstallationMode.installed;
  int preparations = 0;
  int installs = 0;
  Future<String>? prepareGate;
  Object? installFailure;
  Object? prepareFailure;
  final discarded = <String>[];
  @override
  Future<WindowsUpdateEnvironment> getEnvironment() async =>
      WindowsUpdateEnvironment(
        version: WindowsUpdateVersion.parse(currentVersion),
        windowsBuild: 19045,
        arch: arch,
        installationMode: installationMode,
      );
  @override
  Future<String> prepareUpdate(WindowsUpdateRelease release) async {
    preparations++;
    final error = prepareFailure;
    if (error != null) throw error;
    return prepareGate == null ? 'token-$preparations' : await prepareGate!;
  }

  @override
  Future<void> installUpdate(String token) async {
    final error = installFailure;
    if (error != null) throw error;
    installs++;
  }

  @override
  Future<void> discardUpdate(String token) async {
    discarded.add(token);
  }
}
