// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/windows_update_bridge.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/windows_update_panel.dart';

void main() {
  for (final reason in [
    (
      detail:
          'CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate',
      expected: 'certificate_issuer_missing',
    ),
    (
      detail: 'CERTIFICATE_VERIFY_FAILED: certificate has expired',
      expected: 'certificate_expired',
    ),
  ]) {
    test(
      'native TLS ${reason.expected} preserves reason without a Win32 code',
      () async {
        final controller = _controller(
          _FailingApi(
            HandshakeException(
              'Handshake error in client',
              OSError('${reason.detail} private/path: secret', -1),
            ),
          ),
        );
        await controller.checkForUpdates();
        expect(controller.error?.code, 'tls_handshake_failed');
        expect(controller.error?.tlsReason, reason.expected);
        expect(controller.error?.windowsError, isNull);
        expect(controller.error?.statusCode, isNull);
        expect(controller.error.toString(), isNot(contains('private')));
        expect(controller.error.toString(), isNot(contains('secret')));
        final failureLines = DiagnosticLog.recentLines.where(
          (line) =>
              line.contains(' area=update ') &&
              line.contains('code=tls_handshake_failed'),
        );
        expect(failureLines.last, contains('reason=${reason.expected}'));
        expect(failureLines.last, isNot(contains('windows_error=')));
        expect(failureLines.last, isNot(contains('private')));
      },
    );
  }

  testWidgets('TLS issuer detail is visible without sentinel Win32 or raw text', (
    tester,
  ) async {
    final controller = _controller(
      _FailingApi(
        const HandshakeException(
          'Handshake error in client',
          OSError(
            'CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate (private/file.cc: secret)',
            -1,
          ),
        ),
      ),
    );
    await controller.checkForUpdates();
    await tester.pumpWidget(_host(controller));
    await tester.pumpAndSettle();
    expect(
      find.textContaining('TLS : certificate_issuer_missing'),
      findsOneWidget,
    );
    expect(find.textContaining('Code Windows :'), findsNothing);
    expect(find.textContaining('HTTP :'), findsNothing);
    expect(find.textContaining('private/file.cc'), findsNothing);
    expect(find.textContaining('secret'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  test(
    'separate update controllers use distinct trace correlation IDs',
    () async {
      final first = _controller(_SuccessApi());
      final second = _controller(_SuccessApi());
      await first.checkForUpdates();
      await second.checkForUpdates();
      final updateLines = DiagnosticLog.recentLines
          .where((line) => line.contains(' area=update '))
          .toList();
      final starts = updateLines
          .where((line) => line.contains(' event=operation_started '))
          .toList();
      final ids = starts.reversed.take(2).map((line) {
        return RegExp(r'\brequest_id=(\d+)\b').firstMatch(line)!.group(1)!;
      }).toList();
      expect(ids.toSet(), hasLength(2));
      for (final id in ids) {
        final pattern = RegExp('\\brequest_id=$id\\b');
        final correlated = updateLines.where(pattern.hasMatch).join('\n');
        expect(correlated, contains('event=environment_started'));
        expect(correlated, contains('event=manifest_completed'));
        expect(correlated, contains('event=package_comparison_completed'));
        expect(correlated, contains('event=operation_completed'));
        expect(correlated, contains('duration_ms='));
      }
    },
  );

  test(
    'successful checks trace each completed discovery phase in order',
    () async {
      final events = <String>[];
      final stop = DiagnosticLog.observe((area, event, code) {
        if (area == 'update') events.add(event);
      });
      addTearDown(stop);
      final controller = _controller(_SuccessApi());
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.noUpdate);
      expect(events, [
        'operation_started',
        'environment_started',
        'environment_distribution',
        'environment_architecture',
        'environment_completed',
        'compatibility_started',
        'compatibility_completed',
        'manifest_started',
        'manifest_completed',
        'package_comparison_started',
        'package_comparison_completed',
        'version_comparison_started',
        'version_comparison_completed',
        'check_succeeded',
        'operation_completed',
      ]);
    },
  );

  for (final failure in <Object>[
    const HandshakeException('private certificate details'),
    const ApiException(
      statusCode: 503,
      errorCode: 'api_resolution_unavailable',
      localErrorCode: 'broker_unavailable',
      windowsError: 2,
    ),
    ApiException.fromResponse(
      statusCode: 503,
      body: '{"error":"server_error"}',
    ),
  ]) {
    test(
      '${failure.runtimeType} trace stops at the failing manifest phase',
      () async {
        final trace = <({String event, String? code})>[];
        final stop = DiagnosticLog.observe((area, event, code) {
          if (area == 'update') trace.add((event: event, code: code));
        });
        addTearDown(stop);
        final controller = _controller(_FailingApi(failure));
        await controller.checkForUpdates();
        final expectedCode = switch (failure) {
          HandshakeException() => 'tls_handshake_failed',
          ApiException(localErrorCode: final String localCode) => localCode,
          _ => 'update_request_failed',
        };
        expect(
          trace,
          containsAllInOrder([
            (event: 'operation_started', code: 'check'),
            (event: 'environment_started', code: null),
            (event: 'environment_completed', code: null),
            (event: 'manifest_started', code: null),
            (event: 'manifest_failed', code: expectedCode),
            (event: 'operation_failed', code: expectedCode),
          ]),
        );
        expect(
          trace.where((entry) => entry.event == 'manifest_completed'),
          isEmpty,
        );
        expect(
          trace.where((entry) => entry.event == 'package_comparison_started'),
          isEmpty,
        );
        expect(
          trace.where((entry) => entry.event == 'operation_completed'),
          isEmpty,
        );
        expect(
          trace.toString(),
          isNot(contains('private certificate details')),
        );
      },
    );
  }

  test(
    'preparation and installation trace callback and native phases in order',
    () async {
      final events = <String>[];
      final stop = DiagnosticLog.observe((area, event, code) {
        if (area == 'update') events.add(event);
      });
      addTearDown(stop);
      final api = _SuccessApi()
        ..release = WindowsUpdateRelease(
          version: WindowsUpdateVersion.parse('1.0.7'),
          downloadUrl: Uri.https('downloads.example.invalid', '/setup.exe'),
          sha256: List.filled(64, 'a').join(),
          releaseNotes: 'private release notes',
        );
      final bridge = _PreparingBridge();
      final controller = WindowsUpdateController(api: api, bridge: bridge);
      addTearDown(() {
        controller.dispose();
        api.close();
      });
      await controller.checkForUpdates();
      events.clear();
      await controller.prepareUpdate();
      expect(
        events,
        containsAllInOrder([
          'operation_started',
          'environment_started',
          'environment_completed',
          'distribution_started',
          'distribution_completed',
          'manifest_started',
          'manifest_completed',
          'package_comparison_started',
          'package_comparison_completed',
          'artifact_comparison_started',
          'artifact_comparison_completed',
          'download_prepare_started',
          'download_prepare_completed',
          'operation_completed',
        ]),
      );
      events.clear();
      expect(
        await controller.installPreparedUpdate(beforeInstall: () async {}),
        isTrue,
      );
      expect(
        events,
        containsAllInOrder([
          'operation_started',
          'environment_started',
          'environment_completed',
          'manifest_started',
          'manifest_completed',
          'artifact_comparison_started',
          'artifact_comparison_completed',
          'environment_started',
          'environment_completed',
          'preinstall_started',
          'preinstall_completed',
          'install_launch_started',
          'install_launch_completed',
          'operation_completed',
        ]),
      );
      expect(events.toString(), isNot(contains('private')));
      expect(events.toString(), isNot(contains('example.invalid')));
      expect(bridge.installs, 1);
    },
  );

  for (final code in [
    'broker_unavailable',
    'broker_protocol_error',
    'broker_response_timeout',
    'permission_denied',
    'runtime_unavailable',
    'service_configuration_mismatch',
    'api_bootstrap_unavailable',
    'api_resolution_unavailable',
    'api_resolver_invalid_response',
    'native_bridge_unavailable',
    'native_operation_failed',
  ]) {
    test('local $code is retained without a synthetic HTTP 503', () async {
      final api = _FailingApi(
        ApiException(
          statusCode: 503,
          errorCode: 'api_resolution_unavailable',
          localErrorCode: code,
          windowsError: 5,
        ),
      );
      final controller = _controller(api);
      await controller.checkForUpdates();
      expect(controller.status, WindowsUpdateStatus.error);
      expect(controller.error?.code, code);
      expect(controller.error?.windowsError, 5);
      expect(controller.error?.statusCode, isNull);
      expect(controller.error?.stage, 'update_check');
    });
  }

  test('an unobserved 503 never becomes an HTTP failure', () async {
    final controller = _controller(
      _FailingApi(
        const ApiException(statusCode: 503, errorCode: 'unclassified_failure'),
      ),
    );
    await controller.checkForUpdates();
    expect(controller.error?.code, 'update_request_failed');
    expect(controller.error?.statusCode, isNull);
  });

  test(
    'unsafe local codes and invalid Windows details are discarded',
    () async {
      final controller = _controller(
        _FailingApi(
          const ApiException(
            statusCode: 503,
            errorCode: 'api_resolution_unavailable',
            localErrorCode: 'private=secret',
            windowsError: 0x100000000,
          ),
        ),
      );
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_request_failed');
      expect(controller.error?.statusCode, isNull);
      expect(controller.error?.windowsError, isNull);
      expect(controller.error.toString(), isNot(contains('private')));
      expect(controller.error.toString(), isNot(contains('secret')));
    },
  );

  for (final failure in <Object>[
    const HandshakeException('private certificate details'),
    const SocketException('private network details'),
    const HttpException('private protocol details'),
    TimeoutException('private timeout details'),
    const ApiException(
      statusCode: 503,
      errorCode: 'api_resolution_unavailable',
      localErrorCode: 'network_timeout',
    ),
  ]) {
    test(
      '${failure.runtimeType} preserves its actual failure category',
      () async {
        final controller = _controller(_FailingApi(failure));
        await controller.checkForUpdates();
        expect(controller.error?.code, switch (failure) {
          HandshakeException() => 'tls_handshake_failed',
          TimeoutException() || ApiException() => 'update_network_timeout',
          _ => 'update_network_failed',
        });
        expect(controller.error?.statusCode, isNull);
        expect(controller.error.toString(), isNot(contains('private')));
      },
    );
  }

  test(
    'an actual HTTP 503 response retains its observed HTTP status',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final subscription = server.listen((request) {
        request.response.statusCode = 503;
        request.response.headers.contentType = ContentType.json;
        request.response.write('{"error":"service_unavailable"}');
        unawaited(request.response.close());
      });
      addTearDown(subscription.cancel);
      final api = HttpOverrides.runWithHttpOverrides(
        () => ApiClient(baseUri: Uri.parse('http://127.0.0.1:${server.port}/')),
        _RealHttpOverrides(),
      );
      final controller = _controller(api);
      await controller.checkForUpdates();
      expect(controller.error?.code, 'update_request_failed');
      expect(controller.error?.statusCode, 503);
      expect(controller.error?.windowsError, isNull);
    },
  );

  testWidgets(
    'local broker failures display their code without accusing HTTP',
    (tester) async {
      final controller = _controller(
        _FailingApi(
          const ApiException(
            statusCode: 503,
            errorCode: 'api_resolution_unavailable',
            localErrorCode: 'broker_unavailable',
            windowsError: 2,
          ),
        ),
      );
      await controller.checkForUpdates();
      await tester.pumpWidget(_host(controller));
      await tester.pumpAndSettle();
      expect(
        find.text('La recherche de mise à jour a échoué.'),
        findsOneWidget,
      );
      expect(find.textContaining('broker_unavailable'), findsOneWidget);
      expect(find.textContaining('Code Windows : 2'), findsOneWidget);
      expect(find.textContaining('HTTP :'), findsNothing);
      expect(find.textContaining('refusé la demande'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('unclassified update failure gives neutral user feedback', (
    tester,
  ) async {
    final controller = _controller(_FailingApi(StateError('private details')));
    await controller.checkForUpdates();
    await tester.pumpWidget(_host(controller));
    await tester.pumpAndSettle();
    expect(find.text('La recherche de mise à jour a échoué.'), findsOneWidget);
    expect(find.textContaining('update_request_failed'), findsOneWidget);
    expect(find.textContaining('HTTP :'), findsNothing);
    expect(find.textContaining('refusé la demande'), findsNothing);
    expect(find.textContaining('private details'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('only an explicit TLS failure displays TLS feedback', (
    tester,
  ) async {
    final controller = _controller(
      _FailingApi(const HandshakeException('private certificate details')),
    );
    await controller.checkForUpdates();
    await tester.pumpWidget(_host(controller));
    await tester.pumpAndSettle();
    expect(
      find.text('La connexion sécurisée au service n’a pas pu être vérifiée.'),
      findsOneWidget,
    );
    expect(find.textContaining('tls_handshake_failed'), findsOneWidget);
    expect(find.textContaining('HTTP :'), findsNothing);
    expect(find.textContaining('private certificate details'), findsNothing);
    expect(tester.takeException(), isNull);
  });
}

WindowsUpdateController _controller(ApiClient api) {
  final controller = WindowsUpdateController(api: api, bridge: const _Bridge());
  addTearDown(() {
    controller.dispose();
    api.close();
  });
  return controller;
}

Widget _host(WindowsUpdateController controller) => MaterialApp(
  locale: const Locale('fr'),
  supportedLocales: const [Locale('fr')],
  localizationsDelegates: const [
    AppLocalizations.delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
  ],
  home: Scaffold(
    body: SingleChildScrollView(
      child: WindowsUpdatePanel(controller: controller, onInstall: () async {}),
    ),
  ),
);

class _FailingApi extends ApiClient {
  _FailingApi(this.failure) : super(baseUri: Uri.parse('http://localhost/'));

  final Object failure;

  @override
  Future<WindowsUpdateRelease?> latestWindowsUpdate({
    String arch = 'x64',
    String channel = 'stable',
    WindowsUpdatePackage package = WindowsUpdatePackage.installer,
    bool revalidate = false,
  }) async => throw failure;
}

class _SuccessApi extends ApiClient {
  _SuccessApi() : super(baseUri: Uri.parse('http://localhost/'));

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
  const _Bridge();

  @override
  Future<WindowsUpdateEnvironment> getEnvironment() async =>
      WindowsUpdateEnvironment(
        version: WindowsUpdateVersion.parse('1.0.6'),
        windowsBuild: 26200,
        arch: 'x64',
        installationMode: WindowsInstallationMode.installed,
      );
}

class _PreparingBridge extends _Bridge {
  int installs = 0;

  @override
  Future<String> prepareUpdate(WindowsUpdateRelease release) async =>
      'private-staging-token';

  @override
  Future<void> installUpdate(String token) async {
    installs++;
  }
}

// Only this loopback regression opts out of Flutter's HTTP-400 test client.
class _RealHttpOverrides extends HttpOverrides {}
