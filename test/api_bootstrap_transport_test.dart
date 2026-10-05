// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';

const _fixtureDirectory = 'test/fixtures/api-bootstrap';

SecurityContext _clientContext() =>
    SecurityContext(withTrustedRoots: false)
      ..setTrustedCertificates('$_fixtureDirectory/certificate.pem');

Future<HttpServer> _server() => HttpServer.bindSecure(
  InternetAddress.loopbackIPv4,
  0,
  SecurityContext()
    ..useCertificateChain('$_fixtureDirectory/certificate.pem')
    ..usePrivateKey('$_fixtureDirectory/private-key.pem'),
);

void main() {
  test(
    'resolver reports local cause without claiming an HTTP response',
    () async {
      final api = ApiClient(
        baseUri: Uri.parse('https://never-contacted.invalid'),
        resolveApiAddresses: () async => throw PlatformException(
          code: 'runtime_status_unavailable',
          message: 'Sensitive native text must be discarded',
          details: {'win32_error': 5, 'private': 'must be discarded'},
        ),
      );
      addTearDown(api.close);
      await expectLater(
        api.me('synthetic'),
        throwsA(
          isA<ApiException>()
              .having(
                (e) => e.errorCode,
                'compatible code',
                'api_resolution_unavailable',
              )
              .having(
                (e) => e.localErrorCode,
                'local cause',
                'runtime_status_unavailable',
              )
              .having((e) => e.windowsError, 'Windows code', 5)
              .having((e) => e.observedHttpStatus, 'observed HTTP', isNull)
              .having((e) => e.isUnauthorized, 'session revoked', isFalse)
              .having(
                (e) => e.toString(),
                'no native text',
                isNot(contains('Sensitive')),
              ),
        ),
      );
    },
  );

  test('runtime discovery failure retains its local Windows code', () async {
    final api = ApiClient(
      baseUri: Uri.parse('https://never-contacted.invalid'),
      resolveApiAddresses: () async => throw PlatformException(
        code: 'runtime_detection_failed',
        details: {'win32_error': 87},
      ),
    );
    addTearDown(api.close);
    await expectLater(
      api.locations(),
      throwsA(
        isA<ApiException>()
            .having(
              (e) => e.diagnosticErrorCode,
              'native code',
              'runtime_detection_failed',
            )
            .having((e) => e.windowsError, 'Windows code', 87)
            .having((e) => e.observedHttpStatus, 'no HTTP response', isNull),
      ),
    );
  });

  test(
    'resolver discards unapproved codes and invalid Windows details',
    () async {
      for (final failure in [
        PlatformException(
          code: 'private_native_value',
          details: {'win32_error': 5},
        ),
        PlatformException(
          code: 'api_bootstrap_unavailable',
          details: {'win32_error': -1},
        ),
        PlatformException(
          code: 'api_bootstrap_unavailable',
          details: {'win32_error': 'secret'},
        ),
      ]) {
        final api = ApiClient(
          baseUri: Uri.parse('https://never-contacted.invalid'),
          resolveApiAddresses: () async => throw failure,
        );
        addTearDown(api.close);
        await expectLater(
          api.locations(),
          throwsA(
            isA<ApiException>()
                .having(
                  (e) => e.localErrorCode,
                  'approved code',
                  failure.code == 'private_native_value'
                      ? isNull
                      : 'api_bootstrap_unavailable',
                )
                .having(
                  (e) => e.windowsError,
                  'valid Windows code only',
                  isNull,
                )
                .having((e) => e.observedHttpStatus, 'observed HTTP', isNull),
          ),
        );
      }
    },
  );

  test(
    'closing the API interrupts a TLS write stalled by a peer that does not read',
    () async {
      final server = await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
        SecurityContext()
          ..useCertificateChain('$_fixtureDirectory/certificate.pem')
          ..usePrivateKey('$_fixtureDirectory/private-key.pem'),
      );
      addTearDown(server.close);
      final accepted = Completer<void>();
      server.listen((socket) {
        addTearDown(socket.destroy);
        accepted.complete();
        // Deliberately never consume HTTP, so the client's write buffers fill.
      });
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: _clientContext(),
        requestTimeout: const Duration(seconds: 5),
      );
      addTearDown(api.close);
      var completed = false;
      final request = api.login(
        email: 'synthetic@example.invalid',
        password: List.filled(16 * 1024 * 1024, 'x').join(),
      );
      unawaited(
        request.then<void>(
          (_) => completed = true,
          onError: (Object _, StackTrace _) => completed = true,
        ),
      );
      final failure = expectLater(request, throwsA(isA<SocketException>()));
      await accepted.future.timeout(const Duration(seconds: 2));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      expect(completed, isFalse);
      api.close();
      await failure.timeout(const Duration(seconds: 1));
    },
  );

  test(
    'TLS deadline closes a peer that accepts TCP but never completes the handshake',
    () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(server.close);
      final receivedHello = Completer<void>();
      final peerClosed = Completer<void>();
      server.listen((socket) {
        addTearDown(socket.destroy);
        socket.listen(
          (_) {
            if (!receivedHello.isCompleted) receivedHello.complete();
          },
          onDone: () {
            if (!peerClosed.isCompleted) peerClosed.complete();
          },
          onError: (Object _) {
            if (!peerClosed.isCompleted) peerClosed.complete();
          },
        );
      });
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        connectionTimeout: const Duration(milliseconds: 200),
        requestTimeout: const Duration(seconds: 2),
        securityContext: _clientContext(),
      );
      addTearDown(api.close);
      final request = expectLater(
        api.me('synthetic'),
        throwsA(isA<SocketException>()),
      );
      await receivedHello.future.timeout(const Duration(seconds: 1));
      await request;
      await peerClosed.future.timeout(const Duration(seconds: 1));
    },
  );

  test(
    'HTTPS adapter transfers request and response bodies larger than TLS buffers',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      final password = List.filled(256 * 1024, 'x').join();
      final token = List.filled(384 * 1024, 't').join();
      final requestRead = Completer<int>();
      server.listen((request) async {
        await Future<void>.delayed(const Duration(milliseconds: 50));
        final body =
            jsonDecode(await utf8.decoder.bind(request).join())
                as Map<String, dynamic>;
        requestRead.complete((body['password'] as String).length);
        request.response.write(jsonEncode({'access_token': token}));
        await request.response.close();
      });
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: _clientContext(),
      );
      addTearDown(api.close);
      final result = await api.login(
        email: 'synthetic@example.invalid',
        password: password,
      );
      expect(await requestRead.future, password.length);
      expect(result.accessToken.length, token.length);
    },
  );

  test(
    'native-resolved loopback transport preserves HTTPS hostname and validates its certificate',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      final hosts = <String>[];
      server.listen((request) async {
        hosts.add(request.headers.value(HttpHeaders.hostHeader)!);
        request.response.persistentConnection = false;
        request.response.write(
          '{"user_id":"test","email":"test@example.invalid"}',
        );
        await request.response.close();
      });
      var resolutions = 0;
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async {
          resolutions++;
          return ['127.0.0.1'];
        },
        securityContext: _clientContext(),
      );
      addTearDown(api.close);
      expect((await api.me('synthetic')).userId, 'test');
      expect((await api.me('synthetic')).userId, 'test');
      expect(hosts, [
        'api-bootstrap.invalid:${server.port}',
        'api-bootstrap.invalid:${server.port}',
      ]);
      expect(
        resolutions,
        1,
        reason: 'Positive native answers share a bounded cache.',
      );
      api.invalidateBootstrapCache();
      await api.me('synthetic');
      expect(resolutions, 2);
    },
  );

  test(
    'native IP does not bypass the requested hostname certificate check',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      var requests = 0;
      server.listen((request) async {
        requests++;
        await request.response.close();
      }, onError: (Object _) {});
      final api = ApiClient(
        baseUri: Uri.parse('https://wrong-host.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: _clientContext(),
      );
      addTearDown(api.close);
      await expectLater(
        api.me('synthetic'),
        throwsA(isA<HandshakeException>()),
      );
      expect(
        requests,
        0,
        reason: 'No HTTP or bearer token crosses a failed TLS handshake.',
      );
    },
  );

  test(
    'native resolver failure and malformed IPs fail without shared DNS fallback',
    () async {
      for (final malformed in [false, true]) {
        final api = ApiClient(
          baseUri: Uri.parse('https://never-contacted.invalid'),
          resolveApiAddresses: () async {
            if (malformed) return ['not-an-ip'];
            throw StateError('Native resolver unavailable');
          },
        );
        addTearDown(api.close);
        await expectLater(
          api.me('synthetic'),
          throwsA(
            isA<ApiException>().having(
              (error) => error.errorCode,
              'code',
              'api_resolution_unavailable',
            ),
          ),
        );
      }
    },
  );

  test(
    'connection deadline covers a native resolution that never finishes',
    () async {
      final gate = Completer<List<String>>();
      final api = ApiClient(
        baseUri: Uri.parse('https://never-contacted.invalid'),
        resolveApiAddresses: () => gate.future,
        connectionTimeout: const Duration(milliseconds: 40),
        requestTimeout: const Duration(seconds: 1),
      );
      addTearDown(api.close);
      await expectLater(api.me('synthetic'), throwsA(isA<SocketException>()));
      gate.complete(['127.0.0.1']);
      await Future<void>.delayed(Duration.zero);
    },
  );
}
