// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';

const _certificatePem = '''-----BEGIN CERTIFICATE-----
QUJD
-----END CERTIFICATE-----''';
const _tlsKey = '''-----BEGIN OpenVPN tls-crypt-v2 client key-----
QUJD
-----END OpenVPN tls-crypt-v2 client key-----''';

void main() {
  test('a late HTTP opening is aborted after the total deadline', () async {
    final client = _DelayedOpeningClient();
    final api = ApiClient(
      client: client,
      baseUri: Uri.parse('http://127.0.0.1'),
      requestTimeout: const Duration(milliseconds: 30),
    );
    await expectLater(
      api.locations(),
      throwsA(
        isA<ApiException>().having(
          (error) => error.errorCode,
          'code',
          'request_timeout',
        ),
      ),
    );
    final request = _LateRequest();
    client.opening.complete(request);
    await Future<void>.delayed(Duration.zero);
    expect(request.aborted, isTrue);
    api.close();
  });

  test('HTTP headers and body share one total deadline', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}'),
      requestTimeout: const Duration(milliseconds: 500),
    );
    addTearDown(api.close);
    final serverDone = Completer<void>();
    server.listen((request) async {
      try {
        await Future<void>.delayed(const Duration(milliseconds: 320));
        request.response.write('{"locations":');
        await request.response.flush();
        await Future<void>.delayed(const Duration(milliseconds: 320));
        request.response.write('[]}');
        await request.response.close();
      } on SocketException {
        // The client is expected to close a response past its deadline.
      } finally {
        serverDone.complete();
      }
    });
    await expectLater(
      api.locations(),
      throwsA(
        isA<ApiException>().having(
          (error) => error.errorCode,
          'code',
          'request_timeout',
        ),
      ),
    );
    await serverDone.future;
  });

  test('refuse un corps de réponse supérieur à la limite', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    server.listen((request) async {
      final oversizedBody = '{"locations":[]}${List.filled(128, 'x').join()}';
      request.response.write(oversizedBody);
      await request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
      maxResponseBytes: 64,
    );

    await expectLater(
      api.locations(),
      throwsA(
        isA<ApiException>().having(
          (error) => error.errorCode,
          'errorCode',
          'response_too_large',
        ),
      ),
    );
  });

  test(
    'interrompt la lecture lorsque le serveur ne termine pas sa réponse',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final responseStarted = Completer<void>();
      server.listen((request) async {
        request.response.write('{"locations":[');
        await request.response.flush();
        responseStarted.complete();
      });
      final api = ApiClient(
        baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
        requestTimeout: const Duration(milliseconds: 250),
      );

      final result = api.locations();
      await responseStarted.future;
      await expectLater(
        result,
        throwsA(
          isA<ApiException>().having(
            (error) => error.errorCode,
            'errorCode',
            'request_timeout',
          ),
        ),
      );
    },
  );

  test('refuse les redirections API', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    var redirectedRequestSeen = false;
    String? redirectedAuthorization;
    server.listen((request) {
      if (request.uri.path == '/redirected') {
        redirectedRequestSeen = true;
        redirectedAuthorization = request.headers.value(
          HttpHeaders.authorizationHeader,
        );
        request.response
          ..statusCode = HttpStatus.ok
          ..write('{"devices":[]}');
      } else {
        request.response
          ..statusCode = HttpStatus.movedPermanently
          ..headers.set(HttpHeaders.locationHeader, '/redirected')
          ..write('redirected');
      }
      request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
    );

    await expectLater(
      api.devices('test-bearer-token'),
      throwsA(
        isA<ApiException>().having(
          (error) => error.statusCode,
          'statusCode',
          HttpStatus.movedPermanently,
        ),
      ),
    );
    expect(redirectedRequestSeen, isFalse);
    expect(redirectedAuthorization, isNull);
  });

  test('sérialise exactement la demande double pile et son omission', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final bodies = <Map<String, dynamic>>[];
    server.listen((request) async {
      bodies.add(
        jsonDecode(await utf8.decoder.bind(request).join())
            as Map<String, dynamic>,
      );
      final dualStack = bodies.length == 1;
      request.response
        ..statusCode = HttpStatus.ok
        ..headers.contentType = ContentType.json
        ..write(
          jsonEncode({
            'device_id': 'device-1',
            'address': '10.10.0.2/24',
            'dns': ['10.10.0.1'],
            'server_public_key': 'public-key',
            'endpoint': '198.51.100.10:51820',
            'addresses': dualStack
                ? ['10.10.0.2/24', 'fd42::2/128']
                : ['10.10.0.2/24'],
            'allowed_ips': dualStack ? ['0.0.0.0/0', '::/0'] : ['0.0.0.0/0'],
            'ip_families': dualStack ? ['ipv4', 'ipv6'] : ['ipv4'],
          }),
        );
      await request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
    );

    await api.registerDevice(
      token: 'token',
      name: 'Windows',
      publicKey: 'public-key',
      locationId: 'frankfurt-01',
      ipFamilies: dualStackIpFamilies,
    );
    await api.registerDevice(
      token: 'token',
      name: 'Windows',
      publicKey: 'public-key',
      locationId: 'frankfurt-01',
    );

    expect(bodies[0]['ip_families'], ['ipv4', 'ipv6']);
    expect(bodies[1].containsKey('ip_families'), isFalse);
  });

  test(
    'propage IPv6 à la création OpenVPN mais pas au renouvellement',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final bodies = <Map<String, dynamic>>[];
      server.listen((request) async {
        bodies.add(
          jsonDecode(await utf8.decoder.bind(request).join())
              as Map<String, dynamic>,
        );
        final dualStack = bodies.length == 1;
        request.response
          ..statusCode = HttpStatus.created
          ..headers.contentType = ContentType.json
          ..headers.set(HttpHeaders.cacheControlHeader, 'no-store')
          ..write(
            jsonEncode({
              'device_id': 'device-1',
              'protocol': 'openvpn',
              'certificate_pem': _certificatePem,
              'ca_certificate_pem': _certificatePem,
              'tls_crypt_v2_client_key': _tlsKey,
              'endpoint': '198.51.100.10',
              'dns': ['10.10.0.1'],
              'address': '10.10.0.2/24',
              if (dualStack) ...{
                'addresses': ['10.10.0.2/24', 'fd42::2/128'],
                'allowed_ips': ['0.0.0.0/0', '::/0'],
                'ip_families': ['ipv4', 'ipv6'],
              },
              'server_name': 'frankfurt-01.openvpn.fuzevpn.internal',
              'remote_cert_tls_server': true,
              'ciphers': ['AES-256-GCM'],
              'not_after': '2027-01-01T12:00:00Z',
            }),
          );
        await request.response.close();
      });
      final api = ApiClient(
        baseUri: Uri.parse('http://${server.address.address}:${server.port}/'),
      );

      await api.createOpenVpnProfile(
        token: 'token',
        deviceId: 'device-1',
        csrPem: 'csr',
        ipFamilies: dualStackIpFamilies,
      );
      await api.renewOpenVpnProfile(
        token: 'token',
        deviceId: 'device-1',
        csrPem: 'csr',
      );

      expect(bodies[0]['ip_families'], ['ipv4', 'ipv6']);
      expect(bodies[1].containsKey('ip_families'), isFalse);
    },
  );
}

class _DelayedOpeningClient implements HttpClient {
  final opening = Completer<HttpClientRequest>();
  @override
  set connectionTimeout(Duration? value) {}
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) => opening.future;
  @override
  void close({bool force = false}) {}
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _LateRequest implements HttpClientRequest {
  bool aborted = false;
  @override
  void abort([Object? exception, StackTrace? stackTrace]) => aborted = true;
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
