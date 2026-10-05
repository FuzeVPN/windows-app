// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';

void main() {
  test(
    'discovery uses only the public filtered catalogue without a full field',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final api = ApiClient(
        baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
      );
      addTearDown(() async {
        api.close();
        await server.close(force: true);
      });
      final requests = <String>[];
      var published = <Map<String, Object>>[
        {
          'id': 'available-node',
          'city': 'Paris',
          'country_code': 'FR',
          'display_name': 'Paris',
          'supported_protocols': ['wireguard', 'openvpn'],
        },
      ];
      unawaited(
        server.forEach((request) async {
          requests.add('${request.method} ${request.uri}');
          expect(
            request.headers.value(HttpHeaders.authorizationHeader),
            isNull,
          );
          request.response.headers.contentType = ContentType.json;
          request.response.write(jsonEncode({'locations': published}));
          await request.response.close();
        }),
      );

      expect((await api.locations()).map((location) => location.id), [
        'available-node',
      ]);
      published = [];
      expect(await api.locations(), isEmpty);
      expect(requests, ['GET /v1/locations', 'GET /v1/locations']);
    },
  );

  for (final failure in [(409, 'server_full'), (503, 'capacity_unavailable')]) {
    test(
      'registration retains the received ${failure.$1}/${failure.$2}',
      () async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        final api = ApiClient(
          baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
        );
        addTearDown(() async {
          api.close();
          await server.close(force: true);
        });
        var calls = 0;
        unawaited(
          server.forEach((request) async {
            calls++;
            expect(request.method, 'POST');
            expect(request.uri.path, '/v1/devices');
            await request.drain<void>();
            request.response.statusCode = failure.$1;
            request.response.headers.contentType = ContentType.json;
            request.response.write(jsonEncode({'error': failure.$2}));
            await request.response.close();
          }),
        );

        await expectLater(
          api.registerDevice(
            token: 'synthetic-session',
            name: 'Test',
            publicKey: 'synthetic-key',
            locationId: 'available-node',
          ),
          throwsA(
            isA<ApiException>()
                .having((error) => error.errorCode, 'code', failure.$2)
                .having((error) => error.statusCode, 'status', failure.$1)
                .having(
                  (error) => error.observedHttpStatus,
                  'observed status',
                  failure.$1,
                ),
          ),
        );
        expect(calls, 1);
      },
    );
  }
}
