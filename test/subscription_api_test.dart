// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/models.dart';

import 'subscription_models_test.dart' show subscriptionJson;

void main() {
  Future<void> withServer(
    String body,
    Future<void> Function(ApiClient api, List<HttpRequest> requests) verify, {
    int status = 200,
  }) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final api = ApiClient(
      baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
    );
    final requests = <HttpRequest>[];
    server.listen((request) async {
      requests.add(request);
      request.response.statusCode = status;
      if (status == 302) {
        request.response.headers.set(HttpHeaders.locationHeader, '/wrong');
      }
      request.response.write(body);
      await request.response.close();
    });
    try {
      await verify(api, requests);
    } finally {
      api.close();
      await server.close(force: true);
    }
  }

  test('subscription uses the authenticated no-store GET endpoint', () async {
    await withServer(jsonEncode(subscriptionJson()), (api, requests) async {
      final result = await api.subscription('synthetic-token');
      expect(result.status, SubscriptionStatus.active);
      expect(requests, hasLength(1));
      expect(requests.single.method, 'GET');
      expect(requests.single.uri.path, '/v1/billing/subscription');
      expect(requests.single.uri.query, isEmpty);
      expect(
        requests.single.headers.value(HttpHeaders.authorizationHeader),
        'Bearer synthetic-token',
      );
      expect(
        requests.single.headers.value(HttpHeaders.cacheControlHeader),
        'no-store',
      );
    });
  });

  test('malformed billing responses expose only a stable error code', () async {
    for (final body in [
      'not-json',
      '[]',
      'null',
      jsonEncode({...subscriptionJson(), 'has_access': 'true'}),
    ]) {
      await withServer(body, (api, _) async {
        await expectLater(
          api.subscription('synthetic-token'),
          throwsA(
            isA<ApiException>()
                .having((e) => e.statusCode, 'status', 502)
                .having(
                  (e) => e.errorCode,
                  'code',
                  'subscription_response_invalid',
                ),
          ),
        );
      });
    }
  });

  test(
    'auth and server errors preserve the normal strict session contract',
    () async {
      for (final status in [401, 503]) {
        await withServer(jsonEncode({'error': 'unauthorized'}), (api, _) async {
          await expectLater(
            api.subscription('synthetic-token'),
            throwsA(
              isA<ApiException>()
                  .having((e) => e.statusCode, 'status', status)
                  .having(
                    (e) => e.isUnauthorized,
                    'revokes session',
                    status == 401,
                  ),
            ),
          );
        }, status: status);
      }
    },
  );

  test('subscription redirect never forwards the bearer token', () async {
    await withServer('{}', (api, requests) async {
      await expectLater(
        api.subscription('synthetic-token'),
        throwsA(isA<ApiException>()),
      );
      expect(requests, hasLength(1));
    }, status: 302);
  });
}
