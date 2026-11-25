// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/dns_filter.dart';

// No Flutter binding here: it would answer every HTTP request with 400.
void main() {
  test('lit puis modifie le bloqueur de pub du compte', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    final requests = <(String, String, String?, String)>[];
    server.listen((request) async {
      final body = await utf8.decoder.bind(request).join();
      requests.add((
        request.method,
        request.uri.path,
        request.headers.value(HttpHeaders.authorizationHeader),
        body,
      ));
      request.response
        ..headers.contentType = ContentType.json
        ..write(
          jsonEncode({
            'ad_blocking': request.method == 'PUT',
            'available': true,
            'updated_at': null,
          }),
        );
      await request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('http://${server.address.address}:${server.port}'),
    );
    addTearDown(api.close);

    expect(
      await api.dnsFilter('synthetic-token'),
      const DnsFilterSettings(adBlocking: false, available: true),
    );
    expect(
      await api.setAdBlocking(token: 'synthetic-token', enabled: true),
      const DnsFilterSettings(adBlocking: true, available: true),
    );
    expect(requests, [
      ('GET', '/v1/me/dns-filter', 'Bearer synthetic-token', ''),
      (
        'PUT',
        '/v1/me/dns-filter',
        'Bearer synthetic-token',
        '{"ad_blocking":true}',
      ),
    ]);
  });
}
