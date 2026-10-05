// SPDX-License-Identifier: MPL-2.0
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';

void main() {
  final now = DateTime.utc(2026, 9, 30, 12);
  ApiException parse(String value, {DateTime? clock}) =>
      ApiException.fromResponse(
        statusCode: 503,
        body: '{"error":"diagnostics_unavailable"}',
        retryAfterHeader: value,
        now: clock ?? now,
      );

  test('HTTP dates and numeric delays represent the same future retry', () {
    expect(parse('7200').retryAfterSeconds, 7200);
    expect(
      parse(
        HttpDate.format(now.add(const Duration(hours: 2))),
      ).retryAfterSeconds,
      7200,
    );
  });

  test('past and present HTTP dates permit an immediate retry', () {
    expect(parse(HttpDate.format(now)).retryAfterSeconds, 0);
    expect(
      parse(
        HttpDate.format(now.subtract(const Duration(hours: 1))),
      ).retryAfterSeconds,
      0,
    );
  });

  test('both legacy HTTP-date formats retain a future retry', () {
    expect(parse('Wednesday, 30-Sep-26 14:00:00 GMT').retryAfterSeconds, 7200);
    expect(parse('Wed Sep 30 14:00:00 2026').retryAfterSeconds, 7200);
  });

  test('RFC 850 resolves short years across a century boundary', () {
    final clock = DateTime.utc(2099, 12, 31, 23);
    expect(
      parse('Friday, 01-Jan-00 00:00:00 GMT', clock: clock).retryAfterSeconds,
      3600,
    );
  });

  test('RFC 850 applies the 50-year boundary to the full timestamp', () {
    expect(parse('Wednesday, 30-Sep-76 12:00:00 GMT').retryAfterSeconds, 86400);
    expect(parse('Wednesday, 30-Sep-76 12:00:01 GMT').retryAfterSeconds, 0);
    expect(parse('Sunday, 06-Nov-94 08:49:37 GMT').retryAfterSeconds, 0);
  });

  test('a remaining fractional second rounds up', () {
    expect(
      parse(
        HttpDate.format(now.add(const Duration(seconds: 1))),
        clock: now.add(const Duration(milliseconds: 900)),
      ).retryAfterSeconds,
      1,
    );
  });

  test('a far future date suspends reports through their maximum lifetime', () {
    expect(
      parse(
        HttpDate.format(now.add(const Duration(days: 3))),
      ).retryAfterSeconds,
      86400,
    );
  });

  test(
    'malformed dates and invalid numeric values retain bounded fallback',
    () {
      for (final value in ['not-a-date', '-1', '86401', '']) {
        expect(parse(value).retryAfterSeconds, isNull, reason: value);
      }
      expect(parse(' 60 ').retryAfterSeconds, 60);
    },
  );

  test(
    'the transport applies its injected clock to an HTTP-date response',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      server.listen((request) async {
        request.response.statusCode = 503;
        request.response.headers.set(
          HttpHeaders.retryAfterHeader,
          HttpDate.format(now.add(const Duration(hours: 2))),
        );
        request.response.write('{"error":"diagnostics_unavailable"}');
        await request.response.close();
      });
      final api = ApiClient(
        baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
        retryAfterClock: () => now,
      );
      addTearDown(api.close);
      await expectLater(
        api.locations(),
        throwsA(
          isA<ApiException>().having(
            (error) => error.retryAfterSeconds,
            'retry delay',
            7200,
          ),
        ),
      );
    },
  );
}
