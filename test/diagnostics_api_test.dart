// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';

import 'diagnostics_models_test.dart' show syntheticReport;

Map<String, Object?> syntheticReceipt(
  String clientId, {
  bool duplicate = false,
}) => {
  'report_id': 'a1000000-0000-4000-8000-000000000099',
  'client_report_id': clientId,
  'status': 'received',
  'duplicate': duplicate,
  'received_at': '2026-09-16T12:00:00Z',
  'expires_at': '2026-10-16T12:00:00Z',
};

void main() {
  test(
    'POST uses frozen bytes, existing bearer and bounded JSON receipt',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final report = syntheticReport(full: true);
      var calls = 0;
      server.listen((request) async {
        expect(request.method, 'POST');
        expect(request.uri.toString(), '/v1/diagnostics');
        expect(request.headers.contentType?.mimeType, 'application/json');
        expect(
          request.headers.value(HttpHeaders.authorizationHeader),
          'Bearer synthetic-token',
        );
        expect(
          request.headers.value(HttpHeaders.contentEncodingHeader),
          isNull,
        );
        expect(
          await request.fold<List<int>>([], (all, bytes) => all..addAll(bytes)),
          report.bytes,
        );
        final duplicate = calls++ > 0;
        request.response.statusCode = duplicate ? 200 : 201;
        request.response.write(
          jsonEncode(syntheticReceipt(report.reportId, duplicate: duplicate)),
        );
        await request.response.close();
      });
      final api = ApiClient(
        baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
      );
      addTearDown(api.close);
      final first = await api.submitDiagnostic(
        token: 'synthetic-token',
        report: report,
      );
      final repeat = await api.submitDiagnostic(
        token: 'synthetic-token',
        report: report,
      );
      expect(first.clientReportId, report.reportId);
      expect(first.duplicate, false);
      expect(repeat.duplicate, true);
    },
  );
  for (final status in [400, 401, 404, 409, 413, 415, 429, 503]) {
    test(
      'HTTP $status retains only observed status, stable code and Retry-After',
      () async {
        final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
        addTearDown(() => server.close(force: true));
        server.listen((request) async {
          await request.drain<void>();
          request.response.statusCode = status;
          request.response.headers.set('Retry-After', '60');
          request.response.write(
            '{"error":"diagnostics_unavailable","message":"private server detail"}',
          );
          await request.response.close();
        });
        final api = ApiClient(
          baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
        );
        addTearDown(api.close);
        await expectLater(
          api.submitDiagnostic(token: 'synthetic', report: syntheticReport()),
          throwsA(
            isA<ApiException>()
                .having((e) => e.observedHttpStatus, 'observed status', status)
                .having((e) => e.retryAfterSeconds, 'retry', 60)
                .having(
                  (e) => e.toString().contains('private'),
                  'no raw error',
                  false,
                ),
          ),
        );
      },
    );
  }
  test('inconsistent successful receipt is not accepted', () {
    final report = syntheticReport();
    for (final mutation in [
      {'client_report_id': newDiagnosticId()},
      {'duplicate': true},
      {'report_id': report.reportId},
      {'expires_at': '2020-01-01T00:00:00Z'},
      {'message': 'unexpected'},
    ]) {
      expect(
        () => DiagnosticReceipt.fromJson(
          {...syntheticReceipt(report.reportId), ...mutation},
          expectedClientId: report.reportId,
          httpStatus: 201,
        ),
        throwsFormatException,
      );
    }
  });
  test(
    'cancel late opening before credentials; shared client stays open',
    () async {
      final http = _DelayedClient();
      final api = ApiClient(
        client: http,
        baseUri: Uri.parse('http://127.0.0.1'),
      );
      final cancel = DiagnosticRequestCancellation();
      final pending = api.submitDiagnostic(
        token: 'never-written',
        report: syntheticReport(),
        cancellation: cancel,
      );
      cancel.cancel();
      await expectLater(
        pending,
        throwsA(
          isA<DiagnosticsFailure>().having(
            (e) => e.code,
            'cancelled',
            'diagnostic_cancelled',
          ),
        ),
      );
      final request = _LateRequest();
      http.opening.complete(request);
      await Future<void>.delayed(Duration.zero);
      expect(request.aborted, true);
      expect(http.closed, false);
      api.close();
    },
  );
  test('locally synthesized timeout is not an observed HTTP status', () async {
    final api = ApiClient(
      client: _DelayedClient(),
      baseUri: Uri.parse('http://127.0.0.1'),
      requestTimeout: const Duration(milliseconds: 10),
    );
    addTearDown(api.close);
    await expectLater(
      api.submitDiagnostic(token: 'synthetic', report: syntheticReport()),
      throwsA(
        isA<ApiException>().having(
          (e) => e.observedHttpStatus,
          'not observed',
          isNull,
        ),
      ),
    );
  });
  test(
    'cancelling a partial response releases it and leaves ordinary API usable',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      final partial = Completer<void>();
      server.listen((request) async {
        await request.drain<void>();
        if (request.uri.path == '/v1/diagnostics') {
          request.response.statusCode = 201;
          request.response.write('{"status":');
          await request.response.flush();
          partial.complete();
        } else {
          request.response.write('{"locations":[]}');
          await request.response.close();
        }
      });
      final api = ApiClient(
        baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
      );
      addTearDown(api.close);
      final cancel = DiagnosticRequestCancellation();
      final sending = api.submitDiagnostic(
        token: 'synthetic',
        report: syntheticReport(),
        cancellation: cancel,
      );
      await partial.future;
      cancel.cancel();
      await expectLater(sending, throwsA(isA<DiagnosticsFailure>()));
      expect(await api.locations(), isEmpty);
    },
  );
  test('diagnostic redirect never sends the bearer to its target', () async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(() => server.close(force: true));
    var count = 0;
    server.listen((request) async {
      count++;
      await request.drain<void>();
      request.response.statusCode = 302;
      request.response.headers.set('Location', '/other');
      await request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('http://127.0.0.1:${server.port}'),
    );
    addTearDown(api.close);
    await expectLater(
      api.submitDiagnostic(token: 'synthetic', report: syntheticReport()),
      throwsA(
        isA<ApiException>().having(
          (e) => e.observedHttpStatus,
          'redirect',
          302,
        ),
      ),
    );
    expect(count, 1);
  });
}

class _DelayedClient implements HttpClient {
  final opening = Completer<HttpClientRequest>();
  bool closed = false;
  @override
  set connectionTimeout(Duration? value) {}
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) => opening.future;
  @override
  void close({bool force = false}) {
    closed = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _LateRequest implements HttpClientRequest {
  bool aborted = false;
  @override
  void abort([Object? exception, StackTrace? stackTrace]) {
    aborted = true;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}
