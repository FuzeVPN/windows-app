// SPDX-License-Identifier: MPL-2.0
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/diagnostics_models.dart';

const _fixture = 'test/fixtures/api-bootstrap';

Future<HttpServer> _server() => HttpServer.bindSecure(
  InternetAddress.loopbackIPv4,
  0,
  SecurityContext()
    ..useCertificateChain('$_fixture/certificate.pem')
    ..usePrivateKey('$_fixture/private-key.pem'),
);

List<String> _since(int position) =>
    DiagnosticLog.recentLines.skip(position).toList();

void main() {
  test(
    'socket and TLS traces retain numeric cause without exception text',
    () async {
      final position = DiagnosticLog.recentLines.length;
      await DiagnosticLog.recordFailure(
        area: 'trace_test',
        event: 'failed',
        stage: 'tcp_connect',
        requestId: 42,
        error: const SocketException(
          'private endpoint and credential',
          osError: OSError('private operating system text', 10061),
        ),
        durationMs: 259,
      );
      await DiagnosticLog.recordFailure(
        area: 'trace_test',
        event: 'failed',
        stage: 'tls_handshake',
        error: const HandshakeException(
          'CERTIFICATE_VERIFY_FAILED private certificate',
        ),
      );
      final lines = _since(position).join('\n');
      expect(lines, contains('stage=tcp_connect'));
      expect(lines, contains('windows_error=10061'));
      expect(lines, contains('duration_ms=259'));
      expect(lines, contains('request_id=42'));
      expect(lines, contains('error_kind=socket'));
      expect(lines, contains('reason=certificate_verify_failed'));
      expect(lines, isNot(contains('private')));
      expect(diagnosticCode('network_unreachable'), 'network_error');
      expect(
        diagnosticCode('api_resolver_invalid_response'),
        'native_operation_failed',
      );
      expect(diagnosticCode('unregistered_secret'), 'unknown_error');
    },
  );

  test(
    'TLS native details are classified without becoming Windows errors',
    () async {
      const reasons = <String, String>{
        'certificate has expired': 'certificate_expired',
        'certificate is not yet valid': 'certificate_not_yet_valid',
        'Hostname mismatch': 'certificate_hostname_mismatch',
        'unable to get local issuer certificate': 'certificate_issuer_missing',
        'unable to verify the first certificate': 'certificate_issuer_missing',
        'self signed certificate in certificate chain':
            'certificate_self_signed',
        'certificate revoked': 'certificate_revoked',
        'unrecognized verification detail': 'certificate_verify_failed',
      };
      final position = DiagnosticLog.recentLines.length;
      for (final entry in reasons.entries) {
        final error = HandshakeException(
          'Handshake error in client',
          OSError('CERTIFICATE_VERIFY_FAILED: ${entry.key}; private data', -1),
        );
        expect(DiagnosticLog.tlsFailureReason(error), entry.value);
        await DiagnosticLog.recordFailure(
          area: 'trace_test',
          event: 'native_tls_failed',
          stage: 'tls_handshake',
          error: error,
        );
      }
      final lines = _since(position).join('\n');
      expect(lines, contains('reason=certificate_issuer_missing'));
      expect(lines, contains('tls_error=-1'));
      expect(lines, isNot(contains('windows_error=')));
      expect(lines, isNot(contains('private data')));
      expect(lines, isNot(contains('unrecognized verification detail')));
      expect(
        DiagnosticLog.tlsFailureReason(
          const HandshakeException('private unexpected TLS detail'),
        ),
        isNull,
      );
    },
  );

  test('real certificate rejection retains the native TLS reason', () async {
    final server = await _server();
    addTearDown(() => server.close(force: true));
    var httpReached = false;
    server.listen((request) async {
      httpReached = true;
      await request.response.close();
    });
    final api = ApiClient(
      baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
      resolveApiAddresses: () async => ['127.0.0.1'],
      securityContext: SecurityContext(withTrustedRoots: false),
    );
    addTearDown(api.close);
    final position = DiagnosticLog.recentLines.length;
    try {
      await api.locations();
      fail('An untrusted certificate must be rejected.');
    } on HandshakeException catch (error) {
      expect(error.message, isNot(contains('CERTIFICATE_VERIFY_FAILED')));
      expect(error.osError?.message, contains('CERTIFICATE_VERIFY_FAILED'));
      expect(error.osError?.errorCode, -1);
      expect(
        DiagnosticLog.tlsFailureReason(error),
        anyOf('certificate_self_signed', 'certificate_issuer_missing'),
      );
    }
    final lines = _since(position).join('\n');
    expect(httpReached, isFalse);
    expect(lines, contains('event=tcp_completed'));
    expect(lines, contains('event=attempt_failed code=tls_handshake_failed'));
    expect(lines, contains('tls_error=-1'));
    expect(lines, contains('reason=certificate_'));
    expect(lines, isNot(contains('windows_error=-1')));
    expect(lines, isNot(contains('http_status=')));
    expect(lines, isNot(contains('api-bootstrap.invalid')));
  });

  test(
    'persistent socket failures reference a connection, not a request',
    () async {
      final position = DiagnosticLog.recentLines.length;
      await DiagnosticLog.recordFailure(
        area: 'api_transport',
        event: 'socket_failed',
        stage: 'socket_read',
        connectionId: 43,
        error: const SocketException(
          'private transport contents',
          osError: OSError('private system text', 10054),
        ),
      );
      await DiagnosticLog.record(
        area: 'trace_test',
        event: 'invalid_connection',
        connectionId: -1,
      );
      final lines = _since(position);
      expect(lines.first, contains('connection_id=43'));
      expect(lines.first, contains('windows_error=10054'));
      expect(lines.first, isNot(contains('request_id=')));
      expect(lines.last, isNot(contains('connection_id=')));
      expect(lines.join('\n'), isNot(contains('private')));
    },
  );

  test(
    'native resolver failure stops before TCP and never invents HTTP',
    () async {
      final position = DiagnosticLog.recentLines.length;
      final api = ApiClient(
        baseUri: Uri.parse('https://never-contacted.invalid'),
        resolveApiAddresses: () async => throw PlatformException(
          code: 'broker_unavailable',
          message: 'private native contents',
          details: {'win32_error': 5},
        ),
      );
      addTearDown(api.close);
      await expectLater(api.locations(), throwsA(isA<ApiException>()));
      final lines = _since(position).join('\n');
      expect(lines, contains('event=native_resolution_started'));
      expect(lines, contains('event=native_resolution_failed'));
      expect(lines, contains('code=broker_unavailable'));
      expect(lines, contains('windows_error=5'));
      expect(lines, isNot(contains('event=tcp_started')));
      expect(lines, isNot(contains('http_status=503')));
      expect(lines, isNot(contains('never-contacted')));
      expect(lines, isNot(contains('private')));
    },
  );

  test(
    'a successful HTTPS request records every transport and response phase',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      server.listen((request) async {
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode({'locations': []}));
        await request.response.close();
      });
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        securityContext: SecurityContext(withTrustedRoots: false)
          ..setTrustedCertificates('$_fixture/certificate.pem'),
        resolveApiAddresses: () async => ['127.0.0.1'],
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      expect(await api.locations(), isEmpty);
      final lines = _since(position);
      final phases = <String>[
        'event=started',
        'event=open_started',
        'event=connection_started',
        'event=native_resolution_started',
        'event=native_resolution_completed',
        'event=tcp_started',
        'event=tcp_completed',
        'event=tls_started',
        'event=tls_completed',
        'event=open_completed',
        'event=send_started',
        'event=response_received',
        'event=body_started',
        'event=body_completed',
        'event=json_started',
        'event=json_completed',
      ];
      var previous = -1;
      for (final phase in phases) {
        final index = lines.indexWhere((line) => line.contains('$phase '));
        expect(
          index,
          greaterThan(previous),
          reason: '$phase missing/out of order',
        );
        previous = index;
      }
      final ids = lines
          .map((line) => RegExp(r'request_id=(\d+)').firstMatch(line)?.group(1))
          .whereType<String>()
          .toSet();
      expect(ids, hasLength(1));
      expect(
        lines.singleWhere((line) => line.contains('event=connection_started ')),
        contains('connection_id=${ids.single}'),
      );
      expect(lines.join('\n'), contains('http_status=200'));
      expect(lines.join('\n'), isNot(contains('127.0.0.1')));
      expect(lines.join('\n'), isNot(contains('api-bootstrap.invalid')));
      final reusePosition = DiagnosticLog.recentLines.length;
      expect(await api.locations(), isEmpty);
      final reusedLines = _since(reusePosition);
      final reusedIds = reusedLines
          .map((line) => RegExp(r'request_id=(\d+)').firstMatch(line)?.group(1))
          .whereType<String>()
          .toSet();
      expect(reusedIds, hasLength(1));
      expect(reusedIds.single, isNot(ids.single));
      expect(
        reusedLines.join('\n'),
        isNot(contains('event=connection_started ')),
      );
    },
  );

  test('an invalid native address keeps its local origin', () async {
    final api = ApiClient(
      baseUri: Uri.parse('https://never-contacted.invalid'),
      resolveApiAddresses: () async => ['invalid private address'],
    );
    addTearDown(api.close);
    await expectLater(
      api.locations(),
      throwsA(
        isA<ApiException>()
            .having(
              (error) => error.localErrorCode,
              'origin',
              'api_resolver_invalid_response',
            )
            .having(
              (error) => error.observedHttpStatus,
              'observed HTTP',
              isNull,
            ),
      ),
    );
  });
}
