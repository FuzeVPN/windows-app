// SPDX-License-Identifier: MPL-2.0
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';

const _fixture = 'test/fixtures/tls-trust';
const _chainFixture = 'test/fixtures/tls-trust-chain';

Future<HttpServer> _server() => HttpServer.bindSecure(
  InternetAddress.loopbackIPv4,
  0,
  SecurityContext()
    ..useCertificateChain('$_fixture/server-certificate.pem')
    ..usePrivateKey('$_fixture/server-private-key.pem'),
);

Future<Uint8List> _root() =>
    File('$_fixture/root-certificate.der').readAsBytes();

Future<HttpServer> _chainServer([String chain = 'server-chain.pem']) =>
    HttpServer.bindSecure(
      InternetAddress.loopbackIPv4,
      0,
      SecurityContext()
        ..useCertificateChain('$_chainFixture/$chain')
        ..usePrivateKey('$_chainFixture/server-private-key.pem'),
    );

Future<Uint8List> _chainRoot() =>
    File('$_chainFixture/root-certificate.der').readAsBytes();

List<String> _since(int position) =>
    DiagnosticLog.recentLines.skip(position).toList();

void main() {
  test(
    'an issuer callback recovers a complete server chain with strict TLS',
    () async {
      final server = await _chainServer();
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode({'locations': []}));
        await request.response.close();
      });
      final intermediate = await File(
        '$_chainFixture/intermediate-certificate.der',
      ).readAsBytes();
      var verifications = 0;
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (certificate, hostname) async {
          verifications++;
          // Dart passes the issuer whose own issuer cannot be located, not
          // necessarily the certificate authenticating the TLS server.
          expect(certificate, intermediate);
          expect(hostname, 'api-bootstrap.invalid');
          expect(httpRequests, 0);
          return _chainRoot();
        },
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      expect(await api.locations(), isEmpty);
      expect(verifications, 1);
      expect(httpRequests, 1);
      final lines = _since(position).join('\n');
      expect(lines, contains('reason=certificate_issuer_missing'));
      expect(lines, contains('event=tls_retry_started'));
      expect(lines, contains('event=tls_completed'));
      expect(lines, contains('http_status=200'));
    },
  );

  for (final entry in const {
    'wrong-host-chain.pem': 'certificate_hostname_mismatch',
    'expired-chain.pem': 'certificate_expired',
  }.entries) {
    test('CA recovery cannot accept a server with ${entry.value}', () async {
      final server = await _chainServer(entry.key);
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        await request.response.close();
      });
      final intermediate = await File(
        '$_chainFixture/intermediate-certificate.der',
      ).readAsBytes();
      var verifications = 0;
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (certificate, _) async {
          verifications++;
          expect(certificate, intermediate);
          expect(httpRequests, 0);
          return _chainRoot();
        },
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      await expectLater(api.locations(), throwsA(isA<HandshakeException>()));
      expect(verifications, 1);
      expect(httpRequests, 0);
      final lines = _since(position).join('\n');
      expect(lines, contains('event=windows_trust_completed'));
      expect(lines, contains('event=tls_retry_started'));
      expect(lines, contains('reason=${entry.value}'));
      expect(lines, isNot(contains('http_status=')));
    });
  }

  test(
    'missing issuer recovers with an OS verified anchor and strict TLS replay',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        request.response.headers.contentType = ContentType.json;
        request.response.write(jsonEncode({'locations': []}));
        await request.response.close();
      });
      var verifications = 0;
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (certificate, hostname) async {
          verifications++;
          expect(hostname, 'api-bootstrap.invalid');
          expect(certificate, isNotEmpty);
          expect(certificate, isNot(await _root()));
          expect(httpRequests, 0, reason: 'Rejected TLS cannot transmit HTTP.');
          return _root();
        },
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      expect(await api.locations(), isEmpty);
      expect(verifications, 1);
      expect(httpRequests, 1);
      expect(await api.locations(), isEmpty);
      expect(verifications, 1);
      expect(httpRequests, 2);
      final lines = _since(position).join('\n');
      expect(lines, contains('reason=certificate_issuer_missing'));
      expect(lines, contains('event=windows_trust_completed'));
      expect(lines, contains('event=tls_retry_started'));
      expect(lines, contains('event=tls_completed'));
      expect(lines, contains('http_status=200'));
      expect(lines, isNot(contains('api-bootstrap.invalid')));
      expect(lines, isNot(contains('BEGIN CERTIFICATE')));
    },
  );

  test(
    'Windows rejection preserves the TLS failure and never transmits HTTP',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        await request.response.close();
      });
      var verifications = 0;
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (_, _) async {
          verifications++;
          return null;
        },
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      await expectLater(api.locations(), throwsA(isA<HandshakeException>()));
      expect(verifications, 1);
      expect(httpRequests, 0);
      final lines = _since(position).join('\n');
      expect(lines, contains('event=windows_trust_rejected'));
      expect(lines, isNot(contains('event=tls_retry_started')));
      expect(lines, isNot(contains('http_status=')));
    },
  );

  test(
    'an unrelated anchor cannot bypass TLS and replay is bounded to once',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        await request.response.close();
      });
      final unrelatedPem = await File(
        'test/fixtures/api-bootstrap/certificate.pem',
      ).readAsLines();
      final unrelatedAnchor = base64Decode(
        unrelatedPem.where((line) => !line.startsWith('-----')).join(),
      );
      var verifications = 0;
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (_, _) async {
          verifications++;
          return unrelatedAnchor;
        },
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      await expectLater(api.locations(), throwsA(isA<HandshakeException>()));
      expect(verifications, 1);
      expect(httpRequests, 0);
      final lines = _since(position);
      expect(
        lines.where((line) => line.contains('event=tcp_started ')),
        hasLength(2),
      );
      expect(
        lines.where((line) => line.contains('event=tls_retry_started ')),
        hasLength(1),
      );
      expect(lines.join('\n'), isNot(contains('http_status=')));
    },
  );

  test(
    'missing native verification never accepts the failed certificate',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        await request.response.close();
      });
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (_, _) async =>
            throw MissingPluginException('private native message'),
      );
      addTearDown(api.close);
      final position = DiagnosticLog.recentLines.length;
      await expectLater(api.locations(), throwsA(isA<HandshakeException>()));
      expect(httpRequests, 0);
      final lines = _since(position).join('\n');
      expect(
        lines,
        contains('event=windows_trust_failed code=native_bridge_unavailable'),
      );
      expect(lines, isNot(contains('private native message')));
      expect(lines, isNot(contains('event=tls_retry_started')));
    },
  );

  test(
    'closing the API aborts recovery before any second connection',
    () async {
      final server = await _server();
      addTearDown(() => server.close(force: true));
      var httpRequests = 0;
      server.listen((request) async {
        httpRequests++;
        await request.response.close();
      });
      final verificationStarted = Completer<void>();
      final verification = Completer<Uint8List?>();
      final api = ApiClient(
        baseUri: Uri.parse('https://api-bootstrap.invalid:${server.port}'),
        resolveApiAddresses: () async => ['127.0.0.1'],
        securityContext: SecurityContext(withTrustedRoots: false),
        verifyApiCertificate: (_, _) {
          verificationStarted.complete();
          return verification.future;
        },
      );
      addTearDown(api.close);
      addTearDown(() {
        if (!verification.isCompleted) verification.complete(null);
      });
      final position = DiagnosticLog.recentLines.length;
      final failedRequest = expectLater(api.locations(), throwsA(anything));
      await verificationStarted.future.timeout(const Duration(seconds: 2));
      api.close();
      await failedRequest.timeout(const Duration(seconds: 1));
      verification.complete(await _root());
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(httpRequests, 0);
      expect(
        _since(position).where((line) => line.contains('event=tcp_started ')),
        hasLength(1),
      );
      expect(
        _since(position).join('\n'),
        isNot(contains('event=tls_retry_started')),
      );
    },
  );
}
