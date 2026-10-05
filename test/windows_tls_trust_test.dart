// SPDX-License-Identifier: MPL-2.0
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/diagnostic_log.dart';
import 'package:fuzevpn_windows/core/windows_tls_trust.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('com.fuzevpn/windows_tls_trust');
  const trust = WindowsTlsTrust();
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final certificate = Uint8List.fromList([0x30, 0x02, 0x01, 0x00]);
  const hostname = 'api.fuzevpn.com';
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  test('forwards only the public certificate and fixed API hostname', () async {
    MethodCall? request;
    messenger.setMockMethodCallHandler(channel, (call) async {
      request = call;
      return {'trusted': false};
    });
    expect(await trust.verifyApiCertificate(certificate, hostname), isNull);
    expect(request!.method, 'verifyApiCertificate');
    expect(
      (request!.arguments as Map).keys,
      unorderedEquals(['certificate_der', 'hostname']),
    );
    expect((request!.arguments as Map)['certificate_der'], isA<Uint8List>());
    expect((request!.arguments as Map)['certificate_der'], certificate);
    expect((request!.arguments as Map)['hostname'], hostname);
    final trace = DiagnosticLog.recentLines.last;
    expect(trace, contains('area=tls_trust event=rejected'));
    expect(trace, isNot(contains(hostname)));
    expect(trace, isNot(contains('certificate_der')));
    expect(trace, isNot(contains('anchor_der')));
  });

  test('invalid parameters never invoke native trust validation', () async {
    var calls = 0;
    messenger.setMockMethodCallHandler(channel, (_) async {
      calls++;
      return {'trusted': false};
    });
    for (final candidate in [
      '',
      'example.invalid',
      'API.FUZEVPN.COM',
      'api.fuzevpn.com.',
      'api.fuzevpn.com:443',
      'https://api.fuzevpn.com',
      'api.fuzevpn.com\u0000',
    ]) {
      await expectLater(
        trust.verifyApiCertificate(certificate, candidate),
        throwsFormatException,
      );
    }
    for (final invalid in [Uint8List(0), Uint8List(64 * 1024 + 1)]) {
      await expectLater(
        trust.verifyApiCertificate(invalid, hostname),
        throwsFormatException,
      );
    }
    expect(calls, 0);
  });

  test('accepts the size boundary while preserving the byte type', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      final request = call.arguments as Map;
      expect(request['certificate_der'], isA<Uint8List>());
      expect((request['certificate_der'] as Uint8List).length, 64 * 1024);
      return {'trusted': true, 'anchor_der': Uint8List(64 * 1024)};
    });
    final result = await trust.verifyApiCertificate(
      Uint8List(64 * 1024),
      hostname,
    );
    expect(result, isA<Uint8List>());
    expect(result!.length, 64 * 1024);
  });

  test('returns only the native verified trust anchor', () async {
    final anchor = Uint8List.fromList([0x30, 0x03, 0x02, 0x01, 0x01]);
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {'trusted': true, 'anchor_der': anchor},
    );
    final result = await trust.verifyApiCertificate(certificate, hostname);
    expect(result, anchor);
    expect(result, isNot(certificate));
    expect(identical(result, anchor), isFalse);
  });

  test('explicit Windows rejection returns no trust anchor', () async {
    for (final response in [
      {'trusted': false},
      {'trusted': false, 'anchor_der': null},
    ]) {
      messenger.setMockMethodCallHandler(channel, (_) async => response);
      expect(await trust.verifyApiCertificate(certificate, hostname), isNull);
    }
  });

  test('logs only bounded Windows status metadata', () async {
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {
        'trusted': false,
        'trust_status': 0xffffffff,
        'windows_error': 0xffffffff,
      },
    );
    expect(await trust.verifyApiCertificate(certificate, hostname), isNull);
    final rejected = DiagnosticLog.recentLines.last;
    expect(rejected, contains('trust_status=4294967295'));
    expect(rejected, contains('windows_error=4294967295'));
    expect(rejected, isNot(contains(hostname)));
    messenger.setMockMethodCallHandler(
      channel,
      (_) async => {
        'trusted': true,
        'trust_status': 0,
        'windows_error': 0,
        'anchor_der': Uint8List(1),
      },
    );
    expect(await trust.verifyApiCertificate(certificate, hostname), isNotNull);
    final accepted = DiagnosticLog.recentLines.last;
    expect(accepted, contains('event=trusted'));
    expect(accepted, contains('trust_status=0'));
    expect(accepted, isNot(contains('windows_error=')));
  });

  test('rejects malformed or contradictory native responses', () async {
    final invalidResponses = <Object?>[
      null,
      true,
      [],
      {},
      {'trusted': null},
      {'trusted': 'true'},
      {'trusted': 1},
      {'anchor_der': Uint8List(1)},
      {'trusted': true},
      {'trusted': true, 'anchor_der': null},
      {'trusted': true, 'anchor_der': []},
      {
        'trusted': true,
        'anchor_der': [1, 2],
      },
      {'trusted': true, 'anchor_der': 'private text'},
      {'trusted': true, 'anchor_der': Uint8List(0)},
      {'trusted': true, 'anchor_der': Uint8List(64 * 1024 + 1)},
      {'trusted': false, 'anchor_der': Uint8List(1)},
      {'trusted': false, 'unexpected': 'private text'},
      {'trusted': false, 0: 'private text'},
      {'trusted': false, 'trust_status': 0},
      {'trusted': false, 'windows_error': 0},
      {'trusted': false, 'trust_status': null, 'windows_error': 0},
      {'trusted': false, 'trust_status': 'private text', 'windows_error': 0},
      {'trusted': false, 'trust_status': 0.5, 'windows_error': 0},
      {'trusted': false, 'trust_status': -1, 'windows_error': 0},
      {'trusted': false, 'trust_status': 0x100000000, 'windows_error': 0},
      {'trusted': false, 'trust_status': 0, 'windows_error': null},
      {'trusted': false, 'trust_status': 0, 'windows_error': -1},
      {'trusted': false, 'trust_status': 0, 'windows_error': 0x100000000},
      {
        'trusted': true,
        'trust_status': 1,
        'windows_error': 0,
        'anchor_der': Uint8List(1),
      },
      {
        'trusted': true,
        'trust_status': 0,
        'windows_error': 1,
        'anchor_der': Uint8List(1),
      },
    ];
    for (var index = 0; index < invalidResponses.length; index++) {
      messenger.setMockMethodCallHandler(
        channel,
        (_) async => invalidResponses[index],
      );
      await expectLater(
        trust.verifyApiCertificate(certificate, hostname),
        throwsFormatException,
        reason: 'response $index',
      );
    }
  });

  test(
    'missing native channel is an error rather than trusted success',
    () async {
      await expectLater(
        trust.verifyApiCertificate(certificate, hostname),
        throwsA(isA<MissingPluginException>()),
      );
    },
  );

  test('propagates native failures without logging their details', () async {
    messenger.setMockMethodCallHandler(channel, (_) async {
      throw PlatformException(
        code: 'certificate_validation_failed',
        message: 'private exception text',
        details: {'certificate_der': certificate, 'secret': 'private'},
      );
    });
    final before = DiagnosticLog.recentLines;
    await expectLater(
      trust.verifyApiCertificate(certificate, hostname),
      throwsA(
        isA<PlatformException>().having(
          (error) => error.code,
          'code',
          'certificate_validation_failed',
        ),
      ),
    );
    expect(DiagnosticLog.recentLines, before);
  });
}
