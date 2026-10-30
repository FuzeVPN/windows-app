// SPDX-License-Identifier: MPL-2.0
// Synthetic localhost callbacks only; no browser, account API or VPN is used.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/browser_auth.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/main.dart';

import 'connection_ux_test.dart' show ConnectionUxController;

String _secret(int value) =>
    base64Url.encode(List<int>.filled(32, value)).replaceAll('=', '');

class _LoopbackHttpOverrides extends HttpOverrides {}

Future<(int, String)> _get(Uri uri) async {
  expect(uri.host, '127.0.0.1');
  final client = _LoopbackHttpOverrides().createHttpClient(null)
    ..connectionTimeout = const Duration(seconds: 2)
    ..findProxy = (_) => 'DIRECT';
  try {
    final response = await (await client.getUrl(uri)).close();
    return (response.statusCode, await response.transform(utf8.decoder).join());
  } finally {
    client.close(force: true);
  }
}

void main() {
  test('selective protection descriptions preserve their limits in every language', () {
    const webRtc =
        'Bloque l’UDP hors du tunnel VPN. Pour couvrir aussi WebRTC via TCP/TLS, activez le kill switch.';
    const dns =
        'Bloque le DNS hors du tunnel sur les ports 53 et 853. Pour couvrir aussi le DNS via HTTPS, activez le kill switch.';
    for (final language in AppLanguage.values.where(
      (language) => language != AppLanguage.system,
    )) {
      final strings = AppStrings.forLanguage(language);
      final translatedWeb = strings.text(webRtc);
      final translatedDns = strings.text(dns);
      for (final token in ['UDP', 'VPN', 'WebRTC', 'TCP/TLS']) {
        expect(translatedWeb, contains(token), reason: language.name);
      }
      for (final token in ['DNS', '53', '853', 'HTTPS']) {
        expect(translatedDns, contains(token), reason: language.name);
      }
      if (language != AppLanguage.french) {
        expect(translatedWeb, isNot(webRtc), reason: language.name);
        expect(translatedDns, isNot(dns), reason: language.name);
      }
    }
    final english = AppStrings.forLanguage(AppLanguage.english);
    expect(
      english.text(webRtc),
      'Blocks UDP outside the VPN tunnel. To also cover WebRTC over TCP/TLS, enable the kill switch.',
    );
    expect(
      english.text(dns),
      'Blocks DNS outside the tunnel on ports 53 and 853. To also cover DNS over HTTPS, enable the kill switch.',
    );
  });

  for (final scenario in [
    (
      AppLanguage.french,
      'fr',
      'ltr',
      'Autorisation reçue',
      'Autorisation refusée',
      'Demande invalide',
    ),
    (
      AppLanguage.english,
      'en',
      'ltr',
      'Authorization received',
      'Authorization denied',
      'Invalid request',
    ),
    (
      AppLanguage.arabic,
      'ar',
      'rtl',
      'تم استلام التفويض',
      'تم رفض التفويض',
      'طلب غير صالح',
    ),
  ]) {
    test(
      'callback pages follow ${scenario.$2} for success, denial and invalid input',
      () async {
        final auth = BrowserAuth(
          pageTexts: AppStrings.forLanguage(scenario.$1).browserAuthPageTexts,
        );
        final attempt = await auth.start();
        addTearDown(attempt.dispose);
        final invalid = await _get(attempt.redirectUri);
        expect(invalid.$1, HttpStatus.badRequest);
        expect(invalid.$2, contains('<h1>${scenario.$6}</h1>'));
        final state = attempt.state;
        final verifier = attempt.codeVerifier;
        final code = _secret(7);
        final received = await _get(
          attempt.redirectUri.replace(
            queryParameters: {'state': state, 'code': code},
          ),
        );
        expect(received.$1, HttpStatus.ok);
        expect(await attempt.callback, code);
        expect(received.$2, contains('<h1>${scenario.$4}</h1>'));
        for (final body in [invalid.$2, received.$2]) {
          expect(
            body,
            contains('<html lang="${scenario.$2}" dir="${scenario.$3}">'),
          );
          for (final proof in [state, verifier, code]) {
            expect(body, isNot(contains(proof)));
          }
        }
        final deniedAttempt = await auth.start();
        addTearDown(deniedAttempt.dispose);
        final failure = expectLater(
          deniedAttempt.callback,
          throwsA(
            isA<BrowserAuthException>().having(
              (error) => error.code,
              'code',
              'browser_auth_denied',
            ),
          ),
        );
        final denied = await _get(
          deniedAttempt.redirectUri.replace(
            queryParameters: {
              'state': deniedAttempt.state,
              'error': 'access_denied',
            },
          ),
        );
        await failure;
        expect(denied.$1, HttpStatus.ok);
        expect(denied.$2, contains('<h1>${scenario.$5}</h1>'));
        expect(
          denied.$2,
          contains('<html lang="${scenario.$2}" dir="${scenario.$3}">'),
        );
      },
    );
  }

  test(
    'callback locale is captured before asynchronous listener creation',
    () async {
      final auth = BrowserAuth(
        pageTexts: AppStrings.forLanguage(
          AppLanguage.english,
        ).browserAuthPageTexts,
      );
      final pending = auth.start();
      auth.pageTexts = AppStrings.forLanguage(
        AppLanguage.arabic,
      ).browserAuthPageTexts;
      final attempt = await pending;
      addTearDown(attempt.dispose);
      final response = await _get(attempt.redirectUri);
      expect(response.$2, contains('<html lang="en" dir="ltr">'));
      expect(response.$2, contains('Invalid request'));
      expect(response.$2, isNot(contains('طلب غير صالح')));
    },
  );

  test('localized page text and locale attributes cannot introduce markup', () {
    const texts = BrowserAuthPageTexts(
      languageTag: 'en" onload="bad',
      isRightToLeft: false,
      receivedTitle: '<script>bad()</script>',
      receivedMessage: 'A & B <img src=x>',
      deniedTitle: '<denied>',
      deniedMessage: '<denied-message>',
      invalidTitle: '<invalid>',
      invalidMessage: '<invalid-message>',
    );
    expect(texts.receivedPage, contains('lang="en&quot; onload=&quot;bad"'));
    expect(texts.receivedPage, contains('&lt;script&gt;bad()&lt;/script&gt;'));
    expect(texts.receivedPage, contains('A &amp; B &lt;img src=x&gt;'));
    expect(texts.receivedPage, isNot(contains('<script>')));
    expect(texts.deniedPage, contains('&lt;denied-message&gt;'));
    expect(texts.invalidPage, contains('&lt;invalid-message&gt;'));
  });

  const counters = [
    (
      AppLanguage.french,
      'Serveurs : ',
      'Villes : ',
      'Délai avant réessai : ',
      ' s.',
    ),
    (
      AppLanguage.russian,
      'Серверы: ',
      'Города: ',
      'Задержка перед повторной попыткой: ',
      ' с.',
    ),
    (
      AppLanguage.czech,
      'Servery: ',
      'Města: ',
      'Čekání před dalším pokusem: ',
      ' s.',
    ),
    (
      AppLanguage.arabic,
      'الخوادم: ',
      'المدن: ',
      'مدة الانتظار قبل إعادة المحاولة: ',
      ' ث.',
    ),
  ];
  for (final scenario in counters) {
    test('neutral count labels and retry durations in ${scenario.$1.name}', () {
      final strings = AppStrings.forLanguage(scenario.$1);
      for (final n in [0, 1, 2, 3, 4, 5, 11, 21, 22, 101]) {
        expect(strings.serverCount(n), '${scenario.$2}$n');
        expect(strings.cityCount(n), '${scenario.$3}$n');
        expect(strings.retryAfter(n), '${scenario.$4}$n${scenario.$5}');
        expect(
          strings.text('Réessayez dans $n secondes.'),
          '${scenario.$4}$n${scenario.$5}',
        );
      }
    });
  }

  testWidgets(
    'location list uses neutral labels in French, Russian, Czech and Arabic',
    (tester) async {
      tester.view.devicePixelRatio = 1;
      tester.view.physicalSize = const Size(1080, 680);
      addTearDown(tester.view.resetDevicePixelRatio);
      addTearDown(tester.view.resetPhysicalSize);
      for (final scenario in counters) {
        final controller = ConnectionUxController()
          ..language = scenario.$1
          ..section = AppSection.locations;
        await tester.pumpWidget(FuzeVpnApp(controller: controller));
        await tester.pumpAndSettle();
        expect(find.text('${scenario.$3}1 · ${scenario.$2}2'), findsOneWidget);
        expect(find.text('${scenario.$2}2'), findsWidgets);
        expect(tester.takeException(), isNull, reason: scenario.$1.name);
        await tester.pumpWidget(const SizedBox.shrink());
        controller.dispose();
      }
    },
  );
}
