// SPDX-License-Identifier: MPL-2.0
import 'dart:ui' show Locale;

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/core/openvpn_bridge.dart';
import 'package:fuzevpn_windows/core/traffic_statistics.dart';
import 'package:fuzevpn_windows/core/wireguard_bridge.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('TrafficStatistics.fromChannel', () {
    test('lit deux compteurs positifs', () {
      expect(
        TrafficStatistics.fromChannel({'received': 577536, 'sent': 20971520}),
        const TrafficStatistics(received: 577536, sent: 20971520),
      );
    });

    test('ne devine jamais une valeur absente ou invalide', () {
      for (final value in <Object?>[
        null,
        'received',
        <String, Object?>{},
        {'received': 1},
        {'received': 1, 'sent': '2'},
        {'received': -1, 'sent': 2},
        {'received': 1.5, 'sent': 2},
      ]) {
        expect(TrafficStatistics.fromChannel(value), isNull, reason: '$value');
      }
    });
  });

  group('formatByteCount', () {
    String french(int bytes) => formatByteCount(
      bytes,
      const Locale('fr'),
      AppStrings.forLanguage(AppLanguage.french).text,
    );
    String english(int bytes) => formatByteCount(
      bytes,
      const Locale('en'),
      AppStrings.forLanguage(AppLanguage.english).text,
    );

    test('utilise les multiples binaires et les unités de la langue', () {
      expect(french(0), '0 o');
      expect(french(999), '999 o');
      expect(french(564 * 1024), '564 Ko');
      expect(french(20 * 1024 * 1024), '20 Mo');
      expect(french(1536 * 1024), '1,5 Mo');
      expect(english(1536 * 1024), '1.5 MB');
      expect(english(3 * 1024 * 1024 * 1024 * 1024), '3.0 TB');
      expect(english(-5), '0 B');
    });

    test('n’affiche jamais 1 000 d’une unité', () {
      // 999,5 Ko arrondirait à 1 000 Ko : la valeur passe à l’unité suivante.
      expect(french(1023488), '1,0 Mo');
      expect(french(1023487), '999 Ko');
      expect(french((9.96 * 1024 * 1024).round()), '10 Mo');
    });

    test('chaque langue fournit ses cinq unités', () {
      for (final language in AppLanguage.values.where(
        (l) => l != AppLanguage.system,
      )) {
        final strings = AppStrings.forLanguage(language);
        final values = {
          for (final bytes in [1, 2048, 3 << 20, 4 << 30, 5 << 40])
            formatByteCount(bytes, language.locale!, strings.text),
        };
        expect(values, hasLength(5), reason: language.storageValue);
        expect(
          values.every((value) => !value.contains('{value}')),
          isTrue,
          reason: language.storageValue,
        );
      }
    });
  });

  group('bridges', () {
    List<MethodCall> answer(String name, Object? reply) {
      final channel = MethodChannel(name);
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
            calls.add(call);
            return reply;
          });
      addTearDown(
        () => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(channel, null),
      );
      return calls;
    }

    test('WireGuard lit les compteurs sans argument', () async {
      final calls = answer('com.fuzevpn/windows_wireguard', {
        'received': 10,
        'sent': 20,
      });
      expect(
        await WireGuardBridge().trafficStatistics(),
        const TrafficStatistics(received: 10, sent: 20),
      );
      expect(calls.single.method, 'trafficStatistics');
      expect(calls.single.arguments, isNull);
    });

    test('OpenVPN rend null sans tunnel vérifié', () async {
      final calls = answer('com.fuzevpn/windows_openvpn', null);
      expect(await OpenVpnBridge().trafficStatistics(), isNull);
      expect(calls.single.method, 'trafficStatistics');
    });
  });
}
