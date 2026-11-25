// SPDX-License-Identifier: MPL-2.0
import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/api_client.dart';
import 'package:fuzevpn_windows/core/dns_filter.dart';
import 'package:fuzevpn_windows/core/models.dart';
import 'package:fuzevpn_windows/core/secure_store.dart';
import 'package:fuzevpn_windows/core/split_tunnel.dart';
import 'package:fuzevpn_windows/core/windows_update_controller.dart';

import 'support/audit_fixtures.dart' as fixtures;

const _on = DnsFilterSettings(adBlocking: true, available: true);
const _off = DnsFilterSettings(adBlocking: false, available: true);

class _Api extends fixtures.ProbeApi {
  final reads = <String>[];
  final writes = <bool>[];
  final replies = <Future<DnsFilterSettings>>[];
  Object? nextError;

  Future<DnsFilterSettings> _next(DnsFilterSettings fallback) {
    final error = nextError;
    nextError = null;
    if (error != null) return Future.error(error);
    return replies.isEmpty ? Future.value(fallback) : replies.removeAt(0);
  }

  @override
  Future<DnsFilterSettings> dnsFilter(String token) {
    reads.add(token);
    return _next(_off);
  }

  @override
  Future<DnsFilterSettings> setAdBlocking({
    required String token,
    required bool enabled,
  }) {
    writes.add(enabled);
    return _next(DnsFilterSettings(adBlocking: enabled, available: true));
  }
}

class _Store extends fixtures.ProbeStore {
  String? savedToken = 'synthetic-token';

  @override
  Future<SecuritySettings> securitySettings() async =>
      SecuritySettings.secureDefaults;
  @override
  Future<SplitTunnelSettings> splitTunnelSettings() async =>
      SplitTunnelSettings.disabled;
  @override
  Future<String?> token() async => savedToken;
  @override
  Future<void> clearToken() async => savedToken = null;
}

class _NoUpdates extends WindowsUpdateController {
  @override
  Future<void> checkForUpdates() async {}
}

AppController _controller(_Api api, [_Store? store]) => AppController(
  api: api,
  store: store ?? _Store(),
  wireguard: fixtures.ProbeWireGuard(),
  openVpn: fixtures.ProbeOpenVpn(),
  window: fixtures.ProbeWindow(),
  updates: _NoUpdates(),
)..profile = fixtures.account;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('DnsFilterSettings.fromJson', () {
    test('lit le choix et la disponibilité', () {
      expect(
        DnsFilterSettings.fromJson({
          'ad_blocking': true,
          'available': false,
          'updated_at': '2026-11-25T13:09:00Z',
        }),
        const DnsFilterSettings(adBlocking: true, available: false),
      );
    });

    test('refuse une réponse incomplète ou mal typée', () {
      for (final json in <Map<String, dynamic>>[
        {},
        {'ad_blocking': true},
        {'available': true},
        {'ad_blocking': 'true', 'available': true},
        {'ad_blocking': true, 'available': 1},
      ]) {
        expect(
          () => DnsFilterSettings.fromJson(json),
          throwsFormatException,
          reason: '$json',
        );
      }
    });
  });

  group('AppController', () {
    test('aucune requête sans compte ni au démarrage', () async {
      final api = _Api();
      final app = _controller(api);
      addTearDown(app.dispose);
      await app.initialize();
      expect(api.reads, isEmpty);
      app.profile = null;
      await app.refreshDnsFilter();
      expect(api.reads, isEmpty);
      expect(app.dnsFilter, isNull);
    });

    test('regroupe les lectures simultanées', () async {
      final api = _Api();
      final app = _controller(api);
      addTearDown(app.dispose);
      final reply = Completer<DnsFilterSettings>();
      api.replies.add(reply.future);
      final first = app.refreshDnsFilter();
      final second = app.refreshDnsFilter();
      expect(app.isLoadingDnsFilter, isTrue);
      await Future<void>.delayed(Duration.zero);
      expect(api.reads, ['synthetic-token']);
      reply.complete(_on);
      await Future.wait([first, second]);
      expect(app.dnsFilter, _on);
      expect(app.adBlockingShown, isTrue);
      expect(app.isLoadingDnsFilter, isFalse);
    });

    test('affiche la valeur demandée pendant l’enregistrement', () async {
      final api = _Api();
      final app = _controller(api);
      addTearDown(app.dispose);
      await app.setAdBlocking(true);
      expect(api.writes, isEmpty, reason: 'valeur actuelle encore inconnue');

      await app.refreshDnsFilter();
      final reply = Completer<DnsFilterSettings>();
      api.replies.add(reply.future);
      final saving = app.setAdBlocking(true);
      expect(app.isSavingDnsFilter, isTrue);
      expect(app.adBlockingShown, isTrue);
      expect(app.dnsFilter, _off);
      reply.complete(_on);
      await saving;
      expect(api.writes, [true]);
      expect(app.isSavingDnsFilter, isFalse);
      expect(app.dnsFilter, _on);
    });

    test('un échec garde le choix connu et l’explique', () async {
      final api = _Api();
      final app = _controller(api);
      addTearDown(app.dispose);
      await app.refreshDnsFilter();
      api.nextError = const ApiException(
        statusCode: 429,
        errorCode: 'rate_limited',
      );
      await app.setAdBlocking(true);
      expect(app.dnsFilter, _off);
      expect(app.adBlockingShown, isFalse);
      expect(
        app.dnsFilterErrorMessage,
        'Le bloqueur de pub n’a pas pu être modifié. Réessayez.',
      );

      api.nextError = const FormatException('invalid');
      await app.refreshDnsFilter();
      expect(app.dnsFilter, _off);
      expect(
        app.dnsFilterErrorMessage,
        'Le réglage du bloqueur de pub ne peut pas être chargé pour le moment. Réessayez.',
      );
      await app.refreshDnsFilter();
      expect(app.dnsFilterErrorMessage, isNull);
    });

    test('un autre compte ne voit jamais le choix du précédent', () async {
      final api = _Api();
      final app = _controller(api);
      addTearDown(app.dispose);
      final reply = Completer<DnsFilterSettings>();
      api.replies.add(reply.future);
      final loading = app.refreshDnsFilter();
      await Future<void>.delayed(Duration.zero);
      app.profile = const UserProfile(
        userId: 'other-account',
        email: 'other@example.com',
        firstName: 'Other',
        emailVerified: true,
      );
      reply.complete(_on);
      await loading;
      expect(app.dnsFilter, isNull);
      expect(app.adBlockingShown, isFalse);
    });
  });
}
