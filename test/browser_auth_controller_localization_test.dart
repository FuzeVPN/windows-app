// SPDX-License-Identifier: MPL-2.0
// The controller runs with synthetic dependencies. The auth probe stops before
// any listener, browser, account API, token write or VPN operation is created.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/app_controller.dart';
import 'package:fuzevpn_windows/core/browser_auth.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';

import 'support/audit_fixtures.dart' as fixtures;

class _AuthPageProbe extends BrowserAuth {
  BrowserAuthPageTexts? capturedAtStart;
  int startCalls = 0;

  @override
  Future<BrowserAuthAttempt> start() {
    startCalls++;
    capturedAtStart = pageTexts;
    throw BrowserAuthException.canceled;
  }
}

class _StoreProbe extends fixtures.ProbeStore {
  int tokenWrites = 0;

  @override
  Future<void> saveToken(String token) async {
    tokenWrites++;
    fail('Localization must be selected before any token is received.');
  }
}

void main() {
  final binding = TestWidgetsFlutterBinding.ensureInitialized();
  for (final scenario in [
    (
      AppLanguage.english,
      const Locale('fr'),
      'en',
      false,
      'Authorization received',
    ),
    (AppLanguage.arabic, const Locale('en'), 'ar', true, 'تم استلام التفويض'),
    (
      AppLanguage.system,
      const Locale('en', 'GB'),
      'en',
      false,
      'Authorization received',
    ),
    (
      AppLanguage.system,
      const Locale('ar', 'SA'),
      'ar',
      true,
      'تم استلام التفويض',
    ),
    (AppLanguage.system, const Locale('zh', 'TW'), 'zh-Hant', false, '已收到授權'),
    (
      AppLanguage.system,
      const Locale('zz', 'ZZ'),
      'fr',
      false,
      'Autorisation reçue',
    ),
  ]) {
    test(
      '${scenario.$1.name} with Windows ${scenario.$2} selects callback text before start',
      () async {
        binding.platformDispatcher.localeTestValue = scenario.$2;
        binding.platformDispatcher.localesTestValue = [scenario.$2];
        addTearDown(binding.platformDispatcher.clearLocaleTestValue);
        addTearDown(binding.platformDispatcher.clearLocalesTestValue);
        final auth = _AuthPageProbe();
        final api = fixtures.ProbeApi();
        final store = _StoreProbe();
        final wireguard = fixtures.ProbeWireGuard();
        var browserLaunches = 0;
        final controller = AppController(
          api: api,
          store: store,
          wireguard: wireguard,
          openVpn: fixtures.ProbeOpenVpn(),
          window: fixtures.ProbeWindow(),
          browserAuth: auth,
          browserLauncher: (_) async {
            browserLaunches++;
            return false;
          },
        )..language = scenario.$1;
        addTearDown(controller.dispose);

        expect(await controller.signInWithBrowser(), isFalse);
        expect(auth.startCalls, 1);
        final captured = auth.capturedAtStart;
        expect(captured, isNotNull);
        expect(captured!.languageTag, scenario.$3);
        expect(captured.isRightToLeft, scenario.$4);
        expect(captured.receivedTitle, scenario.$5);
        expect(
          captured.receivedPage,
          contains(
            '<html lang="${scenario.$3}" dir="${scenario.$4 ? 'rtl' : 'ltr'}">',
          ),
        );
        expect(api.meCalls, 0);
        expect(store.tokenWrites, 0);
        expect(wireguard.prepareCalls, 0);
        expect(browserLaunches, 0);
        expect(controller.browserSignInStatus, BrowserSignInStatus.idle);
      },
    );
  }
}
