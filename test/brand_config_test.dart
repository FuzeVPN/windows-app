// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/brand_config.dart';
import 'package:fuzevpn_windows/core/api_client.dart';

void main() {
  test('utilise exclusivement l’origine API FuzeVPN', () {
    expect(BrandConfig.apiBaseUrl, 'https://api.fuzevpn.com');
    expect(ApiClient.baseUrl, BrandConfig.apiBaseUrl);
  });

  test('localise exactement les routes du site public', () {
    for (final locale in ['fr', 'en', 'es', 'de', 'nl']) {
      expect(
        BrandConfig.website(locale).toString(),
        'https://fuzevpn.com/$locale/',
      );
      expect(
        BrandConfig.support(locale).toString(),
        'https://fuzevpn.com/$locale/support',
      );
    }
    expect(BrandConfig.website('it'), Uri.parse('https://fuzevpn.com/fr/'));
  });

  test('garde les routes du portail non localisées', () {
    expect(BrandConfig.portalLogin, Uri.parse('https://app.fuzevpn.com/login'));
    expect(
      BrandConfig.portalRegister,
      Uri.parse('https://app.fuzevpn.com/register'),
    );
    expect(
      BrandConfig.portalDashboard,
      Uri.parse('https://app.fuzevpn.com/dashboard'),
    );
    expect(
      BrandConfig.portalVerifyEmail,
      Uri.parse('https://app.fuzevpn.com/verify-email'),
    );
  });
}
