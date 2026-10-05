// SPDX-License-Identifier: MPL-2.0
abstract final class BrandConfig {
  static const appName = 'FuzeVPN';
  static const apiBaseUrl = 'https://api.fuzevpn.com';

  static const _publicHost = 'fuzevpn.com';
  static const _portalHost = 'app.fuzevpn.com';
  static const supportedWebsiteLocales = {'fr', 'en', 'es', 'de', 'nl'};

  static String websiteLocale(String? languageCode) {
    final normalized = languageCode?.toLowerCase();
    return supportedWebsiteLocales.contains(normalized) ? normalized! : 'fr';
  }

  static Uri website(String? languageCode) =>
      Uri.https(_publicHost, '/${websiteLocale(languageCode)}/');

  static Uri support(String? languageCode) =>
      Uri.https(_publicHost, '/${websiteLocale(languageCode)}/support');

  static final portalLogin = Uri.https(_portalHost, '/login');
  static final portalRegister = Uri.https(_portalHost, '/register');
  static final portalDashboard = Uri.https(_portalHost, '/dashboard');
  static final portalVerifyEmail = Uri.https(_portalHost, '/verify-email');
}
