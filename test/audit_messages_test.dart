// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/generated_catalogs.dart';

void main() {
  test('VPN recovery notices are rendered in all 30 catalogs', () {
    const notices = [
      'Windows n’a pas pu configurer le DNS du tunnel OpenVPN.',
      'Le nettoyage du tunnel OpenVPN n’a pas pu être confirmé. Réessayez la déconnexion.',
      'Les réglages de sécurité enregistrés sont illisibles. Les protections par défaut restent activées.',
      'L’état du tunnel VPN ne peut plus être confirmé. Réessayez la déconnexion ou attendez sa vérification.',
      'Le serveur est prêt, mais sa confirmation locale a échoué. La reprise sera retentée automatiquement.',
      'L’arrêt du tunnel OpenVPN n’a pas pu être confirmé. La protection reste active. Réessayez la déconnexion.',
      'La mise à niveau du pilote OpenVPN nécessite un redémarrage de Windows. Redémarrez lorsque vous serez prêt.',
    ];
    expect(translationCatalogs, hasLength(30));
    for (final key in notices) {
      expect(sourceCatalog, contains(key), reason: key);
    }
    for (final language in AppLanguage.values.where(
      (value) => value != AppLanguage.system,
    )) {
      final catalog = translationCatalogs[language.storageValue]!;
      for (final key in notices) {
        expect(
          catalog[key]?.trim(),
          isNotEmpty,
          reason: '${language.name}: $key',
        );
        expect(AppStrings.forLanguage(language).text(key), catalog[key]);
      }
      expect(
        notices.map((key) => catalog[key]).toSet(),
        hasLength(notices.length),
        reason: '${language.name}: recovery failures need distinct guidance',
      );
    }
  });
}
