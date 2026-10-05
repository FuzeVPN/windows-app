// SPDX-License-Identifier: MPL-2.0
import 'package:flutter_test/flutter_test.dart';
import 'package:fuzevpn_windows/l10n/app_localizations.dart';
import 'package:fuzevpn_windows/l10n/generated_catalogs.dart';

void main() {
  test('les textes de l’interface sont disponibles dans les 30 langues', () {
    const expectedKeys = [
      'Villes',
      'Serveurs',
      'Tous les pays',
      'Retour aux villes',
      'Sélectionner {name}',
      'Villes de {name}',
      'Serveurs à {name}',
      'Choisir : {server}',
      'Sélectionné : {server}',
      'Aucun serveur compatible avec le protocole choisi.',
      '1 ville',
      '{count} villes',
      '1 serveur',
      '{count} serveurs',
      'À vérifier',
      "Gérez les appareils associés à votre compte.",
      "Places disponibles : {count}",
      "Activez le VPN pour ajouter cet appareil à votre compte.",
      "Choisissez un emplacement pour votre prochaine connexion.",
      'Serveur complet',
      'Ce serveur n’a plus de place. Choisissez un autre emplacement.',
      'Disponibilité non confirmée',
      'La disponibilité de ce serveur ne peut pas être confirmée pour le moment. Choisissez un autre emplacement ou réessayez plus tard.',
      'Changer d’emplacement interrompra le VPN pendant la reconnexion.',
      "Vérifications réussies ({count})",
      "Vérifications non exécutées ({count})",
      'Confidentialité',
      'Connexion et reconnexion automatiques.',
      'Mon compte',
      'Se déconnecter du compte',
      'Se déconnecter du compte ?',
      'Cette action ferme votre session et demande l’arrêt du VPN.',
      'Gérer mon abonnement sur le Web',
      'Choisissez un emplacement et activez le VPN.',
      'Connexion interrompue',
      'Internet est bloqué par les protections du VPN.',
      'La préparation continue. Internet reste bloqué jusqu’à la connexion ou à l’arrêt des protections.',
      'Quitter FuzeVPN ?',
      'FuzeVPN va se fermer. En version portable, le VPN sera arrêté et ses protections seront retirées si le nettoyage réussit.',
      'FuzeVPN va se fermer. Le VPN peut rester actif si le service Windows est installé.',
      'Impossible de quitter FuzeVPN. Réessayez.',
      'Veuillez patienter pendant l’opération VPN en cours.',
      'Besoin d’aide ?',
      'Actualiser le suivi',
    ];
    expect(translationCatalogs, hasLength(30));
    for (final key in expectedKeys) {
      expect(sourceCatalog, contains(key), reason: key);
      final parameters = _parameters(sourceCatalog[key]!);
      for (final language in AppLanguage.values.where(
        (value) => value != AppLanguage.system,
      )) {
        final translated = translationCatalogs[language.storageValue]![key]!;
        expect(translated.trim(), isNotEmpty);
        expect(
          _parameters(translated),
          parameters,
          reason: '${language.name}: $key',
        );
        expect(
          AppStrings.forLanguage(language).text(key),
          translated,
          reason: '${language.name}: $key',
        );
      }
    }
  });

  test('les actions du compte restent distinctes des actions VPN', () {
    for (final language in AppLanguage.values) {
      final strings = AppStrings.forLanguage(language);
      expect(
        strings.text('Se déconnecter du compte'),
        isNot(strings.text('Déconnecter')),
        reason: language.name,
      );
    }
  });

  test('les confirmations conservent les limites de l’arrêt du VPN', () {
    final strings = AppStrings.forLanguage(AppLanguage.english);
    expect(
      strings.text(
        'Cette action ferme votre session et demande l’arrêt du VPN.',
      ),
      'This action signs you out and requests that the VPN stop.',
    );
    expect(
      strings.text(
        'FuzeVPN va se fermer. En version portable, le VPN sera arrêté et ses protections seront retirées si le nettoyage réussit.',
      ),
      contains('if cleanup succeeds'),
    );
    expect(
      strings.text(
        'FuzeVPN va se fermer. Le VPN peut rester actif si le service Windows est installé.',
      ),
      contains('may remain active'),
    );
  });
}

List<String> _parameters(String text) => RegExp(
  r'\{[A-Za-z_][A-Za-z0-9_]*\}',
).allMatches(text).map((match) => match.group(0)!).toList()..sort();
