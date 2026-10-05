# FuzeVPN pour Windows

[English](README.md) · [Versions](https://github.com/FuzeVPN/windows-app/releases) · [Site](https://fuzevpn.com)

FuzeVPN est un client VPN Windows développé avec Flutter et C++ natif. Il prend
en charge Windows 10 et 11 sur x64 et ARM64, WireGuard et OpenVPN, une version
installée et une version portable, ainsi qu'une interface traduite en 30 langues.
La connexion au service FuzeVPN nécessite un compte FuzeVPN et un abonnement
éligible. La publication de ce client n'inclut pas le serveur du service.

Les paquets Windows contiennent les moteurs VPN et les pilotes nécessaires.
L'interface fonctionne avec les droits de l'utilisateur ; les opérations réseau
privilégiées passent par un service Windows distinct ou un auxiliaire portable
élevé. L'application propose notamment les protections réseau, la reconnexion
automatique, le choix des serveurs, la gestion des appareils et des rapports de
diagnostic facultatifs.

## Télécharger

Les paquets signés sont disponibles dans les
[versions GitHub](https://github.com/FuzeVPN/windows-app/releases). Chaque
version propose des installateurs x64 et ARM64 (`.exe` et `.msi`) et des archives
ZIP portables. Choisissez l'architecture de votre installation Windows.
Conservez le dossier portable complet, notamment ses notices, licences et
pilotes. Vérifiez les téléchargements avec les empreintes fournies.

La version 1.0.6 constitue le premier état public des sources. Ses paquets signés
sont publiés sans modification. Les sources correspondantes des composants
tiers et leurs licences restent incluses ou accompagnent les paquets. Les
paquets ARM64 ont été compilés et leurs architectures et signatures vérifiées ;
cet état des sources ne revendique pas une validation sur un appareil ARM64 physique.

## Développer

Les versions du SDK sont fixées à Flutter 3.44.9 et Dart 3.12.2. Sur un poste Windows x64,
installez Git et Visual Studio 2026 avec les outils C++ et un SDK Windows.
Ajoutez les outils C++ ARM64 pour cette architecture. Les installateurs WiX
nécessitent également .NET 9.
Les scripts compilent les paquets ARM64 depuis ce poste x64.

```powershell
.\tools\bootstrap-windows.ps1 -Architecture x64
.\tools\build-windows-multiarch.ps1 -Architecture x64 -DevTest
```

La préparation télécharge et vérifie les dépendances publiques épinglées.
Une compilation de développement locale ne nécessite pas de certificat de
signature de production. Les guides de [développement](docs/development.md)
et de [distribution](docs/distribution.md), en anglais, détaillent les deux
architectures, la réutilisation hors ligne, les tests et les règles des paquets.

## Documentation

| Guide | Contenu |
| --- | --- |
| [Architecture](docs/architecture.md) | Flutter, processus natifs, stockage et protections réseau |
| [Développement](docs/development.md) | Prérequis, préparation, compilations et tests |
| [Distribution](docs/distribution.md) | Paquets installés et portables, signatures et mises à jour |
| [Diagnostics](docs/diagnostics.md) | Journaux locaux, consentement et signalements sûrs |
| [Localisation](docs/localization.md) | Catalogues, génération et contrôles des traductions |
| [Licences](LICENSING.md) | Périmètre MPL-2.0, licences tierces et marques |

Consultez [CONTRIBUTING.md](CONTRIBUTING.md) avant de contribuer et
[SECURITY.md](SECURITY.md) pour signaler une vulnérabilité en privé.

## Licence

Le code source écrit pour FuzeVPN est disponible sous
[Mozilla Public License 2.0](LICENSE). Les sources tierces, les fichiers issus
des modèles Flutter, les polices et les binaires d'exécution conservent leurs
licences respectives : voir [LICENSING.md](LICENSING.md) et
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). En particulier, la DLL
WireGuardNT officielle reste sous la licence de binaires précompilés de son
éditeur et n'est pas relicenciée sous MPL-2.0.

Le nom et les logos FuzeVPN sont des marques. La licence des sources n'accorde
aucun droit sur ces marques et n'implique aucun soutien aux versions modifiées.
