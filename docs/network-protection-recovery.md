# Protection réseau persistante et récupération

Le kill switch conserve sa politique si l’interface ou le moteur privilégié
s’arrête. Les exceptions de l’interface graphique et du tunnel sont
temporaires : elles disparaissent avec le processus qui les a autorisées. Au
démarrage suivant, le moteur restaure une protection préparée et le compte
Windows propriétaire, puis attend une nouvelle connexion ou une déconnexion
explicite. Il ne réutilise aucune ancienne exception d’interface tunnel.

Pour rétablir l’accès réseau sans VPN, ouvrir FuzeVPN avec le même compte
Windows et choisir **Déconnecter**. Fermer simplement l’application, arrêter
le service conserve l’intention de protection. Le redémarrage Windows conserve
cette intention ; la continuité effective du filtrage pendant le démarrage ou
la reprise de BFE doit être validée sur les versions Windows prises en charge.

## Installation, réparation et désinstallation

Une mise à niveau, une réparation ou son annulation conserve la protection
pendant le remplacement des fichiers. Le service relancé restaure son état
avant d’accepter des requêtes. Une désinstallation complète retire uniquement
les règles possédées par FuzeVPN lors de sa validation finale. Un échec de
suppression conserve le blocage et rétablit la porte de maintenance pour
permettre une réparation ultérieure.

## Récupération administrateur si la copie portable a disparu

La récupération suivante est une demande explicite de retirer le blocage
FuzeVPN. Elle utilise `fuzevpn-runtime.exe`, le petit assistant signé qui
n’importe que des bibliothèques Windows. Elle ne dépend pas de l’ancien
chemin de l’interface ou de ses fichiers VPN.

1. Fermer les autres copies de FuzeVPN. Si le service installé est en cours
   d’exécution, l’arrêter depuis une console PowerShell ouverte en tant
   qu’administrateur :

   ```powershell
   Stop-Service -Name FuzeVPNService
   ```

2. Depuis cette même console administrateur, utiliser l’assistant d’une
   distribution signée intacte, par exemple :

   ```powershell
   & 'C:\Program Files\FuzeVPN\fuzevpn-runtime.exe' --fuzevpn-recover-network
   $LASTEXITCODE
   ```

   Adapter le chemin à l’assistant disponible. Si l’ancienne copie a été
   supprimée et que le réseau est bloqué, une distribution signée peut être
   apportée depuis un autre appareil. Il n’est pas nécessaire de remettre
   l’ancienne interface à son emplacement d’origine. Une copie de développement
   non signée est refusée par cette commande.

La commande vérifie l’élévation, la signature du fichier épinglé, l’exclusivité
du moteur et l’absence de tunnel, processus, carte active ou règle résiduelle
inconnue. Elle valide la signature avec le magasin de confiance local, sans
requête réseau. Elle n’arrête aucun processus ou service elle-même. Si un
moteur est actif ou si Windows ne permet pas d’établir son état, elle conserve
le blocage et renvoie une erreur. Le code `0` signifie que la récupération a
réussi ; `5` indique un refus d’accès ou de validation ; `170` indique qu’une
ressource est encore occupée. Les règles des autres produits ne sont pas
supprimées.

Ne pas remplacer cette commande par l’élévation d’une copie déplacée de
`fuzevpn-service.exe` : ce dernier charge les bibliothèques du moteur VPN et
n’est pas le point d’entrée de récupération autonome.

## Portée des protections sélectives

Lorsque le kill switch est désactivé, la protection WebRTC bloque l’UDP hors
du tunnel, et la protection DNS bloque les ports distants 53 et 853. WebRTC
peut aussi utiliser TCP/TLS ; le DNS peut utiliser HTTPS. Le kill switch doit
être activé pour couvrir également ces transports hors tunnel.

## Validation

Les tests `network_filters`, `native_security` et `runtime_network_recovery`
utilisent des adaptateurs Windows simulés. Ils couvrent la persistance après
perte de tous les handles, le retrait des exceptions UI/tunnel, la restauration
du propriétaire, les échecs de transaction, la maintenance et les conditions
de récupération administrateur. Une validation en machine virtuelle reste
nécessaire pour mesurer les paquets réels au démarrage Windows, à l’arrêt de
BFE et lors des transitions entre fournisseurs WFP. Les documents Microsoft
décrivent différemment le chargement des filtres persistants d’un fournisseur
sans nom de service : [Object Management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
et [FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0).
Les règles de démarrage demandées par le code et les tests simulés ne suffisent
donc pas à certifier l’absence de fuite pendant ces transitions système.
