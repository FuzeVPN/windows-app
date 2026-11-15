# Protection réseau persistante et récupération

Le kill switch conserve sa politique si l’interface ou le moteur privilégié
s’arrête. Les exceptions de l’interface graphique et du tunnel sont
temporaires : elles disparaissent avec le processus qui les a autorisées. Au
démarrage suivant, le moteur restaure une protection préparée et le compte
Windows propriétaire, puis attend une nouvelle connexion ou une déconnexion
explicite. Il ne réutilise aucune ancienne exception d’interface tunnel.

Pour rétablir l’accès réseau sans VPN, ouvrir FuzeVPN avec le même compte
Windows et choisir **Déconnecter**. Fermer la fenêtre, quitter l’interface
d’une copie installée, arrêter le service ou interrompre un processus conserve
l’intention de protection. Le redémarrage Windows conserve cette intention ;
la continuité effective du filtrage pendant le démarrage ou la reprise de BFE
doit être validée sur les versions Windows prises en charge.

## Déconnecter et quitter

Seule une déconnexion explicite retire la protection : ni une erreur, ni un
délai dépassé, ni une annulation qui échoue, ni la fermeture de la fenêtre ne
le font. **Déconnecter** reste disponible pendant une connexion, une
reconnexion automatique ou un renouvellement de certificat : l’opération en
cours est annulée, puis le tunnel est arrêté et la protection retirée.
L’annulation prend effet au retour de l’appel en cours, que rien n’interrompt ;
l’interface affiche « Déconnexion en cours » jusque-là et n’annonce « Non
protégé » qu’après avoir relu l’absence des deux tunnels et des deux
protections. Après une telle demande, FuzeVPN ne se connecte ni ne se
reconnecte plus de lui-même jusqu’à la prochaine connexion demandée par
l’utilisateur ou au prochain lancement.

La reprise automatique ne retire jamais la protection et ne démarre jamais le
moteur privilégié : tant qu’aucun moteur n’existe, elle attend que l’interface
en observe un. Les changements de réseau relancent son cycle de tentatives au
plus cinq fois par interruption ; ensuite l’état « Trafic bloqué » attend
l’utilisateur, avec **Déconnecter** et la nouvelle tentative proposées.

La confirmation **Quitter FuzeVPN** n’est jamais désactivée.

- Copie installée : **Quitter l’interface FuzeVPN** ferme immédiatement
  l’interface et rien d’autre. Le service Windows conserve le tunnel et le
  kill switch, et termine l’opération qu’il a déjà reçue. Tant qu’une
  opération est en cours, qu’Internet est bloqué par une protection conservée
  ou que l’état du VPN est inconnu, la même fenêtre propose **Déconnecter**,
  qui retire la protection sans fermer l’application.
- Copie portable : **Quitter FuzeVPN** effectue d’abord la déconnexion
  explicite, tunnel arrêté et protections retirées, et ne ferme l’application
  qu’une fois cet arrêt confirmé. Si l’arrêt échoue, l’application reste
  ouverte, le blocage est conservé et son motif est affiché, avec
  **Déconnecter** pour réessayer. Un second appui sur **Quitter FuzeVPN**,
  pendant l’arrêt ou après son échec, ferme immédiatement : la protection
  alors conservée est signalée à la prochaine ouverture, comme décrit
  ci-dessous. **Annuler** laisse l’application ouverte ; un arrêt déjà demandé
  se termine quand même.

## Interface ouverte sans moteur privilégié

Après un redémarrage de Windows tant que le service installé, à démarrage
différé, n’est pas lancé, après la relance d’une copie portable ou lorsque le
service est arrêté, aucun processus privilégié ne peut répondre à l’interface.
La politique persistante reste pourtant appliquée par Windows. L’interface lit
alors elle-même, sans élévation et sans rien modifier, l’intention conservée
dans BFE : le protocole qui a armé la protection, l’état du kill switch et le
compte Windows propriétaire. Elle signale cette protection comme active, en
phase préparée, pour ce protocole.

- Une lecture d’état ne démarre jamais le moteur.
- Si Windows ne permet pas de lire l’intention (BFE indisponible, accès refusé,
  délai d’attente dépassé, intention endommagée ou d’une version inconnue),
  l’état est déclaré inconnu. Il n’est jamais supposé absent.
- **Déconnecter** est la seule action qui démarre alors le moteur, comme le
  fait une connexion, avec l’invite d’élévation Windows nécessaire : le moteur
  restaure la politique, puis la retire. Lorsque l’intention est illisible, la
  demande est transmise de la même façon et le moteur tranche. Sans intention
  persistante, rien n’est démarré.
- Si l’intention appartient à un autre compte Windows, la déconnexion est
  refusée sans invite d’élévation. Seul ce compte, ou la récupération
  administrateur décrite plus bas, peut retirer le blocage.

À l’arrêt du moteur, une politique encore active est ramenée à sa base
préparée, sans exception d’interface ni de tunnel, et conservée. Une politique
déjà retirée par une déconnexion explicite n’est pas réinstallée.

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

Les tests `network_filters` et `runtime_absent_channel` couvrent aussi
l’interface ouverte sans moteur : intention lue présente avec son protocole,
son kill switch et son compte, absente, ou inconnue lorsqu’elle est illisible
ou endommagée ; réponses d’état correspondantes ; déconnexion transmise avec
démarrage du moteur, locale sans intention, refusée pour un autre compte. La
lecture réelle par l’interface non élevée repose sur le droit de lecture
accordé à tous les comptes sur le seul filtre d’intention. Un processus non
élevé ouvre bien le moteur de filtrage et obtient une absence confirmée quand
aucune intention n’existe, alors que les filtres des autres produits lui sont
refusés. La lecture d’une intention existante par un compte standard reste à
confirmer en machine virtuelle ; en cas de refus, l’interface affiche un état
inconnu et **Déconnecter** reste transmis au moteur.
