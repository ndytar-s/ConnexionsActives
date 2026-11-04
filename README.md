# ConnexionsActives

**Voyez en un clic quels programmes de votre PC parlent à Internet, ce qu'ils exécutent vraiment, et lesquels sont dignes de confiance.**

ConnexionsActives est un petit outil Windows écrit en AutoHotkey v2. Il liste toutes les connexions réseau établies, identifie le programme derrière chacune, vérifie son origine (chemin et signature numérique) et colore chaque ligne selon un verdict de légitimité clair. Pour les programmes « hôtes » comme Java, Python ou PowerShell, il montre ce qu'ils exécutent réellement (le `.jar`, le script, l'`.exe`). Il retrouve le nom des serveurs distants, vous envoie vers VirusTotal pour les cas douteux, et garde une liste de confiance fondée sur le programme et sa destination. Pas d'installation, pas de service en arrière-plan, un seul fichier lisible de bout en bout.

> Capture d'écran : <img width="1365" height="553" alt="image" src="https://github.com/user-attachments/assets/925ccb61-da6d-46b0-a6c6-9b5bbefd2daf" /><img width="1363" height="468" alt="image" src="https://github.com/user-attachments/assets/f8b4c4c1-f756-43bd-a79b-14d66c3a65f8" />



## Pourquoi cet outil est utile

Votre ordinateur ouvre des dizaines de connexions à chaque instant : navigateur, mises à jour, synchronisation cloud, antivirus, mais aussi parfois un programme que vous n'avez jamais lancé. Windows ne vous montre pas facilement qui est derrière.

Faire cette vérification à la main demande plusieurs étapes : `netstat -noa`, repérer les lignes ESTABLISHED, retrouver chaque PID avec `tasklist`, chercher le fichier, sa signature, sa ligne de commande. ConnexionsActives automatise toute la chaîne et l'affiche dans un seul tableau.

Une signature valide ne suffit plus aujourd'hui : beaucoup d'attaques réutilisent un programme légitime et signé (Java, PowerShell, un outil d'accès à distance) pour faire passer leur propre code. L'outil regarde donc **qui** ouvre la connexion, **ce qu'il exécute** et **où** elle va.

### Cas concrets

**1. Le faux `svchost.exe`**
`svchost.exe` est un processus Windows tout à fait normal. C'est pourquoi les malwares aiment s'en donner le nom. L'outil compare le nom au dossier réel : s'il tourne depuis `C:\Windows\System32`, tout va bien. S'il tourne depuis `C:\Users\...\AppData\Roaming`, il affiche **USURPATION POSSIBLE**.

**2. Le programme inconnu qui se connecte la nuit**
Vous voyez `RtkAudUService64.exe` connecté à un serveur distant. Le bouton **Google** ouvre directement la recherche sur ce nom. Vous découvrez qu'il appartient au pilote audio Realtek, et la colonne Éditeur confirme Realtek.

**3. L'exécutable sans signature qui parle à un serveur inconnu**
Une ligne **orange** : `updater.exe`, non signé, installé dans `AppData\Local\SomeApp`. Le bouton **VirusTotal (fichier)** ouvre la page du fichier. Si VirusTotal ne le connaît pas, l'outil propose de créer un ZIP du dossier de l'application pour l'envoyer à l'analyse.

**4. Le wrapper Java**
`javaw.exe` est signé Oracle, donc légitime. Mais ce qui se connecte, c'est le `.jar` qu'il exécute. L'outil affiche `monapp.jar (via javaw.exe)` en **ambre**, et le bouton VirusTotal vérifie le `.jar`, pas `javaw.exe`. Si la commande contient une charge encodée ou une fenêtre cachée, la ligne passe en **rouge**.
Liste d’hôtes surveillée : Java, Python, Node, PowerShell, mshta, rundll32, wscript, dotnet, etc.

**5. L'outil d'accès à distance**
AnyDesk ou TeamViewer sont légitimes, mais dangereux si vous n'avez pas lancé la session. Même quand vous l'avez lancé vous-même, chaque destination reste à confirmer : lancer le programme n'autorise pas toutes les adresses.

**6. Le poste d'un proche ou d'un collègue**
Une machine devient lente, la connexion sature. En quelques secondes vous voyez quels programmes sont connectés et ceux qui n'ont aucune signature, au lieu de fouiller le gestionnaire de tâches.

**7. L'enseignement et la formation**
Pour montrer à des étudiants ce qu'est un processus, un PID, un port distant, une ligne de commande ou une signature numérique, l'outil rend ces notions visibles sur leur propre machine.

## Fonctionnalités

- Liste des connexions TCP **ESTABLISHED** (détecte aussi l'état « ÉTABLI » des Windows en français)
- **Image = programme réellement exécuté** : pour un hôte, `monapp.jar (via javaw.exe)` ; la commande complète s'affiche en sélectionnant la ligne
- Colonne **Parent** : qui a lancé le processus (Word qui lance PowerShell, par exemple)
- Chemin complet, **signature numérique** et éditeur
- **Verdict de légitimité** avec **couleur** : vert, jaune, ambre, orange, violet, rouge, gris
- Détection des **programmes hôtes** (Java, Python, Node, PowerShell, `mshta`, `rundll32`...), y compris renommés ou embarqués
- Détection des **commandes à risque** : charge encodée, fenêtre cachée, téléchargement ou exécution à distance, chargement depuis un dossier temporaire
- Alerte sur les **outils d'accès à distance** (AnyDesk, TeamViewer, ScreenConnect, RustDesk...) et sur le RDP entrant
- **Liste de confiance** : approuver un programme avec sa destination, avec une note
- **Résolution DNS inverse** des adresses distantes (case à cocher), IPv4 et IPv6
- **Propriétaire de l'adresse (RDAP)** : à qui appartient une adresse publique (Microsoft, Cloudflare, un hébergeur...), même sans nom DNS. Option désactivée par défaut
- Bouton **Google** : recherche le nom du programme exécuté avec « processus légitime ou malware »
- Bouton **VirusTotal (fichier)** : calcule le SHA-256 et ouvre la page du fichier
- Bouton **VirusTotal (adresse IP)** : ouvre la réputation de l'adresse distante
- Bouton **ZIP pour VirusTotal** : crée sur le Bureau un ZIP de l'application pour l'envoyer à l'analyse quand VirusTotal ne la connaît pas
- **Blocage réseau réversible** : bloquer ou autoriser la communication d'un programme, bloquer ou débloquer une adresse distante (règles du Pare-feu Windows, colonne « Pare-feu »)
- Bouton **Arrêter (forcé)** : termine un processus et ses enfants (`taskkill /F /T`, puis PowerShell en secours), avec confirmation
- **Animation d'analyse** : indicateur qui tourne, barre de progression, étape en cours et secondes écoulées
- Double-clic : ouvre le dossier du fichier. Clic droit : toutes les actions, plus copier le chemin ou la commande
- Colonnes triables, les couleurs suivent les lignes

## Les verdicts

| Couleur | Verdict | Signification |
|:--|:--|:--|
| Vert | OFFICIEL Microsoft | Signature valide, éditeur Microsoft |
| Vert | OFFICIEL (noyau Windows) | Processus système `System` (PID 4) |
| Jaune | Signé par un tiers : vérifier l'éditeur | Signature valide, mais à vous de juger l'éditeur (Google, Zoom, Realtek...) |
| Ambre | HÔTE signé (Java, Python...) : vérifier ce qu'il exécute | Programme capable d'exécuter n'importe quel code : le fichier est signé, ce qu'il exécute reste à vérifier |
| Orange | NON SIGNÉ : à vérifier | Aucune signature, hors dossier Windows |
| Violet | ACCÈS À DISTANCE | Outil de prise de contrôle signé, ou connexion RDP entrante : confirmer la session |
| Rouge | SUSPECT (hôte ... : commande encodée, fenêtre cachée...) | Hôte avec une commande à risque |
| Rouge | SUSPECT (outil à distance non signé) | Outil d'accès à distance sans signature valide |
| Rouge | SUSPECT (fichier Windows non signé) | Fichier dans `C:\Windows` sans signature valide |
| Rouge | USURPATION POSSIBLE | Nom de processus système (`svchost.exe`, `lsass.exe`...) hors de `System32` ou `SysWOW64` |
| Gris | INCONNU | Chemin illisible : processus terminé ou droits insuffisants |

La colonne **Confiance** ajuste la couleur de la ligne, sauf pour un verdict rouge :

| Statut | Signification |
|:--|:--|
| Approuvé (vert) | Programme et destination approuvés par vous |
| NOUVELLE destination (orange) | Programme approuvé, mais cette destination ne l'est pas encore. Ce n'est pas un signe de danger : elle n'a simplement pas été vérifiée |
| MODIFIÉ depuis l'approbation (rouge) | Le fichier, la commande ou les fichiers chargés ont changé depuis l'approbation |
| NOUVEAU | Jamais approuvé : la couleur du verdict s'applique |

## Programmes hôtes (wrappers)

Un hôte est un programme légitime qui exécute du code qu'on lui donne : Java, Python, Node, PowerShell, `wscript`, `mshta`, `rundll32`, `dotnet`, `certutil`... Le fichier est signé, donc propre, mais le code qu'il exécute ne l'est pas forcément. L'outil ne se fie donc jamais à l'hôte seul :

- Il détecte les hôtes par **leur nom**, par le **nom d'origine du fichier** (un `java.exe` renommé `updater.exe` est démasqué) et par les **moteurs chargés en mémoire** (`jvm.dll`, `python*.dll`, `lua*.dll`, `node.dll`).
- Il affiche **le programme exécuté** (le `.jar`, le script, l'`.exe`) à la place de l'hôte, et c'est lui que visent les boutons VirusTotal, Google, ZIP et « Ouvrir le dossier ».
- Il analyse la commande : charge encodée, fenêtre cachée, téléchargement ou exécution à distance, URL dans la commande (pour les hôtes qui n'en ont pas besoin), chargement depuis `AppData`, `Temp` ou `Downloads`, lancement depuis Word, Excel, Outlook ou Acrobat.

Limites : la liste d'hôtes n'est pas exhaustive, et un programme compilé qui embarque son propre interpréteur sous un nom ordinaire peut passer inaperçu. Si la commande utilise un chemin relatif (`-jar app.jar`), seul le nom du fichier est affiché.

## Liste de confiance

Principe : **on n'approuve jamais un wrapper, on approuve ce qui est derrière**.

- **Approuver : programme + destination** (par défaut), ou **programme, toutes destinations** pour un programme dont les destinations varient (un navigateur, par exemple).
- Pour un **hôte**, l'approbation porte sur la **commande exacte** et les fichiers qu'elle charge. Un autre `.jar` lancé par le même `java.exe` reste « NOUVEAU ».
- **`svchost.exe`** est approuvé **par groupe de services**, pas tous ensemble.
- Un **outil d'accès à distance** ne s'approuve que **destination par destination**.
- Un programme **suspect** (rouge) ne peut pas être approuvé : vérifiez-le d'abord.
- Une **note** facultative garde la trace de votre vérification (par exemple « VirusTotal 0 détection, propriétaire Microsoft »).

Une destination est enregistrée par son domaine (deux ou trois derniers libellés), par son **nom exact** pour les clouds partagés (Amazon, Azure, Google Cloud, Heroku...) où n'importe qui peut héberger un serveur, et par son **adresse IP** quand elle n'a pas de nom.

Les approbations sont dans `%APPDATA%\ConnexionsActives\confiance.tsv` (une ligne par approbation : programme, empreinte, destination, date, note). Le menu clic droit ouvre ce fichier ; supprimer une ligne retire l'approbation.

**Limite d'intégrité :** le contrôle du fichier repose sur sa **taille et sa date de modification**, pas sur un hash complet. Un attaquant très soigneux peut falsifier ces valeurs.

## Destinations et DNS

**Une destination sans nom DNS n'est jamais suspecte par elle-même.** Beaucoup d'adresses n'ont aucun nom inverse : c'est fréquent chez les CDN et les clouds, et une colonne « Hôte distant » vide n'est pas un signe de danger.

- L'outil ne rend jamais un verdict suspect à cause d'une destination. Le statut « NOUVELLE destination » veut seulement dire « non approuvée ».
- Une destination sans nom est approuvée par son adresse IP, comme les autres.
- Pour juger une adresse, cochez **Propriétaire (RDAP)** pour voir à qui elle appartient, et utilisez **VirusTotal (adresse IP)** : détections, domaines associés. Un score communautaire de -1 laissé par un seul utilisateur ne prouve rien ; regardez le nombre de détections et vérifiez que le propriétaire correspond au programme (Microsoft pour un service Windows, par exemple).
- Une destination ne devrait être jugée suspecte que si **vous l'avez déclarée** comme telle. Cette liste de destinations déclarées suspectes est prévue, elle n'est pas encore dans la version actuelle.

## Installation et utilisation

### Option 1 : l'exécutable (le plus simple)

1. Ouvrez la page [Releases](https://github.com/ndytar-s/ConnexionsActives/releases) et téléchargez `ConnexionsActives.exe`.
2. Double-cliquez dessus et acceptez l'élévation administrateur (nécessaire pour lire le chemin et la commande de tous les processus).
3. Cliquez sur **Analyser** et patientez : l'animation indique l'étape en cours.
4. Pour une ligne que vous ne reconnaissez pas, sélectionnez-la puis utilisez **Google**, **VirusTotal (fichier)** ou **VirusTotal (adresse IP)**.
5. Quand vous avez vérifié un programme et sa destination, cliquez sur **Approuver**.

Aucune installation d'AutoHotkey n'est nécessaire.

### Option 2 : le script source (recommandé si vous voulez tout vérifier)

1. Installez [AutoHotkey v2](https://www.autohotkey.com/) (version 2.0.1 ou plus récente).
2. Téléchargez `ConnexionsActives.ahk` depuis ce dépôt et lisez-le : un seul fichier, en français, commenté.
3. Double-cliquez dessus.

Vous pouvez aussi produire vous-même l'exécutable avec Ahk2Exe (livré avec AutoHotkey) à partir du `.ahk` et comparer avec celui de la release.

### Avertissement antivirus

Les exécutables compilés avec AutoHotkey sont souvent signalés à tort par les antivirus (faux positifs), car le même format est utilisé par certains malwares. Un outil de sécurité distribué sans signature de code est particulièrement exposé à ce problème. Pour vérifier que votre fichier est identique à celui publié, comparez son empreinte avec celle indiquée dans la release :

```powershell
Get-FileHash .\ConnexionsActives.exe -Algorithm SHA256
```

### Vérifier un programme inconnu

1. Sélectionnez la ligne (orange, ambre, violette, rouge ou grise de préférence). La commande complète s'affiche en bas de la fenêtre.
2. **Google** : un premier avis rapide sur le programme exécuté.
3. **VirusTotal (fichier)** : si le fichier est connu, vous voyez le verdict de dizaines d'antivirus.
   **VirusTotal (adresse IP)** : vérifie le serveur distant. Les adresses locales sont refusées, car elles n'existent pas sur Internet.
4. Si VirusTotal affiche « file not found », acceptez la proposition de **ZIP** puis glissez le ZIP sur la page d'envoi qui s'ouvre.
5. Si tout est cohérent, **Approuver** avec une note.

Pour les dossiers système ou personnels (Windows, Program Files, profil, AppData, Bureau, Documents, Téléchargements), seul le fichier est compressé, jamais le dossier entier. Un dossier de plus de 650 Mo est refusé, car c'est la limite de VirusTotal.

**Confidentialité :** les fichiers envoyés à VirusTotal sont accessibles à la communauté de sécurité. N'envoyez pas un dossier qui contient des configurations, des mots de passe ou des journaux personnels. L'outil n'envoie jamais rien automatiquement : il crée le ZIP sur votre Bureau et c'est vous qui décidez de l'envoyer.

## Comment ça marche

```text
netstat -noa  ->  filtre ESTABLISHED  ->  PID, adresse distante
tasklist /FI "PID eq <PID>"  ->  nom de l'image
PowerShell (une fois par programme)  ->  chemin, signature, éditeur, ligne de commande,
                                         parent, taille et date, nom d'origine, moteurs chargés
règles hôtes, commandes à risque, outils à distance  ->  verdict
liste de confiance (programme + commande + destination)  ->  statut et couleur
DNS inverse  ->  nom d'hôte de l'adresse distante
RDAP (option)  ->  propriétaire de l'adresse publique
Get-FileHash (à la demande)  ->  SHA-256  ->  page VirusTotal
tar (à la demande)  ->  ZIP de l'application
```

### Transparence

- Fichiers temporaires dans `%TEMP%` : `ahk_sig.ps1`, `ahk_dns.ps1`, `ahk_rdap.ps1`, `ahk_ips.txt`, `ahk_rdap_ips.txt` et des fichiers `ahk_out_*.txt`, supprimés après lecture. Les scripts PowerShell sont lancés avec `-ExecutionPolicy Bypass` uniquement pour ces fichiers temporaires.
- Fichier permanent : `%APPDATA%\ConnexionsActives\confiance.tsv`, créé seulement quand vous approuvez un programme.
- **Réseau :** pour la résolution DNS, les adresses distantes sont d'abord demandées à votre résolveur habituel. En l'absence de réponse, elles sont demandées au résolveur public Cloudflare (1.1.1.1). Décochez « Résolution DNS » pour l'éviter. Aucune autre donnée n'est envoyée par l'outil.
- **Propriétaire (RDAP)**, désactivé par défaut : les adresses IP publiques sont envoyées à `rdap.org`, puis au registre régional concerné (ARIN, RIPE, AFRINIC, APNIC, LACNIC). L'outil demande confirmation à l'activation. Les résultats sont gardés en mémoire pendant la session seulement.
- VirusTotal n'est contacté que par votre navigateur, quand vous cliquez sur le bouton ou envoyez le ZIP.
- L'outil n'interrompt ni ne bloque aucune connexion : il informe, vous décidez.
- Tout le code est dans un seul fichier, vous pouvez le relire avant de l'exécuter.

## Blocage réseau (Pare-feu Windows)

Deux boutons, aussi dans le clic droit, créent des règles du Pare-feu Windows nommées `ConnexionsActives~...` (le chemin ou l'adresse est dans la description de la règle), **entrantes et sortantes**. Un second clic les désactive : la règle est conservée, rien n'est supprimé. La colonne **Pare-feu** indique « Programme bloqué » et/ou « Adresse bloquée ».

- **Programme : bloquer / autoriser** : bloque toute communication du fichier exécutable. Pour un hôte (`javaw.exe`, `python.exe`...), cela bloque **tous** les programmes qui l'utilisent : l'outil le signale avant de continuer.
- **Adresse : bloquer / débloquer** : bloque une adresse distante pour tous les programmes. Les adresses locales (réseau, passerelle, DNS) sont refusées.
- **Composants système partagés refusés** (`svchost`, `lsass`, `services`...) : les bloquer couperait Internet ou Windows Update. Bloquez plutôt l'adresse.
- Les règles apparaissent dans le Pare-feu Windows avec Sécurité avancée (`wf.msc`) et s'y suppriment si besoin.

Limites : si le Pare-feu Windows est désactivé ou remplacé par celui d'un antivirus tiers, les règles n'ont aucun effet (l'outil le signale quand il le détecte). Les connexions déjà ouvertes sont en général coupées, sinon relancez le programme.

## Arrêt forcé d'un processus

Sélectionnez une ligne puis **Arrêter (forcé)** (ou clic droit). Une fenêtre résume le processus, son fichier, son verdict et sa commande, et demande confirmation (réponse par défaut : Non). Le processus et ses processus enfants sont terminés immédiatement, sans enregistrement des données non sauvegardées.

- **Processus vitaux refusés** : `System`, `smss`, `csrss`, `wininit`, `winlogon`, `services`, `lsass` provoqueraient un écran bleu ou un redémarrage. L'outil refuse, ainsi que d'arrêter son propre processus.
- **`svchost.exe`** : avertissement renforcé, car il héberge des services Windows. Préférez arrêter le service concerné.
- **Processus protégés** (antivirus, EDR, composants système) : Windows les protège même contre les administrateurs. L'outil **ne contourne pas** ces protections ; il explique la situation et propose des pistes (arrêter le service, désactiver le démarrage, mode sans échec).
- **Processus qui réapparaît** : un service, une tâche planifiée ou son parent le relance. Relancez l'analyse et regardez la colonne **Parent**.

## Limites à connaître

- **Ce n'est pas un antivirus ni un EDR.** Une signature valide prouve l'origine du fichier, pas qu'il est inoffensif. Un attaquant qui s'injecte dans un processus de confiance peut échapper à ces contrôles.
- L'outil donne un point de départ pour enquêter, pas un jugement définitif. En cas de doute, utilisez les boutons VirusTotal.
- La page VirusTotal d'un hash n'existe que si le fichier a déjà été analysé par quelqu'un.
- L'analyse prend du temps (environ une à deux secondes par programme), car elle lit la commande, le parent et les modules chargés.
- Les fichiers verrouillés par l'application sont ignorés lors de la création du ZIP.
- Seules les connexions TCP ESTABLISHED sont analysées (UDP n'a pas d'état de connexion).
- C'est une photo de l'instant : cliquez de nouveau sur **Analyser** pour actualiser.
- Windows uniquement.

## Contribuer

Les idées et pull requests sont bienvenues, par exemple :

- actualisation automatique avec alerte sur les nouvelles connexions
- liste de destinations déclarées suspectes
- vérification d'intégrité par hash complet pour les programmes approuvés
- export CSV du tableau
- interface en anglais

## Licence

Distribué sous licence MIT, voir le fichier [LICENSE](LICENSE).

Auteur : [@ndytar-s](https://github.com/ndytar-s)
