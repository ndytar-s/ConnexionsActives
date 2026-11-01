# ConnexionsActives

**Voyez en un clic quels programmes de votre PC parlent à Internet, et lesquels sont dignes de confiance.**

ConnexionsActives est un petit outil Windows écrit en AutoHotkey v2. Il liste toutes les connexions réseau établies, identifie le programme derrière chacune, vérifie son origine (chemin et signature numérique), colore chaque ligne selon un verdict de légitimité clair, retrouve le nom des serveurs distants (DNS inverse) et vous envoie vers VirusTotal pour les programmes douteux. Pas d'installation, pas de service en arrière-plan, un seul fichier lisible de bout en bout.

> Capture d'écran : <img width="1364" height="700" alt="image" src="https://github.com/user-attachments/assets/b2b9ccc4-2a8e-464c-8300-da72e244d3bf" />



## Pourquoi cet outil est utile

Votre ordinateur ouvre des dizaines de connexions à chaque instant : navigateur, mises à jour, synchronisation cloud, antivirus, mais aussi parfois un programme que vous n'avez jamais lancé. Windows ne vous montre pas facilement qui est derrière.

Faire cette vérification à la main demande quatre étapes : `netstat -noa`, repérer les lignes ESTABLISHED, retrouver chaque PID avec `tasklist`, puis chercher le fichier et sa signature. ConnexionsActives automatise toute la chaîne et l'affiche dans un seul tableau.

### Cas concrets

**1. Le faux `svchost.exe`**
`svchost.exe` est un processus Windows tout à fait normal. C'est pourquoi les malwares aiment s'en donner le nom. L'outil compare le nom au dossier réel : s'il tourne depuis `C:\Windows\System32`, tout va bien. S'il tourne depuis `C:\Users\...\AppData\Roaming`, il affiche **USURPATION POSSIBLE**.

**2. Le programme inconnu qui se connecte la nuit**
Vous voyez `RtkAudUService64.exe` connecté à un serveur distant. Le bouton **Google** ouvre directement la recherche sur ce nom. Vous découvrez qu'il appartient au pilote audio Realtek, et la colonne Éditeur confirme Realtek.

**3. L'exécutable sans signature qui parle à un serveur inconnu**
Une ligne **orange** : `updater.exe`, non signé, installé dans `AppData\Local\SomeApp`. Le bouton **VirusTotal (hash)** ouvre la page du fichier. Si VirusTotal ne le connaît pas, l'outil propose de créer un ZIP du dossier de l'application pour l'envoyer à l'analyse.

**4. Le poste d'un proche ou d'un collègue**
Une machine devient lente, la connexion sature. En quelques secondes vous voyez quels programmes sont connectés et ceux qui n'ont aucune signature, au lieu de fouiller le gestionnaire de tâches.

**5. L'enseignement et la formation**
Pour montrer à des étudiants ce qu'est un processus, un PID, un port distant ou une signature numérique, l'outil rend ces notions visibles sur leur propre machine.

## Fonctionnalités

- Liste des connexions TCP **ESTABLISHED** (détecte aussi l'état « ÉTABLI » des Windows en français)
- Nom de l'image (`.exe`) trouvé par PID avec `tasklist`
- Chemin complet du fichier exécuté, **signature numérique** et éditeur
- **Verdict de légitimité** pour chaque ligne, avec **couleur** : vert, jaune, orange, rouge, gris
- **Résolution DNS inverse** des adresses distantes (case à cocher) : colonne « Hôte distant », IPv4 et IPv6
- Bouton **Google** : recherche le nom de l'image avec « processus légitime ou malware »
- Bouton **VirusTotal (fichier)** : calcule le SHA-256 du fichier et ouvre sa page sur VirusTotal
- Bouton **VirusTotal (adresse IP)** : ouvre la réputation de l'adresse distante (propriétaire, détections, domaines associés)
- Bouton **ZIP pour VirusTotal** : crée sur le Bureau un ZIP de l'application complète pour l'envoyer à l'analyse quand VirusTotal ne la connaît pas
- Double-clic : ouvre le dossier du fichier dans l'Explorateur
- Clic droit : toutes les actions, plus « Copier le chemin »
- Colonnes triables, les couleurs suivent les lignes

## Les verdicts

| Couleur | Verdict | Signification |
|:--|:--|:--|
| Vert | OFFICIEL Microsoft | Signature valide, éditeur Microsoft |
| Vert | OFFICIEL (noyau Windows) | Processus système `System` (PID 4) |
| Jaune | Signé par un tiers : vérifier l'éditeur | Signature valide, mais à vous de juger l'éditeur (Google, Zoom, Realtek...) |
| Orange | NON SIGNÉ : à vérifier | Aucune signature, hors dossier Windows |
| Rouge | SUSPECT (fichier Windows non signé) | Fichier dans `C:\Windows` sans signature valide |
| Rouge | USURPATION POSSIBLE | Nom de processus système (`svchost.exe`, `lsass.exe`...) hors de `System32` ou `SysWOW64` |
| Gris | INCONNU | Chemin illisible : processus terminé ou droits insuffisants |

## Installation et utilisation

### Option 1 : l'exécutable (le plus simple)

1. Ouvrez la page [Releases](https://github.com/ndytar-s/ConnexionsActives/releases) et téléchargez `ConnexionsActives.exe`.
2. Double-cliquez dessus et acceptez l'élévation administrateur (nécessaire pour lire le chemin de tous les processus).
3. Cliquez sur **Analyser**.
4. Pour une image que vous ne reconnaissez pas, sélectionnez la ligne puis utilisez **Google**, **VirusTotal (fichier)** ou **VirusTotal (adresse IP)**.

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

1. Sélectionnez la ligne (orange, rouge ou grise de préférence).
2. **Google** : un premier avis rapide sur le nom du fichier.
3. **VirusTotal (fichier)** : si le fichier est connu, vous voyez directement le verdict de dizaines d'antivirus.
   **VirusTotal (adresse IP)** : vérifie le serveur distant (à qui il appartient, s'il est signalé). Les adresses locales sont refusées, car elles n'existent pas sur Internet.
4. Si VirusTotal affiche « file not found », acceptez la proposition de **ZIP** puis glissez le ZIP sur la page d'envoi qui s'ouvre.

Pour les dossiers système (Windows, Program Files, profil, AppData...), seul l'exécutable est compressé, jamais le dossier entier. Un dossier de plus de 650 Mo est refusé, car c'est la limite de VirusTotal.

**Confidentialité :** les fichiers envoyés à VirusTotal sont accessibles à la communauté de sécurité. N'envoyez pas un dossier qui contient des configurations, des mots de passe ou des journaux personnels. L'outil n'envoie jamais rien automatiquement : il crée le ZIP sur votre Bureau et c'est vous qui décidez de l'envoyer.

## Comment ça marche

```text
netstat -noa  ->  filtre ESTABLISHED  ->  PID, adresse distante
tasklist /FI "PID eq <PID>"  ->  nom de l'image
PowerShell Get-AuthenticodeSignature  ->  chemin, signature, éditeur
règles de verdict  ->  tableau coloré
DNS inverse  ->  nom d'hôte de l'adresse distante
Get-FileHash (à la demande)  ->  SHA-256  ->  page VirusTotal
tar (à la demande)  ->  ZIP de l'application
```

### Transparence

- Fichiers temporaires dans `%TEMP%` : `ahk_sig.ps1`, `ahk_dns.ps1`, `ahk_ips.txt` et des fichiers `ahk_out_*.txt`, supprimés après lecture. Les scripts PowerShell sont lancés avec `-ExecutionPolicy Bypass` uniquement pour ces fichiers temporaires.
- **Réseau :** pour la résolution DNS, les adresses distantes sont d'abord demandées à votre résolveur habituel. En l'absence de réponse, elles sont demandées au résolveur public Cloudflare (1.1.1.1). Décochez « Résolution DNS » pour l'éviter. Aucune autre donnée n'est envoyée par l'outil.
- VirusTotal n'est contacté que par votre navigateur, quand vous cliquez sur le bouton ou envoyez le ZIP.
- Tout le code est dans un seul fichier, vous pouvez le relire avant de l'exécuter.

## Limites à connaître

- **Ce n'est pas un antivirus.** Une signature valide prouve l'origine du fichier, pas qu'il est inoffensif. Un programme légitime peut être détourné, et un malware peut être signé avec un certificat volé.
- L'outil donne un point de départ pour enquêter, pas un jugement définitif. En cas de doute, utilisez le bouton VirusTotal.
- Beaucoup d'adresses n'ont aucun nom DNS (fréquent chez les CDN et les clouds) : une colonne « Hôte distant » vide n'est pas suspecte en soi.
- La page VirusTotal d'un hash n'existe que si le fichier a déjà été analysé par quelqu'un.
- Les fichiers verrouillés par l'application sont ignorés lors de la création du ZIP.
- Seules les connexions TCP ESTABLISHED sont analysées (UDP n'a pas d'état de connexion).
- Une photo de l'instant : cliquez de nouveau sur **Analyser** pour actualiser.
- Windows uniquement.

## Contribuer

Les idées et pull requests sont bienvenues, par exemple :

- export CSV du tableau
- actualisation automatique
- colonne optionnelle « propriétaire de l'adresse » (RDAP)
- interface en anglais

## Licence

<<<<<<< HEAD
Distribué sous licence MIT 
=======
Distribué sous licence MIT, voir le fichier [LICENSE](LICENSE).
>>>>>>> ef017a3 (Ajout de la vérification VirusTotal par adresse IP)

Auteur : [@ndytar-s](https://github.com/ndytar-s)
