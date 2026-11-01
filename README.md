# ConnexionsActives

**Voyez en un clic quels programmes de votre PC parlent à Internet, et lesquels sont dignes de confiance.**

ConnexionsActives est un petit outil Windows écrit en AutoHotkey v2. Il liste toutes les connexions réseau établies, identifie le programme derrière chacune, vérifie son origine (chemin et signature numérique) et affiche un verdict de légitimité clair. Pas d'installation, pas de service en arrière-plan, un seul fichier lisible de bout en bout.

> Capture d'écran : <img width="1365" height="751" alt="image" src="https://github.com/user-attachments/assets/3c2e9292-2ec8-43d2-a339-c641c29d3de5" />


## Pourquoi cet outil est utile

Votre ordinateur ouvre des dizaines de connexions à chaque instant : navigateur, mises à jour, synchronisation cloud, antivirus, mais aussi parfois un programme que vous n'avez jamais lancé. Windows ne vous montre pas facilement qui est derrière.

Faire cette vérification à la main demande quatre étapes : `netstat -noa`, repérer les lignes ESTABLISHED, retrouver chaque PID avec `tasklist`, puis chercher le fichier et sa signature. ConnexionsActives automatise toute la chaîne et l'affiche dans un seul tableau.

### Cas concrets

**1. Le faux `svchost.exe`**
`svchost.exe` est un processus Windows tout à fait normal. C'est pourquoi les malwares aiment s'en donner le nom. L'outil compare le nom au dossier réel : s'il tourne depuis `C:\Windows\System32`, tout va bien. S'il tourne depuis `C:\Users\...\AppData\Roaming`, il affiche **USURPATION POSSIBLE**.

**2. Le programme inconnu qui se connecte la nuit**
Vous voyez `RtkAudUService64.exe` connecté à un serveur distant. Le bouton **Vérifier sur Google** ouvre directement la recherche sur ce nom. Vous découvrez qu'il appartient au pilote audio Realtek, et la colonne Éditeur confirme Realtek.

**3. Le poste d'un proche ou d'un collègue**
Une machine devient lente, la connexion sature. En quelques secondes vous voyez quels programmes sont connectés et ceux qui n'ont aucune signature, au lieu de fouiller le gestionnaire de tâches.

**4. L'enseignement et la formation**
Pour montrer à des étudiants ce qu'est un processus, un PID, un port distant ou une signature numérique, l'outil rend ces notions visibles sur leur propre machine.

## Fonctionnalités

- Liste des connexions TCP **ESTABLISHED** (détecte aussi l'état « ÉTABLI » des Windows en français)
- Nom de l'image (`.exe`) trouvé par PID avec `tasklist`
- Chemin complet du fichier exécuté
- Statut de la **signature numérique** et nom de l'éditeur
- **Verdict de légitimité** lisible pour chaque ligne
- Bouton et menu clic droit **Vérifier sur Google**
- Double-clic : ouvre le dossier du fichier dans l'Explorateur
- Clic droit : copier le chemin
- Compatible IPv4 et IPv6

## Les verdicts

| Verdict | Signification |
|:--|:--|
| OFFICIEL Microsoft | Signature valide, éditeur Microsoft |
| OFFICIEL (noyau Windows) | Processus système `System` (PID 4) |
| Signé par un tiers : vérifier l'éditeur | Signature valide, mais à vous de juger l'éditeur (Google, Zoom, Realtek...) |
| NON SIGNÉ : à vérifier | Aucune signature, hors dossier Windows |
| SUSPECT (fichier Windows non signé) | Fichier dans `C:\Windows` sans signature valide |
| USURPATION POSSIBLE | Nom de processus système (`svchost.exe`, `lsass.exe`...) hors de `System32` ou `SysWOW64` |
| INCONNU | Chemin illisible : processus terminé ou droits insuffisants |

## Installation et utilisation

### Option 1 : l'exécutable (le plus simple)

1. Ouvrez la page [Releases](https://github.com/ndytar-s/ConnexionsActives/releases) et téléchargez `ConnexionsActives.exe`.
2. Double-cliquez dessus et acceptez l'élévation administrateur (nécessaire pour lire le chemin de tous les processus).
3. Cliquez sur **Analyser**.
4. Pour une image que vous ne reconnaissez pas, sélectionnez la ligne puis **Vérifier sur Google**.

Aucune installation d'AutoHotkey n'est nécessaire.

### Option 2 : le script source (recommandé si vous voulez tout vérifier)

1. Installez [AutoHotkey v2](https://www.autohotkey.com/).
2. Téléchargez `ConnexionsActives.ahk` depuis ce dépôt et lisez-le : un seul fichier, quelques dizaines de lignes.
3. Double-cliquez dessus.

Vous pouvez aussi produire vous-même l'exécutable avec Ahk2Exe (livré avec AutoHotkey) à partir du `.ahk` et comparer avec celui de la release.

### Avertissement antivirus

Les exécutables compilés avec AutoHotkey sont souvent signalés à tort par les antivirus (faux positifs), car le même format est utilisé par certains malwares. Un outil de sécurité distribué sans signature de code est particulièrement exposé à ce problème. Pour vérifier que votre fichier est identique à celui publié, comparez son empreinte avec celle indiquée dans la release :

```powershell
Get-FileHash .\ConnexionsActives.exe -Algorithm SHA256
```

## Comment ça marche

```text
netstat -noa  ->  filtre ESTABLISHED  ->  PID
tasklist /FI "PID eq <PID>"  ->  nom de l'image
PowerShell Get-AuthenticodeSignature  ->  chemin, signature, éditeur
règles de verdict  ->  tableau
```

Transparence : l'outil écrit deux types de fichiers temporaires dans `%TEMP%` (`ahk_sig.ps1` et des fichiers `ahk_out_*.txt` supprimés après lecture). Le script PowerShell est lancé avec `-ExecutionPolicy Bypass` uniquement pour ce fichier temporaire. Tout le code est dans un seul fichier, vous pouvez le relire avant de l'exécuter.

## Limites à connaître

- **Ce n'est pas un antivirus.** Une signature valide prouve l'origine du fichier, pas qu'il est inoffensif. Un programme légitime peut être détourné, et un malware peut être signé avec un certificat volé.
- L'outil donne un point de départ pour enquêter, pas un jugement définitif. En cas de doute, comparez l'adresse distante et le fichier sur [VirusTotal](https://www.virustotal.com/).
- Seules les connexions TCP ESTABLISHED sont analysées (UDP n'a pas d'état de connexion).
- Une photo de l'instant : cliquez de nouveau sur **Analyser** pour actualiser.
- Windows uniquement.

## Contribuer

Les idées et pull requests sont bienvenues, par exemple :

- export CSV du tableau
- couleurs selon le verdict
- résolution inverse DNS des adresses distantes
- lien direct vers VirusTotal avec le hash du fichier
- actualisation automatique

## Licence

Distribué sous licence MIT 

Auteur : [@ndytar-s](https://github.com/ndytar-s)
