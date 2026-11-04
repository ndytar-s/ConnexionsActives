#Requires AutoHotkey v2.0.1
#SingleInstance Force

; Les droits admin permettent de lire le chemin de tous les processus
if !A_IsAdmin {
    try Run('*RunAs "' A_ScriptFullPath '"')
    ExitApp
}

COL_CHEMIN := 8                      ; numéro de la colonne "Chemin"
COL_VERDICT := 11                    ; numéro de la colonne "Verdict"
COL_TRUST := 13                      ; numéro de la colonne "Confiance"
TAILLE_MAX_ZIP := 650 * 1024 * 1024  ; limite de taille de fichier de VirusTotal

; Script PowerShell temporaire : chemin, signature, ligne de commande, parent, empreinte, moteur embarqué
psFile := A_Temp "\ahk_sig.ps1"
try FileDelete(psFile)
FileAppend("
(
param($id)
$sep = [char]31
$w = Get-CimInstance Win32_Process -Filter "ProcessId=$id" -ErrorAction SilentlyContinue
$p = (Get-Process -Id $id -ErrorAction SilentlyContinue).Path
if (-not $p -and $w) { $p = $w.ExecutablePath }
$cmd = ''
$par = ''
if ($w) {
    $cmd = [string]$w.CommandLine -replace '[\r\n]+', ' '
    $pp = Get-Process -Id $w.ParentProcessId -ErrorAction SilentlyContinue
    if ($pp) { $par = $pp.ProcessName + '.exe' }
}
$st = ''
$cn = ''
$sz = ''
$mt = ''
$of = ''
if ($p) {
    $s = Get-AuthenticodeSignature -FilePath $p
    $st = [string]$s.Status
    if ($s.SignerCertificate) { $cn = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
    $fi = Get-Item -LiteralPath $p -ErrorAction SilentlyContinue
    if ($fi) {
        $sz = $fi.Length
        $mt = $fi.LastWriteTimeUtc.Ticks
        $of = $fi.VersionInfo.OriginalFilename
    }
}
$eng = @()
try {
    foreach ($m in (Get-Process -Id $id -ErrorAction Stop).Modules) {
        $n = $m.ModuleName.ToLower()
        if ($n -eq 'jvm.dll') { $eng += 'Java' }
        elseif ($n -like 'python*.dll') { $eng += 'Python' }
        elseif ($n -like 'lua*.dll') { $eng += 'Lua' }
        elseif ($n -eq 'node.dll') { $eng += 'Node' }
    }
} catch {}
$eg = (($eng | Select-Object -Unique) -join ',')
[string]::Join($sep, @($p, $st, $cn, $cmd, $par, $sz, $mt, $of, $eg))
)", psFile, "UTF-8")

rowColors := Map()                   ; couleurs par identifiant de ligne (stable au tri)

; Script PowerShell temporaire : DNS inverse (résolveur local, puis 1.1.1.1 en secours)
dnsFile := A_Temp "\ahk_dns.ps1"
try FileDelete(dnsFile)
FileAppend("
(
param($f)
foreach ($ip in Get-Content $f) {
    $ip = $ip.Trim()
    if (-not $ip) { continue }
    $n = ''
    foreach ($srv in @('', '1.1.1.1')) {
        try {
            if ($srv) { $r = Resolve-DnsName -Name $ip -Server $srv -DnsOnly -QuickTimeout -ErrorAction Stop }
            else { $r = Resolve-DnsName -Name $ip -DnsOnly -QuickTimeout -ErrorAction Stop }
            $x = $r | Where-Object { $_.NameHost } | Select-Object -First 1
            if ($x) { $n = $x.NameHost; break }
        } catch {}
    }
    "$ip|$n"
}
)", dnsFile, "UTF-8")

ownerCache := Map()                  ; propriétaires déjà trouvés pendant cette session

; Script PowerShell temporaire : propriétaire d'une adresse IP publique via RDAP (rdap.org -> registre régional)
rdapFile := A_Temp "\ahk_rdap.ps1"
try FileDelete(rdapFile)
FileAppend("
(
param($f)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
foreach ($ip in Get-Content $f) {
    $ip = $ip.Trim()
    if (-not $ip) { continue }
    $o = ''
    try {
        $r = Invoke-RestMethod -Uri "https://rdap.org/ip/$ip" -TimeoutSec 8 -ErrorAction Stop
        $o = [string]$r.name
        $fn = ''
        foreach ($e in $r.entities) {
            if ($e.vcardArray -and $e.vcardArray.Count -gt 1) {
                foreach ($v in $e.vcardArray[1]) {
                    if ($v[0] -eq 'fn') { $fn = [string]$v[3]; break }
                }
            }
            if ($fn) { break }
        }
        if ($fn -and $fn -ne $o) { $o = $fn + ' (' + $o + ')' }
        if ($r.country) { $o = $o + ' [' + $r.country + ']' }
    } catch {}
    "$ip|$o"
}
)", rdapFile, "UTF-8")

rowData := Map()                     ; données par identifiant de ligne (confiance, destination...)
trust := Map()                       ; liste de confiance : "lieu<TAB>empreinte" -> destinations approuvées
lieuKnown := Map()                   ; lieux déjà approuvés une fois (détecte les modifications)
trustFile := A_AppData "\ConnexionsActives\confiance.tsv"
busy := false                        ; analyse en cours
etat := ""                           ; message affiché pendant l'analyse
t0 := 0                              ; heure de début de l'analyse
kFrame := 0                          ; image courante de l'animation

; Hôtes : programmes capables d'exécuter du code arbitraire (wrappers, interpréteurs, outils système détournables).
; Un hôte, même signé, n'est jamais approuvé seul : seule sa commande exacte et sa charge utile le sont.
hotes := Map()
for hn in ["java.exe", "javaw.exe", "javaws.exe", "python.exe", "pythonw.exe", "py.exe", "node.exe", "deno.exe", "bun.exe"
    , "ruby.exe", "perl.exe", "php.exe", "lua.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"
    , "rundll32.exe", "regsvr32.exe", "cmd.exe", "dotnet.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe"
    , "wmic.exe", "bash.exe", "wsl.exe", "certutil.exe", "bitsadmin.exe", "curl.exe", "wget.exe", "ssh.exe"
    , "autohotkey.exe", "autohotkey32.exe", "autohotkey64.exe", "autohotkeyu64.exe"]
    hotes[hn] := 1

; Noms de domaine partagés (cloud) : approuvés au nom exact, jamais par domaine, car n'importe qui peut y héberger un serveur
PARTAGES := ["amazonaws.com", "cloudfront.net", "googleusercontent.com", "cloudapp.azure.com", "cloudapp.net"
    , "azurewebsites.net", "herokuapp.com", "digitaloceanspaces.com", "vultrusercontent.com"]

sysNames := Map("svchost.exe", 1, "lsass.exe", 1, "csrss.exe", 1, "services.exe", 1
    , "winlogon.exe", 1, "smss.exe", 1, "wininit.exe", 1, "spoolsv.exe", 1, "taskhostw.exe", 1)

g := Gui("+Resize", "Connexions ETABLIES et légitimité des processus (v1.3)")
btn := g.Add("Button", "w100", "Analyser")
btnWeb := g.Add("Button", "x+8 w110", "Google")
btnVT := g.Add("Button", "x+8 w150", "VirusTotal (fichier)")
btnIP := g.Add("Button", "x+8 w170", "VirusTotal (adresse IP)")
btnZip := g.Add("Button", "x+8 w170", "ZIP pour VirusTotal")
btnOk := g.Add("Button", "x+8 w110", "Approuver")
chk := g.Add("CheckBox", "x+15 yp+5 Checked", "Résolution DNS")
chkRdap := g.Add("CheckBox", "x+10 yp", "Propriétaire (RDAP)")
btnKill := g.Add("Button", "xm w150", "Arrêter (forcé)")
prog := g.Add("Progress", "xm w1150 h12 Range0-100")
status := g.Add("Text", "xm w1150"
    , "Prêt. Vert : officiel ou approuvé | Jaune : tiers signé | Ambre : hôte (Java, Python, PowerShell...) | Orange : non signé ou nouvelle destination | Violet : accès à distance | Rouge : suspect | Gris : inconnu")
lv := g.Add("ListView", "xm w1150 r24 Grid"
    , ["Image", "PID", "Local", "Distant", "Hôte distant (DNS)", "Propriétaire (RDAP)", "Port distant", "Chemin", "Signature", "Éditeur", "Verdict", "Parent", "Confiance"])

lv.Opt("+LV0x010000")                ; LVS_EX_DOUBLEBUFFER : évite les défauts d'affichage
btn.OnEvent("Click", Analyser)
btnWeb.OnEvent("Click", (*) => RechercherGoogle(lv, lv.GetNext(0)))
btnVT.OnEvent("Click", (*) => VirusTotalHash(lv, lv.GetNext(0)))
btnIP.OnEvent("Click", (*) => VirusTotalIP(lv, lv.GetNext(0)))
btnZip.OnEvent("Click", (*) => ZipApplication(lv, lv.GetNext(0)))
btnOk.OnEvent("Click", (*) => ApprouverLigne(lv, lv.GetNext(0), false))
chkRdap.OnEvent("Click", ConfirmerRdap)
btnKill.OnEvent("Click", (*) => ArreterProcessus(lv, lv.GetNext(0)))

ctxMenu := Menu()
ctxMenu.Add("Vérifier sur Google", (*) => RechercherGoogle(lv, lv.GetNext(0)))
ctxMenu.Add("VirusTotal (fichier, par hash)", (*) => VirusTotalHash(lv, lv.GetNext(0)))
ctxMenu.Add("VirusTotal (adresse IP distante)", (*) => VirusTotalIP(lv, lv.GetNext(0)))
ctxMenu.Add("Créer un ZIP de l'application", (*) => ZipApplication(lv, lv.GetNext(0)))
ctxMenu.Add()
ctxMenu.Add("Approuver : programme + destination", (*) => ApprouverLigne(lv, lv.GetNext(0), false))
ctxMenu.Add("Approuver : programme (toutes destinations)", (*) => ApprouverLigne(lv, lv.GetNext(0), true))
ctxMenu.Add("Ouvrir la liste de confiance", (*) => OuvrirListeConfiance())
ctxMenu.Add()
ctxMenu.Add("Arrêter le processus (forcé)", (*) => ArreterProcessus(lv, lv.GetNext(0)))
ctxMenu.Add()
ctxMenu.Add("Ouvrir l'emplacement du fichier", (*) => OuvrirDossier(lv, lv.GetNext(0)))
ctxMenu.Add("Copier la ligne de commande", (*) => (d := DonneesLigne(lv, lv.GetNext(0))) ? A_Clipboard := d.cmd : 0)
ctxMenu.Add("Copier le chemin", (*) => (r := lv.GetNext(0)) ? A_Clipboard := lv.GetText(r, COL_CHEMIN) : 0)

lv.OnEvent("DoubleClick", OuvrirDossier)
lv.OnEvent("ItemSelect", AfficherCommande)
lv.OnEvent("ContextMenu", (ctrl, item, isRC, x, y) => item ? ctxMenu.Show(x, y) : 0)
lv.OnNotify(-12, CustomDraw)         ; NM_CUSTOMDRAW : couleur des lignes
g.OnEvent("Size", (gui, mm, w, h) => mm != -1 ? lv.Move(, , w - 20, h - 145) : 0)
g.Show()
return

; ---------------------------------------------------------------- Analyse

Analyser(*) {
    global busy, t0, kFrame, btn, prog, status
    if busy
        return
    busy := true
    t0 := A_TickCount
    kFrame := 0
    btn.Enabled := false
    prog.Value := 0
    SetTimer(Tick, 150)                    ; animation : tourne même pendant les longues attentes
    msg := "Analyse interrompue par une erreur."
    try {
        msg := AnalyserCorps()
    } finally {
        SetTimer(Tick, 0)
        busy := false
        btn.Enabled := true
        prog.Value := 100
        status.Value := msg
    }
}

; Animation : petit indicateur qui tourne + message de l'étape + secondes écoulées
Tick() {
    global status, etat, t0, kFrame
    static frames := ["|", "/", "-", "\"]
    kFrame++
    status.Value := frames[Mod(kFrame, 4) + 1] "  " etat "  (" Round((A_TickCount - t0) / 1000) " s)"
}

Etape(msg, pct) {
    global etat, prog
    etat := msg
    prog.Value := pct
    Tick()
}

AnalyserCorps() {
    global lv, chk, chkRdap, rowColors, rowData, t0
    lv.Delete()
    rowColors.Clear()
    rowData.Clear()
    LoadTrust()
    Etape("Lecture des connexions (netstat)...", 3)
    out := RunCmd("netstat -noa")
    conns := []
    ips := Map()
    pids := Map()
    for ligne in StrSplit(out, "`n", "`r") {
        ; Fonctionne en anglais (ESTABLISHED) et en français (ÉTABLI)
        if !RegExMatch(ligne, "i)^\s*TCP\s+(\S+)\s+(\S+)\s+(ESTABLISHED|\S*TABLI)\s+(\d+)\s*$", &m)
            continue
        conns.Push({adr: m[1], dist: m[2], pid: m[4]})
        pids[m[4]] := 1
        ip := IpDe(m[2])
        if (ip != "")
            ips[ip] := 1
    }

    noms := Map()
    if chk.Value {
        Etape("Résolution DNS de " ips.Count " adresses distantes...", 8)
        noms := ResoudreDNS(ips)
    }

    owners := Map()
    if chkRdap.Value {
        Etape("Propriétaire de " ips.Count " adresses (RDAP)...", 14)
        owners := ResoudreProprietaires(ips)
    }

    cache := Map()
    total := pids.Count
    idx := 0
    for pid in pids {
        idx++
        Etape("Analyse du processus " idx "/" total " (PID " pid ")...", 30 + Round(65 * idx / total))
        cache[pid] := Inspecter(pid)
    }

    Etape("Construction du tableau...", 97)
    for cn in conns {
        i := cache[cn.pid]
        ip := IpDe(cn.dist)
        fqdn := noms.Get(ip, "")
        port := RegExReplace(cn.dist, ".*:")

        verdict := i.verdict
        if (RegExMatch(cn.adr, ":3389$") && InStr(verdict, "SUSPECT") != 1 && InStr(verdict, "USURPATION") != 1)
            verdict := "ACCÈS À DISTANCE (RDP entrant) : vérifier qui se connecte"

        d := {lieu: i.lieu, fp: i.fp, dest: DestKey(fqdn, ip), verdict: verdict, hote: i.hote, outil: i.outil
            , nom: i.nom, gnom: i.gnom, cmd: i.cmd, owner: owners.Get(ip, "")}
        t := StatutConfiance(d)
        n := lv.Add(, i.img, cn.pid, cn.adr, cn.dist, fqdn, owners.Get(ip, ""), port, i.chemin, i.statut, i.editeur, verdict, i.parent, t)
        id := SendMessage(0x10B4, n - 1, 0, lv)     ; LVM_MAPINDEXTOID
        rowData[id] := d
        c := CouleurLigne(verdict, t)
        if IsObject(c)
            rowColors[id] := c
    }
    Loop 13
        lv.ModifyCol(A_Index, "AutoHdr")
    WinRedraw(lv.Hwnd)
    return conns.Length " connexions ESTABLISHED analysées en " Round((A_TickCount - t0) / 1000) " s. Sélectionnez une ligne pour voir sa commande. Vert : officiel/approuvé | Jaune : tiers | Ambre : hôte | Orange : non signé/nouvelle destination | Violet : accès à distance | Rouge : suspect | Gris : inconnu"
}

DonneesLigne(ctrl, row) {
    global rowData
    if !row
        return ""
    id := SendMessage(0x10B4, row - 1, 0, ctrl)
    return rowData.Has(id) ? rowData[id] : ""
}

AfficherCommande(ctrl, item, selected) {
    global status, busy
    if (busy || !selected)
        return
    d := DonneesLigne(ctrl, item)
    if IsObject(d)
        status.Value := "Commande : " d.cmd
}

Inspecter(pid) {
    global psFile, sysNames, hotes
    ; tasklist /FI "PID eq <pid>" : retrouve l'image (nom du .exe)
    t := RunCmd('tasklist /FI "PID eq ' pid '" /FO CSV /NH')
    nom := RegExMatch(t, '^"([^"]+)"', &mm) ? mm[1] : "(introuvable)"

    ; Chemin, signature, ligne de commande, parent, empreinte, fichier d'origine, moteur embarqué
    r := RunCmd('powershell -NoProfile -ExecutionPolicy Bypass -File "' psFile '" ' pid)
    p := StrSplit(Trim(r, " `r`n"), Chr(31))
    chemin := p.Length >= 1 ? p[1] : ""
    statut := p.Length >= 2 ? p[2] : ""
    editeur := p.Length >= 3 ? p[3] : ""
    cmd := p.Length >= 4 ? p[4] : ""
    parent := p.Length >= 5 ? p[5] : ""
    taille := p.Length >= 6 ? p[6] : ""
    mtime := p.Length >= 7 ? p[7] : ""
    original := p.Length >= 8 ? p[8] : ""
    moteur := p.Length >= 9 ? p[9] : ""

    ; Verdict de base
    if (pid = "4" || nom = "System")
        verdict := "OFFICIEL (noyau Windows)"
    else if (chemin = "")
        verdict := "INCONNU (accès refusé ou processus terminé)"
    else {
        sys32 := InStr(chemin, A_WinDir "\System32\") = 1 || InStr(chemin, A_WinDir "\SysWOW64\") = 1
        if (sysNames.Has(StrLower(nom)) && !sys32)
            verdict := "USURPATION POSSIBLE (nom système, mauvais dossier)"
        else if (statut = "Valid" && InStr(editeur, "Microsoft"))
            verdict := "OFFICIEL Microsoft"
        else if (statut = "Valid")
            verdict := "Signé par un tiers : vérifier l'éditeur"
        else if (InStr(chemin, A_WinDir "\") = 1)
            verdict := "SUSPECT (fichier Windows non signé)"
        else
            verdict := "NON SIGNÉ : à vérifier"
    }

    ; Hôte : le fichier peut être légitime, c'est ce qu'il exécute qui compte
    nomL := StrLower(nom)
    hote := hotes.Has(nomL) || (original != "" && hotes.Has(StrLower(original))) || (moteur != "")
    if (hote && chemin != "" && InStr(verdict, "USURPATION") != 1) {
        susp := CommandeSuspecte(cmd, chemin, nomL, original, parent)
        etiquette := (moteur != "") ? moteur : nom
        if (susp != "")
            verdict := "SUSPECT (hôte " etiquette " : " susp ")"
        else if (InStr(verdict, "OFFICIEL") = 1 || InStr(verdict, "Sign") = 1)
            verdict := "HÔTE signé (" etiquette ") : vérifier ce qu'il exécute"
    }

    ; Outils d'accès à distance : légitimes mais dangereux si vous n'avez pas lancé la session
    outil := RegExMatch(nom, "i)^(anydesk|teamviewer|tv_w32|tv_x64|screenconnect|connectwise|rustdesk|ultraviewer|supremo|winvnc|tvnserver|vncserver|radmin|splashtop|quickassist|aa_v3|logmein|meshagent|ngrok|frpc|chisel)") ? true : false
    if (outil && InStr(verdict, "USURPATION") != 1 && InStr(verdict, "SUSPECT") != 1)
        verdict := (statut = "Valid") ? "ACCÈS À DISTANCE (outil signé) : confirmer la session" : "SUSPECT (outil à distance non signé)"

    ; Identité approuvable : le fichier, et pour un hôte (ou svchost) aussi sa commande et ses fichiers chargés
    payload := hote ? PayloadFp(cmd, chemin) : ""
    ctxCmd := hote || (nomL = "svchost.exe")      ; svchost : chaque groupe de services s'approuve séparément
    cmdN := ctxCmd ? RegExReplace(Trim(cmd), "\s+", " ") : ""
    lieu := (chemin = "") ? "" : (ctxCmd ? chemin "|" cmdN : chemin)
    fp := taille "#" mtime "#" payload

    ; Image affichée : pour un hôte, le programme réellement exécuté (.jar, script, .exe...)
    cible := ""
    img := nom
    gnom := nom
    if hote {
        cible := PremierePayload(cmd, chemin)
        if (cible != "") {
            SplitPath(cible, &pf)
            img := pf " (via " nom ")"
            gnom := pf
        } else if RegExMatch(cmd, 'i)-jar\s+"?([^"\s]+)', &mj) {
            img := mj[1] " (via " nom ")"
            gnom := mj[1]
        }
    }
    cheminAff := (cible != "") ? cible : chemin
    editeurAff := (cible != "" && editeur != "") ? editeur " (hôte " nom ")" : editeur
    return {nom: nom, img: img, gnom: gnom, chemin: cheminAff, statut: statut, editeur: editeurAff, verdict: verdict
        , cmd: cmd, parent: parent, hote: hote, outil: outil, lieu: lieu, fp: fp}
}

Ajout(&r, txt) {
    r .= (r = "" ? "" : ", ") . txt
}

CommandeSuspecte(cmd, chemin, nomL, original, parent) {
    global hotes
    c := StrReplace(cmd, chemin, "")          ; on ignore le chemin de l'hôte lui-même
    r := ""
    if (original != "" && StrLower(original) != nomL && hotes.Has(StrLower(original)))
        Ajout(&r, "renommé, fichier d'origine " original)
    if (RegExMatch(c, "i)\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}") || InStr(c, "FromBase64String"))
        Ajout(&r, "commande encodée")
    if RegExMatch(c, "i)-w(?:in(?:dowstyle)?)?\s+hidden")
        Ajout(&r, "fenêtre cachée")
    if RegExMatch(c, "i)downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-expression|\biex\b|bitstransfer|urlcache")
        Ajout(&r, "téléchargement ou exécution à distance")
    if (RegExMatch(nomL, "^(mshta|regsvr32|rundll32|wscript|cscript|msbuild|wmic|certutil|bitsadmin)\.exe$") && RegExMatch(c, "i)https?://"))
        Ajout(&r, "URL dans la commande")
    if RegExMatch(c, "i)\\(?:AppData|Temp|Downloads|ProgramData)\\|\\Users\\Public\\")
        Ajout(&r, "chargé depuis un dossier utilisateur ou temporaire")
    if RegExMatch(parent, "i)^(winword|excel|powerpnt|outlook|acrord32|acrobat)\.exe$")
        Ajout(&r, "lancé par " parent)
    return r
}

; Empreinte (taille, date) des fichiers chargés par la commande : script, jar, dll...
PayloadFp(cmd, chemin) {
    pos := 1
    fp := ""
    while RegExMatch(cmd, 'i)([A-Z]:\\[^"|<>*?]+?\.(?:jar|py|pyw|js|mjs|ps1|vbs|vbe|jse|wsf|hta|dll|bat|cmd|exe|ahk|rb|pl|php))(?=["\s,]|$)', &m, pos) {
        pos := m.Pos + m.Len
        f := m[1]
        if (f = chemin || !FileExist(f))
            continue
        fp .= f "#" FileGetSize(f) "#" FileGetTime(f, "M") ";"
    }
    return fp
}

; Fichier principal exécuté par un hôte : cible de -jar, sinon premier script, jar, dll ou exe de la commande
PremierePayload(cmd, chemin) {
    if (RegExMatch(cmd, 'i)-jar\s+"?([A-Z]:\\[^"|<>*?]+?\.jar)', &mj) && FileExist(mj[1]))
        return mj[1]
    pos := 1
    while RegExMatch(cmd, 'i)([A-Z]:\\[^"|<>*?]+?\.(?:jar|py|pyw|js|mjs|ps1|vbs|vbe|jse|wsf|hta|dll|bat|cmd|exe|ahk|rb|pl|php))(?=["\s,]|$)', &m, pos) {
        pos := m.Pos + m.Len
        if (m[1] != chemin && FileExist(m[1]))
            return m[1]
    }
    return ""
}

; ---------------------------------------------------------------- Confiance

; Destination approuvable : domaine (2 ou 3 derniers libellés), nom exact pour les clouds partagés, sinon l'adresse IP
DestKey(fqdn, ip) {
    global PARTAGES
    if (fqdn = "" || fqdn = "localhost")
        return ip
    f := StrLower(RTrim(fqdn, "."))
    for sfx in PARTAGES
        if (f = sfx || SubStr(f, -StrLen(sfx) - 1) = "." sfx)
            return f
    parts := StrSplit(f, ".")
    n := parts.Length
    if (n <= 2)
        return f
    k := (StrLen(parts[n]) = 2 && RegExMatch(parts[n - 1], "^(co|com|org|net|gov|ac|edu)$")) ? 3 : 2
    res := parts[n - k + 1]
    Loop k - 1
        res .= "." parts[n - k + 1 + A_Index]
    return res
}

LoadTrust() {
    global trust, lieuKnown, trustFile
    trust.Clear()
    lieuKnown.Clear()
    if !FileExist(trustFile)
        return
    for ligne in StrSplit(FileRead(trustFile, "UTF-8"), "`n", "`r") {
        p := StrSplit(ligne, "`t")
        if (p.Length < 3)
            continue
        k := p[1] "`t" p[2]
        if !trust.Has(k)
            trust[k] := Map()
        trust[k][p[3]] := 1
        lieuKnown[p[1]] := 1
    }
}

StatutConfiance(d) {
    global trust, lieuKnown
    if (d.lieu = "")
        return "Non évaluable"
    k := d.lieu "`t" d.fp
    if trust.Has(k) {
        dest := trust[k]
        return (dest.Has("*") || dest.Has(d.dest)) ? "Approuvé" : "NOUVELLE destination"
    }
    return lieuKnown.Has(d.lieu) ? "MODIFIÉ depuis l'approbation" : "NOUVEAU"
}

RefreshTrust() {
    global lv, rowData, rowColors
    Loop lv.GetCount() {
        id := SendMessage(0x10B4, A_Index - 1, 0, lv)
        if !rowData.Has(id)
            continue
        d := rowData[id]
        t := StatutConfiance(d)
        lv.Modify(A_Index, "Col" COL_TRUST, t)
        c := CouleurLigne(d.verdict, t)
        if IsObject(c)
            rowColors[id] := c
    }
    WinRedraw(lv.Hwnd)
}

ApprouverLigne(ctrl, row, toutes) {
    global rowData, trustFile
    if !row {
        MsgBox("Sélectionnez d'abord une ligne.")
        return
    }
    id := SendMessage(0x10B4, row - 1, 0, ctrl)
    if !rowData.Has(id)
        return
    d := rowData[id]
    if (d.lieu = "") {
        MsgBox("Programme illisible (chemin inconnu) : impossible de l'approuver.", "Approbation", "Icon!")
        return
    }
    if (InStr(d.verdict, "SUSPECT") = 1 || InStr(d.verdict, "USURPATION") = 1) {
        MsgBox("Ce programme est jugé suspect. Vérifiez-le d'abord (VirusTotal, Google) avant toute approbation.", "Approbation refusée", "Icon!")
        return
    }
    if (toutes && d.outil) {
        MsgBox("Un outil d'accès à distance ne s'approuve que destination par destination.", "Approbation refusée", "Icon!")
        return
    }
    dest := toutes ? "*" : d.dest
    detail := "Programme : " d.nom "`nFichier : " StrSplit(d.lieu, "|")[1]
    if d.hote
        detail .= "`nCommande : " SubStr(d.cmd, 1, 300) "`n(L'hôte seul n'est pas approuvé : uniquement cette commande exacte et ses fichiers.)"
    detail .= "`nDestination : " (toutes ? "toutes les destinations" : d.dest)
    if (d.owner != "")
        detail .= "`nPropriétaire de l'adresse : " d.owner
    rep := MsgBox(detail "`n`nApprouver ?", "Liste de confiance", "YesNo Iconi")
    if (rep != "Yes")
        return
    ib := InputBox("Note facultative (ex : vérifié sur VirusTotal, propriétaire Microsoft).`nLaissez vide si inutile.", "Liste de confiance")
    if (ib.Result != "OK")
        return
    note := RegExReplace(ib.Value, "[\t\r\n]+", " ")
    DirCreate(A_AppData "\ConnexionsActives")
    FileAppend(d.lieu "`t" d.fp "`t" dest "`t" FormatTime(, "yyyy-MM-dd") "`t" note "`n", trustFile, "UTF-8")
    LoadTrust()
    RefreshTrust()
}

OuvrirListeConfiance() {
    global trustFile
    if FileExist(trustFile)
        Run('notepad.exe "' trustFile '"')
    else
        MsgBox("Aucune approbation enregistrée pour le moment.")
}

; ---------------------------------------------------------------- Couleurs

BGR(rouge, vert, bleu) => rouge | (vert << 8) | (bleu << 16)

CouleurVerdict(v) {
    if (InStr(v, "USURPATION") = 1 || InStr(v, "SUSPECT") = 1)
        return [BGR(156, 0, 6), BGR(255, 199, 206)]      ; rouge
    if (InStr(v, "ACCÈS") = 1)
        return [BGR(80, 20, 120), BGR(225, 205, 245)]    ; violet
    if (InStr(v, "HÔTE") = 1)
        return [BGR(0, 0, 0), BGR(255, 217, 102)]        ; ambre
    if (InStr(v, "NON SIGN") = 1)
        return [BGR(0, 0, 0), BGR(255, 204, 153)]        ; orange
    if (InStr(v, "Sign") = 1)
        return [BGR(0, 0, 0), BGR(255, 235, 156)]        ; jaune
    if (InStr(v, "OFFICIEL") = 1)
        return [BGR(0, 60, 0), BGR(198, 239, 206)]       ; vert
    if (InStr(v, "INCONNU") = 1)
        return [BGR(0, 0, 0), BGR(217, 217, 217)]        ; gris
    return ""
}

; Couleur d'une ligne : le verdict, ajusté par la liste de confiance (sauf pour un verdict rouge)
CouleurLigne(v, t) {
    c := CouleurVerdict(v)
    if (InStr(v, "USURPATION") = 1 || InStr(v, "SUSPECT") = 1)
        return c
    if (InStr(t, "MODIFI") = 1)
        return [BGR(156, 0, 6), BGR(255, 199, 206)]      ; rouge : fichier ou commande changé
    if (InStr(t, "Approuv") = 1)
        return [BGR(0, 60, 0), BGR(198, 239, 206)]       ; vert : approuvé par vous
    if (InStr(t, "NOUVELLE") = 1)
        return [BGR(0, 0, 0), BGR(255, 204, 153)]        ; orange : destination jamais approuvée
    return c
}

; Gestionnaire NM_CUSTOMDRAW (même principe que la classe LV_Colors d'AHK v2)
CustomDraw(ctrl, lParam) {
    static P := A_PtrSize
    static offItem := 3 * P + 16 + 2 * P     ; dwItemSpec (NMCUSTOMDRAW)
    static offTxt := 3 * P + 16 + 5 * P      ; clrText (NMLVCUSTOMDRAW), clrTextBk juste après
    Critical -1
    if (NumGet(lParam, "UPtr") != ctrl.Hwnd)
        return
    stage := NumGet(lParam, 3 * P, "UInt")
    if (stage = 0x1)                         ; CDDS_PREPAINT
        return 0x20                          ; CDRF_NOTIFYITEMDRAW
    if (stage = 0x10001) {                   ; CDDS_ITEMPREPAINT
        id := SendMessage(0x10B4, NumGet(lParam, offItem, "UPtr"), 0, ctrl)    ; LVM_MAPINDEXTOID
        if rowColors.Has(id) {
            c := rowColors[id]
            NumPut("UInt", c[1], lParam, offTxt)         ; couleur du texte
            NumPut("UInt", c[2], lParam, offTxt + 4)     ; couleur du fond
        }
    }
    return 0
}

; ---------------------------------------------------------------- DNS inverse

IpDe(dist) {
    if RegExMatch(dist, "^\[?(.*?)\]?:\d+$", &m)
        return RegExReplace(m[1], "%.*$")      ; retire l'identifiant de zone IPv6
    return ""
}

EstPrive(ip) {
    if InStr(ip, ":")
        return RegExMatch(ip, "i)^(fe80|fc|fd)") ? true : false
    return RegExMatch(ip, "^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0)") ? true : false
}

; Adresses locales : getnameinfo (noms du réseau local). Adresses publiques : un seul appel PowerShell.
ResoudreDNS(ips) {
    global dnsFile
    res := Map()
    publics := ""
    for ip in ips {
        if (ip = "127.0.0.1" || ip = "::1")
            res[ip] := "localhost"
        else if EstPrive(ip)
            res[ip] := ReverseDNS(ip)
        else
            publics .= ip "`n"
    }
    if (publics != "") {
        lst := A_Temp "\ahk_ips.txt"
        try FileDelete(lst)
        FileAppend(publics, lst, "UTF-8-RAW")
        out := RunCmd('powershell -NoProfile -ExecutionPolicy Bypass -File "' dnsFile '" "' lst '"')
        try FileDelete(lst)
        for l in StrSplit(out, "`n", "`r") {
            p := StrSplit(l, "|")
            if (p.Length >= 2 && Trim(p[2]) != "")
                res[Trim(p[1])] := RTrim(Trim(p[2]), ".")
        }
    }
    return res
}

ReverseDNS(ip) {
    static init := DllCall("ws2_32\WSAStartup", "UShort", 0x0202, "Ptr", Buffer(512), "Int")
    if InStr(ip, ":")
        sa := Buffer(28, 0), fam := 23, off := 8, len := 28    ; sockaddr_in6
    else
        sa := Buffer(16, 0), fam := 2, off := 4, len := 16     ; sockaddr_in
    NumPut("UShort", fam, sa, 0)
    if (DllCall("ws2_32\InetPtonW", "Int", fam, "WStr", ip, "Ptr", sa.Ptr + off, "Int") != 1)
        return ""
    host := Buffer(2050, 0)
    ; flag 4 = NI_NAMEREQD : échoue s'il n'y a pas de nom (au lieu de renvoyer l'IP)
    if (DllCall("ws2_32\getnameinfo", "Ptr", sa, "Int", len, "Ptr", host, "UInt", 1025
        , "Ptr", 0, "UInt", 0, "Int", 4, "Int") = 0)
        return StrGet(host, "CP0")
    return ""
}

; ---------------------------------------------------------------- Propriétaire (RDAP)

; Adresses publiques uniquement : un seul appel PowerShell pour toutes les adresses non encore connues
ResoudreProprietaires(ips) {
    global rdapFile, ownerCache
    res := Map()
    aInterroger := ""
    for ip in ips {
        if (ip = "127.0.0.1" || ip = "::1" || EstPrive(ip))
            continue
        if ownerCache.Has(ip)
            res[ip] := ownerCache[ip]
        else
            aInterroger .= ip "`n"
    }
    if (aInterroger != "") {
        lst := A_Temp "\ahk_rdap_ips.txt"
        try FileDelete(lst)
        FileAppend(aInterroger, lst, "UTF-8-RAW")
        out := RunCmd('powershell -NoProfile -ExecutionPolicy Bypass -File "' rdapFile '" "' lst '"')
        try FileDelete(lst)
        for l in StrSplit(out, "`n", "`r") {
            p := StrSplit(l, "|", , 2)
            if (p.Length >= 2) {
                ip := Trim(p[1])
                ownerCache[ip] := Trim(p[2])
                if (Trim(p[2]) != "")
                    res[ip] := Trim(p[2])
            }
        }
    }
    return res
}

; Avertit avant d'envoyer des adresses IP à un service tiers
ConfirmerRdap(ctrl, *) {
    if !ctrl.Value
        return
    rep := MsgBox("Les adresses IP publiques de vos connexions seront envoyées à rdap.org, puis au registre régional concerné "
        . "(ARIN, RIPE, AFRINIC, APNIC, LACNIC) pour connaître leur propriétaire.`n`nContinuer ?"
        , "Propriétaire des adresses (RDAP)", "YesNo Iconi")
    if (rep != "Yes")
        ctrl.Value := 0
}

; ---------------------------------------------------------------- VirusTotal

HashFichier(chemin) {
    q := "'"
    ps := StrReplace(chemin, "'", "''")
    out := RunCmd('powershell -NoProfile -Command "(Get-FileHash -LiteralPath ' q ps q ' -Algorithm SHA256).Hash"')
    h := Trim(out, " `r`n")
    return RegExMatch(h, "^[0-9A-Fa-f]{64}$") ? h : ""
}

VirusTotalHash(ctrl, row) {
    if !row {
        MsgBox("Sélectionnez d'abord une ligne.")
        return
    }
    chemin := ctrl.GetText(row, COL_CHEMIN)
    if (chemin = "") {
        MsgBox("Chemin inconnu : impossible de calculer le hash.")
        return
    }
    h := HashFichier(chemin)
    if (h = "") {
        MsgBox("Impossible de calculer le hash (fichier inaccessible).")
        return
    }
    Run("https://www.virustotal.com/gui/file/" h)
    if (InStr(ctrl.GetText(row, COL_VERDICT), "OFFICIEL") != 1) {
        rep := MsgBox("Si VirusTotal affiche « file not found », ce fichier ne lui est pas connu.`n`n"
            . "Voulez-vous créer un ZIP de l'application pour l'envoyer à l'analyse ?"
            , "VirusTotal", "YesNo Iconi")
        if (rep = "Yes")
            ZipApplication(ctrl, row)
    }
}

VirusTotalIP(ctrl, row) {
    if !row {
        MsgBox("Sélectionnez d'abord une ligne.")
        return
    }
    ip := IpDe(ctrl.GetText(row, 4))    ; colonne "Distant"
    if (ip = "") {
        MsgBox("Adresse distante introuvable.")
        return
    }
    if (ip = "127.0.0.1" || ip = "::1" || EstPrive(ip)) {
        MsgBox("L'adresse " ip " est locale : elle n'existe pas sur Internet, VirusTotal ne peut rien en dire.")
        return
    }
    Run("https://www.virustotal.com/gui/ip-address/" ip)
}

EstDossierPartage(d) {
    d := RTrim(d, "\")
    if (StrLen(d) <= 2 || InStr(d "\", A_WinDir "\") = 1)
        return true
    for p in [A_ProgramFiles, EnvGet("ProgramFiles(x86)"), EnvGet("USERPROFILE"), A_AppData, EnvGet("LOCALAPPDATA"), A_Temp, A_Desktop, A_MyDocuments, EnvGet("USERPROFILE") "\Downloads"]
        if (p != "" && d = RTrim(p, "\"))
            return true
    return false
}

TailleDossier(dossier) {
    total := 0
    Loop Files, dossier "\*", "FR" {
        total += A_LoopFileSize
        if (total > TAILLE_MAX_ZIP)
            break
    }
    return total
}

ZipApplication(ctrl, row) {
    if !row {
        MsgBox("Sélectionnez d'abord une ligne.")
        return
    }
    chemin := ctrl.GetText(row, COL_CHEMIN)
    if (chemin = "" || !FileExist(chemin)) {
        MsgBox("Chemin introuvable : impossible de créer le ZIP.")
        return
    }
    SplitPath(chemin, &fichier, &dossier)

    ; Dossier partagé ou système (Windows, Program Files, profil...) : seul l'exécutable est compressé
    seul := EstDossierPartage(dossier)
    if !seul && (TailleDossier(dossier) > TAILLE_MAX_ZIP) {
        rep := MsgBox("Le dossier dépasse 650 Mo, la limite de VirusTotal.`n`nCompresser seulement l'exécutable ?"
            , "ZIP", "YesNo Icon!")
        if (rep != "Yes")
            return
        seul := true
    }

    cible := seul ? "uniquement le fichier :`n" chemin : "tout le dossier :`n" dossier
    rep := MsgBox("Un ZIP de " cible "`nsera créé sur le Bureau.`n`n"
        . "ATTENTION : les fichiers envoyés à VirusTotal sont accessibles à la communauté de sécurité. "
        . "N'envoyez pas un dossier contenant des données personnelles (configuration, mots de passe, journaux).`n`nContinuer ?"
        , "ZIP pour VirusTotal", "YesNo Icon!")
    if (rep != "Yes")
        return

    zip := A_Desktop "\" RegExReplace(fichier, "\.[^.]+$") "_" A_Now ".zip"
    if seul
        cmd := 'tar -a -c -f "' zip '" -C "' dossier '" "' fichier '"'
    else
        cmd := 'tar -a -c -f "' zip '" -C "' dossier '" .'
    out := Trim(RunCmd(cmd), " `r`n")

    if !FileExist(zip) {
        MsgBox("Échec de la compression :`n" out, "ZIP", "Icon!")
        return
    }
    note := (out != "") ? "`n`nAvertissements (fichiers verrouillés ignorés) :`n" SubStr(out, 1, 400) : ""
    MsgBox("ZIP créé sur le Bureau :`n" zip "`n`nLa page d'envoi de VirusTotal va s'ouvrir : glissez le ZIP dedans." note
        , "ZIP pour VirusTotal", "Iconi")
    Run('explorer.exe /select,"' zip '"')
    Run("https://www.virustotal.com/gui/home/upload")
}

; ---------------------------------------------------------------- Arrêt forcé

; Arrête un processus et ses enfants (taskkill /F /T), puis PowerShell en secours.
; Les processus protégés par Windows ou par un antivirus ne sont volontairement pas contournés.
ArreterProcessus(ctrl, row) {
    global rowColors
    if !row {
        MsgBox("Sélectionnez d'abord une ligne.")
        return
    }
    pid := Integer(ctrl.GetText(row, 2))
    d := DonneesLigne(ctrl, row)
    nom := IsObject(d) ? d.nom : ctrl.GetText(row, 1)
    nomL := StrLower(nom)

    if (pid = ProcessExist()) {
        MsgBox("Ce processus est ConnexionsActives lui-même.", "Arrêt refusé", "Icon!")
        return
    }
    vitaux := Map("system", 1, "registry", 1, "smss.exe", 1, "csrss.exe", 1, "wininit.exe", 1
        , "winlogon.exe", 1, "services.exe", 1, "lsass.exe", 1)
    if (pid <= 4 || vitaux.Has(nomL)) {
        MsgBox("« " nom " » est un processus vital de Windows : l'arrêter provoque un écran bleu ou un redémarrage immédiat. "
            . "L'outil refuse.", "Arrêt refusé", "Icon!")
        return
    }

    detail := "Processus : " nom " (PID " pid ")`nFichier : " ctrl.GetText(row, COL_CHEMIN) "`nVerdict : " ctrl.GetText(row, COL_VERDICT)
    if (IsObject(d) && d.cmd != "")
        detail .= "`nCommande : " SubStr(d.cmd, 1, 200)
    if (nomL = "svchost.exe")
        detail .= "`n`nsvchost héberge des services Windows : en arrêter un au hasard peut faire redémarrer le PC. "
            . "Préférez arrêter le service concerné (services.msc)."
    detail .= "`n`nLe processus et ses processus enfants seront terminés immédiatement, sans enregistrer les données non sauvegardées."
    rep := MsgBox(detail "`n`nArrêter de force ?", "Arrêt forcé", "YesNo Icon! Default2")
    if (rep != "Yes")
        return

    out := Trim(RunCmd("taskkill /PID " pid " /F /T"), " `r`n")
    Sleep(600)
    if ProcessExist(pid) {
        out .= "`n" Trim(RunCmd('powershell -NoProfile -Command "Stop-Process -Id ' pid ' -Force"'), " `r`n")
        Sleep(600)
    }

    if ProcessExist(pid) {
        MsgBox("Windows refuse d'arrêter ce processus.`n`n"
            . "Causes fréquentes :`n"
            . "- processus protégé (antivirus, EDR, composant système) : Windows l'interdit même aux administrateurs, c'est voulu`n"
            . "- le processus est déjà en cours d'arrêt`n`n"
            . "Pistes : arrêter son service (services.msc ou sc stop), désactiver son démarrage (Gestionnaire des tâches, onglet Démarrage, "
            . "ou Autoruns), ou démarrer en mode sans échec puis supprimer le programme.`n`n"
            . "Réponse de Windows :`n" SubStr(out, 1, 400), "Arrêt impossible", "Icon!")
        return
    }

    ; Marque les lignes de ce processus comme arrêtées
    Loop ctrl.GetCount() {
        if (ctrl.GetText(A_Index, 2) != pid)
            continue
        id := SendMessage(0x10B4, A_Index - 1, 0, ctrl)
        ctrl.Modify(A_Index, "Col" COL_TRUST, "Arrêté")
        rowColors[id] := [BGR(90, 90, 90), BGR(217, 217, 217)]
    }
    WinRedraw(ctrl.Hwnd)
    MsgBox(nom " (PID " pid ") a été arrêté.`n`nS'il réapparaît, un service, une tâche planifiée ou son processus parent le relance : "
        . "relancez l'analyse et regardez la colonne Parent.", "Arrêt forcé", "Iconi")
}

; ---------------------------------------------------------------- Divers

OuvrirDossier(ctrl, row) {
    if !row
        return
    chemin := ctrl.GetText(row, COL_CHEMIN)
    if (chemin != "")
        Run('explorer.exe /select,"' chemin '"')
}

RechercherGoogle(ctrl, row) {
    if !row {
        MsgBox("Sélectionnez d'abord une ligne.")
        return
    }
    d := DonneesLigne(ctrl, row)
    nom := IsObject(d) ? d.gnom : ctrl.GetText(row, 1)
    if (nom = "" || nom = "(introuvable)")
        return
    Run("https://www.google.com/search?q=" UriEncode('"' nom '" processus légitime ou malware'))
}

UriEncode(s) {
    buf := Buffer(StrPut(s, "UTF-8"))
    StrPut(s, buf, "UTF-8")
    res := ""
    Loop buf.Size - 1 {
        c := NumGet(buf, A_Index - 1, "UChar")
        res .= ((c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c = 45 || c = 46 || c = 95)
            ? Chr(c) : Format("%{:02X}", c)
    }
    return res
}

RunCmd(cmd) {
    tmp := A_Temp "\ahk_out_" A_TickCount ".txt"
    RunWait(A_ComSpec ' /c ' cmd ' > "' tmp '" 2>&1', , "Hide")
    try txt := FileRead(tmp, "CP" DllCall("GetOEMCP"))
    catch
        txt := ""
    try FileDelete(tmp)
    return txt
}
