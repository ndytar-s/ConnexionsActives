#Requires AutoHotkey v2.0.1
#SingleInstance Force

; Les droits admin permettent de lire le chemin de tous les processus
if !A_IsAdmin {
    try Run('*RunAs "' A_ScriptFullPath '"')
    ExitApp
}

COL_CHEMIN := 7                      ; numéro de la colonne "Chemin"
COL_VERDICT := 10                    ; numéro de la colonne "Verdict"
TAILLE_MAX_ZIP := 650 * 1024 * 1024  ; limite de taille de fichier de VirusTotal

; Script PowerShell temporaire : chemin + statut de signature + éditeur
psFile := A_Temp "\ahk_sig.ps1"
try FileDelete(psFile)
FileAppend("
(
param($id)
$p = (Get-Process -Id $id -ErrorAction SilentlyContinue).Path
if (-not $p) { '||'; exit }
$s = Get-AuthenticodeSignature -FilePath $p
$cn = ''
if ($s.SignerCertificate) { $cn = $s.SignerCertificate.GetNameInfo('SimpleName', $false) }
"$p|$($s.Status)|$cn"
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

sysNames := Map("svchost.exe", 1, "lsass.exe", 1, "csrss.exe", 1, "services.exe", 1
    , "winlogon.exe", 1, "smss.exe", 1, "wininit.exe", 1, "spoolsv.exe", 1, "taskhostw.exe", 1)

g := Gui("+Resize", "Connexions ETABLIES et légitimité des processus (v1.2)")
btn := g.Add("Button", "w100", "Analyser")
btnWeb := g.Add("Button", "x+8 w110", "Google")
btnVT := g.Add("Button", "x+8 w150", "VirusTotal (fichier)")
btnIP := g.Add("Button", "x+8 w170", "VirusTotal (adresse IP)")
btnZip := g.Add("Button", "x+8 w170", "ZIP pour VirusTotal")
chk := g.Add("CheckBox", "x+15 yp+5 Checked", "Résolution DNS")
status := g.Add("Text", "xm w1150"
    , "Prêt. Vert : officiel | Jaune : signé par un tiers | Orange : non signé | Rouge : suspect | Gris : inconnu")
lv := g.Add("ListView", "xm w1150 r24 Grid"
    , ["Image", "PID", "Local", "Distant", "Hôte distant (DNS)", "Port distant", "Chemin", "Signature", "Éditeur", "Verdict"])

lv.Opt("+LV0x010000")                ; LVS_EX_DOUBLEBUFFER : évite les défauts d'affichage
btn.OnEvent("Click", Analyser)
btnWeb.OnEvent("Click", (*) => RechercherGoogle(lv, lv.GetNext(0)))
btnVT.OnEvent("Click", (*) => VirusTotalHash(lv, lv.GetNext(0)))
btnIP.OnEvent("Click", (*) => VirusTotalIP(lv, lv.GetNext(0)))
btnZip.OnEvent("Click", (*) => ZipApplication(lv, lv.GetNext(0)))

ctxMenu := Menu()
ctxMenu.Add("Vérifier sur Google", (*) => RechercherGoogle(lv, lv.GetNext(0)))
ctxMenu.Add("VirusTotal (fichier, par hash)", (*) => VirusTotalHash(lv, lv.GetNext(0)))
ctxMenu.Add("VirusTotal (adresse IP distante)", (*) => VirusTotalIP(lv, lv.GetNext(0)))
ctxMenu.Add("Créer un ZIP de l'application", (*) => ZipApplication(lv, lv.GetNext(0)))
ctxMenu.Add()
ctxMenu.Add("Ouvrir l'emplacement du fichier", (*) => OuvrirDossier(lv, lv.GetNext(0)))
ctxMenu.Add("Copier le chemin", (*) => (r := lv.GetNext(0)) ? A_Clipboard := lv.GetText(r, COL_CHEMIN) : 0)

lv.OnEvent("DoubleClick", OuvrirDossier)
lv.OnEvent("ContextMenu", (ctrl, item, isRC, x, y) => item ? ctxMenu.Show(x, y) : 0)
lv.OnNotify(-12, CustomDraw)         ; NM_CUSTOMDRAW : couleur des lignes
g.OnEvent("Size", (gui, mm, w, h) => mm != -1 ? lv.Move(, , w - 20, h - 90) : 0)
g.Show()
return

; ---------------------------------------------------------------- Analyse

Analyser(*) {
    global lv, status, chk, rowColors
    lv.Delete()
    rowColors.Clear()
    status.Value := "netstat en cours..."
    out := RunCmd("netstat -noa")
    conns := []
    ips := Map()
    for ligne in StrSplit(out, "`n", "`r") {
        ; Fonctionne en anglais (ESTABLISHED) et en français (ÉTABLI)
        if !RegExMatch(ligne, "i)^\s*TCP\s+(\S+)\s+(\S+)\s+(ESTABLISHED|\S*TABLI)\s+(\d+)\s*$", &m)
            continue
        conns.Push({adr: m[1], dist: m[2], pid: m[4]})
        ip := IpDe(m[2])
        if (ip != "")
            ips[ip] := 1
    }

    noms := Map()
    if chk.Value {
        status.Value := "Résolution DNS de " ips.Count " adresses distantes..."
        noms := ResoudreDNS(ips)
    }

    cache := Map()
    for cn in conns {
        if !cache.Has(cn.pid) {
            status.Value := "Analyse du PID " cn.pid "..."
            cache[cn.pid] := Inspecter(cn.pid)
        }
        i := cache[cn.pid]
        port := RegExReplace(cn.dist, ".*:")
        n := lv.Add(, i.nom, cn.pid, cn.adr, cn.dist, noms.Get(IpDe(cn.dist), ""), port, i.chemin, i.statut, i.editeur, i.verdict)
        c := CouleurVerdict(i.verdict)
        if IsObject(c)
            rowColors[SendMessage(0x10B4, n - 1, 0, lv)] := c    ; LVM_MAPINDEXTOID
    }
    Loop 10
        lv.ModifyCol(A_Index, "AutoHdr")
    WinRedraw(lv.Hwnd)
    status.Value := conns.Length " connexions ESTABLISHED analysées. Vert : officiel | Jaune : tiers signé | Orange : non signé | Rouge : suspect | Gris : inconnu"
}

Inspecter(pid) {
    global psFile, sysNames
    ; tasklist /FI "PID eq <pid>" : retrouve l'image (nom du .exe)
    t := RunCmd('tasklist /FI "PID eq ' pid '" /FO CSV /NH')
    nom := RegExMatch(t, '^"([^"]+)"', &mm) ? mm[1] : "(introuvable)"

    ; Chemin + signature numérique
    r := RunCmd('powershell -NoProfile -ExecutionPolicy Bypass -File "' psFile '" ' pid)
    p := StrSplit(Trim(r, " `r`n"), "|")
    chemin := p.Length >= 1 ? p[1] : ""
    statut := p.Length >= 2 ? p[2] : ""
    editeur := p.Length >= 3 ? p[3] : ""

    ; Verdict
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
    return {nom: nom, chemin: chemin, statut: statut, editeur: editeur, verdict: verdict}
}

; ---------------------------------------------------------------- Couleurs

BGR(rouge, vert, bleu) => rouge | (vert << 8) | (bleu << 16)

CouleurVerdict(v) {
    if (InStr(v, "USURPATION") = 1 || InStr(v, "SUSPECT") = 1)
        return [BGR(156, 0, 6), BGR(255, 199, 206)]      ; rouge
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
    for p in [A_ProgramFiles, EnvGet("ProgramFiles(x86)"), EnvGet("USERPROFILE"), A_AppData, EnvGet("LOCALAPPDATA"), A_Temp, A_Desktop]
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
    nom := ctrl.GetText(row, 1)
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
