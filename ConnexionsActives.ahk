#Requires AutoHotkey v2.0
#SingleInstance Force

; Les droits admin permettent de lire le chemin de tous les processus
if !A_IsAdmin {
    try Run('*RunAs "' A_ScriptFullPath '"')
    ExitApp
}

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

sysNames := Map("svchost.exe", 1, "lsass.exe", 1, "csrss.exe", 1, "services.exe", 1
    , "winlogon.exe", 1, "smss.exe", 1, "wininit.exe", 1, "spoolsv.exe", 1, "taskhostw.exe", 1)

g := Gui("+Resize", "Connexions ETABLIES et légitimité des processus")
btn := g.Add("Button", "w120", "Analyser")
btnWeb := g.Add("Button", "x+10 w200", "Vérifier sur Google")
status := g.Add("Text", "x+10 yp+5 w500", "Prêt. Double-clic : ouvre le dossier. Clic droit : plus d'options.")
btnWeb.OnEvent("Click", (*) => RechercherGoogle(lv, lv.GetNext(0)))

ctxMenu := Menu()
ctxMenu.Add("Vérifier sur Google", (*) => RechercherGoogle(lv, lv.GetNext(0)))
ctxMenu.Add("Ouvrir l'emplacement du fichier", (*) => OuvrirDossier(lv, lv.GetNext(0)))
ctxMenu.Add("Copier le chemin", (*) => (r := lv.GetNext(0)) ? A_Clipboard := lv.GetText(r, 6) : 0)
lv := g.Add("ListView", "xm w1100 r25 Grid"
    , ["Image", "PID", "Local", "Distant", "Port distant", "Chemin", "Signature", "Éditeur", "Verdict"])
btn.OnEvent("Click", Analyser)
lv.OnEvent("DoubleClick", OuvrirDossier)
lv.OnEvent("ContextMenu", (ctrl, item, isRC, x, y) => item ? ctxMenu.Show(x, y) : 0)
g.OnEvent("Size", (gui, mm, w, h) => mm != -1 ? lv.Move(, , w - 20, h - 50) : 0)
g.Show()
return

Analyser(*) {
    global lv, status, psFile, sysNames
    lv.Delete()
    status.Value := "netstat en cours..."
    out := RunCmd("netstat -noa")
    cache := Map()
    nb := 0
    for ligne in StrSplit(out, "`n", "`r") {
        ; Fonctionne en anglais (ESTABLISHED) et en français (ÉTABLI)
        if !RegExMatch(ligne, "i)^\s*TCP\s+(\S+)\s+(\S+)\s+(ESTABLISHED|\S*TABLI)\s+(\d+)\s*$", &m)
            continue
        adrLocale := m[1], dist := m[2], pid := m[4]
        port := RegExReplace(dist, ".*:")
        if !cache.Has(pid) {
            status.Value := "Analyse du PID " pid "..."
            cache[pid] := Inspecter(pid)
        }
        i := cache[pid]
        lv.Add(, i.nom, pid, adrLocale, dist, port, i.chemin, i.statut, i.editeur, i.verdict)
        nb++
    }
    Loop 9
        lv.ModifyCol(A_Index, "AutoHdr")
    status.Value := nb " connexions ESTABLISHED analysées."
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

OuvrirDossier(ctrl, row) {
    if !row
        return
    chemin := ctrl.GetText(row, 6)
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
