<#
.SYNOPSIS
    Console graphique du durcissement CIS : voir chaque contrôle, choisir
    ligne par ligne, générer un script sur mesure.

.DESCRIPTION
    1. Elle LIT le moteur Harden-Windows-CIS.ps1 : tables, liste noire,
       garde-fous, profil de machine. Rien n'est recopié ici — les définitions
       sont extraites du moteur par analyse syntaxique et exécutées telles
       quelles. Quand le moteur change, la console suit ; si un nom qu'elle
       emprunte disparaît, elle refuse de démarrer.
    2. Elle LIT LE POSTE : pour chaque contrôle, la valeur en place, la
       conformité au sens de la règle Wazuh, et le garde-fou qui l'écarte.
    3. Elle laisse CHOISIR, contrôle par contrôle : Appliquer, Retirer (retour
       à « non configuré »), ou rien ; et ajuster une valeur cible.
    4. Elle GÉNÈRE un script autonome, lié à ce poste, qui simule par défaut,
       sauvegarde tout avant d'écrire (point de restauration, .reg, audit,
       comptes, Rollback.cmd) et RELIT chaque réglage après.

    Ce qu'elle refuse, comme le moteur :
      - la LISTE NOIRE (protection LSA et VBS / Credential Guard sur un poste
        qui ouvre sa session par carte à puce) : affichée, jamais
        sélectionnable, et revérifiée par le script généré avant toute écriture ;
      - les GARDE-FOUS DURS (carte à puce, veille) : « Appliquer » n'est pas
        proposé — seul « Retirer » l'est, puisque c'est le sens qui répare ;
      - le TIER 3 : affiché avec sa raison, décision humaine hors console.
    Les garde-fous d'USAGE (imprimante, webcam, Bluetooth…) peuvent être passés
    outre, après une confirmation qui les énumère.

    La console n'écrit rien sur le poste : elle écrit des scripts. Seul le
    bouton « Appliquer en administrateur » en exécute un, après confirmation.

    Mode portable (clé USB, partage réseau) : un fichier PORTABLE à côté de la
    console, ou -Portable. Profils partagés dans donnees\profils\ (le
    profil-parc.json y est préchargé à l'ouverture), scripts et traces de
    chaque poste dans donnees\postes\<POSTE>\, et un journal-parc.csv.
    Sauvegarde et Rollback.cmd restent SUR LE POSTE : la clé repart, le retour
    arrière non.

.PARAMETER Engine
    Chemin de Harden-Windows-CIS.ps1. Par défaut : à côté de la console, sinon
    dans le dossier parent.

.PARAMETER Choix
    Profil de choix (.json) à charger au démarrage.

.PARAMETER SmartCardLogon
    Impose le profil carte à puce (même sens que dans le moteur).

.PARAMETER NoSmartCard
    Déclare que le poste n'ouvre pas de session par carte (même sens que dans
    le moteur).

.PARAMETER Portable
    Range profils, scripts et traces à côté de la console (sinon : présence
    d'un fichier PORTABLE).

.PARAMETER SelfTest
    Sans fenêtre : inventaire, présélection TIER 1+2, aller-retour d'un profil
    et script d'essai, écrits dans ce dossier.

.PARAMETER Snapshot
    Rend la fenêtre hors écran dans cette image PNG.

.EXAMPLE
    .\Console-CIS.cmd
    Ouvre la console en lecture seule (double-clic).

.EXAMPLE
    .\Console-CIS.ps1 -SelfTest .\essai
    Vérifie la console sans interface et écrit l'inventaire du poste.
#>
# #Requires vient APRÈS l'aide : placé avant, il la rend invisible à Get-Help.
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Engine,          # chemin de Harden-Windows-CIS.ps1
    [string]$Choix,           # profil de choix (.json) à charger au démarrage
    [switch]$SmartCardLogon,  # même sens que dans le moteur
    [switch]$NoSmartCard,     # même sens que dans le moteur
    [switch]$Portable,        # données à côté de la console (sinon : fichier PORTABLE)
    [string]$SelfTest,
    [string]$Snapshot
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$ConsoleVersion        = '1.3'
$NoWindow              = [bool]$SelfTest
$Dash                  = [string][char]0x2014

# WPF exige un thread STA : powershell.exe l'est par défaut, pas forcément pwsh.
if (-not $NoWindow -and [Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    $relaunch = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Engine)         { $relaunch += @('-Engine', "`"$Engine`"") }
    if ($Choix)          { $relaunch += @('-Choix', "`"$Choix`"") }
    if ($SmartCardLogon) { $relaunch += '-SmartCardLogon' }
    if ($NoSmartCard)    { $relaunch += '-NoSmartCard' }
    if ($Portable)       { $relaunch += '-Portable' }
    if ($Snapshot)       { $relaunch += @('-Snapshot', "`"$Snapshot`"") }
    Start-Process powershell.exe -ArgumentList $relaunch
    return
}

if (-not $NoWindow) { Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase }

if (-not ('CisConsole.Item' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
namespace CisConsole {
    public class Item : INotifyPropertyChanged {
        public event PropertyChangedEventHandler PropertyChanged;
        void Raise(string p) { PropertyChangedEventHandler h = PropertyChanged; if (h != null) h(this, new PropertyChangedEventArgs(p)); }

        public string Key { get; set; }
        public string Code { get; set; }
        public int Id { get; set; }
        public string IdText { get { return Id > 0 ? Id.ToString() : ""; } }
        public string Kind { get; set; }
        public string Tier { get; set; }
        public string Family { get; set; }
        public string Title { get; set; }
        public string Setting { get; set; }
        public string Detail { get; set; }
        public string Lock { get; set; }
        public string LockLabel { get; set; }
        public string Guard { get; set; }
        public string DefaultTarget { get; set; }
        public bool CanEditTarget { get; set; }
        public object Payload { get; set; }

        string[] _choices = new string[] { "—" };
        public string[] Choices { get { return _choices; } set { _choices = value; Raise("Choices"); Raise("CanAct"); } }
        public bool CanAct { get { return _choices != null && _choices.Length > 1; } }

        string _current;
        public string Current { get { return _current; } set { _current = value; Raise("Current"); } }

        string _state;
        public string State { get { return _state; } set { _state = value; Raise("State"); Raise("StateLabel"); } }
        public string StateLabel { get {
            switch (_state) {
                case "OK": return "✔ Conforme";
                case "KO": return "✖ Non conforme";
                case "NR": return "? Illisible";
                default:   return "—";
            } } }

        string _target;
        public string Target { get { return _target; } set { _target = value; Raise("Target"); Raise("IsCustom"); } }
        public bool IsCustom { get { return CanEditTarget && !String.Equals((_target ?? "").Trim(), DefaultTarget ?? ""); } }

        string _action = "—";
        public string Action {
            get { return _action; }
            set {
                // WPF pousse null dans SelectedItem quand une ligne de la grille
                // change d'objet (défilement) : l'accepter effacerait un choix
                // sans que personne l'ait demandé. On ignore aussi toute valeur
                // que ce contrôle ne permet pas.
                if (value == null) return;
                if (_choices != null && Array.IndexOf(_choices, value) < 0) return;
                string v = value;
                if (v == _action) return;
                _action = v; Raise("Action"); Raise("Pending");
            }
        }
        public bool Pending { get { return _action != "—"; } }
    }
}
'@
}

# ============================================================================
#  Fonctions COMMUNES à la console et aux scripts générés. Ce bloc est
#  exécuté ici ET recopié tel quel dans chaque script : une seule lecture du
#  poste, pas deux qui divergeraient. ASCII pur, comme le moteur.
# ============================================================================
$SharedFnText = @'
function Format-Val($v) {
    if ($null -eq $v) { return '(absente)' }
    if ($v -is [array]) {
        if ($v.Count -eq 0) { return '(vide)' }
        return ($v -join ' ; ')
    }
    return "$v"
}

# REG_DWORD est relu en Int32 signe : 0xFFFFFFFF revient en -1. On compare
# donc sur l'entier non signe, jamais sur la valeur brute.
function ConvertTo-U32($v) {
    try { $n = [int64]"$v" } catch { return $null }
    if ($n -lt 0) { $n += 4294967296 }
    return $n
}

# net accounts : les libelles sont traduits, l'ORDRE des lignes ne l'est pas.
# Une valeur non numerique (Jamais, Aucun, Illimite, Never, None...) rend $null.
function Read-AccountPolicy {
    $keys  = 'forcelogoff','minpwage','maxpwage','minpwlen','uniquepw','lockoutthreshold','lockoutduration','lockoutwindow'
    $lines = @(& net.exe accounts 2>$null | Where-Object { $_ -match ':' })
    $h = @{}
    for ($i = 0; $i -lt $keys.Count -and $i -lt $lines.Count; $i++) {
        $raw = ($lines[$i] -split ':')[-1].Trim()
        $h[$keys[$i]] = if ($raw -match '^\d+$') { [int]$raw } else { $null }
    }
    return $h
}

# auditpol exige l'elevation. La sortie /r est un CSV aux libelles traduits :
# on se repere sur le GUID, et le reglage est la colonne qui le suit.
# Reconnait le francais et l'anglais (Succes/Success, Echec/Failure).
function Read-AuditMap {
    $out = @(& auditpol.exe /get /category:* /r 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $out.Count) { return $null }
    $map = @{}
    foreach ($line in $out) {
        $f = @("$line" -split ',')
        for ($i = 0; $i -lt $f.Count; $i++) {
            if ($f[$i] -match '^\{[0-9A-Fa-f-]{36}\}$') {
                $inc = if ($i + 1 -lt $f.Count) { $f[$i + 1] } else { '' }
                $map[$f[$i].ToUpper()] = @{ S = [bool]($inc -match 'Succ'); F = [bool]($inc -match 'chec|Fail'); Text = $inc }
                break
            }
        }
    }
    return $map
}

# Type de demarrage lu dans le registre, dans le vocabulaire de sc.exe :
# Get-Service ne distingue pas le demarrage differe, ni ne voit les pilotes
# comme mrxsmb10. $null = service absent du poste.
function Get-SvcStart($name) {
    $p = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction SilentlyContinue
    if (-not $p -or $null -eq $p.Start) { return $null }
    switch ([int]$p.Start) {
        0 { return 'boot' }
        1 { return 'system' }
        2 { if ($p.DelayedAutostart -eq 1) { return 'delayed-auto' } else { return 'auto' } }
        3 { return 'demand' }
        4 { return 'disabled' }
    }
    return 'demand'
}
'@

# ============================================================================
#  Chargement du moteur
# ============================================================================
function Stop-Console($msg) {
    if ($NoWindow) { Write-Host $msg -ForegroundColor Red; exit 1 }
    [System.Windows.MessageBox]::Show($msg, 'Console CIS', 'OK', 'Error') | Out-Null
    exit 1
}

$script:EnginePath = $null
foreach ($c in @($Engine, (Join-Path $PSScriptRoot 'Harden-Windows-CIS.ps1'), (Join-Path (Split-Path $PSScriptRoot -Parent) 'Harden-Windows-CIS.ps1'))) {
    if ($c -and (Test-Path -LiteralPath $c)) { $script:EnginePath = (Resolve-Path -LiteralPath $c).Path; break }
}
if (-not $script:EnginePath) {
    Stop-Console "Moteur introuvable : Harden-Windows-CIS.ps1 doit se trouver à côté de la console ou dans le dossier parent (ou -Engine <chemin>)."
}

$tok = $null; $perr = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($script:EnginePath, [ref]$tok, [ref]$perr)
if ($perr.Count) { Stop-Console ("Le moteur ne s'analyse pas : " + $perr[0].Message) }

# Ce que la console emprunte au moteur. Si l'un de ces noms disparaît, la
# console refuse de démarrer plutôt que de raisonner sur des tables absentes.
$WantVars = 'ForbiddenIds','ForbiddenValues','SmartCardForbiddenIds','SmartCardForbiddenValues','SmartCardDlls',
            'NeverTouchServices','CisRegistry','CisServices','CisDelete','CisBlocked','CisManual','CisAudit',
            'CisAccountPolicy','CisVBS'
$WantFns  = 'Get-MachineProfile','Set-SmartCardPolicy','Test-GuardBlocks','Test-Forbidden','Get-RegValue',
            'Test-RowCompliant','Get-SafetySnapshot','Compare-SafetySnapshot'
$script:EngineFn = @{}
$defs  = New-Object System.Collections.Generic.List[string]
$found = @{}
foreach ($st in $ast.EndBlock.Statements) {
    if ($st -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $st.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $WantVars -contains $st.Left.VariablePath.UserPath) {
        $defs.Add($st.Extent.Text); $found[$st.Left.VariablePath.UserPath] = $true
    } elseif ($st -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $WantFns -contains $st.Name) {
        $defs.Add($st.Extent.Text); $script:EngineFn[$st.Name] = $st.Extent.Text; $found[$st.Name] = $true
    }
}
$missing = @(@($WantVars) + @($WantFns) | Where-Object { -not $found[$_] })
if ($missing.Count) {
    Stop-Console ("Le moteur ne définit plus : " + ($missing -join ', ') + "`nLa console doit être mise à jour avec lui.")
}

# Texte de la bannière : repris des valeurs par défaut du moteur.
$script:BannerDefault = @{ LegalNoticeTitle = 'Ordinateur personnel'; LegalNoticeText = '' }
if ($ast.ParamBlock) {
    foreach ($p in $ast.ParamBlock.Parameters) {
        $n = $p.Name.VariablePath.UserPath
        if ($script:BannerDefault.ContainsKey($n) -and $p.DefaultValue) {
            try { $script:BannerDefault[$n] = [string]$p.DefaultValue.SafeGetValue() } catch { }
        }
    }
}

$script:EngineSha  = (Get-FileHash -LiteralPath $script:EnginePath -Algorithm SHA256).Hash
$script:EngineDate = (Get-Item -LiteralPath $script:EnginePath).LastWriteTime

# Variables que les fonctions du moteur lisent comme ses propres paramètres.
$KeepService  = @()
$IgnoreGuards = $false
$EnableVBS    = $false
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

. ([scriptblock]::Create($defs -join "`r`n"))
. ([scriptblock]::Create($SharedFnText))

# Set-SmartCardPolicy ÉTEND ces tables : on garde l'état d'origine pour que
# chaque relecture reparte de zéro au lieu d'empiler les extensions.
$script:Base = @{
    ForbiddenIds    = @($ForbiddenIds)
    ForbiddenValues = @($ForbiddenValues)
    CisBlocked      = @($CisBlocked)
    CisManual       = @($CisManual)
}

# ============================================================================
#  Données propres à la console
# ============================================================================
$script:OutDir     = Join-Path $env:LOCALAPPDATA 'CIS-Console'
$script:ProfileDir = $script:OutDir
$script:ParcLog    = $null
$script:ParcProfile = $null
$script:PortableNote = $null

# ---------------------------------------------------------------- mode portable
# Une clé USB ou un partage qu'on promène de poste en poste. Les profils sont
# communs au parc ; tout ce qui concerne un poste vit dans son propre dossier,
# nommé d'après lui, pour qu'aucun script ne se trompe de machine en chemin
# (le script généré refuse de toute façon un autre poste, code 3).
$script:IsPortable = [bool]$Portable -or (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'PORTABLE'))
if ($script:IsPortable) {
    $data = Join-Path $PSScriptRoot 'donnees'
    $probe = Join-Path $data ("_essai-ecriture-{0}.tmp" -f $PID)
    try {
        New-Item -ItemType Directory -Path (Join-Path $data 'profils') -Force -ErrorAction Stop | Out-Null
        [IO.File]::WriteAllText($probe, 'x')
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
        $script:OutDir      = Join-Path $data "postes\$env:COMPUTERNAME"
        $script:ProfileDir  = Join-Path $data 'profils'
        $script:ParcLog     = Join-Path $data 'journal-parc.csv'
    } catch {
        # Clé verrouillée en écriture : la console reste utilisable, mais ses
        # fichiers restent sur le poste — on le dit plutôt que d'échouer plus tard.
        $script:PortableNote = "Support en lecture seule : scripts et profils écrits dans $script:OutDir (sur ce poste)."
        if (Test-Path -LiteralPath (Join-Path $data 'profils')) { $script:ProfileDir = Join-Path $data 'profils' }
    }
    $script:ParcProfile = Join-Path $script:ProfileDir 'profil-parc.json'
}

function ConvertTo-ElevatedPath([string]$p) {
    # Un lecteur réseau mappé (Z:) n'existe pas dans la session élevée par UAC :
    # tout chemin transmis à une relance en administrateur passe donc en UNC.
    if (-not $p -or $p -notmatch '^([A-Za-z]):\\') { return $p }
    try {
        $root = (Get-PSDrive -Name $Matches[1] -PSProvider FileSystem -ErrorAction Stop).DisplayRoot
        if ($root -and $root.StartsWith('\\')) { return $root.TrimEnd('\') + $p.Substring(2) }
    } catch { }
    return $p
}

function Write-ParcLog([string]$evt, [string]$detail) {
    # Une ligne par geste et par poste : ce qui a été fait où, sans ouvrir la clé.
    if (-not $script:ParcLog) { return }
    try {
        $enc = New-Object System.Text.UTF8Encoding($true)
        if (-not (Test-Path -LiteralPath $script:ParcLog)) {
            [IO.File]::WriteAllText($script:ParcLog, "date;poste;utilisateur;admin;score;evenement;detail`r`n", $enc)
        }
        $s = $script:Score
        $score = if ($s) { "$($s.Pass)/$($s.Total)" } else { '' }
        $line = @((Get-Date -Format 's'), $env:COMPUTERNAME, $env:USERNAME, $isAdmin, $score, $evt,
                  ($detail -replace '[;\r\n]', ' ')) -join ';'
        [IO.File]::AppendAllText($script:ParcLog, $line + "`r`n", $enc)
    } catch { }
}

function Save-ExecutionTrace([datetime]$since) {
    # Après une application : on rapatrie sur la clé le résultat et le journal,
    # jamais Rollback.cmd — il n'a de sens que sur le poste, avec ses .reg.
    if (-not $script:IsPortable -or $script:PortableNote) { return $null }
    $root = Join-Path $env:ProgramData 'CIS-Console-Backup'
    # v1.2 — le dossier des sauvegardes est fermé aux seuls administrateurs (voir
    # $backupRoot plus bas) : une console NON élevée ne peut pas le lister. Ce refus
    # était avalé par SilentlyContinue et devenait « aucune sauvegarde trouvée »,
    # lu comme une application sans point de retour. On dit maintenant POURQUOI
    # on ne trouve rien.
    if (-not (Test-Path -LiteralPath $root)) { return $null }
    try {
        $all = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop)
    } catch {
        if ($_.Exception -is [UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied') {
            return @{ Illisible = $true; Backup = $root }
        }
        return $null
    }
    $b = $all | Where-Object { $_.CreationTime -ge $since.AddSeconds(-5) } | Sort-Object CreationTime | Select-Object -Last 1
    if (-not $b) { return $null }
    $dst = Join-Path $script:OutDir ("execution-{0}" -f $b.Name)
    New-Item -ItemType Directory -Path $dst -Force | Out-Null
    foreach ($f in 'resultat.json', 'execution.log') {
        $src = Join-Path $b.FullName $f
        if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $dst -Force -ErrorAction SilentlyContinue }
    }
    return @{ Backup = $b.FullName; Copy = $dst }
}

# Politique de comptes : ce que la règle CIS accepte, pas seulement la
# valeur que le moteur écrit.
$AccountRules = [ordered]@{
    uniquepw         = @{ Id = 26000; Min = 24;             Title = "Ensure 'Enforce password history' is set to '24 or more password(s)'." }
    maxpwage         = @{ Id = 26001; Min = 1;   Max = 365; Title = "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'." }
    minpwage         = @{ Id = 26002; Min = 1;              Title = "Ensure 'Minimum password age' is set to '1 or more day(s)'." }
    minpwlen         = @{ Id = 26003; Min = 14;             Title = "Ensure 'Minimum password length' is set to '14 or more character(s)'." }
    lockoutduration  = @{ Id = 26005; Min = 15;             Title = "Ensure 'Account lockout duration' is set to '15 or more minute(s)'." }
    lockoutthreshold = @{ Id = 26006; Min = 1;   Max = 5;   Title = "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'." }
    lockoutwindow    = @{ Id = 26007; Min = 15;             Title = "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'." }
}

# Démarrage par défaut de Windows 11 (vocabulaire sc.exe), pour « Retirer »
# un service désactivé. Un service absent de cette table ne propose pas
# « Retirer » : on ne devine pas un défaut.
$ServiceDefaults = @{
    BTAGService = 'demand'; bthserv = 'demand'; MapsBroker = 'delayed-auto'; lfsvc = 'demand'; lltdsvc = 'demand'
    LxssManager = 'demand'; MSiSCSI = 'demand'; sshd = 'demand'; PNRPsvc = 'demand'; p2psvc = 'demand'
    p2pimsvc = 'demand'; PNRPAutoReg = 'demand'; Spooler = 'auto'; wercplsupport = 'demand'; RasAuto = 'demand'
    SessionEnv = 'demand'; TermService = 'demand'; UmRdpService = 'demand'; RpcLocator = 'demand'
    LanmanServer = 'auto'; SSDPSRV = 'demand'; upnphost = 'demand'; WerSvc = 'demand'; Wecsvc = 'demand'
    WMPNetworkSvc = 'demand'; icssvc = 'demand'; WpnService = 'auto'; PushToInstall = 'demand'; WinRM = 'demand'
    XboxGipSvc = 'demand'; XblAuthManager = 'demand'; XblGameSave = 'demand'; XboxNetApiSvc = 'demand'
}
$StartLabels = @{
    'auto' = 'Automatique'; 'delayed-auto' = 'Automatique (différé)'; 'demand' = 'Manuel'
    'disabled' = 'Désactivé'; 'boot' = 'Démarrage'; 'system' = 'Système'
}

# Les « choix assumés » du moteur : la valeur retenue n'est pas
# la plus stricte que la règle tolère, et voici pourquoi.
$Notes = @{
    26061 = "Choix du moteur : 1 = auditer. 2 = refuser le NTLM sortant — plus strict, mais coupe l'accès aux partages SMB/NAS hors domaine."
    26192 = "Choix du moteur : 2 = NetBIOS coupé sur les réseaux publics. 0 = partout — casse la découverte NAS et imprimantes."
    26191 = "Choix du moteur : 2 = DoH autorisé. 3 = exigé — plus de résolution de noms si le résolveur ne gère pas DoH."
    26214 = "Choix du moteur : 0 = négocier. 1 = Kerberos seul — casse l'impression hors domaine."
    26030 = "Choix du moteur : 1 = verrouiller au retrait de la carte. 2 ou 3 = fermer / déconnecter la session."
    26352 = "Coupe la caméra pour TOUTES les applications, sans message explicite : l'application dit seulement qu'aucune caméra n'est disponible."
    26332 = "Avec 26333, BitLocker sur le volume système n'accepte plus que TPM+PIN, jamais TPM seul."
    26333 = "Avec 26332, BitLocker sur le volume système n'accepte plus que TPM+PIN, jamais TPM seul."
}

# Ce que relit la console pour afficher l'état des contrôles absents des tables
# du moteur — en TIER 3, ou en liste noire sur un poste à carte —, avec la
# valeur attendue par la règle CIS.
$ExtraProbe = @{
    26269 = @{ Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\Windows\System';  Name = 'AllowCustomSSPsAPs'; Data = '0' }
    26270 = @{ Hive = 'HKLM'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa';        Name = 'RunAsPPL';           Data = '1' }
    26443 = @{ Hive = 'HKLM'; Path = 'SOFTWARE\Policies\Microsoft\WindowsStore';    Name = 'RemoveWindowsStore'; Data = '1' }
}

$LockLabels = @{
    ''        = ''
    'usage'   = [string][char]0x26A0 + ' usage'
    'dur'     = [string][char]0x26D4 + ' garde-fou dur'
    'noire'   = [string][char]0x26D4 + ' liste noire'
    'manuel'  = [string][char]0x270B + ' manuel'
    'score'   = [string][char]0x26A0 + ' score seul'
    'protege' = [string][char]0x26D4 + ' protégé'
}

# ============================================================================
#  Lecture du poste
# ============================================================================
function Read-RegState($hive, $path, $name) {
    $root = if ($hive -eq 'HKCU') { [Microsoft.Win32.Registry]::CurrentUser } else { [Microsoft.Win32.Registry]::LocalMachine }
    try {
        $k = $root.OpenSubKey($path, $false)
        if (-not $k) { return @{ Readable = $true; Exists = $false; Value = $null } }
        try {
            $v = $k.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            return @{ Readable = $true; Exists = ($null -ne $v); Value = $v }
        } finally { $k.Close() }
    } catch {
        return @{ Readable = $false; Exists = $false; Value = $null }
    }
}

function Read-Machine {
    $script:ForbiddenIds    = @($script:Base.ForbiddenIds)
    $script:ForbiddenValues = @($script:Base.ForbiddenValues)
    $script:CisBlocked      = @($script:Base.CisBlocked)
    $script:CisManual       = @($script:Base.CisManual)
    $script:Machine = Get-MachineProfile
    Set-SmartCardPolicy $script:Machine
}

# Deux passes : sans -IgnoreGuards (tout ce qui écarte) puis avec (ce qui
# reste = garde-fou dur). La distinction vient du moteur, pas d'ici.
function Get-GuardInfo($guard, $fam) {
    $script:IgnoreGuards = $true
    $hard = Test-GuardBlocks $guard $fam $script:Machine
    $script:IgnoreGuards = $false
    $soft = Test-GuardBlocks $guard $fam $script:Machine
    if ($hard) { return @{ Lock = 'dur';   Why = $hard } }
    if ($soft) { return @{ Lock = 'usage'; Why = $soft } }
    return @{ Lock = ''; Why = '' }
}

function Get-CisExpect($row) {
    if ($row.Accept) {
        if ($row.Accept -like 'range:*') { $b = ($row.Accept -replace '^range:', '') -split '-'; return "de $($b[0]) à $($b[1])" }
        return ($row.Accept -split '\|') -join ' ou '
    }
    return "$($row.Data)"
}

# Même logique que Test-RowCompliant du moteur, appliquée à une valeur
# proposée plutôt qu'à la valeur en place.
function Test-CisValue($row, $value) {
    if ($row.Accept) {
        if ($row.Accept -like 'range:*') {
            $b = ($row.Accept -replace '^range:', '') -split '-'
            try { $n = [int64]$value } catch { return $false }
            return ($n -ge [int64]$b[0] -and $n -le [int64]$b[1])
        }
        foreach ($a in ($row.Accept -split '\|')) { if ("$a" -eq "$value") { return $true } }
        return $false
    }
    return ("$value" -eq "$($row.Data)")
}

function Test-AccountValue($key, $v) {
    $r = $AccountRules[$key]
    if ($null -eq $v) { return $false }
    if ($v -lt $r.Min) { return $false }
    if ($r.Max -and $v -gt $r.Max) { return $false }
    return $true
}

function Format-Target($row) {
    if ($row.Type -eq 'Multi') {
        if ([string]::IsNullOrEmpty($row.Data)) { return '(vide)' }
        return (($row.Data -split '\|') -join ' ; ')
    }
    return "$($row.Data)"
}

function New-CisItem([hashtable]$h) {
    $it = New-Object CisConsole.Item
    foreach ($k in $h.Keys) { $it.$k = $h[$k] }
    $it.LockLabel = $LockLabels["$($it.Lock)"]
    return $it
}

function Add-RegistryItems($list) {
    foreach ($g in ($CisRegistry | Group-Object { $_.Id })) {
        $rows  = @($g.Group); $r0 = $rows[0]; $id = [int]$g.Name
        $reads = @(foreach ($r in $rows) { Read-RegState $r.Hive $r.Path $r.Name })
        $rowOk = @(foreach ($r in $rows) { [bool](Test-RowCompliant $r) })
        $readable = -not @($reads | Where-Object { -not $_.Readable }).Count
        $present  = [bool]@($reads | Where-Object { $_.Exists }).Count

        # Score : mêmes lignes et même règle que « Harden-Windows-CIS.ps1 -Verify ».
        if ($ForbiddenIds -notcontains $id -and $r0.Tier -ne 9) {
            $script:Score.Total += $rows.Count
            $script:Score.Pass  += @($rowOk | Where-Object { $_ }).Count
        }

        $state = if (-not $readable) { 'NR' } elseif ($rowOk -contains $false) { 'KO' } else { 'OK' }
        if (-not $readable) { $cur = '(illisible sans élévation)' }
        elseif ($rows.Count -eq 1) { $cur = Format-Val $reads[0].Value }
        else { $cur = (@(for ($i = 0; $i -lt $rows.Count; $i++) { "$($rows[$i].Name)=$(Format-Val $reads[$i].Value)" }) -join ' ; ') }
        $tgt = if ($rows.Count -eq 1) { Format-Target $r0 } else { (@($rows | ForEach-Object { "$($_.Name)=$(Format-Target $_)" }) -join ' ; ') }

        $black = ($ForbiddenIds -contains $id) -or [bool]@($rows | Where-Object { Test-Forbidden $_.Hive $_.Path $_.Name }).Count
        $gi = if ($black) { @{ Lock = 'noire'; Why = 'Liste noire du moteur : jamais appliqué.' } } else { Get-GuardInfo '' $r0.Fam }
        $policy = -not @($rows | Where-Object { $_.Path -notmatch '\\Policies\\' }).Count

        $ch = @($Dash)
        if ($gi.Lock -in '', 'usage') { $ch += 'Appliquer' }
        if ($gi.Lock -ne 'noire' -and $present -and $policy) { $ch += 'Retirer' }

        $d = New-Object System.Collections.Generic.List[string]
        foreach ($r in $rows) {
            if ($r.Accept)       { $d.Add("$($r.Name) : la règle Wazuh accepte $(Get-CisExpect $r).") }
            elseif ($r.AbsentOk) { $d.Add("$($r.Name) : l'absence de la valeur suffit aussi à la règle Wazuh.") }
        }
        if ($Notes.ContainsKey($id)) { $d.Add($Notes[$id]) }
        if ($r0.Fam -eq 'sleep') { $d.Add("Veille : les quatre contrôles 26281-26284 se retirent ENSEMBLE — une seule clé restante sous Policies\Power suffit à faire refuser toute écriture à powercfg. Le script généré lance ensuite gpupdate, sans quoi l'override reste en cache.") }
        if (-not $policy) { $d.Add("Valeur système hors stratégie : pas de « Retirer » (son absence ne veut pas dire « valeur par défaut »). Pour revenir en arrière : le Rollback.cmd du passage qui l'a posée.") }
        elseif ($ch -contains 'Retirer') { $d.Add("Retirer = supprimer la valeur de stratégie : retour à « non configuré », le comportement par défaut de Windows.") }

        $list.Add((New-CisItem @{
            Key = "reg:$id"; Code = 'reg'; Id = $id; Kind = 'Registre'; Tier = "$($r0.Tier)"; Family = $r0.Fam
            Title = $r0.Title
            Setting = (@($rows | ForEach-Object { "$($_.Hive)\$($_.Path)\$($_.Name)  ($($_.Type))" }) -join "`n")
            Current = $cur; State = $state; DefaultTarget = $tgt; Target = $tgt
            CanEditTarget = ($rows.Count -eq 1 -and $r0.Type -in 'DWord', 'String' -and $ch -contains 'Appliquer')
            Lock = $gi.Lock; Guard = $gi.Why; Choices = $ch; Detail = ($d -join "`n"); Payload = $rows
        }))
    }
}

function Add-DeleteItems($list) {
    foreach ($dd in $CisDelete) {
        $rs    = Read-RegState $dd.Hive $dd.Path $dd.Name
        $state = if (-not $rs.Readable) { 'NR' } elseif ($rs.Exists) { 'KO' } else { 'OK' }
        $black = ($ForbiddenIds -contains $dd.Id) -or (Test-Forbidden $dd.Hive $dd.Path $dd.Name)
        $gi = if ($black) { @{ Lock = 'noire'; Why = 'Liste noire du moteur.' } }
              elseif ($dd.Tier -eq 9) { @{ Lock = 'score'; Why = $dd.Note } }
              else { @{ Lock = ''; Why = '' } }
        $ch = @($Dash); if ($gi.Lock -ne 'noire') { $ch += 'Appliquer' }
        $list.Add((New-CisItem @{
            Key = "del:$($dd.Id)"; Code = 'del'; Id = $dd.Id; Kind = 'Suppression'; Tier = "$($dd.Tier)"; Family = $dd.Fam
            Title = $dd.Title; Setting = "$($dd.Hive)\$($dd.Path)\$($dd.Name)"
            Current = $(if ($rs.Readable) { Format-Val $rs.Value } else { '(illisible sans élévation)' })
            State = $state; DefaultTarget = '(absente)'; Target = '(absente)'
            Lock = $gi.Lock; Guard = $gi.Why; Choices = $ch; Payload = $dd
            Detail = "Appliquer = SUPPRIMER cette valeur : la règle Wazuh exige son absence.`n$($dd.Note)"
        }))
    }
}

function Add-ServiceItems($list) {
    foreach ($s in $CisServices) {
        $st = Get-SvcStart $s.Service
        $ok = ($null -eq $st -or $st -eq 'disabled')
        $script:Score.Total++; if ($ok) { $script:Score.Pass++ }
        $gi = if ($NeverTouchServices -contains $s.Service) { @{ Lock = 'protege'; Why = 'Service protégé (carte à puce / supervision) : jamais désactivé.' } }
              else { Get-GuardInfo $s.Guard 'service' }
        $def = $ServiceDefaults[$s.Service]
        $ch = @($Dash)
        if ($null -ne $st -and $st -ne 'disabled' -and $gi.Lock -in '', 'usage') { $ch += 'Appliquer' }
        if ($st -eq 'disabled' -and $def -and $gi.Lock -ne 'protege') { $ch += 'Retirer' }
        $det = if ($def) { "Retirer = remettre le démarrage par défaut de Windows 11 : $($StartLabels[$def])." }
               else { "Pas de « Retirer » : démarrage par défaut non répertorié pour ce service." }
        if ($s.Guard) { $det = "Garde-fou du moteur : « $($s.Guard) ».`n$det" }
        $list.Add((New-CisItem @{
            Key = "svc:$($s.Id)"; Code = 'svc'; Id = $s.Id; Kind = 'Service'; Tier = "$($s.Tier)"; Family = 'service'
            Title = $s.Title; Setting = "service $($s.Service)"
            Current = $(if ($null -eq $st) { '(non installé)' } else { $StartLabels[$st] })
            State = $(if ($ok) { 'OK' } else { 'KO' }); DefaultTarget = 'Désactivé'; Target = 'Désactivé'
            Lock = $gi.Lock; Guard = $gi.Why; Choices = $ch; Detail = $det; Payload = $s
        }))
    }
}

function Add-AuditItems($list) {
    foreach ($a in $CisAudit) {
        $want = if ($a.S -and $a.F) { 'Succès et échec' } elseif ($a.S) { 'Succès' } else { 'Échec' }
        $wantEn = if ($a.S -and $a.F) { 'Success and Failure' } elseif ($a.S) { 'Success' } else { 'Failure' }
        if ($null -eq $script:AuditMap) { $cur = '(illisible sans élévation)'; $state = 'NR' }
        else {
            $c = $script:AuditMap[$a.Guid.ToUpper()]
            if (-not $c) { $cur = '(inconnue)'; $state = 'NR' }
            else {
                $cur = if ($c.S -and $c.F) { 'Succès et échec' } elseif ($c.S) { 'Succès' } elseif ($c.F) { 'Échec' } else { 'Aucun audit' }
                $state = if ((-not $a.S -or $c.S) -and (-not $a.F -or $c.F)) { 'OK' } else { 'KO' }
            }
        }
        $det = "Le script généré AJOUTE les indicateurs requis sans retirer ceux déjà actifs."
        if (-not $script:Machine.English) {
            $det += "`nWindows non anglais : la règle Wazuh compare la sortie d'auditpol à la chaîne anglaise « $wantEn » — ce contrôle reste en échec au scan même appliqué. Plafond de mesure connu, pas un trou de sécurité."
        }
        $list.Add((New-CisItem @{
            Key = "aud:$($a.Id)"; Code = 'aud'; Id = $a.Id; Kind = 'Audit'; Tier = '1'; Family = 'audit'
            Title = "Ensure 'Audit $($a.Sub)' is set to include '$wantEn'."
            Setting = "auditpol /subcategory:$($a.Guid)"
            Current = $cur; State = $state; DefaultTarget = "$want (au moins)"; Target = "$want (au moins)"
            Lock = ''; Guard = ''; Choices = @($Dash, 'Appliquer'); Detail = $det; Payload = $a
        }))
    }
}

function Add-AccountItems($list) {
    foreach ($k in $AccountRules.Keys) {
        $r = $AccountRules[$k]; $v = $script:AcctNow[$k]
        $cur  = if ($null -ne $v) { "$v" } elseif ($script:AcctNow.Count) { '(jamais / aucun)' } else { '(illisible)' }
        $rule = if ($r.Max) { "de $($r.Min) à $($r.Max)" } else { "$($r.Min) ou plus" }
        $det  = "Règle CIS : $rule. Valeur écrite par le moteur : $($CisAccountPolicy[$k])."
        if ($k -eq 'lockoutwindow') { $det += "`nDoit rester inférieure ou égale à la durée de verrouillage." }
        $list.Add((New-CisItem @{
            Key = "acc:$k"; Code = 'acc'; Id = $r.Id; Kind = 'Comptes'; Tier = '1'; Family = 'comptes'
            Title = $r.Title; Setting = "net accounts /$($k):<valeur>"
            Current = $cur; State = $(if (Test-AccountValue $k $v) { 'OK' } else { 'KO' })
            DefaultTarget = "$($CisAccountPolicy[$k])"; Target = "$($CisAccountPolicy[$k])"; CanEditTarget = $true
            Lock = ''; Guard = ''; Choices = @($Dash, 'Appliquer'); Detail = $det; Payload = $k
        }))
    }
}

function Add-OtherItems($list) {
    # -- Compte invité (26009), adressé par SID comme dans le moteur
    $g = $null
    try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1 } catch { }
    $gch = @($Dash); if ($g -and $g.Enabled) { $gch += 'Appliquer' }
    $list.Add((New-CisItem @{
        Key = 'guest'; Code = 'guest'; Id = 26009; Kind = 'Comptes'; Tier = '1'; Family = 'comptes'
        Title = "Ensure 'Accounts: Guest account status' is set to 'Disabled'."; Setting = 'compte local SID -501'
        Current = $(if (-not $g) { '(absent)' } elseif ($g.Enabled) { "Activé ($($g.Name))" } else { "Désactivé ($($g.Name))" })
        State = $(if (-not $g -or -not $g.Enabled) { 'OK' } else { 'KO' }); DefaultTarget = 'Désactivé'; Target = 'Désactivé'
        Lock = ''; Guard = ''; Choices = $gch; Payload = $null
        Detail = "Adressé par SID (-501) et non par le nom « Guest », traduit sur un Windows non anglais."
    }))

    # -- Bannière de connexion (26026 texte, 26027 titre) — TIER 2 du moteur
    $bp = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    foreach ($b in @(
        @{ Id = 26026; Name = 'legalnoticetext';    Def = $script:BannerDefault.LegalNoticeText;  Title = "Configure 'Interactive logon: Message text for users attempting to log on'." }
        @{ Id = 26027; Name = 'legalnoticecaption'; Def = $script:BannerDefault.LegalNoticeTitle; Title = "Configure 'Interactive logon: Message title for users attempting to log on'." })) {
        $rs = Read-RegState 'HKLM' $bp $b.Name
        $ok = $rs.Exists -and -not [string]::IsNullOrWhiteSpace("$($rs.Value)")
        $ch = @($Dash, 'Appliquer'); if ($rs.Exists) { $ch += 'Retirer' }
        $list.Add((New-CisItem @{
            Key = "ban:$($b.Id)"; Code = 'ban'; Id = $b.Id; Kind = 'Bannière'; Tier = '2'; Family = 'banner'
            Title = $b.Title; Setting = "HKLM\$bp\$($b.Name)  (String)"
            Current = $(if ($rs.Exists) { "$($rs.Value)" } else { '(absente)' }); State = $(if ($ok) { 'OK' } else { 'KO' })
            DefaultTarget = $b.Def; Target = $b.Def; CanEditTarget = $true
            Lock = ''; Guard = ''; Choices = $ch; Payload = @{ Hive = 'HKLM'; Path = $bp; Name = $b.Name }
            Detail = "Affichée avant chaque ouverture de session. La cible est modifiable."
        }))
    }

    # -- TIER 3 : affiché, jamais automatisé
    foreach ($mm in $CisManual) {
        $probe = $CisVBS | Where-Object { $_.Id -eq $mm.Id } | Select-Object -First 1
        if (-not $probe -and $ExtraProbe.ContainsKey([int]$mm.Id)) { $probe = $ExtraProbe[[int]$mm.Id] }
        $cur = $Dash; $state = ''
        if ($probe) {
            $rs = Read-RegState $probe.Hive $probe.Path $probe.Name
            $cur = if ($rs.Readable) { Format-Val $rs.Value } else { '(illisible)' }
            $state = if (-not $rs.Readable) { 'NR' } elseif ($rs.Exists -and "$($rs.Value)" -eq "$($probe.Data)") { 'OK' } else { 'KO' }
        }
        $det = "Décision humaine : la console ne l'automatise pas."
        if ($mm.Id -eq 26011) { $det += "`nGet-LocalUser | Where-Object { `$_.SID -match '-500$' } | Rename-LocalUser -NewName <nom>" }
        if ($mm.Id -eq 26012) { $det += "`nGet-LocalUser | Where-Object { `$_.SID -match '-501$' } | Rename-LocalUser -NewName <nom>" }
        $list.Add((New-CisItem @{
            Key = "man:$($mm.Id)"; Code = 'man'; Id = $mm.Id; Kind = 'TIER 3'; Tier = '3'; Family = 'tier3'
            Title = $mm.Title; Setting = $(if ($probe) { "$($probe.Hive)\$($probe.Path)\$($probe.Name)" } else { '' })
            Current = $cur; State = $state; DefaultTarget = $Dash; Target = $Dash
            Lock = 'manuel'; Guard = $mm.Why; Choices = @($Dash); Detail = $det; Payload = $null
        }))
    }

    # -- Liste noire effective (socle + extension carte à puce)
    foreach ($bb in $CisBlocked) {
        $probe = if ($ExtraProbe.ContainsKey([int]$bb.Id)) { $ExtraProbe[[int]$bb.Id] } else { $CisVBS | Where-Object { $_.Id -eq $bb.Id } | Select-Object -First 1 }
        $cur = $Dash; $set = ''
        if ($probe) {
            $rs  = Read-RegState $probe.Hive $probe.Path $probe.Name
            $cur = if ($rs.Readable) { Format-Val $rs.Value } else { '(illisible)' }
            $set = "$($probe.Hive)\$($probe.Path)\$($probe.Name)"
        }
        $why = if ($bb.Motif) { $bb.Motif }
               elseif ($bb.Id -in 26269, 26270) { "Profil carte à puce : LSASS en processus protégé refuse de charger un module non signé PPL, et AllowCustomSSPsAPs = 0 interdit les packages tiers — l'ouverture de session par carte échouerait." }
               else { "Profil carte à puce : LSA isolé par l'hyperviseur ne charge aucun package d'authentification tiers, et le verrou UEFI ne se retire pas sans accès physique." }
        $list.Add((New-CisItem @{
            Key = "bl:$($bb.Id)"; Code = 'bl'; Id = $bb.Id; Kind = 'Liste noire'; Tier = $Dash; Family = 'liste-noire'
            Title = $bb.Title; Setting = $set; Current = $cur; State = ''; DefaultTarget = $Dash; Target = $Dash
            Lock = 'noire'; Guard = $why; Choices = @($Dash); Payload = $null
            Detail = "Jamais appliqué, sous aucune option. Le script généré revérifie cette liste avant toute écriture."
        }))
    }
}

function Import-PosteState {
    Read-Machine
    $script:AuditMap = if ($isAdmin) { Read-AuditMap } else { $null }
    $script:AcctNow  = Read-AccountPolicy
    $script:Score    = @{ Pass = 0; Total = 0 }
    $list = New-Object System.Collections.Generic.List[object]
    Add-RegistryItems $list
    Add-DeleteItems   $list
    Add-ServiceItems  $list
    Add-AuditItems    $list
    Add-AccountItems  $list
    Add-OtherItems    $list
    $typed = New-Object 'System.Collections.Generic.List[CisConsole.Item]'
    foreach ($i in ($list | Sort-Object Id, Key)) { $typed.Add($i) }
    return , $typed
}

function Get-ProfileFlags($m) {
    $f = @()
    if ($m.Laptop)  { $f += 'portable' }
    if ($m.Domain)  { $f += 'domaine AD' }
    if ($m.AzureAD) { $f += 'Entra ID' }
    if (-not ($m.Domain -or $m.AzureAD)) { $f += 'WORKGROUP' }
    if ($m.BitLocker -and $m.BitLockerKnown) { $f += 'BitLocker actif' } elseif ($m.BitLocker) { $f += 'BitLocker indéterminé (supposé actif)' }
    if ($m.SmartCardLogonStack) { $f += 'connexion par carte' } elseif ($m.SmartCard) { $f += 'carte à puce' }
    if ($m.MicrosoftAccount) { $f += 'compte Microsoft' }
    if ($m.HelloPin)  { $f += 'PIN Hello' }
    if ($m.Printers)  { $f += 'imprimante' }
    if ($m.Camera)    { $f += 'webcam' }
    if (-not $m.SleepRead) { $f += 'veille illisible' } elseif (-not $m.ModernStandby) { $f += 'veille S3 classique' }
    if ($m.Bluetooth) { $f += 'Bluetooth' }
    if ($m.WSL)       { $f += 'WSL' }
    if ($m.SSHD)      { $f += 'serveur SSH' }
    if ($m.RDP)       { $f += 'RDP actif' }
    if ($m.Shares)    { $f += 'partages SMB' }
    if ($m.Xbox)      { $f += 'Xbox' }
    if ($m.Wazuh)     { $f += 'agent Wazuh' }
    return $f
}

function Get-PosteText {
    $m = $script:Machine
    $L = New-Object System.Collections.Generic.List[string]
    $L.Add('POSTE')
    $L.Add("  $($m.Host) — $($m.OS) (build $($m.Build)), langue $($m.Culture)")
    $L.Add('  Détecté : ' + ((Get-ProfileFlags $m) -join ' | '))
    $L.Add('  Session : ' + $(if ($isAdmin) { 'administrateur — lecture complète' } else { "non élevée — politique d'audit et état BitLocker illisibles (BitLocker supposé actif, comme le moteur)" }))
    $L.Add('')
    $L.Add('PILE CARTE À PUCE')
    $L.Add('  Profil carte à puce : ' + $(if ($CardMode) { "ACTIF — $CardReason" } else { "inactif — $CardReason" }))
    $L.Add('  Lecteur             : ' + $(if ($m.SmartCardReader) { $m.ReaderNames -join ', ' } else { 'aucun' }))
    $L.Add('  Package dans LSA    : ' + $(if ($m.EIDRegistered) { 'déclaré' } else { 'absent' }))
    $L.Add("  DLL EID             : $($m.EIDDlls.Count)/$($SmartCardDlls.Count)")
    $L.Add("  RunAsPPL            : $($m.RunAsPPL)")
    $L.Add('  Credential Guard    : ' + $(if ($m.CredGuardRunning) { 'EN COURS — incompatible avec la carte' } else { 'inactif' }))
    $L.Add('  HVCI                : ' + $(if ($m.HvciRunning) { 'en cours' } else { 'inactif' }))
    $L.Add('')
    $L.Add('VEILLE')
    $L.Add('  powercfg /a         : ' + $(if ($m.SleepRead) { 'lu' } else { 'ILLISIBLE — la famille sleep est bloquée par prudence' }))
    $L.Add('  Modern Standby (S0) : ' + $(if ($m.ModernStandby) { 'oui' } else { 'non' }) + '     S3 : ' + $(if ($m.SleepS3) { 'disponible' } else { 'indisponible' }))
    $L.Add('')
    $L.Add("LISTE NOIRE EFFECTIVE ($(@($ForbiddenIds).Count) contrôles) : " + ((@($ForbiddenIds) | Sort-Object) -join ', '))
    $L.Add('')
    $L.Add('ÉCARTÉS PAR UN GARDE-FOU SUR CE POSTE')
    foreach ($it in ($script:Items | Where-Object { $_.Lock -in 'dur', 'usage', 'score', 'protege' } | Sort-Object Id)) {
        $L.Add(('  [{0}] {1,-8} {2}' -f $it.IdText, $it.Lock, $it.Guard))
    }
    $L.Add('')
    $L.Add('MOTEUR')
    $L.Add("  $($script:EnginePath)")
    $L.Add("  SHA-256 $($script:EngineSha) — modifié le $($script:EngineDate.ToString('yyyy-MM-dd HH:mm'))")
    $L.Add("  Console $ConsoleVersion — scripts générés dans $($script:OutDir)")
    return ($L -join "`r`n")
}

# ============================================================================
#  Plan : des choix de la grille aux opérations du script
# ============================================================================
function ConvertTo-PsLiteral($v) {
    if ($null -eq $v) { return '$null' }
    if ($v -is [bool]) { if ($v) { return '$true' } else { return '$false' } }
    if ($v -is [int] -or $v -is [long]) { return "$v" }
    if ($v -is [System.Collections.IDictionary]) {
        $parts = foreach ($k in $v.Keys) { "$k=$(ConvertTo-PsLiteral $v[$k])" }
        return '@{ ' + ($parts -join '; ') + ' }'
    }
    if ($v -is [array]) { return '@(' + ((@($v) | ForEach-Object { ConvertTo-PsLiteral $_ }) -join ', ') + ')' }
    # PowerShell ferme aussi une chaîne entre apostrophes sur les guillemets
    # typographiques simples : on les double comme l'apostrophe droite.
    return "'" + ([regex]::Replace("$v", "['‘’‚‛]", { param($x) $x.Value + $x.Value })) + "'"
}

function Get-Plan {
    $ops  = New-Object System.Collections.Generic.List[object]
    $warn = New-Object System.Collections.Generic.List[string]
    $err  = New-Object System.Collections.Generic.List[string]
    foreach ($it in @($script:Items | Where-Object { $_.Pending } | Sort-Object Id, Key)) {
        $tag = "[$($it.IdText)]"
        if ($it.Choices -notcontains $it.Action) { $err.Add("$tag « $($it.Action) » n'est pas permis pour ce contrôle."); continue }
        if ($it.Action -eq 'Appliquer' -and $it.Lock -in 'usage', 'score') { $warn.Add("$tag garde-fou passé outre : $($it.Guard)") }
        switch ($it.Code) {
            'reg' {
                $rows = @($it.Payload)
                if ($it.Action -eq 'Retirer') {
                    foreach ($r in $rows) {
                        if ($null -ne (Get-RegValue $r.Hive $r.Path $r.Name)) {
                            $ops.Add([ordered]@{ Op = 'reg-del'; Id = $it.Id; Hive = $r.Hive; Path = $r.Path; Name = $r.Name })
                        }
                    }
                    if ($it.Family -ne 'sleep') { $warn.Add("$tag retiré — retour à « non configuré », le poste perd ce durcissement.") }
                } else {
                    foreach ($r in $rows) {
                        $data = "$($r.Data)"
                        if ($it.CanEditTarget) {
                            $t = "$($it.Target)".Trim()
                            if ($r.Type -eq 'DWord') {
                                $n = 0L
                                if (-not [int64]::TryParse($t, [ref]$n) -or $n -lt 0 -or $n -gt 4294967295) {
                                    $err.Add("$tag cible « $t » : un entier entre 0 et 4294967295 est attendu."); continue
                                }
                                $t = "$n"
                            }
                            if ($t -ne $data -and -not (Test-CisValue $r $t)) {
                                $warn.Add("$tag cible $t hors tolérance CIS (attendu : $(Get-CisExpect $r)) — le contrôle restera en échec au scan.")
                            }
                            $data = $t
                        }
                        $ops.Add([ordered]@{ Op = 'reg-set'; Id = $it.Id; Hive = $r.Hive; Path = $r.Path; Name = $r.Name; Type = $r.Type; Data = $data })
                    }
                }
            }
            'del' {
                $r = $it.Payload
                $ops.Add([ordered]@{ Op = 'reg-del'; Id = $it.Id; Hive = $r.Hive; Path = $r.Path; Name = $r.Name })
            }
            'ban' {
                $r = $it.Payload
                if ($it.Action -eq 'Retirer') {
                    $ops.Add([ordered]@{ Op = 'reg-del'; Id = $it.Id; Hive = $r.Hive; Path = $r.Path; Name = $r.Name })
                } else {
                    $ops.Add([ordered]@{ Op = 'reg-set'; Id = $it.Id; Hive = $r.Hive; Path = $r.Path; Name = $r.Name; Type = 'String'; Data = "$($it.Target)" })
                }
            }
            'svc' {
                $s = $it.Payload
                if ($it.Action -eq 'Retirer') {
                    $ops.Add([ordered]@{ Op = 'svc'; Id = $it.Id; Service = $s.Service; Start = $ServiceDefaults[$s.Service] })
                    $warn.Add("$tag service $($s.Service) réactivé ($($StartLabels[$ServiceDefaults[$s.Service]])).")
                } else {
                    $ops.Add([ordered]@{ Op = 'svc'; Id = $it.Id; Service = $s.Service; Start = 'disabled' })
                }
            }
            'aud' {
                $a = $it.Payload
                $ops.Add([ordered]@{ Op = 'audit'; Id = $it.Id; Sub = $a.Sub; Guid = $a.Guid; S = [bool]$a.S; F = [bool]$a.F })
            }
            'acc' {
                $t = "$($it.Target)".Trim(); $n = 0
                if (-not [int]::TryParse($t, [ref]$n) -or $n -lt 0) { $err.Add("$tag cible « $t » : un entier positif est attendu."); continue }
                if (-not (Test-AccountValue $it.Payload $n)) { $warn.Add("$tag $($it.Payload) = $n hors règle CIS — le contrôle restera en échec.") }
                $ops.Add([ordered]@{ Op = 'acct'; Id = $it.Id; Key = $it.Payload; Value = $n })
            }
            'guest' { $ops.Add([ordered]@{ Op = 'guest'; Id = $it.Id }) }
            default { $err.Add("$tag type « $($it.Kind) » non actionnable.") }
        }
    }

    # net accounts refuse une fenêtre d'observation plus longue que la durée de verrouillage.
    $eff = @{}
    foreach ($k in 'lockoutduration', 'lockoutwindow') {
        $o = $ops | Where-Object { $_.Op -eq 'acct' -and $_.Key -eq $k } | Select-Object -First 1
        $eff[$k] = if ($o) { $o.Value } else { $script:AcctNow[$k] }
    }
    if ($null -ne $eff.lockoutwindow -and $null -ne $eff.lockoutduration -and $eff.lockoutwindow -gt $eff.lockoutduration -and $eff.lockoutduration -gt 0) {
        $warn.Add("Fenêtre d'observation ($($eff.lockoutwindow) min) plus longue que la durée de verrouillage ($($eff.lockoutduration) min) : net accounts risque de refuser.")
    }

    # Vérifications propres à la console, en attendant que le moteur les porte :
    # ses garde-fous ne voient qu'une webcam en état OK — une webcam coupée par
    # une touche de confidentialité (HP) est en « Unknown » et passe donc
    # inaperçue — et, pour Xbox, que les services Xbox Live, pas les
    # accessoires. Ce sont des avertissements, pas des verrous.
    $pend = @{}
    foreach ($it in $script:Items) { if ($it.Action -eq 'Appliquer') { $pend[$it.Id] = $true } }
    if ($pend[26352] -or $pend[26112]) {
        $dev = @(Get-PnpDevice -ErrorAction SilentlyContinue)
        $cam = @($dev | Where-Object { $_.Class -eq 'Camera' -or $_.Service -eq 'usbvideo' })
        if ($pend[26352] -and $cam.Count) {
            $warn.Add("[26352] une webcam existe sur ce poste ($((@($cam | ForEach-Object { "$($_.FriendlyName) : $($_.Status)" })) -join ', ')) — même déconnectée, 26352 la couperait pour toutes les applications.")
        }
        $xb = @($dev | Where-Object { $_.FriendlyName -match 'Xbox' })
        if ($pend[26112] -and $xb.Count) {
            $warn.Add("[26112] accessoire Xbox présent ($((@($xb | ForEach-Object { $_.FriendlyName })) -join ', ')) : XboxGipSvc gère les accessoires Xbox.")
        }
    }

    # Double verrou : liste noire et services protégés, sur les opérations finales.
    foreach ($o in $ops) {
        if ($ForbiddenIds -contains $o.Id) { $err.Add("[$($o.Id)] en liste noire.") }
        if ($o.Op -like 'reg-*' -and (Test-Forbidden $o.Hive $o.Path $o.Name)) { $err.Add("[$($o.Id)] $($o.Name) : valeur en liste noire.") }
        if ($o.Op -eq 'svc' -and $NeverTouchServices -contains $o.Service) { $err.Add("[$($o.Id)] service protégé $($o.Service).") }
    }
    return @{ Ops = $ops; Warn = $warn; Err = $err }
}

# ============================================================================
#  Script généré — gabarit (ASCII ; le fichier est écrit en UTF-8 avec BOM
#  pour qu'une bannière accentuée survive à PowerShell 5.1)
# ============================================================================
$GeneratedTemplate = @'
# ============================================================================
#  __NAME__
#  Durcissement CIS SUR MESURE pour __HOST__, genere le __DATE__
#  par Console-CIS.ps1 __VER__, depuis Harden-Windows-CIS.ps1
#  (SHA-256 __SHA__).
#
#  Sans -Apply : SIMULATION. Lit le poste et affiche ce qui changerait.
#  Avec -Apply : PowerShell EN ADMINISTRATEUR. Avant toute ecriture : point de
#    restauration, export .reg des cles touchees, sauvegarde de la politique
#    d'audit et des comptes, Rollback.cmd. Apres : chaque reglage est RELU sur
#    la machine -- on ne conclut pas qu'un reglage a pris du seul fait que la
#    commande a abouti.
#  Lie a __HOST__ : refuse de tourner sur un autre poste sans -AnyHost.
#
#  __COUNT__ operation(s) :
__SUMMARY__
# ============================================================================
[CmdletBinding()]
param([switch]$Apply, [switch]$AnyHost)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$TargetHost = '__HOST__'
$CardMode   = __CARDMODE__

$Ops = @(
__OPS__
)

# Liste noire du moteur au moment de la generation (extension carte a puce
# comprise si le profil etait actif). Reverifiee ici avant toute ecriture :
# un script retouche a la main ne peut pas la contourner.
$ForbiddenIds       = @(__FIDS__)
$ForbiddenValues    = @(
__FVALS__
)
$NeverTouchServices = @(__NEVER__)
$SmartCardDlls      = @(__DLLS__)

# -- Fonctions reprises du moteur, a l'identique ---------------------------
__ENGINEFN__

# -- Fonctions communes a la console et aux scripts generes ----------------
__SHAREDFN__

function Get-OpLabel($o) {
    switch ($o.Op) {
        'reg-set' { return ('{0}\{1} :: {2} = {3}' -f $o.Hive, $o.Path, $o.Name, $o.Data) }
        'reg-del' { return ('{0}\{1} :: {2} -> SUPPRIMER' -f $o.Hive, $o.Path, $o.Name) }
        'svc'     { return ('service {0} -> {1}' -f $o.Service, $o.Start) }
        'audit'   { return ('audit {0} -> {1}{2}' -f $o.Sub, $(if ($o.S) { '+succes' } else { '' }), $(if ($o.F) { '+echec' } else { '' })) }
        'acct'    { return ('net accounts /{0}:{1}' -f $o.Key, $o.Value) }
        'guest'   { return 'compte invite (SID -501) -> desactive' }
    }
    return $o.Op
}

function Get-OpState($o) {
    switch ($o.Op) {
        'reg-set' {
            $cur = Get-RegValue $o.Hive $o.Path $o.Name
            $done = $false
            if ($null -ne $cur) {
                switch ($o.Type) {
                    'Multi'  { $done = ((@($cur) -join '|') -eq $o.Data) }
                    'String' { $done = ("$cur" -eq $o.Data) }
                    default  { $done = ((ConvertTo-U32 $cur) -eq (ConvertTo-U32 $o.Data)) }
                }
            }
            return @{ Now = (Format-Val $cur); Done = $done }
        }
        'reg-del' {
            $cur = Get-RegValue $o.Hive $o.Path $o.Name
            return @{ Now = (Format-Val $cur); Done = ($null -eq $cur) }
        }
        'svc' {
            $st = Get-SvcStart $o.Service
            if ($null -eq $st) { return @{ Now = '(non installe)'; Done = ($o.Start -eq 'disabled') } }
            return @{ Now = $st; Done = ($st -eq $o.Start -or ($o.Start -like '*auto' -and $st -like '*auto')) }
        }
        'audit' {
            if ($null -eq $script:Audit) { return @{ Now = '(illisible sans elevation)'; Done = $false } }
            $c = $script:Audit[$o.Guid.ToUpper()]
            if (-not $c) { return @{ Now = '(inconnue)'; Done = $false } }
            return @{ Now = $c.Text; Done = ((-not $o.S -or $c.S) -and (-not $o.F -or $c.F)) }
        }
        'acct' {
            $v = $script:Acct[$o.Key]
            return @{ Now = $(if ($null -eq $v) { '(jamais / aucun)' } else { "$v" }); Done = ($null -ne $v -and $v -eq $o.Value) }
        }
        'guest' {
            $g = $null
            try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1 } catch { }
            if (-not $g) { return @{ Now = '(absent)'; Done = $true } }
            return @{ Now = $(if ($g.Enabled) { 'active' } else { 'desactive' }); Done = (-not $g.Enabled) }
        }
    }
    return @{ Now = '?'; Done = $false }
}

# =============================== EXECUTION ===============================
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host '============================================================' -ForegroundColor White
Write-Host ("  CIS SUR MESURE -- {0} -- {1} operation(s)" -f $TargetHost, $Ops.Count) -ForegroundColor White
Write-Host ("  {0}" -f $(if ($Apply) { 'APPLICATION' } else { 'SIMULATION (aucune ecriture)' })) -ForegroundColor White
Write-Host '============================================================' -ForegroundColor White

if ($env:COMPUTERNAME -ne $TargetHost -and -not $AnyHost) {
    Write-Host ("ARRET : script genere pour {0}, ce poste est {1}." -f $TargetHost, $env:COMPUTERNAME) -ForegroundColor Red
    Write-Host "  Ses choix ont ete faits sur l'etat de $TargetHost. -AnyHost pour passer outre." -ForegroundColor Yellow
    exit 3
}
if ($Apply -and -not $isAdmin) {
    Write-Host '-Apply exige une PowerShell EN ADMINISTRATEUR.' -ForegroundColor Red
    exit 1
}

$bad = @()
foreach ($o in $Ops) {
    if ($ForbiddenIds -contains $o.Id) { $bad += "id $($o.Id)" }
    if ($o.Op -like 'reg-*' -and (Test-Forbidden $o.Hive $o.Path $o.Name)) { $bad += "$($o.Hive)\$($o.Path) :: $($o.Name)" }
    if ($o.Op -eq 'svc' -and $NeverTouchServices -contains $o.Service) { $bad += "service $($o.Service)" }
}
if ($bad.Count) {
    Write-Host 'ARRET : des operations violent la liste noire du moteur :' -ForegroundColor Red
    $bad | Select-Object -Unique | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
    Write-Host "  Rien n'a ete ecrit." -ForegroundColor Red
    exit 2
}

$script:Acct  = Read-AccountPolicy
$script:Audit = if ($isAdmin) { Read-AuditMap } else { $null }

Write-Host "`n-- Etat actuel -> effet attendu -----------------------------" -ForegroundColor Cyan
$pre = @{}; $todo = 0
for ($i = 0; $i -lt $Ops.Count; $i++) {
    $o = $Ops[$i]; $s = Get-OpState $o; $pre[$i] = $s.Now
    if ($s.Done) { $mark = 'deja en place'; $col = 'DarkGray' } else { $mark = 'A CHANGER'; $col = 'Yellow'; $todo++ }
    Write-Host ("  [{0}] {1}" -f $o.Id, (Get-OpLabel $o)) -ForegroundColor $col
    Write-Host ("          actuel : {0}   -> {1}" -f $s.Now, $mark) -ForegroundColor DarkGray
}
Write-Host ("`n  {0} operation(s) sur {1} changeraient quelque chose." -f $todo, $Ops.Count) -ForegroundColor White

if (-not $Apply) {
    Write-Host "`nSIMULATION -- rien n'a ete ecrit. Pour appliquer, dans une PowerShell EN ADMINISTRATEUR :" -ForegroundColor Yellow
    Write-Host ("  & '{0}' -Apply" -f $PSCommandPath) -ForegroundColor Yellow
    exit 0
}

# -- Sauvegarde -------------------------------------------------------------
# ProgramData plutot que le profil : pas d'espace dans le chemin (auditpol
# /backup le supporte mal) et la meme place quel que soit le compte eleve.
#
# Mais ProgramData LEGUE l'ecriture a BUILTIN\Utilisateurs : le dossier porte
# Rollback.cmd, qu'un administrateur lancera ELEVE, et n'importe quel compte
# local pourrait le modifier (constate le 2026-09-21 sur la premiere
# execution). On en reprend donc la propriete, on coupe l'heritage, on ne
# garde qu'Administrateurs et SYSTEM -- par SID, les noms sont traduits -- et
# on RELIT l'ACL : aucune sauvegarde dans un dossier qu'on n'a pas prouve ferme.
$ts         = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupRoot = Join-Path $env:ProgramData 'CIS-Console-Backup'
$backupDir  = Join-Path $backupRoot $ts
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
& icacls.exe $backupRoot /setowner '*S-1-5-32-544' /T /C 2>&1 | Out-Null
& icacls.exe $backupRoot /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' 2>&1 | Out-Null
$acl  = Get-Acl -LiteralPath $backupRoot
$open = @($acl.Access | Where-Object {
    $ace = $_
    $sid = try { $ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$($ace.IdentityReference)" }
    $sid -notin 'S-1-5-32-544', 'S-1-5-18' })
$ownerSid = try { (New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$($acl.Owner)" }
if ($open.Count -or $ownerSid -notin 'S-1-5-32-544', 'S-1-5-18') {
    Write-Host "ARRET : $backupRoot n'est pas reserve a Administrateurs et SYSTEM :" -ForegroundColor Red
    Write-Host "   proprietaire : $($acl.Owner)" -ForegroundColor Red
    $open | ForEach-Object { Write-Host "   $($_.IdentityReference) : $($_.FileSystemRights)" -ForegroundColor Red }
    Write-Host "  Un Rollback.cmd modifiable par un autre compte serait lance ELEVE. Rien n'a ete ecrit." -ForegroundColor Red
    exit 4
}
New-Item -ItemType Directory -Path (Join-Path $backupDir 'registry') -Force | Out-Null
$transcript = $false
try { Start-Transcript -Path (Join-Path $backupDir 'execution.log') -ErrorAction Stop | Out-Null; $transcript = $true } catch { }
Copy-Item -LiteralPath $PSCommandPath -Destination $backupDir -ErrorAction SilentlyContinue

Write-Host "`n-- Sauvegarde -> $backupDir" -ForegroundColor Cyan
Write-Host "  Dossier reserve a Administrateurs et SYSTEM (ACL relue)." -ForegroundColor Green
$before = Get-SafetySnapshot

# Checkpoint-Computer signale un refus (un point deja cree dans les dernieres
# 24 h) par un AVERTISSEMENT, pas par une erreur : un try/catch conclut a tort
# qu'il a reussi -- constate le 2026-09-21, le message « cree » suivait le
# refus. On compare donc les numeros de sequence avant et apres.
function Get-LastRestorePoint { try { [int64](@(Get-ComputerRestorePoint -ErrorAction Stop) | Measure-Object SequenceNumber -Maximum).Maximum } catch { $null } }
$rpBefore = Get-LastRestorePoint
$rpWarn   = $null
try {
    Checkpoint-Computer -Description "Avant CIS sur mesure ($ts)" -RestorePointType MODIFY_SETTINGS `
        -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable rpWarn
} catch { $rpWarn = $_.Exception.Message }
$rpAfter = Get-LastRestorePoint
if ($null -ne $rpAfter -and $rpAfter -gt [int64]$rpBefore) {
    Write-Host "  Point de restauration cree (sequence $rpAfter)." -ForegroundColor Green
} elseif ($rpWarn) {
    Write-Host "  Point de restauration NON cree : $(@($rpWarn) -join ' ')" -ForegroundColor Yellow
    Write-Host '  Le retour arriere repose sur Rollback.cmd (on continue).' -ForegroundColor Yellow
} else {
    Write-Host '  Point de restauration : creation NON prouvee (protection systeme desactivee ?). On continue avec Rollback.cmd.' -ForegroundColor Yellow
}

$regOps   = @($Ops | Where-Object { $_.Op -like 'reg-*' })
$keys     = @($regOps | ForEach-Object { "$($_.Hive)\$($_.Path)" } | Select-Object -Unique)
$exported = 0
foreach ($k in $keys) {
    $safe = $k -replace '[\\:*?"<>| ]', '_'
    & reg.exe export "$k" (Join-Path $backupDir "registry\$safe.reg") /y 2>$null 1>$null
    if ($LASTEXITCODE -eq 0) { $exported++ }
}
Write-Host ("  {0} cle(s) exportee(s) sur {1} (une cle absente n'a rien a sauvegarder)." -f $exported, $keys.Count) -ForegroundColor Green

$hasAudit = [bool]@($Ops | Where-Object { $_.Op -eq 'audit' }).Count
if ($hasAudit) {
    & auditpol.exe /backup "/file:$(Join-Path $backupDir 'audit-avant.csv')" 2>$null 1>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "  Politique d'audit sauvegardee." -ForegroundColor Green }
    else { Write-Host '  Sauvegarde auditpol ECHOUEE : pas de retour arriere pour l audit.' -ForegroundColor Red }
}
& net.exe accounts > (Join-Path $backupDir 'net-accounts-avant.txt') 2>&1

$policyDel = [bool]@($Ops | Where-Object { $_.Op -eq 'reg-del' -and $_.Path -match '\\Policies\\' }).Count
$rb = New-Object System.Collections.Generic.List[string]
$rb.Add('@echo off')
$rb.Add("REM Retour arriere du CIS sur mesure du $ts ($TargetHost)")
$rb.Add('REM A lancer dans une invite de commandes EN ADMINISTRATEUR.')
$rb.Add('echo Restauration des cles de registre exportees...')
$rb.Add('for %%f in ("%~dp0registry\*.reg") do reg import "%%f" >nul 2>&1')
foreach ($o in @($regOps | Where-Object { $_.Op -eq 'reg-set' })) {
    if ($null -eq (Get-RegValue $o.Hive $o.Path $o.Name)) {
        $rb.Add(('reg delete "{0}\{1}" /v "{2}" /f >nul 2>&1' -f $o.Hive, $o.Path, $o.Name))
    }
}
foreach ($o in @($Ops | Where-Object { $_.Op -eq 'svc' })) {
    $st = Get-SvcStart $o.Service
    if ($st -and $st -notin 'boot', 'system') { $rb.Add(('sc config {0} start= {1} >nul 2>&1' -f $o.Service, $st)) }
}
if ($hasAudit) { $rb.Add('auditpol /restore /file:"%~dp0audit-avant.csv" >nul 2>&1') }
foreach ($k in 'lockoutwindow', 'lockoutduration', 'lockoutthreshold', 'uniquepw', 'minpwlen', 'minpwage', 'maxpwage') {
    if (@($Ops | Where-Object { $_.Op -eq 'acct' -and $_.Key -eq $k }).Count) {
        $old = $script:Acct[$k]
        $val = if ($null -ne $old) { $old } elseif ($k -eq 'maxpwage') { 'unlimited' } else { 0 }
        $rb.Add(('net accounts /{0}:{1} >nul 2>&1' -f $k, $val))
    }
}
if (@($Ops | Where-Object { $_.Op -eq 'guest' }).Count) {
    $g = $null
    try { $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1 } catch { }
    if ($g -and $g.Enabled) {
        $rb.Add('powershell -NoProfile -Command "Get-LocalUser | Where-Object { $_.SID.Value -match ''-501$'' } | Enable-LocalUser"')
    }
}
if ($policyDel -or $regOps.Count) { $rb.Add('gpupdate /target:computer /force >nul 2>&1') }
$rb.Add('echo Termine. REDEMARRER le poste pour que tout reprenne effet.')
$rb.Add('pause')
Set-Content -Path (Join-Path $backupDir 'Rollback.cmd') -Value $rb -Encoding ASCII
Write-Host "  Retour arriere pret : $backupDir\Rollback.cmd" -ForegroundColor Green

# -- Application ------------------------------------------------------------
Write-Host "`n-- Application ----------------------------------------------" -ForegroundColor Cyan
$fail = 0

# 1. Politique de comptes : un seul appel, dans un ordre qui respecte les
#    contraintes de net accounts.
$acctOps = @($Ops | Where-Object { $_.Op -eq 'acct' })
if ($acctOps.Count) {
    $netArgs = @(foreach ($k in 'maxpwage', 'minpwage', 'minpwlen', 'uniquepw', 'lockoutthreshold', 'lockoutduration', 'lockoutwindow') {
        $o = $acctOps | Where-Object { $_.Key -eq $k } | Select-Object -First 1
        if ($o) { "/$($k):$($o.Value)" }
    })
    $out = & net.exe accounts @netArgs 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Host ("  net accounts {0} : OK" -f ($netArgs -join ' ')) -ForegroundColor Green }
    else { $fail++; Write-Host ("  net accounts : ECHEC (code {0}) {1}" -f $LASTEXITCODE, ($out -join ' ')) -ForegroundColor Red }
}

# 2. Compte invite, par SID
foreach ($o in @($Ops | Where-Object { $_.Op -eq 'guest' })) {
    try {
        $g = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' } | Select-Object -First 1
        if ($g -and $g.Enabled) { Disable-LocalUser -SID $g.SID -ErrorAction Stop }
        Write-Host '  Compte invite : desactive.' -ForegroundColor Green
    } catch { $fail++; Write-Host "  Compte invite : ECHEC $($_.Exception.Message)" -ForegroundColor Red }
}

# 3. Audit, par GUID : on AJOUTE les indicateurs requis, on n'en retire aucun.
foreach ($o in @($Ops | Where-Object { $_.Op -eq 'audit' })) {
    $a = @("/subcategory:$($o.Guid)")
    if ($o.S) { $a += '/success:enable' }
    if ($o.F) { $a += '/failure:enable' }
    & auditpol.exe /set @a 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $fail++; Write-Host ("  audit {0} : ECHEC (code {1})" -f $o.Sub, $LASTEXITCODE) -ForegroundColor Red }
}

# 4. Registre : ecritures
foreach ($o in @($Ops | Where-Object { $_.Op -eq 'reg-set' })) {
    if (Test-Forbidden $o.Hive $o.Path $o.Name) { Write-Host "  REFUS (liste noire) $($o.Name)" -ForegroundColor Red; continue }
    $full = "$($o.Hive):\$($o.Path)"
    try {
        if (-not (Test-Path -LiteralPath $full)) { New-Item -Path $full -Force -ErrorAction Stop | Out-Null }
        switch ($o.Type) {
            'Multi' {
                $v = if ([string]::IsNullOrEmpty($o.Data)) { [string[]]@() } else { [string[]]($o.Data -split '\|') }
                New-ItemProperty -LiteralPath $full -Name $o.Name -Value $v -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
            }
            'String' {
                New-ItemProperty -LiteralPath $full -Name $o.Name -Value $o.Data -PropertyType String -Force -ErrorAction Stop | Out-Null
            }
            default {
                $n = [int64]$o.Data
                if ($n -gt [int32]::MaxValue) { $n -= 4294967296 }
                New-ItemProperty -LiteralPath $full -Name $o.Name -Value ([int32]$n) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
            }
        }
    } catch { $fail++; Write-Host ("  [{0}] {1} : ECHEC {2}" -f $o.Id, $o.Name, $_.Exception.Message) -ForegroundColor Red }
}

# 5. Registre : suppressions
foreach ($o in @($Ops | Where-Object { $_.Op -eq 'reg-del' })) {
    if (Test-Forbidden $o.Hive $o.Path $o.Name) { Write-Host "  REFUS (liste noire) $($o.Name)" -ForegroundColor Red; continue }
    try {
        if ($null -ne (Get-RegValue $o.Hive $o.Path $o.Name)) {
            Remove-ItemProperty -LiteralPath "$($o.Hive):\$($o.Path)" -Name $o.Name -Force -ErrorAction Stop
        }
    } catch { $fail++; Write-Host ("  [{0}] {1} : ECHEC {2}" -f $o.Id, $o.Name, $_.Exception.Message) -ForegroundColor Red }
}

# 6. Services
foreach ($o in @($Ops | Where-Object { $_.Op -eq 'svc' })) {
    if ($NeverTouchServices -contains $o.Service) { continue }
    if ($null -eq (Get-SvcStart $o.Service)) { Write-Host "  [absent] $($o.Service)" -ForegroundColor DarkGray; continue }
    & sc.exe config $o.Service start= $o.Start 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { $fail++; Write-Host ("  service {0} : ECHEC (code {1})" -f $o.Service, $LASTEXITCODE) -ForegroundColor Red; continue }
    if ($o.Start -eq 'disabled') { Stop-Service -Name $o.Service -Force -ErrorAction SilentlyContinue }
    elseif ($o.Start -like '*auto') { Start-Service -Name $o.Service -ErrorAction SilentlyContinue }
}

# 7. Strategies retirees : certains composants (alimentation, notamment)
#    gardent l'override en cache ; seul un rafraichissement le purge. Sans
#    lui, une suppression reussie semble ne pas prendre (constate le
#    2026-09-16 avec la veille).
if ($policyDel) {
    Write-Host '  gpupdate /target:computer /force ...' -ForegroundColor DarkGray
    'N' | & gpupdate.exe /target:computer /force > (Join-Path $backupDir 'gpupdate.txt') 2>&1
}

# -- Relecture : on mesure, on ne suppose pas -------------------------------
Write-Host "`n-- Relecture de chaque reglage ------------------------------" -ForegroundColor Cyan
$script:Acct  = Read-AccountPolicy
$script:Audit = Read-AuditMap
$okCount = 0
$report  = New-Object System.Collections.Generic.List[object]
for ($i = 0; $i -lt $Ops.Count; $i++) {
    $o = $Ops[$i]; $s = Get-OpState $o
    if ($s.Done) { $okCount++ }
    else { Write-Host ("  ECART [{0}] {1} -- relu : {2}" -f $o.Id, (Get-OpLabel $o), $s.Now) -ForegroundColor Red }
    $report.Add([ordered]@{ id = $o.Id; operation = (Get-OpLabel $o); avant = $pre[$i]; apres = $s.Now; conforme = [bool]$s.Done })
}
Write-Host ("  {0}/{1} operation(s) relue(s) conformes a la cible." -f $okCount, $Ops.Count) -ForegroundColor $(if ($okCount -eq $Ops.Count) { 'Green' } else { 'Yellow' })
$report | ConvertTo-Json -Depth 3 | Set-Content -Path (Join-Path $backupDir 'resultat.json') -Encoding UTF8

$after = Get-SafetySnapshot
Compare-SafetySnapshot $before $after

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host ("  TERMINE : {0} echec(s) d'execution, {1}/{2} relus conformes." -f $fail, $okCount, $Ops.Count) -ForegroundColor Green
Write-Host "  Sauvegarde et journal : $backupDir" -ForegroundColor Green
Write-Host "  Retour arriere        : $backupDir\Rollback.cmd (invite EN ADMINISTRATEUR)" -ForegroundColor Green
Write-Host '============================================================' -ForegroundColor Green
if ($CardMode) {
    Write-Host "AVANT DE REDEMARRER : garder un acces de secours (mot de passe Windows du compte)." -ForegroundColor Yellow
    Write-Host "  LSA ne recharge ses packages qu'au demarrage : une casse de la connexion par carte" -ForegroundColor Yellow
    Write-Host "  ne se verrait qu'a ce moment-la. Controle : certutil -scinfo." -ForegroundColor Yellow
}
Write-Host 'Plusieurs reglages ne prennent effet qu apres REDEMARRAGE.' -ForegroundColor Yellow
if ($transcript) { Stop-Transcript | Out-Null }
'@

function New-GeneratedScript($plan, $name) {
    # .ToArray() et non @() : sous PowerShell 5.1, @() sur une List[object]
    # de dictionnaires lève « Les types des arguments ne correspondent pas ».
    $ops = $plan.Ops.ToArray()
    # Dans un switch, $_ désigne la valeur testée : on nomme l'opération.
    $sum = (@(foreach ($o in $ops) {
        $label = switch ($o.Op) {
            'reg-set' { '{0}\{1} :: {2} = {3}' -f $o.Hive, $o.Path, $o.Name, $o.Data }
            'reg-del' { '{0}\{1} :: {2} -> supprimer' -f $o.Hive, $o.Path, $o.Name }
            'svc'     { 'service {0} -> {1}' -f $o.Service, $o.Start }
            'audit'   { 'audit {0}' -f $o.Sub }
            'acct'    { 'net accounts /{0}:{1}' -f $o.Key, $o.Value }
            'guest'   { 'compte invite -> desactive' }
        }
        '#    [{0}] {1}' -f $o.Id, $label
    })) -join "`r`n"
    $opsText   = (@($ops | ForEach-Object { '    ' + (ConvertTo-PsLiteral $_) }) -join "`r`n")
    $fvalsText = (@($ForbiddenValues | ForEach-Object { '    ' + (ConvertTo-PsLiteral $_) }) -join "`r`n")
    $engineFn  = (@('Get-RegValue', 'Test-Forbidden', 'Get-SafetySnapshot', 'Compare-SafetySnapshot') |
                  ForEach-Object { $script:EngineFn[$_] }) -join "`r`n`r`n"

    $t = $GeneratedTemplate
    $t = $t.Replace('__NAME__', $name).Replace('__HOST__', $env:COMPUTERNAME)
    $t = $t.Replace('__DATE__', (Get-Date -Format 'yyyy-MM-dd HH:mm')).Replace('__VER__', $ConsoleVersion)
    $t = $t.Replace('__SHA__', $script:EngineSha).Replace('__COUNT__', "$($ops.Count)")
    $t = $t.Replace('__CARDMODE__', $(if ($CardMode) { '$true' } else { '$false' }))
    $t = $t.Replace('__FIDS__', ((@($ForbiddenIds) | Sort-Object) -join ', '))
    $t = $t.Replace('__NEVER__', ((@($NeverTouchServices) | ForEach-Object { ConvertTo-PsLiteral $_ }) -join ', '))
    $t = $t.Replace('__DLLS__', ((@($SmartCardDlls) | ForEach-Object { ConvertTo-PsLiteral $_ }) -join ', '))
    # Les blocs volumineux en dernier : aucun jeton ne doit y être remplacé.
    $t = $t.Replace('__SUMMARY__', $sum).Replace('__OPS__', $opsText).Replace('__FVALS__', $fvalsText)
    $t = $t.Replace('__ENGINEFN__', $engineFn).Replace('__SHAREDFN__', $SharedFnText)
    return ($t -replace "`r?`n", "`r`n")
}

function Save-GeneratedScript($plan, $path) {
    $text = New-GeneratedScript $plan (Split-Path $path -Leaf)
    $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$e)
    if ($e.Count) { throw "script généré invalide : $($e[0].Message) (ligne $($e[0].Extent.StartLineNumber))" }
    $dir = Split-Path $path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($true)))
    # Ce qu'on croit avoir écrit n'est pas une preuve : on relit le disque.
    if ([IO.File]::ReadAllText($path) -ne $text) { throw "la relecture de $path ne correspond pas à ce qui a été écrit" }
    return $path
}

function Get-AutoPath {
    Join-Path $script:OutDir ("CIS-sur-mesure-{0}-{1}.ps1" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

# ============================================================================
#  Profils de choix (.json)
# ============================================================================
function Export-Choices($path) {
    $choices = @($script:Items | Where-Object { $_.Pending -or $_.IsCustom } | ForEach-Object {
        [ordered]@{ key = $_.Key; id = $_.Id; action = $_.Action; cible = $(if ($_.CanEditTarget) { $_.Target } else { $null }) }
    })
    $doc = [ordered]@{
        format = 'console-cis/1'; poste = $env:COMPUTERNAME; date = (Get-Date -Format s)
        moteur_sha256 = $script:EngineSha; choix = $choices
    }
    $dir = Split-Path $path -Parent
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    [IO.File]::WriteAllText($path, ($doc | ConvertTo-Json -Depth 5), (New-Object System.Text.UTF8Encoding($false)))
    return $choices.Count
}

function Import-Choices($path) {
    $doc = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($doc.format -ne 'console-cis/1') { throw "format de profil inconnu : $($doc.format)" }
    $byKey = @{}; foreach ($i in $script:Items) { $byKey[$i.Key] = $i }
    $ok = 0; $refused = New-Object System.Collections.Generic.List[string]
    $script:Bulk = $true
    try {
        foreach ($c in @($doc.choix)) {
            $it = $byKey[$c.key]
            if (-not $it) { $refused.Add("[$($c.id)] inconnu du moteur actuel"); continue }
            if ($it.CanEditTarget -and $null -ne $c.cible) { $it.Target = [string]$c.cible }
            if ($it.Choices -contains $c.action) { $it.Action = $c.action; $ok++ }
            elseif ($c.action -ne $Dash) { $refused.Add("[$($c.id)] « $($c.action) » n'est plus permis sur ce poste ($($it.LockLabel))") }
        }
    } finally { $script:Bulk = $false }
    $msg = "$ok choix repris depuis $(Split-Path $path -Leaf)"
    if ($doc.poste -and $doc.poste -ne $env:COMPUTERNAME) { $msg += " — profil fait sur $($doc.poste)" }
    if ($doc.moteur_sha256 -and $doc.moteur_sha256 -ne $script:EngineSha) { $msg += ' — le moteur a changé depuis' }
    return @{ Message = $msg; Refused = $refused }
}

function Invoke-Preset([string[]]$tiers) {
    $script:Bulk = $true; $n = 0
    try {
        foreach ($it in $script:Items) {
            if ($it.Code -notin 'reg', 'del', 'svc', 'aud', 'acc', 'guest', 'ban') { continue }
            if ($tiers -notcontains $it.Tier) { continue }
            if ($it.Lock) { continue }                                  # tout garde-fou écarte, comme le moteur
            if ($it.State -eq 'OK') { continue }
            if ($it.State -eq 'NR' -and $it.Code -ne 'aud') { continue } # on n'écrit pas à l'aveugle
            if ($it.Choices -notcontains 'Appliquer') { continue }
            if ($it.Action -ne 'Appliquer') { $it.Action = 'Appliquer'; $n++ }
        }
    } finally { $script:Bulk = $false }
    return $n
}

# ============================================================================
#  Mode vérification sans fenêtre
# ============================================================================
if ($SelfTest) {
    $script:Items = Import-PosteState
    Write-Host ("Moteur   : {0} (SHA-256 {1})" -f $script:EnginePath, $script:EngineSha.Substring(0, 16))
    Write-Host ("Poste    : {0} | admin={1} | carte={2} ({3})" -f $env:COMPUTERNAME, $isAdmin, $CardMode, $CardReason)
    Write-Host ("Profil   : {0}" -f ((Get-ProfileFlags $script:Machine) -join ' | '))
    Write-Host ("Score    : {0}/{1} (estimation -Verify)" -f $script:Score.Pass, $script:Score.Total)
    Write-Host ("Contrôles: {0}" -f $script:Items.Count)
    $script:Items | Group-Object Kind | Sort-Object Name | ForEach-Object {
        $g = $_.Group
        Write-Host ("  {0,-12} {1,4}  OK={2,-4} KO={3,-4} NR={4,-4} actionnables={5}" -f $_.Name, $_.Count,
            @($g | Where-Object State -eq 'OK').Count, @($g | Where-Object State -eq 'KO').Count,
            @($g | Where-Object State -eq 'NR').Count, @($g | Where-Object CanAct).Count)
    }
    Write-Host 'Verrous :'
    $script:Items | Where-Object Lock | Group-Object Lock | ForEach-Object { Write-Host ("  {0,-8} {1}" -f $_.Name, (($_.Group | ForEach-Object IdText) -join ' ')) }

    # Inventaire complet, pour relire le poste hors de la fenêtre.
    $csv = Join-Path $SelfTest ("inventaire-{0}.csv" -f $env:COMPUTERNAME)
    $script:Items | Select-Object Id, Kind, Tier, Family, State, Lock, Current, Target, Title, Guard, Setting |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8 -Delimiter ';'
    Write-Host "Inventaire : $csv"

    # -SelfTest -Choix <profil> : génère le script d'un profil, sans fenêtre.
    if ($Choix) {
        $r = Import-Choices $Choix
        Write-Host $r.Message
        $r.Refused | ForEach-Object { Write-Host "  NON REPRIS $_" -ForegroundColor Yellow }
        $plan = Get-Plan
        $plan.Warn | ForEach-Object { Write-Host "  AVERTISSEMENT $_" -ForegroundColor Yellow }
        $plan.Err  | ForEach-Object { Write-Host "  ERREUR $_" -ForegroundColor Red }
        Write-Host ("Plan     : {0} opération(s), {1} avertissement(s), {2} erreur(s)" -f $plan.Ops.Count, $plan.Warn.Count, $plan.Err.Count)
        if (-not $plan.Err.Count -and $plan.Ops.Count) {
            $out = Save-GeneratedScript $plan (Join-Path $SelfTest ("{0}.ps1" -f [IO.Path]::GetFileNameWithoutExtension($Choix)))
            Write-Host "Script   : $out"
        }
        exit 0
    }

    $n = Invoke-Preset @('1', '2')

    # Aller-retour d'un profil : ce qui est enregistré doit revenir à l'identique.
    $prof = Join-Path $SelfTest 'profil-selftest.json'
    $saved = Export-Choices $prof
    foreach ($i in $script:Items) { $i.Action = $Dash }
    $back = Import-Choices $prof
    $again = @($script:Items | Where-Object { $_.Pending }).Count
    Write-Host ("Profil   : {0} choix enregistrés, {1} repris, {2} refusé(s) — {3}" -f $saved, $again, $back.Refused.Count, $(if ($saved -eq $again) { 'OK' } else { 'ÉCART' }))

    # Chemins d'avertissement : un « Retirer » et une cible hors tolérance CIS.
    $ret = $script:Items | Where-Object { $_.Code -eq 'reg' -and $_.Choices -contains 'Retirer' -and $_.State -eq 'OK' } | Select-Object -First 1
    if ($ret) { $ret.Action = 'Retirer'; Write-Host "Essai    : Retirer sur [$($ret.Id)] $($ret.Setting)" }
    $cus = $script:Items | Where-Object { $_.Key -eq 'reg:26025' } | Select-Object -First 1
    if ($cus) { $cus.Target = '1200'; Write-Host "Essai    : cible 1200 sur [26025] (CIS : $($cus.Detail -replace "`n.*", ''))" }

    $plan = Get-Plan
    $plan.Warn | ForEach-Object { Write-Host "  AVERTISSEMENT $_" -ForegroundColor Yellow }
    Write-Host ("Présélection TIER 1+2 : {0} contrôle(s) -> {1} opération(s), {2} avertissement(s), {3} erreur(s)" -f $n, $plan.Ops.Count, $plan.Warn.Count, $plan.Err.Count)
    $plan.Err | ForEach-Object { Write-Host "  ERREUR $_" -ForegroundColor Red }
    $out = Save-GeneratedScript $plan (Join-Path $SelfTest ("selftest-{0}.ps1" -f $env:COMPUTERNAME))
    Write-Host "Script   : $out"
    $pe = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$pe)
    Write-Host ("Syntaxe  : script généré, {0} erreur(s)" -f @($pe).Count)
    Write-Host ''
    Write-Host (Get-PosteText)
    # Le code de sortie sert à la CI : un profil qui ne revient pas à l'identique,
    # une erreur de plan ou un script généré invalide font échouer l'auto-test.
    $fail = ($saved -ne $again) -or @($plan.Err).Count -or @($pe).Count
    exit $(if ($fail) { 1 } else { 0 })
}

# ============================================================================
#  Interface
# ============================================================================
$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Console CIS" Width="1400" Height="880" MinWidth="1080" MinHeight="620"
        WindowStartupLocation="CenterScreen" Background="#F3F4F6" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style TargetType="Button">
      <Setter Property="Background" Value="White"/>
      <Setter Property="Foreground" Value="#1F2937"/>
      <Setter Property="BorderBrush" Value="#C7CCD4"/>
      <Setter Property="Padding" Value="12,6"/>
      <Setter Property="Margin" Value="6,0,0,0"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}"
                    BorderThickness="1" CornerRadius="4" Padding="{TemplateBinding Padding}">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Opacity" Value="0.85"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
      <Setter Property="Background" Value="#1D4ED8"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="BorderBrush" Value="#1D4ED8"/>
    </Style>
    <Style x:Key="Label" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#6B7280"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
      <Setter Property="Margin" Value="14,0,6,0"/>
    </Style>
  </Window.Resources>

  <Grid Background="#F3F4F6">
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="Auto"/>
    </Grid.RowDefinitions>

    <!-- En-tête : poste, moteur, score -->
    <Border Grid.Row="0" Background="#111827" Padding="18,12">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <StackPanel Margin="0,0,18,0" ToolTip="Même calcul que Harden-Windows-CIS.ps1 -Verify : registre et services, hors audit et TIER 3.">
            <TextBlock x:Name="ScoreText" Foreground="White" FontSize="24" FontWeight="SemiBold" HorizontalAlignment="Right" Text="…"/>
            <TextBlock x:Name="ScoreSub" Foreground="#9CA3AF" FontSize="11" HorizontalAlignment="Right"/>
            <ProgressBar x:Name="ScoreBar" Height="5" Width="220" Margin="0,5,0,0" Minimum="0" Maximum="100"
                         Foreground="#22C55E" Background="#374151" BorderThickness="0"/>
          </StackPanel>
          <StackPanel VerticalAlignment="Center">
            <Border x:Name="AdminBadge" CornerRadius="3" Padding="8,3" Background="#92400E" HorizontalAlignment="Right">
              <TextBlock x:Name="AdminText" Foreground="White" FontSize="11"/>
            </Border>
            <Button x:Name="BtnElevate" Content="Relancer en administrateur" Margin="0,6,0,0" Padding="10,4" FontSize="12"/>
          </StackPanel>
        </StackPanel>
        <StackPanel VerticalAlignment="Center">
          <TextBlock x:Name="TitleText" Foreground="White" FontSize="19" FontWeight="SemiBold" Text="Console CIS"/>
          <TextBlock x:Name="ProfileText" Foreground="#D1D5DB" FontSize="12" TextWrapping="Wrap" Margin="0,3,0,0"/>
          <TextBlock x:Name="EngineText" Foreground="#6B7280" FontSize="11" Margin="0,3,0,0"/>
        </StackPanel>
      </DockPanel>
    </Border>

    <!-- Filtres -->
    <Border Grid.Row="1" Background="White" BorderBrush="#E5E7EB" BorderThickness="0,0,0,1" Padding="14,9">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal">
          <TextBlock x:Name="ShownText" Foreground="#6B7280" VerticalAlignment="Center" Margin="0,0,10,0"/>
          <Button x:Name="BtnRefresh" Content="Relire le poste"/>
        </StackPanel>
        <WrapPanel VerticalAlignment="Center">
          <TextBlock Text="Rechercher" Style="{StaticResource Label}" Margin="0,0,6,0"/>
          <TextBox x:Name="Search" Width="230" Padding="4,3" VerticalContentAlignment="Center"
                   ToolTip="ID, titre, clé de registre, famille, raison d'un garde-fou…"/>
          <TextBlock Text="Type" Style="{StaticResource Label}"/>
          <ComboBox x:Name="FKind" Width="130"/>
          <TextBlock Text="Famille" Style="{StaticResource Label}"/>
          <ComboBox x:Name="FFam" Width="135"/>
          <TextBlock Text="Palier" Style="{StaticResource Label}"/>
          <ComboBox x:Name="FTier" Width="135"/>
          <TextBlock Text="État" Style="{StaticResource Label}"/>
          <ComboBox x:Name="FState" Width="200"/>
        </WrapPanel>
      </DockPanel>
    </Border>

    <TabControl Grid.Row="2" Margin="10,10,10,0" Background="White" BorderBrush="#E5E7EB">
      <TabItem Header="  Contrôles  ">
        <Grid Margin="6">
          <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <DataGrid x:Name="Grid" AutoGenerateColumns="False" CanUserAddRows="False" CanUserDeleteRows="False"
                    CanUserResizeRows="False" HeadersVisibility="Column" GridLinesVisibility="Horizontal"
                    HorizontalGridLinesBrush="#F0F1F3" SelectionMode="Single" SelectionUnit="FullRow"
                    RowHeight="28" Background="White" BorderBrush="#E5E7EB" EnableRowVirtualization="True"
 ScrollViewer.CanContentScroll="True">
            <DataGrid.ColumnHeaderStyle>
              <Style TargetType="DataGridColumnHeader">
                <Setter Property="Background" Value="#F9FAFB"/>
                <Setter Property="Foreground" Value="#374151"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
                <Setter Property="Padding" Value="6,6"/>
                <Setter Property="BorderBrush" Value="#E5E7EB"/>
                <Setter Property="BorderThickness" Value="0,0,1,1"/>
              </Style>
            </DataGrid.ColumnHeaderStyle>
            <DataGrid.RowStyle>
              <Style TargetType="DataGridRow">
                <Style.Triggers>
                  <DataTrigger Binding="{Binding Pending}" Value="True">
                    <Setter Property="Background" Value="#FEF3C7"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding Lock}" Value="noire">
                    <Setter Property="Foreground" Value="#9CA3AF"/>
                  </DataTrigger>
                  <DataTrigger Binding="{Binding Lock}" Value="manuel">
                    <Setter Property="Foreground" Value="#9CA3AF"/>
                  </DataTrigger>
                </Style.Triggers>
              </Style>
            </DataGrid.RowStyle>
            <DataGrid.Columns>
              <DataGridTemplateColumn Header="Action" Width="112" SortMemberPath="Action">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <ComboBox ItemsSource="{Binding Choices}" IsEnabled="{Binding CanAct}" Height="23" FontSize="12"
                              Margin="2,0" VerticalContentAlignment="Center"
                              SelectedItem="{Binding Action, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"/>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTextColumn Header="ID" Binding="{Binding IdText}" Width="56" IsReadOnly="True" SortMemberPath="Id"/>
              <DataGridTextColumn Header="Type" Binding="{Binding Kind}" Width="88" IsReadOnly="True"/>
              <DataGridTextColumn Header="Palier" Binding="{Binding Tier}" Width="50" IsReadOnly="True"/>
              <DataGridTextColumn Header="Famille" Binding="{Binding Family}" Width="98" IsReadOnly="True"/>
              <DataGridTemplateColumn Header="Contrôle" Width="*" SortMemberPath="Title">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Title}" ToolTip="{Binding Title}" TextTrimming="CharacterEllipsis"
                               VerticalAlignment="Center" Margin="4,0"/>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTemplateColumn Header="Actuel" Width="130" SortMemberPath="Current">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding Current}" ToolTip="{Binding Current}" TextTrimming="CharacterEllipsis"
                               VerticalAlignment="Center" Margin="4,0" FontFamily="Consolas" FontSize="12"/>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTemplateColumn Header="Cible" Width="130" SortMemberPath="Target">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <TextBox Text="{Binding Target, Mode=TwoWay, UpdateSourceTrigger=LostFocus}" IsEnabled="{Binding CanEditTarget}"
                             ToolTip="{Binding Target}" VerticalContentAlignment="Center" Height="23" Margin="2,0"
                             FontFamily="Consolas" FontSize="12">
                      <TextBox.Style>
                        <Style TargetType="TextBox">
                          <Setter Property="BorderBrush" Value="#D1D5DB"/>
                          <Style.Triggers>
                            <Trigger Property="IsEnabled" Value="False">
                              <Setter Property="BorderThickness" Value="0"/>
                              <Setter Property="Background" Value="Transparent"/>
                            </Trigger>
                            <DataTrigger Binding="{Binding IsCustom}" Value="True">
                              <Setter Property="Foreground" Value="#B45309"/>
                              <Setter Property="FontWeight" Value="Bold"/>
                              <Setter Property="BorderBrush" Value="#F59E0B"/>
                            </DataTrigger>
                          </Style.Triggers>
                        </Style>
                      </TextBox.Style>
                    </TextBox>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTemplateColumn Header="État" Width="118" SortMemberPath="State">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding StateLabel}" VerticalAlignment="Center" Margin="4,0">
                      <TextBlock.Style>
                        <Style TargetType="TextBlock">
                          <Setter Property="Foreground" Value="#9CA3AF"/>
                          <Style.Triggers>
                            <DataTrigger Binding="{Binding State}" Value="OK"><Setter Property="Foreground" Value="#15803D"/></DataTrigger>
                            <DataTrigger Binding="{Binding State}" Value="KO">
                              <Setter Property="Foreground" Value="#B91C1C"/><Setter Property="FontWeight" Value="SemiBold"/>
                            </DataTrigger>
                          </Style.Triggers>
                        </Style>
                      </TextBlock.Style>
                    </TextBlock>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
              <DataGridTemplateColumn Header="Garde-fou" Width="136" SortMemberPath="Lock">
                <DataGridTemplateColumn.CellTemplate>
                  <DataTemplate>
                    <TextBlock Text="{Binding LockLabel}" ToolTip="{Binding Guard}" VerticalAlignment="Center" Margin="4,0"
                               TextTrimming="CharacterEllipsis" Foreground="#B45309"/>
                  </DataTemplate>
                </DataGridTemplateColumn.CellTemplate>
              </DataGridTemplateColumn>
            </DataGrid.Columns>
          </DataGrid>

          <!-- Détail du contrôle sélectionné -->
          <Border Grid.Row="1" Background="#F9FAFB" BorderBrush="#E5E7EB" BorderThickness="1" Margin="0,8,0,0"
                  Padding="12,9" Height="128" DataContext="{Binding SelectedItem, ElementName=Grid}">
            <ScrollViewer VerticalScrollBarVisibility="Auto">
              <Grid>
                <Grid.ColumnDefinitions>
                  <ColumnDefinition Width="*"/>
                  <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Margin="0,0,18,0">
                  <TextBlock x:Name="DetailHint" Text="Sélectionner une ligne pour voir le détail du contrôle." Foreground="#9CA3AF"/>
                  <TextBlock Text="{Binding Title}" FontWeight="SemiBold" TextWrapping="Wrap"/>
                  <TextBlock Text="{Binding Setting}" FontFamily="Consolas" FontSize="12" Foreground="#374151"
                             TextWrapping="Wrap" Margin="0,4,0,0"/>
                </StackPanel>
                <StackPanel Grid.Column="1">
                  <TextBlock Text="{Binding Guard}" Foreground="#B45309" FontWeight="SemiBold" TextWrapping="Wrap"/>
                  <TextBlock Text="{Binding Detail}" Foreground="#4B5563" TextWrapping="Wrap" Margin="0,3,0,0"/>
                </StackPanel>
              </Grid>
            </ScrollViewer>
          </Border>
        </Grid>
      </TabItem>
      <TabItem Header="  Poste et garde-fous  ">
        <TextBox x:Name="PosteBox" IsReadOnly="True" FontFamily="Consolas" FontSize="12" Margin="6" Padding="10"
                 BorderThickness="0" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto"/>
      </TabItem>
    </TabControl>

    <!-- Pied : choix et génération -->
    <Border Grid.Row="3" Background="White" BorderBrush="#E5E7EB" BorderThickness="0,1,0,0" Padding="14,10" Margin="0,10,0,0">
      <DockPanel>
        <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center">
          <Button x:Name="BtnPreset" Content="Présélection…"/>
          <Button x:Name="BtnClear" Content="Tout désélectionner"/>
          <Button x:Name="BtnLoad" Content="Charger un profil…"/>
          <Button x:Name="BtnSave" Content="Enregistrer le profil…"/>
          <Button x:Name="BtnExport" Content="Générer le script…"/>
          <Button x:Name="BtnSimulate" Content="Simuler"/>
          <Button x:Name="BtnApply" Content="Appliquer en administrateur…" Style="{StaticResource Primary}"/>
        </StackPanel>
        <StackPanel VerticalAlignment="Center" Margin="0,0,12,0">
          <TextBlock x:Name="PendingText" FontWeight="SemiBold" Foreground="#111827"/>
          <TextBlock x:Name="Status" Foreground="#6B7280" FontSize="12" TextWrapping="Wrap"/>
        </StackPanel>
      </DockPanel>
    </Border>
  </Grid>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader ([xml]$Xaml)
$script:Window = [Windows.Markup.XamlReader]::Load($reader)
$script:ui = @{}
foreach ($n in 'ScoreText','ScoreSub','ScoreBar','AdminBadge','AdminText','BtnElevate','TitleText','ProfileText','EngineText',
               'ShownText','BtnRefresh','Search','FKind','FFam','FTier','FState','Grid','DetailHint','PosteBox',
               'BtnPreset','BtnClear','BtnLoad','BtnSave','BtnExport','BtnSimulate','BtnApply','PendingText','Status') {
    $script:ui[$n] = $script:Window.FindName($n)
}
$script:Bulk  = $false
$script:View  = $null
$script:Items = New-Object 'System.Collections.Generic.List[CisConsole.Item]'
$script:Watch = $null

function Set-Status($msg) { $script:ui.Status.Text = $msg }

function Show-Message($text, $icon = 'Information', $buttons = 'OK') {
    return [System.Windows.MessageBox]::Show($script:Window, $text, 'Console CIS', $buttons, $icon)
}

function Invoke-Safe([scriptblock]$sb) {
    try { & $sb }
    catch {
        Set-Status ("Erreur : " + $_.Exception.Message)
        Show-Message ("Erreur inattendue :`n`n" + $_.Exception.Message + "`n" + $_.InvocationInfo.PositionMessage) 'Error' | Out-Null
    }
}

function Set-Busy($msg) {
    if ($msg) {
        $script:Window.Cursor = [System.Windows.Input.Cursors]::Wait
        Set-Status $msg
        $script:Window.Dispatcher.Invoke([action]{ }, [System.Windows.Threading.DispatcherPriority]::Render)
    } else {
        $script:Window.Cursor = $null
    }
}

function Update-View {
    if (-not $script:View) { return }
    try { [void]$script:ui.Grid.CommitEdit([System.Windows.Controls.DataGridEditingUnit]::Row, $true) } catch { }
    try { $script:View.Refresh() } catch { }
    $script:ui.ShownText.Text = "$($script:View.Count) / $($script:Items.Count) affichés"
}

function Update-Footer {
    $a = @($script:Items | Where-Object { $_.Action -eq 'Appliquer' }).Count
    $r = @($script:Items | Where-Object { $_.Action -eq 'Retirer' }).Count
    $c = @($script:Items | Where-Object { $_.IsCustom }).Count
    $t = if ($a + $r) { "$a à appliquer · $r à retirer" } else { 'Aucune action choisie' }
    if ($c) { $t += " · $c cible(s) modifiée(s)" }
    $script:ui.PendingText.Text = $t
    $has = ($a + $r) -gt 0
    $script:ui.BtnExport.IsEnabled   = $has
    $script:ui.BtnSimulate.IsEnabled = $has
    $script:ui.BtnApply.IsEnabled    = $has
    $script:ui.BtnSave.IsEnabled     = ($has -or $c -gt 0)
    $script:ui.BtnClear.IsEnabled    = $has
}

function Set-Combo($cb, $values) {
    $sel = $cb.SelectedItem
    $cb.ItemsSource = @($values)
    if ($sel -and @($values) -contains $sel) { $cb.SelectedItem = $sel } else { $cb.SelectedIndex = 0 }
}

function Update-Header {
    $m = $script:Machine
    $suffix = if ($script:IsPortable) { ' (portable)' } else { '' }
    $script:Window.Title = "Console CIS — $($m.Host)$suffix"
    $script:ui.TitleText.Text = "Console CIS — $($m.Host)$suffix"
    $script:ui.ProfileText.Text = "$($m.OS) · build $($m.Build) · " + ((Get-ProfileFlags $m) -join ' · ')
    $script:ui.EngineText.Text = "Moteur $(Split-Path $script:EnginePath -Leaf) · SHA-256 $($script:EngineSha.Substring(0, 16))… · $($script:EngineDate.ToString('yyyy-MM-dd')) · console $ConsoleVersion"
    if ($script:IsPortable) { $script:ui.EngineText.Text += " · données : $script:OutDir" }
    $s = $script:Score
    $pct = [math]::Round(100 * $s.Pass / [math]::Max($s.Total, 1))
    $script:ui.ScoreText.Text = "$pct %"
    $script:ui.ScoreSub.Text = "$($s.Pass) / $($s.Total) contrôles — estimation -Verify"
    $script:ui.ScoreBar.Value = $pct
    $bc = New-Object System.Windows.Media.BrushConverter
    if ($isAdmin) {
        $script:ui.AdminText.Text = 'Administrateur — lecture complète'
        $script:ui.AdminBadge.Background = $bc.ConvertFromString('#166534')
        $script:ui.BtnElevate.Visibility = 'Collapsed'
    } else {
        $script:ui.AdminText.Text = 'Lecture seule — audit et BitLocker illisibles'
        $script:ui.AdminBadge.Background = $bc.ConvertFromString('#92400E')
    }
}

$script:OnItemChanged = {
    param($sender, $e)
    if ($e.PropertyName -notin 'Action', 'Target') { return }
    if ($script:Bulk) { return }
    # Veille : une clé restante sous Policies\Power suffit à bloquer powercfg.
    if ($e.PropertyName -eq 'Action' -and $sender.Family -eq 'sleep' -and $sender.Action -eq 'Retirer') {
        $script:Bulk = $true
        try {
            foreach ($o in $script:Items) {
                if ($o.Family -eq 'sleep' -and $o.Choices -contains 'Retirer' -and $o.Action -ne 'Retirer') { $o.Action = 'Retirer' }
            }
        } finally { $script:Bulk = $false }
        Set-Status 'Veille : les contrôles 26281-26284 présents sont retirés ensemble — une seule clé restante suffit à faire refuser powercfg.'
    }
    Update-Footer
}

function Update-All {
    Set-Busy 'Lecture du poste (profil, registre, services, comptes)…'
    try {
        $keep = @{}
        foreach ($i in $script:Items) { if ($i.Pending -or $i.IsCustom) { $keep[$i.Key] = @{ Action = $i.Action; Target = $i.Target } } }
        $typed = Import-PosteState
        $lost = 0
        $script:Bulk = $true
        foreach ($i in $typed) {
            if ($keep.ContainsKey($i.Key)) {
                $k = $keep[$i.Key]
                if ($i.CanEditTarget -and $null -ne $k.Target) { $i.Target = $k.Target }
                if ($i.Choices -contains $k.Action) { $i.Action = $k.Action } elseif ($k.Action -ne $Dash) { $lost++ }
            }
            $i.add_PropertyChanged($script:OnItemChanged)
        }
        $script:Bulk = $false
        $script:Items = New-Object 'System.Collections.ObjectModel.ObservableCollection[CisConsole.Item]' (, $typed)
        $script:ui.Grid.ItemsSource = $script:Items
        $script:View = [System.Windows.Data.CollectionViewSource]::GetDefaultView($script:Items)
        $script:View.Filter = $script:FilterPred

        Set-Combo $script:ui.FKind  (@('Tous les types') + @($script:Items | ForEach-Object Kind | Sort-Object -Unique))
        Set-Combo $script:ui.FFam   (@('Toutes les familles') + @($script:Items | ForEach-Object Family | Sort-Object -Unique))
        Set-Combo $script:ui.FTier  (@('Tous les paliers') + @($script:Items | ForEach-Object Tier | Sort-Object -Unique))
        if (-not $script:ui.FState.ItemsSource) {
            Set-Combo $script:ui.FState @('Tous les états', 'Non conformes', 'Conformes', 'Illisibles', 'Actions choisies',
                                          'Cibles modifiées', 'Écartés par un garde-fou', 'Liste noire et TIER 3')
        }
        Update-Header
        Update-View
        Update-Footer
        $script:ui.PosteBox.Text = Get-PosteText
        $msg = "Poste lu à $(Get-Date -Format 'HH:mm:ss')."
        if ($lost) { $msg += " $lost choix abandonné(s) : plus permis dans le nouvel état du poste." }
        Set-Status $msg
    } finally {
        $script:Bulk = $false
        Set-Busy $null
    }
}

$script:FilterPred = [Predicate[object]]{
    param($o)
    $ui = $script:ui
    $q = "$($ui.Search.Text)".Trim()
    if ($q) {
        $hay = "$($o.Id) $($o.Title) $($o.Setting) $($o.Family) $($o.Guard) $($o.Current)"
        if ($hay.IndexOf($q, [StringComparison]::OrdinalIgnoreCase) -lt 0) { return $false }
    }
    if ($ui.FKind.SelectedIndex -gt 0 -and $o.Kind   -ne $ui.FKind.SelectedItem) { return $false }
    if ($ui.FFam.SelectedIndex  -gt 0 -and $o.Family -ne $ui.FFam.SelectedItem)  { return $false }
    if ($ui.FTier.SelectedIndex -gt 0 -and $o.Tier   -ne $ui.FTier.SelectedItem) { return $false }
    switch ($ui.FState.SelectedIndex) {
        1 { return ($o.State -eq 'KO') }
        2 { return ($o.State -eq 'OK') }
        3 { return ($o.State -eq 'NR') }
        4 { return [bool]$o.Pending }
        5 { return [bool]$o.IsCustom }
        6 { return ($o.Lock -in 'usage', 'dur', 'score', 'protege') }
        7 { return ($o.Lock -in 'noire', 'manuel') }
    }
    return $true
}

function Confirm-Plan($plan, $verb) {
    if ($plan.Err.Count) {
        Show-Message ("Génération refusée :`n`n" + (@($plan.Err) -join "`n")) 'Error' | Out-Null
        return $false
    }
    if (-not $plan.Ops.Count) {
        Show-Message "Aucune opération à générer : les valeurs à retirer sont peut-être déjà absentes." | Out-Null
        return $false
    }
    if ($plan.Warn.Count) {
        $lines = @($plan.Warn | Select-Object -First 18)
        if ($plan.Warn.Count -gt 18) { $lines += "… et $($plan.Warn.Count - 18) autre(s)" }
        $r = Show-Message ("Points d'attention avant de $verb :`n`n" + ($lines -join "`n") + "`n`nContinuer ?") 'Warning' 'YesNo'
        return ($r -eq 'Yes')
    }
    return $true
}

function Start-Watch($proc, $what) {
    $script:WatchProc = $proc
    $script:WatchWhat = $what
    $script:WatchStart = Get-Date
    if ($script:Watch) { $script:Watch.Stop() }
    $script:Watch = New-Object System.Windows.Threading.DispatcherTimer
    $script:Watch.Interval = [TimeSpan]::FromSeconds(2)
    $script:Watch.Add_Tick({
        $done = $true
        try { $done = $script:WatchProc.HasExited } catch { }
        if ($done) {
            $script:Watch.Stop()
            Invoke-Safe {
                Update-All
                $msg = "$($script:WatchWhat) terminé — poste relu à $(Get-Date -Format 'HH:mm:ss')."
                if ($script:WatchWhat -eq 'Application') {
                    $tr = Save-ExecutionTrace $script:WatchStart
                    if ($tr -and $tr.Illisible) {
                        $msg += " Sauvegarde non vérifiable : $($tr.Backup) est réservé aux administrateurs et cette console n'est pas élevée. Rollback.cmd est sur le poste ; pour le constater, relancer la console en administrateur."
                        Write-ParcLog 'application-relue' 'sauvegarde illisible : console non élevée (ProgramData\CIS-Console-Backup réservé aux administrateurs)'
                    } elseif ($tr) {
                        $msg += " Résultat copié dans $($tr.Copy) ; Rollback.cmd reste sur le poste : $($tr.Backup)"
                        Write-ParcLog 'application-relue' $tr.Backup
                    } else { Write-ParcLog 'application-relue' 'aucune sauvegarde trouvée (fenêtre fermée avant écriture ?)' }
                }
                Set-Status $msg
            }
        }
    })
    $script:Watch.Start()
}

# ---------------------------------------------------------------- événements
$script:ui.Search.Add_TextChanged({ Update-View })
foreach ($cb in 'FKind', 'FFam', 'FTier', 'FState') { $script:ui[$cb].Add_SelectionChanged({ Update-View }) }
$script:ui.Grid.Add_SelectionChanged({ $script:ui.DetailHint.Visibility = $(if ($script:ui.Grid.SelectedItem) { 'Collapsed' } else { 'Visible' }) })
$script:ui.BtnRefresh.Add_Click({ Invoke-Safe { Update-All } })

$presetMenu = New-Object System.Windows.Controls.ContextMenu
foreach ($p in @(
    @{ Label = 'TIER 1 — contrôles non conformes (comme -Apply)'; Tiers = @('1') }
    @{ Label = 'TIER 1 + 2 — non conformes (comme -Apply -IncludeOptional)'; Tiers = @('1', '2') })) {
    $mi = New-Object System.Windows.Controls.MenuItem
    $mi.Header = $p.Label
    $mi.Tag = $p.Tiers
    $mi.Add_Click({
        param($s, $e)
        Invoke-Safe {
            $n = Invoke-Preset ([string[]]$s.Tag)
            Update-Footer; Update-View
            Set-Status "Présélection : $n contrôle(s) ajouté(s). Les contrôles sous garde-fou, déjà conformes ou illisibles sont laissés de côté, comme le ferait le moteur."
        }
    })
    [void]$presetMenu.Items.Add($mi)
}
$script:ui.BtnPreset.ContextMenu = $presetMenu
$script:ui.BtnPreset.Add_Click({ $script:ui.BtnPreset.ContextMenu.PlacementTarget = $script:ui.BtnPreset; $script:ui.BtnPreset.ContextMenu.IsOpen = $true })

$script:ui.BtnClear.Add_Click({
    Invoke-Safe {
        $script:Bulk = $true
        try { foreach ($i in $script:Items) { $i.Action = $Dash } } finally { $script:Bulk = $false }
        Update-Footer; Update-View
        Set-Status 'Toutes les actions ont été retirées (les cibles modifiées sont conservées).'
    }
})

$script:ui.BtnSave.Add_Click({
    Invoke-Safe {
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'Profil de durcissement (*.json)|*.json'
        if (-not (Test-Path -LiteralPath $script:ProfileDir)) { New-Item -ItemType Directory -Path $script:ProfileDir -Force | Out-Null }
        $dlg.InitialDirectory = $script:ProfileDir
        # En portable, le nom proposé est celui que chaque poste précharge.
        $dlg.FileName = $(if ($script:ParcProfile) { Split-Path $script:ParcProfile -Leaf } else { "profil-cis-$($env:COMPUTERNAME).json" })
        if ($dlg.ShowDialog($script:Window)) {
            $n = Export-Choices $dlg.FileName
            Write-ParcLog 'profil-enregistre' "$n choix -> $(Split-Path $dlg.FileName -Leaf)"
            Set-Status "Profil enregistré : $n choix dans $($dlg.FileName)"
        }
    }
})

$script:ui.BtnLoad.Add_Click({
    Invoke-Safe {
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Profil de durcissement (*.json)|*.json'
        if (Test-Path -LiteralPath $script:ProfileDir) { $dlg.InitialDirectory = $script:ProfileDir }
        if ($dlg.ShowDialog($script:Window)) {
            $r = Import-Choices $dlg.FileName
            Update-Footer; Update-View
            Set-Status $r.Message
            if ($r.Refused.Count) { Show-Message ("$($r.Message)`n`nNon repris :`n" + (@($r.Refused) -join "`n")) 'Warning' | Out-Null }
        }
    }
})

$script:ui.BtnExport.Add_Click({
    Invoke-Safe {
        $plan = Get-Plan
        if (-not (Confirm-Plan $plan 'générer')) { return }
        $dlg = New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Filter = 'Script PowerShell (*.ps1)|*.ps1'
        if (-not (Test-Path -LiteralPath $script:OutDir)) { New-Item -ItemType Directory -Path $script:OutDir -Force | Out-Null }
        $dlg.InitialDirectory = $script:OutDir
        $dlg.FileName = Split-Path (Get-AutoPath) -Leaf
        if ($dlg.ShowDialog($script:Window)) {
            $p = Save-GeneratedScript $plan $dlg.FileName
            Write-ParcLog 'script-genere' "$($plan.Ops.Count) op. -> $(Split-Path $p -Leaf)"
            Set-Status "Script écrit ($($plan.Ops.Count) opérations) : $p — simulation par défaut, -Apply en administrateur pour appliquer."
        }
    }
})

$script:ui.BtnSimulate.Add_Click({
    Invoke-Safe {
        $plan = Get-Plan
        if ($plan.Err.Count) { Confirm-Plan $plan 'simuler' | Out-Null; return }
        if (-not $plan.Ops.Count) { Show-Message 'Aucune opération à simuler.' | Out-Null; return }
        $p = Save-GeneratedScript $plan (Get-AutoPath)
        Write-ParcLog 'simulation' "$($plan.Ops.Count) op. -> $(Split-Path $p -Leaf)"
        Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$p`"")
        Set-Status "Simulation lancée dans une fenêtre séparée (rien n'est écrit) : $p"
    }
})

$script:ui.BtnApply.Add_Click({
    Invoke-Safe {
        $plan = Get-Plan
        if (-not (Confirm-Plan $plan 'appliquer')) { return }
        $nA = @($script:Items | Where-Object { $_.Action -eq 'Appliquer' }).Count
        $nR = @($script:Items | Where-Object { $_.Action -eq 'Retirer' }).Count
        $txt = "Exécuter $($plan.Ops.Count) opération(s) sur $($env:COMPUTERNAME), en administrateur ?`n`n" +
               "  $nA contrôle(s) à appliquer, $nR à retirer.`n`n" +
               "Avant toute écriture : point de restauration, export .reg, sauvegarde de l'audit et des comptes, Rollback.cmd " +
               "(dans ProgramData\CIS-Console-Backup). Après : chaque réglage est relu.`n`n" +
               "Plusieurs réglages ne prennent effet qu'après redémarrage."
        if ($CardMode) { $txt += "`n`nPoste à connexion par carte : garder le mot de passe Windows sous la main AVANT de redémarrer." }
        if ((Show-Message $txt 'Question' 'YesNo') -ne 'Yes') { return }
        $p = Save-GeneratedScript $plan (Get-AutoPath)
        try {
            $proc = Start-Process powershell.exe -Verb RunAs -PassThru -ErrorAction Stop `
                        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$(ConvertTo-ElevatedPath $p)`"", '-Apply')
        } catch {
            Set-Status "Élévation refusée : rien n'a été exécuté. Le script reste disponible : $p"
            return
        }
        Write-ParcLog 'application-lancee' "$($plan.Ops.Count) op. ($nA appliquer, $nR retirer) -> $(Split-Path $p -Leaf)"
        Set-Status "Exécution en cours dans la fenêtre administrateur. La console relira le poste quand elle sera fermée."
        Start-Watch $proc 'Application'
    }
})

$script:ui.BtnElevate.Add_Click({
    Invoke-Safe {
        $a = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$(ConvertTo-ElevatedPath $PSCommandPath)`"")
        if ($Engine)         { $a += @('-Engine', "`"$(ConvertTo-ElevatedPath $script:EnginePath)`"") }
        if ($Portable)       { $a += '-Portable' }
        if ($SmartCardLogon) { $a += '-SmartCardLogon' }
        if ($NoSmartCard)    { $a += '-NoSmartCard' }
        # Les choix en cours survivent au changement de session.
        if (@($script:Items | Where-Object { $_.Pending -or $_.IsCustom }).Count) {
            $tmp = Join-Path $script:OutDir '_session-en-cours.json'
            [void](Export-Choices $tmp)
            $a += @('-Choix', "`"$(ConvertTo-ElevatedPath $tmp)`"")
        }
        try { Start-Process powershell.exe -Verb RunAs -ArgumentList $a -ErrorAction Stop }
        catch { Set-Status "Élévation refusée : la console reste en lecture seule."; return }
        $script:Window.Close()
    }
})

if (-not $Snapshot) { $script:Window.Add_ContentRendered({
    Invoke-Safe {
        Update-All
        Write-ParcLog 'ouverture' "console $ConsoleVersion, moteur $($script:EngineSha.Substring(0, 16))"
        # Le profil de parc n'est qu'une présélection : rien ne part sans les
        # boutons, et ce que ce poste interdit est refusé et énuméré.
        $src = if ($Choix) { $Choix } elseif ($script:ParcProfile -and (Test-Path -LiteralPath $script:ParcProfile)) { $script:ParcProfile }
        if ($src -and (Test-Path -LiteralPath $src)) {
            $r = Import-Choices $src
            Update-Footer; Update-View
            Set-Status $r.Message
            if (-not $Choix -and $r.Refused.Count) {
                Show-Message ("Profil de parc préchargé — $($r.Message)`n`nNon repris sur ce poste :`n" + (@($r.Refused) -join "`n")) 'Warning' | Out-Null
            }
        }
        if ($script:PortableNote) { Set-Status $script:PortableNote }
    }
}) }

# ---------------------------------------------------------------- rendu hors écran
if ($Snapshot) {
    $w = $script:Window
    $w.WindowStartupLocation = 'Manual'; $w.Left = -32000; $w.Top = -32000
    $w.ShowInTaskbar = $false; $w.ShowActivated = $false
    $w.Show()
    Update-All
    if ($Choix -and (Test-Path -LiteralPath $Choix)) { [void](Import-Choices $Choix) } else { [void](Invoke-Preset @('1', '2')) }
    Update-Footer; Update-View
    $script:ui.FState.SelectedIndex = 1
    $first = $script:Items | Where-Object { $_.Pending } | Select-Object -First 1
    if ($first) { $script:ui.Grid.SelectedItem = $first }
    $w.UpdateLayout()
    $w.Dispatcher.Invoke([action]{ }, [System.Windows.Threading.DispatcherPriority]::ApplicationIdle)
    $c = $w.Content
    $rtb = New-Object System.Windows.Media.Imaging.RenderTargetBitmap([int]$c.ActualWidth, [int]$c.ActualHeight, 96, 96, [System.Windows.Media.PixelFormats]::Pbgra32)
    $rtb.Render($c)
    $enc = New-Object System.Windows.Media.Imaging.PngBitmapEncoder
    $enc.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($rtb))
    $fs = [IO.File]::Create($Snapshot)
    try { $enc.Save($fs) } finally { $fs.Close() }
    $w.Close()
    exit 0
}

[void]$script:Window.ShowDialog()
