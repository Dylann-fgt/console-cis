<#
.SYNOPSIS
    Durcissement CIS de Windows 11, avec garde-fous d'usage et retour arriere.

.DESCRIPTION
    Applique le CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 tel que le
    verifie le module SCA de Wazuh (cis_win11_enterprise.yml, 482 controles).
    Chemin, nom et donnee de chaque reglage sont repris textuellement de la
    regle Wazuh : aucune valeur n'est devinee.

    Sans -Apply, le script SIMULE : il lit le poste et dit ce qu'il ferait.
    Avec -Apply, il sauvegarde AVANT d'ecrire (point de restauration, export
    de chaque cle touchee, Rollback.cmd), applique, puis relit.

    Avant d'agir, il dresse le profil de la machine (imprimante, Bluetooth,
    webcam, WSL, serveur SSH, RDP, partages, BitLocker, compte Microsoft, code
    PIN, domaine, carte a puce, etats de veille...) et ECARTE les controles
    qui casseraient un usage constate. Chaque controle ecarte est imprime avec
    sa raison : rien n'est passe sous silence.

    PALIERS
      TIER 1   -Apply                    reglages sans effet visible a l'usage
      TIER 2   -Apply -IncludeOptional   services, ASR, Store, winget, veille,
                                         RDP, banniere... visibles a l'usage
      TIER 3   jamais automatique        liste en fin de rapport, avec la raison
      Score    -ScoreOnly                controles qui font gagner du score en
                                         degradant la securite reelle

    GARDE-FOUS D'USAGE -- -IgnoreGuards passe outre
      Imprimante, Bluetooth, webcam, WSL, SSH, RDP, partages, geolocalisation,
      Xbox, notifications, BitLocker, LAPS, compte Microsoft, code PIN.

    GARDE-FOUS DURS -- -IgnoreGuards ne les leve PAS
      Carte a puce. Si le poste ouvre sa session par carte a puce grace a un
        package d'authentification tiers (EIDAuthenticate), la protection LSA
        (26269, 26270) et le bloc VBS / Credential Guard (26225-26230) passent
        en LISTE NOIRE : LSASS en processus protege, ou isole par
        l'hyperviseur, ne charge plus ce package, et le verrou UEFI ne se
        retire pas sans acces physique. -EnableVBS refuse alors de tourner.
        Hors de ce profil, ces controles sont en TIER 3.
      Veille. Sur un poste sans Modern Standby (S0), 26281-26284 supprimeraient
        le DERNIER etat de veille et renverraient toute mise en veille sur la
        veille prolongee : une reprise ratee y jette les ecritures en cache.
        Un etat de veille illisible bloque aussi.

    La liste noire est verifiee a chaque execution : si une table la viole, le
    script s'arrete avec le code 2 sans rien ecrire.

    Independant de la langue de Windows : auditpol est adresse par GUID, les
    comptes integres par SID (-500, -501).

.PARAMETER Apply
    Applique les changements. Sans lui : simulation, rien n'est ecrit.
    Exige une PowerShell en administrateur (pas d'auto-elevation).

.PARAMETER IncludeOptional
    Ajoute le TIER 2 (services, ASR, Store, veille, RDP, banniere...).

.PARAMETER Verify
    Lit le poste et estime le score CIS, sans Wazuh et sans rien ecrire. Ne
    demande pas l'elevation ; quelques cles et l'etat BitLocker restent alors
    illisibles (BitLocker est suppose actif).

.PARAMETER EnableVBS
    Applique aussi le bloc VBS / Credential Guard (26225-26230), avec verrou
    UEFI. Refuse (code 2) si le profil carte a puce est actif.

.PARAMETER SmartCardLogon
    Impose le profil carte a puce. Sans ce commutateur, il est detecte.

.PARAMETER NoSmartCard
    Declare que ce poste n'ouvre PAS de session par carte a puce, meme si un
    lecteur est branche.

.PARAMETER StrictNTLM
    26061 : refuser le NTLM sortant (2) au lieu de l'auditer (1). Peut couper
    l'acces aux partages SMB et aux NAS.

.PARAMETER StrictNetBIOS
    26192 : desactiver NetBIOS partout (0) au lieu des seuls reseaux publics
    (2). Peut casser la decouverte de NAS et d'imprimantes.

.PARAMETER ScoreOnly
    Applique aussi les controles qui font gagner du score en degradant la
    securite reelle (26389 : couper la protection cloud de Defender).

.PARAMETER IgnoreGuards
    Applique meme les controles qui casseraient un usage detecte. Ne leve pas
    les garde-fous durs.

.PARAMETER SkipFamily
    Familles de controles a exclure, ex. -SkipFamily store,winget,sleep

.PARAMETER KeepService
    Services a ne jamais desactiver, en plus des services proteges.

.PARAMETER LegalNoticeTitle
    Titre de la banniere affichee avant l'ouverture de session (TIER 2).

.PARAMETER LegalNoticeText
    Texte de la banniere affichee avant l'ouverture de session (TIER 2).

.EXAMPLE
    .\Harden-Windows-CIS.ps1 -Verify
    Score estime du poste ; rien n'est modifie.

.EXAMPLE
    .\Harden-Windows-CIS.ps1 -IncludeOptional
    Simulation TIER 1 + 2 : ce qui serait applique, et ce qui serait ecarte.

.EXAMPLE
    .\Harden-Windows-CIS.ps1 -Apply
    Applique le TIER 1, dans une PowerShell en administrateur. Redemarrer.

.NOTES
    Codes de sortie : 0 succes ; 1 -Apply sans droits administrateur ;
    2 liste noire violee par une table, ou -EnableVBS sur un poste a carte.

    Sauvegarde et journal : %LOCALAPPDATA%\CIS-Hardening-Backup\<date>\
    (harden.log, exports .reg, Rollback.cmd). Plusieurs reglages ne prennent
    effet qu'apres un redemarrage.

    Ce fichier est ASSEMBLE par tools\assemble.ps1 a partir de
    tools\engine-head.ps1, des tables et de tools\engine-tail.ps1 : on modifie
    les sources, jamais ce fichier. Historique : CHANGELOG.md.
#>
# Aide ci-dessus : aucune ligne ne doit commencer par un point hors des
# mots-cles (.SYNOPSIS...). PowerShell la prendrait pour un mot-cle inconnu
# et ignorerait l'aide entiere, sans message.

[CmdletBinding()]
param(
    [switch]$Apply,             # sans ce commutateur : simulation
    [switch]$IncludeOptional,   # ajoute le TIER 2
    [switch]$Verify,            # relit le poste et calcule le score, sans rien ecrire
    [switch]$EnableVBS,         # opt-in explicite : VBS / Credential Guard (26225-26230)
    [switch]$SmartCardLogon,    # force le profil carte a puce (sinon : detecte)
    [switch]$NoSmartCard,       # declare que ce poste n'ouvre PAS de session par carte
    [switch]$StrictNTLM,        # RestrictSendingNTLMTraffic = 2 (refuser) au lieu de 1 (auditer)
    [switch]$StrictNetBIOS,     # EnableNetbios = 0 (partout) au lieu de 2 (reseaux publics)
    [switch]$ScoreOnly,         # controles qui gagnent du score en degradant la securite reelle
    [switch]$IgnoreGuards,      # applique meme les controles qui casseraient un usage detecte
    [string[]]$SkipFamily = @(),# familles a exclure, ex. -SkipFamily store,winget,sleep
    [string[]]$KeepService = @(),# services a ne jamais desactiver, en plus des garde-fous
    [string]$LegalNoticeTitle = "Ordinateur personnel",
    [string]$LegalNoticeText  = "Acces reserve a l'utilisateur autorise. Toute utilisation est journalisee."
)

# PAS de $ErrorActionPreference = "Stop" global : ce script enchaine des
# commandes NATIVES (reg.exe, net.exe, auditpol.exe). Sous "Stop", une seule
# d'entre elles ecrivant sur stderr leve une exception qui tue tout le script
# sans message clair -- la sauvegarde s'arretait ainsi apres quelques cles des
# qu'une cle inexistante etait rencontree. Chaque etape sensible a son propre
# try/catch avec -ErrorAction Stop explicite.
$ErrorActionPreference = "Continue"
$ProgressPreference    = "SilentlyContinue"

$ts        = Get-Date -Format "yyyyMMdd-HHmmss"
$backupDir = Join-Path $env:LOCALAPPDATA "CIS-Hardening-Backup\$ts"
$logPath   = Join-Path $backupDir "harden.log"

function Write-Log($msg, $color = "Gray") {
    Write-Host $msg -ForegroundColor $color
    if (Test-Path $backupDir) { Add-Content -Path $logPath -Value "$(Get-Date -Format o)  $msg" }
}

# -- 0. Droits administrateur ---------------------------------------------
# -Verify ne fait que LIRE : l'exiger en administrateur n'apportait rien et
# empechait de mesurer un poste depuis une session ordinaire. Tout ce qui
# ECRIT (-Apply) reste reserve a une PowerShell elevee.
$id      = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and $Apply) {
    Write-Host "-Apply doit etre execute dans une PowerShell EN ADMINISTRATEUR." -ForegroundColor Red
    Write-Host "Clic droit sur PowerShell -> Executer en tant qu'administrateur, puis :" -ForegroundColor Yellow
    Write-Host "  $($MyInvocation.MyCommand.Path) -Apply" -ForegroundColor Yellow
    exit 1
}
if (-not $isAdmin) {
    Write-Host "Session non elevee : lecture seule. Certaines cles peuvent etre illisibles." -ForegroundColor DarkYellow
}

# ============================ LISTE NOIRE ================================
# Ce qui figure ici n'est JAMAIS ecrit, quelles que soient les options. C'est
# declare dans le code, et pas seulement absent des tables : une regeneration
# future des tables ne peut pas le reintroduire par erreur sans declencher
# l'assertion Assert-NoForbiddenWrite (arret, code 2).
#
# SOCLE -- vaut sur TOUTE machine. Aucun controle : seulement les trois listes
# ou vivent les packages d'authentification de LSA. Aucun controle CIS ne les
# ecrit aujourd'hui ; les declarer garantit qu'aucune regeneration future des
# tables ne pourra les ecraser en silence. C'est leur alteration qui fait
# tomber une ouverture de session par carte a puce.
$ForbiddenIds = @()
$ForbiddenValues = @(
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='Authentication Packages' }
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='Security Packages' }
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='Notification Packages' }
)

# EXTENSION "CARTE A PUCE" -- ajoutee a l'execution par Set-SmartCardPolicy
# des que le profil carte a puce est actif (detecte ou -SmartCardLogon). Hors
# de ce profil, ces controles restent en TIER 3 : affiches, jamais automatises.
#   - Protection LSA (26269, 26270). AllowCustomSSPsAPs = 0 interdit
#     explicitement les packages d'authentification tiers ; LSASS en
#     processus protege (RunAsPPL) refuse tout module non signe pour PPL. Dans
#     les deux cas, le package de la carte n'est plus charge.
#   - VBS / Credential Guard (26225-26230). LSA isole par l'hyperviseur ne
#     charge aucun package d'authentification tiers, et le verrou UEFI de
#     26229 ne se retire pas sans acces physique. HVCI (26227) bloque en prime
#     le chargement d'un module non signe dans LSASS.
$SmartCardForbiddenIds = @(26225, 26226, 26227, 26228, 26229, 26230, 26269, 26270)
$SmartCardForbiddenValues = @(
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';            Name='RunAsPPL' }
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';            Name='RunAsPPLBoot' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System';      Name='AllowCustomSSPsAPs' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='LsaCfgFlags' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='EnableVirtualizationBasedSecurity' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='RequirePlatformSecurityFeatures' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HypervisorEnforcedCodeIntegrity' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HVCIMATRequired' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='ConfigureKernelShadowStacksLaunch' }
)

# Les 3 DLL qui portent la connexion par carte sur un compte LOCAL
# (EIDAuthenticate). Leur disparition suffit a faire tomber la connexion par
# carte -- un desinstalleur tiers les a deja emportees : le script les releve
# avant et apres, il ne les touche jamais.
$SmartCardDlls = @(
    'EIDAuthenticationPackage.dll',
    'EIDPasswordChangeNotification.dll',
    'EIDCredentialProvider.dll'
)
# Services jamais desactives, meme si un futur CIS les listait : la pile de la
# carte a puce, et les agents de supervision (Wazuh ; SupervisionAgent est
# l'agent d'un projet de supervision distinct). Un service absent du poste est
# simplement ignore. -KeepService en ajoute d'autres.
$NeverTouchServices = @(
    'SCardSvr',      # Carte a puce
    'ScDeviceEnum',  # Enumeration des peripheriques de carte a puce
    'SCPolicySvc',   # Strategie de retrait de la carte a puce
    'CertPropSvc',   # Propagation du certificat
    'WazuhSvc',      # agent Wazuh
    'wazuh',
    'SupervisionAgent'
) + $KeepService

