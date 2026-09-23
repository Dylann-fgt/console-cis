# ============================================================================
#  Harden-Windows-CIS.ps1 -- Durcissement CIS Windows 11, version GENERALISEE
#
#  Successeur de Harden-CIS-Win11.ps1 (2026-07-21, taille pour POSTE-01) et de
#  Finish-CIS-Win11.ps1 (2026-07-22). Reecrit le 2026-07-25 pour etre pose sur
#  N'IMPORTE QUEL poste Windows 11, sans le connaitre a l'avance.
#
#  CE QUI CHANGE PAR RAPPORT A L'ANCIEN SCRIPT
#  -------------------------------------------
#  1. COUVERTURE COMPLETE. L'ancien script ne portait que les 361 controles
#     REELLEMENT EN ECHEC sur POSTE-01 : les 115 qui y passaient deja n'y
#     etaient pas, alors qu'ils peuvent echouer ailleurs. Les tables de ce
#     script sont extraites des 482 controles du fichier de regles Wazuh
#       C:\Program Files (x86)\ossec-agent\ruleset\sca\cis_win11_enterprise.yml
#     (CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0), c'est-a-dire
#     du fichier que Wazuh utilise LUI-MEME pour verifier. Aucune valeur n'est
#     devinee : chemin, nom et donnee sont repris textuellement de la regle.
#
#  2. PROFIL DE LA MACHINE. Le script commence par interroger le poste
#     (imprimantes, Bluetooth, WSL, RDP, partages, BitLocker, compte
#     Microsoft, domaine, lecteur de carte a puce...) et n'applique pas les
#     controles qui casseraient un usage constate. Un controle ignore est
#     ecrit dans le rapport avec sa raison, jamais passe sous silence.
#
#  3. DEUX GARDE-FOUS DURS, verifies AVANT et APRES l'execution :
#       - la protection LSA (LSASS en Protected Process Light, RunAsPPL) n'est
#         JAMAIS activee -- controles 26269 et 26270 mis en liste noire dans
#         le code, pas seulement absents des tables ;
#       - les services de la carte a puce (SCardSvr, ScDeviceEnum, SCPolicySvc,
#         CertPropSvc) ne sont jamais desactives, et leur etat est compare
#         avant/apres.
#     Motif : le 2026-07-21, deux controles LSASS s'etaient glisses dans le
#     palier automatique. LSASS en PPL refuse de charger un CSP non signe pour
#     PPL -> l'ouverture de session par carte GIDS echoue. Un filtre par mot
#     clef "smart card" ne suffit pas : ces controles parlent de "LSASS".
#
#  REVISION DU 2026-08-03 -- PROFIL "CARTE A PUCE"
#  -----------------------------------------------
#  Ce poste ouvre sa session Windows par carte a puce GIDS grace a un package
#  d'authentification TIERS charge dans LSASS (EIDAuthenticate). TROIS reglages
#  tuent cette pile, pas un seul :
#    (a) RunAsPPL / RunAsPPLBoot -- LSASS en PPL refuse un CSP non signe PPL ;
#    (b) AllowCustomSSPsAPs = 0  -- interdit explicitement le package tiers ;
#    (c) LsaCfgFlags (Credential Guard, controle 26229) -- LSA isole par le
#        hyperviseur ne charge AUCUN package d'authentification tiers, et le
#        verrou UEFI ne se retire pas sans acces physique a la machine.
#  (c) etait le trou de la version du 2026-07-25 : la liste noire ne portait
#  que (a) et (b), pendant que -EnableVBS ecrivait LsaCfgFlags sans que rien
#  ne s'y oppose. Un seul passage avec cette option et la carte ne rouvrait
#  plus de session, avec un retour arriere bloque par le verrou UEFI.
#  Depuis cette revision :
#    - le profil carte a puce est DETECTE (DLL EID presentes ET packages
#      declares dans HKLM\...\Control\Lsa), forcable par -SmartCardLogon et
#      annulable par -NoSmartCard ;
#    - quand il est actif, TOUT le bloc VBS/Credential Guard (26225-26230)
#      passe en liste noire et -EnableVBS REFUSE de s'executer au lieu de
#      casser la connexion ;
#    - les trois listes de packages LSA sont elles aussi intouchables ;
#    - l'instantane avant/apres couvre la pile complete : RunAsPPL,
#      AllowCustomSSPsAPs, LsaCfgFlags, Credential Guard en cours, les 3 DLL
#      EID, les 3 listes de packages et les 4 services de la carte.
#  -Verify n'exige plus les droits administrateur : il ne fait que lire.
#
#  REVISION DU 2026-08-03 (soir) -- GARDE-FOU "WEBCAM"
#  ----------------------------------------------------
#  Le controle 26352 "Allow Use of Camera" ecrit AllowCamera = 0 et coupe la
#  camera pour TOUTES les applications de la machine. Le symptome ne designe
#  pas sa cause : l'application annonce qu'aucune camera n'est disponible,
#  alors que le peripherique est en etat OK et que les autorisations de
#  confidentialite sont sur "Autoriser". On cherche du cote du pilote, la
#  cause est une strategie de groupe. Constate sur POSTE-01, ou l'ancien
#  Harden-CIS-Win11.ps1 l'avait pose le 2026-07-21.
#  26352 passe donc en famille 'camera' et sous garde-fou : il est ECARTE des
#  qu'une webcam est reconnue par Windows, avec sa raison imprimee.
#  -IgnoreGuards l'applique quand meme (poste sans usage video assume).
#  Pour lever le blocage sur un poste deja durci : scripts/ (non publies) 
#  debloquer-camera.ps1 -Apply.
#
#  4. INDEPENDANCE DE LA LANGUE. auditpol est adresse par GUID (l'appel par
#     nom echoue en erreur 87 sur un Windows francais) et les comptes integres
#     par SID (-500 / -501) plutot que par les noms "Administrator"/"Guest".
#
#  5. RETOUR ARRIERE REEL. La sauvegarde produit un Rollback.cmd pret a
#     l'emploi qui reimporte toutes les cles exportees.
#
#  6. MODE VERIFICATION. -Verify relit le poste et calcule un score estime,
#     sans Wazuh et sans rien modifier. Utile sur une machine ou l'agent n'est
#     pas installe, ou pour mesurer avant/apres sans attendre le scan SCA.
#
#  PALIERS
#  -------
#    TIER 1  (-Apply)                  reglages sans effet visible sur l'usage
#    TIER 2  (-Apply -IncludeOptional) services, ASR, Store, winget, veille,
#                                      RDP, banniere... -> visible a l'usage
#    TIER 3  (jamais automatique)      liste en fin de rapport, decision humaine
#    LISTE NOIRE                       26269 / 26270 toujours ; + 26225-26230
#                                      des que le profil carte a puce est actif
#
#  SECURITE DE L'OPERATION
#    Sans -Apply : simulation pure, aucune ecriture.
#    Avec -Apply : point de restauration + export .reg de toutes les cles
#    touchees + Rollback.cmd, avant la moindre modification.
#    PowerShell EN ADMINISTRATEUR obligatoire (pas d'auto-elevation).
#    Plusieurs reglages ne prennent effet qu'apres REDEMARRAGE.
# ============================================================================

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
# sans message clair -- constate le 2026-07-21, la sauvegarde s'arretait apres
# 8 cles des qu'une cle inexistante etait rencontree. Chaque etape sensible a
# son propre try/catch avec -ErrorAction Stop explicite.
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
# Ces controles ne sont JAMAIS appliques, quelles que soient les options.
# Ils sont declares ici, dans le code, et pas seulement absents des tables :
# une regeneration future des tables ne peut pas les reintroduire par erreur
# sans declencher l'assertion Assert-NoForbiddenWrite.
#
# SOCLE -- vaut sur TOUTE machine, avec ou sans carte a puce. La protection
# LSA reste desactivee sur ce parc : c'est une decision prise, pas un oubli.
$ForbiddenIds = @(26269, 26270)
$ForbiddenValues = @(
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='RunAsPPL' }
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='RunAsPPLBoot' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System';             Name='AllowCustomSSPsAPs' }
    # Les trois listes ou vit le package d'authentification de la carte
    # (EIDAuthenticationPackage / EIDPasswordChangeNotification). Aucun
    # controle CIS ne les ecrit aujourd'hui ; les y mettre garantit qu'aucune
    # regeneration future des tables ne pourra les ecraser en silence.
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='Authentication Packages' }
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='Security Packages' }
    @{ Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';                   Name='Notification Packages' }
)

# EXTENSION "CARTE A PUCE" -- ajoutee a l'execution par Set-SmartCardPolicy
# des que le profil carte a puce est actif (detecte ou -SmartCardLogon).
# Credential Guard isole LSA dans l'hyperviseur : un package d'authentification
# TIERS n'y est plus charge du tout, et le verrou UEFI de 26229 ne se retire
# pas sans acces physique. HVCI (26227) bloque en prime le chargement d'un
# module non signe dans LSASS -- la pile OpenSC/EID n'y survit pas.
$SmartCardForbiddenIds = @(26225, 26226, 26227, 26228, 26229, 26230)
$SmartCardForbiddenValues = @(
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='LsaCfgFlags' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='EnableVirtualizationBasedSecurity' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='RequirePlatformSecurityFeatures' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HypervisorEnforcedCodeIntegrity' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HVCIMATRequired' }
    @{ Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='ConfigureKernelShadowStacksLaunch' }
)

# Les 3 DLL qui portent la connexion par carte sur un compte LOCAL. Leur
# disparition avait mis la connexion par carte a terre le 2026-07-21 (un
# desinstalleur tiers les avait emportees) : le script les releve avant et
# apres, il ne les touche jamais.
$SmartCardDlls = @(
    'EIDAuthenticationPackage.dll',
    'EIDPasswordChangeNotification.dll',
    'EIDCredentialProvider.dll'
)
# Services indispensables a la carte a puce et a la supervision : jamais
# desactives, meme si un futur CIS les listait.
$NeverTouchServices = @(
    'SCardSvr',      # Carte a puce
    'ScDeviceEnum',  # Enumeration des peripheriques de carte a puce
    'SCPolicySvc',   # Strategie de retrait de la carte a puce
    'CertPropSvc',   # Propagation du certificat
    'WazuhSvc',      # agent Wazuh (XDR)
    'wazuh',
    'SupervisionAgent'
) + $KeepService

