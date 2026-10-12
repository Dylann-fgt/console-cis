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


# ============================ TABLES DE DONNEES ==========================
#  Genere le 2026-10-12 par tools/ depuis
#    C:\Program Files (x86)\ossec-agent\ruleset\sca\cis_win11_enterprise.yml
#  (CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0, 482 controles).
#  Ne pas editer a la main : regenerer les tables et reassembler.
#
#  Tier 1 = sur      Tier 2 = -IncludeOptional     Tier 9 = -ScoreOnly
#  Fam    = famille, sert aux garde-fous (fve, laps, service, store, rdp...)
# =========================================================================

$CisRegistry = @(
    @{ Id=26004; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\SAM'; Name='RelaxMinimumPasswordLengthLimits'; Type='DWord'; Data='1'; Title='Ensure ''Relax minimum password length limits'' is set to ''Enabled''.' }
    @{ Id=26008; Tier=2; Fam='msaccount'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='NoConnectedUser'; Type='DWord'; Data='3'; Title='Ensure ''Accounts: Block Microsoft accounts'' is set to ''Users can''t add or log on with Microsoft accounts''.' }
    @{ Id=26010; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='LimitBlankPasswordUse'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Accounts: Limit local account use of blank passwords to console logon only'' is set to ''Enabled''.' }
    @{ Id=26013; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='SCENoApplyLegacyAuditPolicy'; Type='DWord'; Data='1'; Title='Ensure ''Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'' is set to ''Enabled''.' }
    @{ Id=26014; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='CrashOnAuditFail'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Audit: Shut down system immediately if unable to log security audits'' is set to ''Disabled''.' }
    @{ Id=26015; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers'; Name='AddPrinterDrivers'; Type='DWord'; Data='1'; Title='Ensure ''Devices: Prevent users from installing printer drivers'' is set to ''Enabled''.' }
    @{ Id=26016; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireSignOrSeal'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Domain member: Digitally encrypt or sign secure channel data (always)'' is set to ''Enabled''.' }
    @{ Id=26017; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\Netlogon\Parameters'; Name='SealSecureChannel'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Domain member: Digitally encrypt secure channel data (when possible)'' is set to ''Enabled''.' }
    @{ Id=26018; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\Netlogon\Parameters'; Name='SignSecureChannel'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Domain member: Digitally sign secure channel data (when possible)'' is set to ''Enabled''.' }
    @{ Id=26019; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\Netlogon\Parameters'; Name='DisablePasswordChange'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Domain member: Disable machine account password changes'' is set to ''Disabled''.' }
    @{ Id=26020; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\Netlogon\Parameters'; Name='MaximumPasswordAge'; Type='DWord'; Data='30'; Title='Ensure ''Domain member: Maximum machine account password age'' is set to ''30 or fewer days, but not 0''.' }
    @{ Id=26021; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\Netlogon\Parameters'; Name='RequireStrongKey'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Domain member: Require strong (Windows 2000 or later) session key'' is set to ''Enabled''.' }
    @{ Id=26022; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableCAD'; Type='DWord'; Data='0'; Title='Ensure ''Interactive logon: Do not require CTRL+ALT+DEL'' is set to ''Disabled''.' }
    @{ Id=26023; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DontDisplayLastUserName'; Type='DWord'; Data='1'; Title='Ensure ''Interactive logon: Don''t display last signed-in'' is set to ''Enabled''.' }
    @{ Id=26024; Tier=2; Fam='lockout'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='MaxDevicePasswordFailedAttempts'; Type='DWord'; Data='10'; Accept='range:1-30'; Title='Ensure ''Interactive logon: Machine account lockout threshold'' is set to ''10 or fewer invalid logon attempts, but not 0''.'; Note='Wazuh accepte <=30 et !=0 ; 10 = valeur CIS. Verrouille l''appareil et peut exiger la cle de recuperation BitLocker -> ignore si BDE actif.' }
    @{ Id=26025; Tier=2; Fam='inactivity'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='InactivityTimeoutSecs'; Type='DWord'; Data='900'; Title='Ensure ''Interactive logon: Machine inactivity limit'' is set to ''900 or fewer second(s), but not 0''.' }
    @{ Id=26028; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='CachedLogonsCount'; Type='DWord'; Data='4'; Title='Ensure ''Interactive logon: Number of previous logons to cache (in case domain controller is not available)'' is set to ''4 or fewer logon(s)''.' }
    @{ Id=26029; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='PasswordExpiryWarning'; Type='DWord'; Data='14'; AbsentOk=$true; Accept='range:5-14'; Title='Ensure ''Interactive logon: Prompt user to change password before expiration'' is set to ''between 5 and 14 days''.'; Note='Wazuh : >=5 et <=14.' }
    @{ Id=26030; Tier=1; Fam='smartcard-ok'; Hive='HKLM'; Path='Software\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='ScRemoveOption'; Type='String'; Data='1'; Accept='1|2|3'; Title='Ensure ''Interactive logon: Smart card removal behavior'' is set to ''Lock Workstation'' or higher.'; Note='1 = Verrouiller la station au retrait de la carte (REG_SZ). Coherent avec une authentification par carte a puce, ne la casse pas.' }
    @{ Id=26031; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='RequireSecuritySignature'; Type='DWord'; Data='1'; Title='Ensure ''Microsoft network client: Digitally sign communications (always)'' is set to ''Enabled''.' }
    @{ Id=26032; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnableSecuritySignature'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Microsoft network client: Digitally sign communications (if server agrees)'' is set to ''Enabled''.' }
    @{ Id=26033; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Name='EnablePlainTextPassword'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Microsoft network client: Send unencrypted password to third-party SMB servers'' is set to ''Disabled''.' }
    @{ Id=26034; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='AutoDisconnect'; Type='DWord'; Data='15'; AbsentOk=$true; Title='Ensure ''Microsoft network server: Amount of idle time required before suspending session'' is set to ''15 or fewer minute(s)''.' }
    @{ Id=26035; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='RequireSecuritySignature'; Type='DWord'; Data='1'; Title='Ensure ''Microsoft network server: Digitally sign communications (always)'' is set to ''Enabled''.' }
    @{ Id=26036; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='EnableSecuritySignature'; Type='DWord'; Data='1'; Title='Ensure ''Microsoft network server: Digitally sign communications (if client agrees)'' is set to ''Enabled''.' }
    @{ Id=26037; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='EnableForcedLogOff'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Microsoft network server: Disconnect clients when logon hours expire'' is set to ''Enabled''.' }
    @{ Id=26038; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Name='SMBServerNameHardeningLevel'; Type='DWord'; Data='1'; Title='Ensure ''Microsoft network server: Server SPN target name validation level'' is set to ''Accept if provided by client'' or higher.' }
    @{ Id=26039; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymousSAM'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Network access: Do not allow anonymous enumeration of SAM accounts'' is set to ''Enabled''.' }
    @{ Id=26040; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa'; Name='RestrictAnonymous'; Type='DWord'; Data='1'; Title='Ensure ''Network access: Do not allow anonymous enumeration of SAM accounts and shares'' is set to ''Enabled''.' }
    @{ Id=26041; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa'; Name='DisableDomainCreds'; Type='DWord'; Data='1'; Title='Ensure ''Network access: Do not allow storage of passwords and credentials for network authentication'' is set to ''Enabled''.' }
    @{ Id=26042; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='EveryoneIncludesAnonymous'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Network access: Let Everyone permissions apply to anonymous users'' is set to ''Disabled''.' }
    @{ Id=26043; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='NullSessionPipes'; Type='Multi'; Data=''; AbsentOk=$true; Title='Ensure ''Network access: Named Pipes that can be accessed anonymously'' is set to ''None''.'; Note='Wazuh exige que la valeur ne contienne AUCUN caractere -> liste vide.' }
    @{ Id=26044; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths'; Name='Machine'; Type='Multi'; Data='System\CurrentControlSet\Control\ProductOptions|System\CurrentControlSet\Control\Server Applications|Software\Microsoft\Windows NT\CurrentVersion'; AbsentOk=$true; Title='Ensure ''Network access: Remotely accessible registry paths'' is configured.'; Note='Les 3 chemins exacts attendus par la regle Wazuh.' }
    @{ Id=26045; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths'; Name='Machine'; Type='Multi'; Data='System\CurrentControlSet\Control\Print\Printers|System\CurrentControlSet\Services\Eventlog|Software\Microsoft\OLAP Server|Software\Microsoft\Windows NT\CurrentVersion\Print|Software\Microsoft\Windows NT\CurrentVersion\Windows|System\CurrentControlSet\Control\ContentIndex|System\CurrentControlSet\Control\Terminal Server|System\CurrentControlSet\Control\Terminal Server\UserConfig|System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration|Software\Microsoft\Windows NT\CurrentVersion\Perflib|System\CurrentControlSet\Services\SysmonLog'; Title='Ensure ''Network access: Remotely accessible registry paths and sub-paths'' is configured.'; Note='Les 11 sous-chemins attendus par la regle Wazuh.' }
    @{ Id=26046; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='RestrictNullSessAccess'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Network access: Restrict anonymous access to Named Pipes and Shares'' is set to ''Enabled''.' }
    @{ Id=26047; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa'; Name='restrictremotesam'; Type='String'; Data='O:BAG:BAD:(A;;RC;;;BA)'; AbsentOk=$true; Title='Ensure ''Network access: Restrict clients allowed to make remote calls to SAM'' is set to ''Administrators: Remote Access: Allow''.'; Note='SDDL : seuls les administrateurs peuvent interroger SAM a distance.' }
    @{ Id=26048; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LanManServer\Parameters'; Name='NullSessionShares'; Type='Multi'; Data=''; AbsentOk=$true; Title='Ensure ''Network access: Shares that can be accessed anonymously'' is set to ''None''.'; Note='Aucun partage accessible en session nulle.' }
    @{ Id=26049; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='ForceGuest'; Type='DWord'; Data='0'; Title='Ensure ''Network access: Sharing and security model for local accounts'' is set to ''Classic - local users authenticate as themselves''.' }
    @{ Id=26050; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='UseMachineId'; Type='DWord'; Data='1'; Title='Ensure ''Network security: Allow Local System to use computer identity for NTLM'' is set to ''Enabled''.' }
    @{ Id=26051; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa\MSV1_0'; Name='allownullsessionfallback'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Network security: Allow LocalSystem NULL session fallback'' is set to ''Disabled''.' }
    @{ Id=26052; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa\pku2u'; Name='AllowOnlineID'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Network Security: Allow PKU2U authentication requests to this computer to use online identities'' is set to ''Disabled''.' }
    @{ Id=26053; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; Name='SupportedEncryptionTypes'; Type='DWord'; Data='2147483644'; Accept='2147483644|2147483640'; Title='Ensure ''Network security: Configure encryption types allowed for Kerberos'' is set to ''AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types''.'; Note='AES128+AES256+types futurs, RC4/DES exclus.' }
    @{ Id=26054; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='NoLMHash'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Network security: Do not store LAN Manager hash value on next password change'' is set to ''Enabled''.' }
    @{ Id=26056; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa'; Name='LmCompatibilityLevel'; Type='DWord'; Data='5'; Title='Ensure ''Network security: LAN Manager authentication level'' is set to ''Send NTLMv2 response only. Refuse LM & NTLM''.' }
    @{ Id=26057; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Services\LDAP'; Name='LDAPClientIntegrity'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Network security: LDAP client signing requirements'' is set to ''Negotiate signing'' or higher.' }
    @{ Id=26058; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinClientSec'; Type='DWord'; Data='537395200'; Title='Ensure ''Network security: Minimum session security for NTLM SSP based (including secure RPC) clients'' is set to ''Require NTLMv2 session security, Requ' }
    @{ Id=26059; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Lsa\MSV1_0'; Name='NTLMMinServerSec'; Type='DWord'; Data='537395200'; Title='Ensure ''Network security: Minimum session security for NTLM SSP based (including secure RPC) servers'' is set to ''Require NTLMv2 session security, Requ' }
    @{ Id=26060; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='AuditReceivingNTLMTraffic'; Type='DWord'; Data='2'; Title='Ensure ''Network security: Restrict NTLM: Audit Incoming NTLM Traffic'' is set to ''Enable auditing for all accounts''.' }
    @{ Id=26061; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name='RestrictSendingNTLMTraffic'; Type='DWord'; Data='1'; Accept='1|2'; Title='Ensure ''Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'' is set to ''Audit all'' or higher.'; Note='1 = Auditer tout (accepte par Wazuh). 2 = Refuser tout : casse l''acces aux partages SMB/NAS -> reserve a -StrictNTLM.' }
    @{ Id=26062; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Session Manager\Kernel'; Name='ObCaseInsensitive'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''System objects: Require case insensitivity for non-Windows subsystems'' is set to ''Enabled''.' }
    @{ Id=26063; Tier=1; Fam='base'; Hive='HKLM'; Path='System\CurrentControlSet\Control\Session Manager'; Name='ProtectionMode'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)'' is set to ''Enabled''.' }
    @{ Id=26064; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='FilterAdministratorToken'; Type='DWord'; Data='1'; Title='Ensure ''User Account Control: Admin Approval Mode for the Built-in Administrator account'' is set to ''Enabled''.' }
    @{ Id=26065; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorAdmin'; Type='DWord'; Data='2'; Title='Ensure ''User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode'' is set to ''Prompt for consent on the secure '; Note='Demander le consentement sur le bureau securise.' }
    @{ Id=26066; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='ConsentPromptBehaviorUser'; Type='DWord'; Data='0'; Title='Ensure ''User Account Control: Behavior of the elevation prompt for standard users'' is set to ''Automatically deny elevation requests''.' }
    @{ Id=26067; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableInstallerDetection'; Type='DWord'; Data='1'; Title='Ensure ''User Account Control: Detect application installations and prompt for elevation'' is set to ''Enabled''.' }
    @{ Id=26068; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableSecureUIAPaths'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''User Account Control: Only elevate UIAccess applications that are installed in secure locations'' is set to ''Enabled''.' }
    @{ Id=26069; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableLUA'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''User Account Control: Run all administrators in Admin Approval Mode'' is set to ''Enabled''.' }
    @{ Id=26070; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='PromptOnSecureDesktop'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''User Account Control: Switch to the secure desktop when prompting for elevation'' is set to ''Enabled''.' }
    @{ Id=26071; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableVirtualization'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''User Account Control: Virtualize file and registry write failures to per-user locations'' is set to ''Enabled''.' }
    @{ Id=26116; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name='EnableFirewall'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Windows Firewall: Domain: Firewall state'' is set to ''On (recommended)''.' }
    @{ Id=26117; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name='DefaultInboundAction'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Windows Firewall: Domain: Inbound connections'' is set to ''Block (default)''.' }
    @{ Id=26118; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; Name='DisableNotifications'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Domain: Settings: Display a notification'' is set to ''No''.' }
    @{ Id=26119; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogFilePath'; Type='String'; Data='%SystemRoot%\System32\logfiles\firewall\domainfw.log'; Title='Ensure ''Windows Firewall: Domain: Logging: Name'' is set to ''%SystemRoot%System32\\logfiles\\firewall\\domainfw.log''.'; Note='Wazuh ne verifie qu''une sous-chaine ; on ecrit le vrai chemin Windows.' }
    @{ Id=26120; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogFileSize'; Type='DWord'; Data='16384'; Title='Ensure ''Windows Firewall: Domain: Logging: Size limit (KB)'' is set to ''16,384 KB or greater''.' }
    @{ Id=26121; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogDroppedPackets'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Domain: Logging: Log dropped packets'' is set to ''Yes''.' }
    @{ Id=26122; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'; Name='LogSuccessfulConnections'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Domain: Logging: Log successful connections'' is set to ''Yes''.' }
    @{ Id=26123; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name='EnableFirewall'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Windows Firewall: Private: Firewall state'' is set to ''On (recommended)''.' }
    @{ Id=26124; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name='DefaultInboundAction'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Windows Firewall: Private: Inbound connections'' is set to ''Block (default)''.' }
    @{ Id=26125; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; Name='DisableNotifications'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Private: Settings: Display a notification'' is set to ''No''.' }
    @{ Id=26126; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogFilePath'; Type='String'; Data='%SystemRoot%\System32\logfiles\firewall\privatefw.log'; Title='Ensure ''Windows Firewall: Private: Logging: Name'' is set to ''%SystemRoot%\\System32\\logfiles\\firewall\\privatefw.log''.'; Note='idem profil prive.' }
    @{ Id=26127; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogFileSize'; Type='DWord'; Data='16384'; Title='Ensure ''Windows Firewall: Private: Logging: Size limit (KB)'' is set to ''16,384 KB or greater''.' }
    @{ Id=26128; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogDroppedPackets'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Private: Logging: Log dropped packets'' is set to ''Yes''.' }
    @{ Id=26129; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'; Name='LogSuccessfulConnections'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Private: Logging: Log successful connections'' is set to ''Yes''.' }
    @{ Id=26130; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='EnableFirewall'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Windows Firewall: Public: Firewall state'' is set to ''On (recommended)''.' }
    @{ Id=26131; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='DefaultInboundAction'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Windows Firewall: Public: Inbound connections'' is set to ''Block (default)''.' }
    @{ Id=26132; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='DisableNotifications'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Public: Settings: Display a notification'' is set to ''No''.' }
    @{ Id=26133; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='AllowLocalPolicyMerge'; Type='DWord'; Data='0'; Title='Ensure ''Windows Firewall: Public: Settings: Apply local firewall rules'' is set to ''No''.' }
    @{ Id=26134; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; Name='AllowLocalIPsecPolicyMerge'; Type='DWord'; Data='0'; Title='Ensure ''Windows Firewall: Public: Settings: Apply local connection security rules'' is set to ''No''.' }
    @{ Id=26135; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogFilePath'; Type='String'; Data='%SystemRoot%\System32\logfiles\firewall\publicfw.log'; Title='Ensure ''Windows Firewall: Public: Logging: Name'' is set to ''%SystemRoot%\\System32\\logfiles\\firewall\\publicfw.log''.'; Note='idem profil public.' }
    @{ Id=26136; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogFileSize'; Type='DWord'; Data='16384'; Title='Ensure ''Windows Firewall: Public: Logging: Size limit (KB)'' is set to ''16,384 KB or greater''.' }
    @{ Id=26137; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogDroppedPackets'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Public: Logging: Log dropped packets'' is set to ''Yes''.' }
    @{ Id=26138; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'; Name='LogSuccessfulConnections'; Type='DWord'; Data='1'; Title='Ensure ''Windows Firewall: Public: Logging: Log successful connections'' is set to ''Yes''.' }
    @{ Id=26166; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenCamera'; Type='DWord'; Data='1'; Title='Ensure ''Prevent enabling lock screen camera'' is set to ''Enabled''.' }
    @{ Id=26167; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Personalization'; Name='NoLockScreenSlideshow'; Type='DWord'; Data='1'; Title='Ensure ''Prevent enabling lock screen slide show'' is set to ''Enabled''.' }
    @{ Id=26168; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\InputPersonalization'; Name='AllowInputPersonalization'; Type='DWord'; Data='0'; Title='Ensure ''Allow users to enable online speech recognition services'' is set to ''Disabled''.' }
    @{ Id=26169; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='AllowOnlineTips'; Type='DWord'; Data='0'; Title='Ensure ''Allow Online Tips'' is set to ''Disabled''.' }
    @{ Id=26170; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='LocalAccountTokenFilterPolicy'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Apply UAC restrictions to local accounts on network logons'' is set to ''Enabled''.' }
    @{ Id=26171; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Print'; Name='RpcAuthnLevelPrivacyEnabled'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Configure RPC packet level privacy setting for incoming connections'' is set to ''Enabled''.' }
    @{ Id=26173; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name='SMB1'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Configure SMB v1 server'' is set to ''Disabled''.' }
    @{ Id=26174; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Cryptography\Wintrust\Config'; Name='EnableCertPaddingCheck'; Type='DWord'; Data='1'; Title='Ensure ''Enable Certificate Padding'' is set to ''Enabled''.' }
    @{ Id=26175; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Name='DisableExceptionChainValidation'; Type='DWord'; Data='0'; Title='Ensure ''Enable Structured Exception Handling Overwrite Protection (SEHOP)'' is set to ''Enabled''.' }
    @{ Id=26176; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NodeType'; Type='DWord'; Data='2'; Title='Ensure ''NetBT NodeType configuration'' is set to ''Enabled: P-node (recommended)''.' }
    @{ Id=26177; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Name='UseLogonCredential'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''WDigest Authentication'' is set to ''Disabled''.' }
    @{ Id=26178; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='AutoAdminLogon'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''MSS: (AutoAdminLogon) Enable Automatic Logon'' is set to ''Disabled''.' }
    @{ Id=26179; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'; Name='DisableIPSourceRouting'; Type='DWord'; Data='2'; Title='Ensure ''MSS: (DisableIPSourceRouting IPv6) IP source routing protection level is set to ''Enabled: Highest protection, source routing is completely dis' }
    @{ Id=26180; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='DisableIPSourceRouting'; Type='DWord'; Data='2'; Title='Ensure ''MSS: (DisableIPSourceRouting) IP source routing protection level '' is set to ''Enabled: Highest protection, source routing is completely disabl' }
    @{ Id=26181; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\RasMan\Parameters'; Name='DisableSavePassword'; Type='DWord'; Data='1'; Title='Ensure ''MSS: (DisableSavePassword) Prevent the dial-up password from being saved'' is set to ''Enabled''.' }
    @{ Id=26182; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='EnableICMPRedirect'; Type='DWord'; Data='0'; Title='Ensure ''MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes'' is set to ''Disabled''.' }
    @{ Id=26183; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='KeepAliveTime'; Type='DWord'; Data='300000'; Title='Ensure ''MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds'' is set to ''Enabled: 300,000 or 5 minutes''.' }
    @{ Id=26184; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Name='NoNameReleaseOnDemand'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers'' is set to ''Enabled''.' }
    @{ Id=26185; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='PerformRouterDiscovery'; Type='DWord'; Data='0'; Title='Ensure ''MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses'' is set to ''Disabled''.' }
    @{ Id=26186; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Session Manager'; Name='SafeDllSearchMode'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''MSS: (SafeDllSearchMode) Enable Safe DLL search mode'' is set to ''Enabled''.' }
    @{ Id=26187; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; Name='ScreenSaverGracePeriod'; Type='DWord'; Data='5'; AbsentOk=$true; Title='Ensure ''MSS: (ScreenSaverGracePeriod) The time in seconds before the screen saver grace period expires'' is set to ''Enabled: 5 or fewer seconds''.' }
    @{ Id=26188; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'; Name='TcpMaxDataRetransmissions'; Type='DWord'; Data='3'; Title='Ensure ''MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted'' is set to ''Enabled: 3''.' }
    @{ Id=26189; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; Name='TcpMaxDataRetransmissions'; Type='DWord'; Data='3'; Title='Ensure ''MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted'' is set to ''Enabled: 3''.' }
    @{ Id=26190; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\Eventlog\Security'; Name='WarningLevel'; Type='DWord'; Data='90'; AbsentOk=$true; Title='Ensure ''MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning'' is set to ''Enabled: 90% or le' }
    @{ Id=26191; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='DoHPolicy'; Type='DWord'; Data='2'; Accept='2|3'; Title='Ensure ''Configure DNS over HTTPS (DoH) name resolution'' is set to ''Enabled: Allow DoH'' or higher.'; Note='2 = autoriser DoH (accepte). 3 = exiger DoH : coupe la resolution si le resolveur ne le gere pas.' }
    @{ Id=26192; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableNetbios'; Type='DWord'; Data='2'; AbsentOk=$true; Accept='0|2'; Title='Ensure ''Configure NetBIOS settings'' is set to ''Enabled: Disable NetBIOS name resolution on public networks''.'; Note='2 = NetBIOS desactive sur les reseaux publics (accepte par Wazuh). 0 = partout : peut casser la decouverte NAS/imprimante -> -StrictNetBIOS.' }
    @{ Id=26193; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name='EnableMulticast'; Type='DWord'; Data='0'; Title='Ensure ''Turn off multicast name resolution'' is set to ''Enabled''.' }
    @{ Id=26194; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableFontProviders'; Type='DWord'; Data='0'; Title='Ensure ''Enable Font Providers'' is set to ''Disabled''.' }
    @{ Id=26195; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; Name='AllowInsecureGuestAuth'; Type='DWord'; Data='0'; Title='Ensure ''Enable insecure guest logons'' is set to ''Disabled''.' }
    @{ Id=26196; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\LLTD'; Name='EnableLLTDIO'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn on Mapper I/O (LLTDIO) driver'' is set to ''Disabled''.' }
    @{ Id=26197; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\LLTD'; Name='EnableRspndr'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn on Responder (RSPNDR) driver'' is set to ''Disabled''.' }
    @{ Id=26198; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Peernet'; Name='Disabled'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Microsoft Peer-to-Peer Networking Services'' is set to ''Enabled''.' }
    @{ Id=26199; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_AllowNetBridge_NLA'; Type='DWord'; Data='0'; Title='Ensure ''Prohibit installation and configuration of Network Bridge on your DNS domain network'' is set to ''Enabled''.' }
    @{ Id=26200; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_ShowSharedAccessUI'; Type='DWord'; Data='0'; Title='Ensure ''Prohibit use of Internet Connection Sharing on your DNS domain network'' is set to ''Enabled''.' }
    @{ Id=26201; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Network Connections'; Name='NC_StdDomainUserSetLocation'; Type='DWord'; Data='1'; Title='Ensure ''Require domain users to elevate when setting a network''s location'' is set to ''Enabled''.' }
    @{ Id=26202; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\NETLOGON'; Type='String'; Data='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Title='Ensure ''Hardened UNC Paths'' is set to ''Enabled, with Require Mutual Authentication, Require Integrity and Require Privacy set for all NETLOGON and SYSVOL shares''.'; Note='Chemins UNC durcis (sans effet hors domaine, sans risque).' }
    @{ Id=26202; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'; Name='\\*\SYSVOL'; Type='String'; Data='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Title='Ensure ''Hardened UNC Paths'' -- partage SYSVOL.'; Note='Chemins UNC durcis (sans effet hors domaine, sans risque).' }
    @{ Id=26203; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters'; Name='DisabledComponents'; Type='DWord'; Data='255'; Title='Disable IPv6 (Ensure TCPIP6 Parameter ''DisabledComponents'' is set to ''0xff (255)'').' }
    @{ Id=26204; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; Name='DisableFlashConfigRegistrar'; Type='DWord'; Data='0'; Title='Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled''.' }
    @{ Id=26204; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; Name='DisableInBand802DOT11Registrar'; Type='DWord'; Data='0'; Title='Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled''.' }
    @{ Id=26204; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; Name='DisableUPnPRegistrar'; Type='DWord'; Data='0'; Title='Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled''.' }
    @{ Id=26204; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; Name='DisableWPDRegistrar'; Type='DWord'; Data='0'; Title='Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled''.' }
    @{ Id=26204; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars'; Name='EnableRegistrars'; Type='DWord'; Data='0'; Title='Ensure ''Configuration of wireless settings using Windows Connect Now'' is set to ''Disabled''.' }
    @{ Id=26205; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WCN\UI'; Name='DisableWcnUi'; Type='DWord'; Data='1'; Title='Ensure ''Prohibit access of the Windows Connect Now wizards'' is set to ''Enabled''.' }
    @{ Id=26206; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name='fMinimizeConnections'; Type='DWord'; Data='3'; Title='Ensure ''Minimize the number of simultaneous connections to the Internet or a Windows Domain'' is set to ''Enabled: 3 = Prevent Wi-Fi when on Ethernet''.' }
    @{ Id=26207; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'; Name='fBlockNonDomain'; Type='DWord'; Data='1'; Title='Ensure ''Prohibit connection to non-domain networks when connected to domain authenticated network'' is set to ''Enabled''.' }
    @{ Id=26208; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Name='AutoConnectAllowedOEM'; Type='DWord'; Data='0'; Title='Ensure ''Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services'' is ' }
    @{ Id=26209; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers'; Name='RegisterSpoolerRemoteRpcEndPoint'; Type='DWord'; Data='2'; Title='Ensure ''Allow Print Spooler to accept client connections'' is set to ''Disabled''.' }
    @{ Id=26210; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers'; Name='RedirectionguardPolicy'; Type='DWord'; Data='1'; Title='Ensure ''Configure Redirection Guard'' is set to ''Enabled: Redirection Guard Enabled''.' }
    @{ Id=26211; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcUseNamedPipeProtocol'; Type='DWord'; Data='0'; Title='Ensure ''Configure RPC connection settings: Protocol to use for outgoing RPC connections'' is set to ''Enabled: RPC over TCP''.' }
    @{ Id=26212; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcAuthentication'; Type='DWord'; Data='0'; Title='Ensure ''Configure RPC connection settings: Use authentication for outgoing RPC connections'' is set to ''Enabled: Default''.' }
    @{ Id=26213; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcProtocols'; Type='DWord'; Data='5'; Title='Ensure ''Configure RPC listener settings: Protocols to allow for incoming RPC connections'' is set to ''Enabled: RPC over TCP''.' }
    @{ Id=26214; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\RPC'; Name='ForceKerberosForRpc'; Type='DWord'; Data='0'; Accept='0|1'; Title='Ensure ''Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:'' is set to ''Enabled: Negotiate'' or higher.'; Note='0 = Negocier (accepte). 1 = Kerberos obligatoire : casse l''impression reseau hors domaine.' }
    @{ Id=26215; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\RPC'; Name='RpcTcpPort'; Type='DWord'; Data='0'; Title='Ensure ''Configure RPC over TCP port'' is set to ''Enabled: 0''.' }
    @{ Id=26216; Tier=1; Fam='print-rpc'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name='RestrictDriverInstallationToAdministrators'; Type='DWord'; Data='1'; Title='Ensure ''Limits print driver installation to Administrators'' is set to ''Enabled''.' }
    @{ Id=26217; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers'; Name='CopyFilesPolicy'; Type='DWord'; Data='1'; Title='Ensure ''Manage processing of Queue-specific files'' is set to ''Enabled: Limit Queue-specific files to Color profiles''.' }
    @{ Id=26218; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name='NoWarningNoElevationOnInstall'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Point and Print Restrictions: When installing drivers for a new connection'' is set to ''Enabled: Show warning and elevation prompt''.' }
    @{ Id=26219; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'; Name='UpdatePromptSettings'; Type='DWord'; Data='0'; Title='Ensure ''Point and Print Restrictions: When updating drivers for an existing connection'' is set to ''Enabled: Show warning and elevation prompt''.' }
    @{ Id=26220; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; Name='NoCloudApplicationNotification'; Type='DWord'; Data='1'; Title='Ensure ''Turn off notifications network usage'' is set to ''Enabled''.' }
    @{ Id=26221; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='HideRecommendedPersonalizedSites'; Type='DWord'; Data='1'; Title='Ensure ''Remove Personalized Website Recommendations from the Recommended section in the Start Menu'' is set to ''Enabled''.' }
    @{ Id=26222; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled'; Type='DWord'; Data='1'; Title='Ensure ''Include command line in process creation events'' is set to ''Enabled''.' }
    @{ Id=26223; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters'; Name='AllowEncryptionOracle'; Type='DWord'; Data='0'; Title='Ensure ''Encryption Oracle Remediation'' is set to ''Enabled: Force Updated Clients''.' }
    @{ Id=26224; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'; Name='AllowProtectedCreds'; Type='DWord'; Data='1'; Title='Ensure ''Remote host allows delegation of non- exportable credentials'' is set to ''Enabled''.' }
    @{ Id=26231; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Name='DenyDeviceIDs'; Type='DWord'; Data='1'; Title='Ensure ''Prevent installation of devices that match any of these device IDs'' is set to ''Enabled''.'; Note='Active le blocage par identifiant de peripherique.' }
    @{ Id=26232; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs'; Name='1'; Type='String'; Data='PCI\CC_0C0A'; Title='Ensure ''Prevent installation of devices that match any of these device IDs: Prevent installation of devices that match any of these device IDs'' is set'; Note='Identifiant CIS de la classe Bluetooth. NB : la regle Wazuh 26232 cherche une valeur NOMMEE ''PCI\CC_0C0A'' sous une sous-cle ''1'' -- ce n''est pas la facon dont Windows stocke la liste ; on ecrit la forme correcte pour Windows, le controle peut rester en echec.' }
    @{ Id=26233; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Name='DenyDeviceIDsRetroactive'; Type='DWord'; Data='1'; Title='Ensure ''Prevent installation of devices that match any of these device IDs: Also apply to matching devices that are already installed.'' is set to ''Tru'; Note='Applique aussi aux peripheriques deja installes.' }
    @{ Id=26234; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Name='DenyDeviceClasses'; Type='DWord'; Data='1'; Title='Ensure ''Prevent installation of devices using drivers that match these device setup classes'' is set to ''Enabled''.'; Note='Active le blocage par classe de peripherique.' }
    @{ Id=26235; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'; Name='1'; Type='String'; Data='{d48179be-ec20-11d1-b6b8-00c04fa372a7}'; Title='Ensure ''Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these d'; Note='Classe IEEE 1394 / AVC (DMA par FireWire) -- GUID issu de la remediation CIS du YAML.' }
    @{ Id=26235; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'; Name='2'; Type='String'; Data='{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}'; Title='Ensure ''Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these d'; Note='Classe IEEE 1394 / AVC (DMA par FireWire) -- GUID issu de la remediation CIS du YAML.' }
    @{ Id=26235; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'; Name='3'; Type='String'; Data='{c06ff265-ae09-48f0-812c-16753d7cba83}'; Title='Ensure ''Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these d'; Note='Classe IEEE 1394 / AVC (DMA par FireWire) -- GUID issu de la remediation CIS du YAML.' }
    @{ Id=26235; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses'; Name='4'; Type='String'; Data='{6bdd1fc1-810f-11d0-bec7-08002be2092f}'; Title='Ensure ''Prevent installation of devices using drivers that match these device setup classes: Prevent installation of devices using drivers for these d'; Note='Classe IEEE 1394 / AVC (DMA par FireWire) -- GUID issu de la remediation CIS du YAML.' }
    @{ Id=26236; Tier=2; Fam='deviceinstall'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'; Name='DenyDeviceClassesRetroactive'; Type='DWord'; Data='1'; Title='Ensure ''Prevent installation of devices using drivers that match these device setup classes: Also apply to matching devices that are already installed'; Note='Applique aussi aux peripheriques deja installes.' }
    @{ Id=26237; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Device Metadata'; Name='PreventDeviceMetadataFromNetwork'; Type='DWord'; Data='1'; Title='Ensure ''Prevent device metadata retrieval from the Internet'' is set to ''Enabled''.' }
    @{ Id=26238; Tier=1; Fam='base'; Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Policies\EarlyLaunch'; Name='DriverLoadPolicy'; Type='DWord'; Data='3'; Title='Ensure ''Boot-Start Driver Initialization Policy'' is set to ''Enabled: Good, unknown and bad but critical''.' }
    @{ Id=26239; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Name='NoBackgroundPolicy'; Type='DWord'; Data='0'; Title='Ensure ''Configure registry policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE''.' }
    @{ Id=26240; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'; Name='NoGPOListChanges'; Type='DWord'; Data='0'; Title='Ensure ''Configure registry policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE''.' }
    @{ Id=26241; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; Name='NoBackgroundPolicy'; Type='DWord'; Data='0'; Title='Ensure ''Configure security policy processing: Do not apply during periodic background processing'' is set to ''Enabled: FALSE''.' }
    @{ Id=26242; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}'; Name='NoGPOListChanges'; Type='DWord'; Data='0'; Title='Ensure ''Configure security policy processing: Process even if the Group Policy objects have not changed'' is set to ''Enabled: TRUE''.' }
    @{ Id=26243; Tier=2; Fam='cdp'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableCdp'; Type='DWord'; Data='0'; Title='Ensure ''Continue experiences on this device'' is set to ''Disabled''.' }
    @{ Id=26245; Tier=2; Fam='store'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoUseStoreOpenWith'; Type='DWord'; Data='1'; Title='Ensure ''Turn off access to the Store'' is set to ''Enabled''.' }
    @{ Id=26246; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableWebPnPDownload'; Type='DWord'; Data='1'; Title='Ensure ''Turn off downloading of print drivers over HTTP'' is set to ''Enabled''.' }
    @{ Id=26247; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\TabletPC'; Name='PreventHandwritingDataSharing'; Type='DWord'; Data='1'; Title='Ensure ''Turn off handwriting personalization data sharing'' is set to ''Enabled''.' }
    @{ Id=26248; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'; Name='PreventHandwritingErrorReports'; Type='DWord'; Data='1'; Title='Ensure ''Turn off handwriting recognition error reporting'' is set to ''Enabled''.' }
    @{ Id=26249; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard'; Name='ExitOnMSICW'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com'' is set to ''Enabled''.' }
    @{ Id=26250; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoWebServices'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Internet download for Web publishing and online ordering wizards'' is set to ''Enabled''.' }
    @{ Id=26251; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Name='DisableHTTPPrinting'; Type='DWord'; Data='1'; Title='Ensure ''Turn off printing over HTTP'' is set to ''Enabled''.' }
    @{ Id=26252; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control'; Name='NoRegistration'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Registration if URL connection is referring to Microsoft.com'' is set to ''Enabled''.' }
    @{ Id=26253; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\SearchCompanion'; Name='DisableContentFileUpdates'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Search Companion content file updates'' is set to ''Enabled''.' }
    @{ Id=26254; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoOnlinePrintsWizard'; Type='DWord'; Data='1'; Title='' }
    @{ Id=26255; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoPublishingWizard'; Type='DWord'; Data='1'; Title='' }
    @{ Id=26256; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Messenger\Client'; Name='CEIP'; Type='DWord'; Data='2'; Title='Ensure ''Turn off the Windows Messenger Customer Experience Improvement Program'' is set to ''Enabled''.' }
    @{ Id=26257; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\SQMClient\Windows'; Name='CEIPEnable'; Type='DWord'; Data='0'; Title='Ensure ''Turn off Windows Customer Experience Improvement Program'' is set to ''Enabled''.' }
    @{ Id=26258; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'; Name='Disabled'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Windows Error Reporting'' is set to ''Enabled''.' }
    @{ Id=26259; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'; Name='DevicePKInitBehavior'; Type='DWord'; Data='0'; Title='Ensure ''Support device authentication using certificate'' is set to ''Enabled: Automatic''.' }
    @{ Id=26259; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters'; Name='DevicePKInitEnabled'; Type='DWord'; Data='1'; Title='Ensure ''Support device authentication using certificate'' is set to ''Enabled: Automatic''.' }
    @{ Id=26260; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'; Name='DeviceEnumerationPolicy'; Type='DWord'; Data='0'; Title='Ensure ''Enumeration policy for external devices incompatible with Kernel DMA Protection'' is set to ''Enabled: Block All''.' }
    @{ Id=26262; Tier=1; Fam='laps'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Name='PwdExpirationProtectionEnabled'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow password expiration time longer than required by policy'' is set to ''Enabled''.' }
    @{ Id=26263; Tier=1; Fam='laps'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Name='ADPasswordEncryptionEnabled'; Type='DWord'; Data='1'; Title='Ensure ''Enable password encryption'' is set to ''Enabled''.' }
    @{ Id=26264; Tier=1; Fam='laps'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Name='PasswordComplexity'; Type='DWord'; Data='4'; Title='Ensure ''Password Settings: Password Complexity'' is set to ''Enabled: Large letters + small letters + numbers + special characters''.' }
    @{ Id=26265; Tier=1; Fam='laps'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Name='PasswordLength'; Type='DWord'; Data='15'; Title='Ensure ''Password Settings: Password Length'' is set to ''Enabled: 15 or more''.' }
    @{ Id=26266; Tier=1; Fam='laps'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Name='PasswordAgeDays'; Type='DWord'; Data='30'; Title='Ensure ''Password Settings: Password Age (Days)'' is set to ''Enabled: 30 or fewer''.' }
    @{ Id=26267; Tier=1; Fam='laps'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'; Name='PostAuthenticationResetDelay'; Type='DWord'; Data='8'; Accept='range:1-8'; Title='Ensure ''Post-authentication actions: Grace period (hours)'' is set to ''Enabled: 8 or fewer hours, but not 0''.'; Note='Wazuh : >0 et <=8.' }
    @{ Id=26271; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Control Panel\International'; Name='BlockUserInputMethodsForSignIn'; Type='DWord'; Data='1'; Title='Ensure ''Disallow copying of user input methods to the system account for sign-in'' is set to ''Enabled''.' }
    @{ Id=26272; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='BlockUserFromShowingAccountDetailsOnSignin'; Type='DWord'; Data='1'; Title='Ensure ''Block user from showing account details on sign-in'' is set to ''Enabled''.' }
    @{ Id=26273; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontDisplayNetworkSelectionUI'; Type='DWord'; Data='1'; Title='Ensure ''Do not display network selection UI'' is set to ''Enabled''.' }
    @{ Id=26274; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='DontEnumerateConnectedUsers'; Type='DWord'; Data='1'; Title='Ensure ''Do not enumerate connected users on domain-joined computers'' is set to ''Enabled''.' }
    @{ Id=26275; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnumerateLocalUsers'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Enumerate local users on domain-joined computers'' is set to ''Disabled''.' }
    @{ Id=26276; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='DisableLockScreenAppNotifications'; Type='DWord'; Data='1'; Title='Ensure ''Turn off app notifications on the lock screen'' is set to ''Enabled''.' }
    @{ Id=26277; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='BlockDomainPicturePassword'; Type='DWord'; Data='1'; Title='Ensure ''Turn off picture password sign-in'' is set to ''Enabled''.' }
    @{ Id=26278; Tier=2; Fam='pin'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowDomainPINLogon'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn on convenience PIN sign-in'' is set to ''Disabled''.' }
    @{ Id=26279; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='AllowCrossDeviceClipboard'; Type='DWord'; Data='0'; Title='Ensure ''Allow Clipboard synchronization across devices'' is set to ''Disabled''.' }
    @{ Id=26280; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='UploadUserActivities'; Type='DWord'; Data='0'; Title='Ensure ''Allow upload of User Activities'' is set to ''Disabled''.' }
    @{ Id=26281; Tier=2; Fam='sleep'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; Name='DCSettingIndex'; Type='DWord'; Data='0'; Title='Ensure ''Allow network connectivity during connected-standby (on battery)'' is set to ''Disabled''.' }
    @{ Id=26282; Tier=2; Fam='sleep'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9'; Name='ACSettingIndex'; Type='DWord'; Data='0'; Title='Ensure ''Allow network connectivity during connected-standby (plugged in)'' is set to ''Disabled''.' }
    @{ Id=26283; Tier=2; Fam='sleep'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'; Name='DCSettingIndex'; Type='DWord'; Data='0'; Title='Ensure ''Allow standby states (S1-S3) when sleeping (on battery)'' is set to ''Disabled''.' }
    @{ Id=26284; Tier=2; Fam='sleep'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab'; Name='ACSettingIndex'; Type='DWord'; Data='0'; Title='Ensure ''Allow standby states (S1-S3) when sleeping (plugged in)'' is set to ''Disabled''.' }
    @{ Id=26285; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='DCSettingIndex'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Require a password when a computer wakes (on battery)'' is set to ''Enabled''.' }
    @{ Id=26286; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'; Name='ACSettingIndex'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Require a password when a computer wakes (plugged in)'' is set to ''Enabled''.' }
    @{ Id=26287; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowUnsolicited'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Configure Offer Remote Assistance'' is set to ''Disabled''.' }
    @{ Id=26288; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fAllowToGetHelp'; Type='DWord'; Data='0'; Title='Ensure ''Configure Solicited Remote Assistance'' is set to ''Disabled''.' }
    @{ Id=26289; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name='EnableAuthEpResolution'; Type='DWord'; Data='1'; Title='Ensure ''Enable RPC Endpoint Mapper Client Authentication'' is set to ''Enabled''.' }
    @{ Id=26290; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Rpc'; Name='RestrictRemoteClients'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Restrict Unauthenticated RPC clients'' is set to ''Enabled: Authenticated''.' }
    @{ Id=26291; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'; Name='DisableQueryRemoteServer'; Type='DWord'; Data='0'; Title='Ensure ''Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider'' is set to ''Disabled''.' }
    @{ Id=26292; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'; Name='ScenarioExecutionEnabled'; Type='DWord'; Data='0'; Title='Ensure ''Enable/Disable PerfTrack'' is set to ''Disabled''.' }
    @{ Id=26293; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name='DisabledByGroupPolicy'; Type='DWord'; Data='1'; Title='Ensure ''Turn off the advertising ID'' is set to ''Enabled''.' }
    @{ Id=26294; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient'; Name='Enabled'; Type='DWord'; Data='1'; Title='Ensure ''Enable Windows NTP Client'' is set to ''Enabled''.' }
    @{ Id=26295; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer'; Name='Enabled'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Enable Windows NTP Server'' is set to ''Disabled''.' }
    @{ Id=26296; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager'; Name='AllowSharedLocalAppData'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow a Windows app to share application data between users'' is set to ''Disabled''.' }
    @{ Id=26297; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Appx'; Name='BlockNonAdminUserInstall'; Type='DWord'; Data='1'; Title='Ensure ''Prevent non-admin users from installing packaged Windows apps'' is set to ''Enabled''.' }
    @{ Id=26298; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; Name='LetAppsActivateWithVoiceAboveLock'; Type='DWord'; Data='2'; Title='Ensure ''Let Windows apps activate with voice while the system is locked'' is set to ''Enabled: Force Deny''.' }
    @{ Id=26299; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='MSAOptional'; Type='DWord'; Data='1'; Title='Ensure ''Allow Microsoft accounts to be optional'' is set to ''Enabled''.' }
    @{ Id=26300; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='BlockHostedAppAccessWinRT'; Type='DWord'; Data='1'; Title='Ensure ''Block launching Universal Windows apps with Windows Runtime API access from hosted content.'' is set to ''Enabled''.' }
    @{ Id=26301; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoAutoplayfornonVolume'; Type='DWord'; Data='1'; Title='Ensure ''Disallow Autoplay for non-volume devices'' is set to ''Enabled''.' }
    @{ Id=26302; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoAutorun'; Type='DWord'; Data='1'; Title='Ensure ''Set the default behavior for AutoRun'' is set to ''Enabled: Do not execute any autorun commands''.' }
    @{ Id=26303; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='NoDriveTypeAutoRun'; Type='DWord'; Data='255'; Title='Ensure ''Turn off Autoplay'' is set to ''Enabled: All drives''.' }
    @{ Id=26304; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; Name='EnhancedAntiSpoofing'; Type='DWord'; Data='1'; Title='Ensure ''Configure enhanced anti-spoofing'' is set to ''Enabled''.' }
    @{ Id=26305; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVDiscoveryVolumeType'; Type='String'; Data=''; Title='Ensure ''Allow access to BitLocker-protected fixed data drives from earlier versions of Windows'' is set to ''Disabled''.'; Note='Wazuh exige une valeur vide (pas d''agent de deverrouillage BitLocker To Go).' }
    @{ Id=26306; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVRecovery'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered'' is set to ''Enabled''.' }
    @{ Id=26307; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVManageDRA'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Allow data recovery agent'' is set to ''Enabled: True''.' }
    @{ Id=26308; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVRecoveryPassword'; Type='DWord'; Data='1'; Accept='1|2'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Recovery Password'' is set to ''Enabled: Allow 48-digit recovery password'' or high'; Note='1 = autoriser le mot de passe de recuperation 48 chiffres.' }
    @{ Id=26309; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVRecoveryKey'; Type='DWord'; Data='1'; Accept='1|2'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Recovery Key'' is set to ''Enabled: Allow 256-bit recovery key'' or higher.'; Note='1 = autoriser la cle de recuperation 256 bits.' }
    @{ Id=26310; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVHideRecoveryPage'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Omit recovery options from the BitLocker setup wizard'' is set to ''Enabled: True''' }
    @{ Id=26311; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVActiveDirectoryBackup'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Save BitLocker recovery information to AD DS for fixed data drives'' is set to ''E' }
    @{ Id=26312; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVActiveDirectoryInfoToStore'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Configure storage of BitLocker recovery information to AD DS'' is set to ''Enabled' }
    @{ Id=26313; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVRequireActiveDirectoryBackup'; Type='DWord'; Data='0'; Title='Ensure ''Choose how BitLocker-protected fixed drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for fixed ' }
    @{ Id=26314; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVHardwareEncryption'; Type='DWord'; Data='0'; Title='Ensure ''Configure use of hardware-based encryption for fixed data drives'' is set to ''Disabled''.' }
    @{ Id=26315; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVPassphrase'; Type='DWord'; Data='0'; Title='Ensure ''Configure use of passwords for fixed data drives'' is set to ''Disabled''.' }
    @{ Id=26316; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='FDVAllowUserCert'; Type='DWord'; Data='1'; Title='Ensure ''Configure use of smart cards on fixed data drives'' is set to ''Enabled''.' }
    @{ Id=26318; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='UseEnhancedPin'; Type='DWord'; Data='1'; Title='Ensure ''Allow enhanced PINs for startup'' is set to ''Enabled''.' }
    @{ Id=26319; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSAllowSecureBootForIntegrity'; Type='DWord'; Data='1'; Title='Ensure ''Allow Secure Boot for integrity validation'' is set to ''Enabled''.' }
    @{ Id=26320; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSRecovery'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered'' is set to ''Enabled''.' }
    @{ Id=26321; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSManageDRA'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent'' is set to ''Enabled: False''.' }
    @{ Id=26322; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSRecoveryPassword'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Recovery Password'' is set to ''Enabled: Require 48-digit recovery pass' }
    @{ Id=26323; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSRecoveryKey'; Type='DWord'; Data='0'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Recovery Key'' is set to ''Enabled: Do not allow 256-bit recovery key''.' }
    @{ Id=26324; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSHideRecoveryPage'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Omit recovery options from the BitLocker setup wizard'' is set to ''Ena' }
    @{ Id=26325; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSActiveDirectoryBackup'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Allow data recovery agent'' is set to ''Enabled: False''.' }
    @{ Id=26326; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSActiveDirectoryInfoToStore'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Configure storage of BitLocker recovery information to AD DS:'' is set' }
    @{ Id=26327; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSRequireActiveDirectoryBackup'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected operating system drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS' }
    @{ Id=26328; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSHardwareEncryption'; Type='DWord'; Data='0'; Title='Ensure ''Configure use of hardware-based encryption for operating system drives'' is set to ''Disabled''.' }
    @{ Id=26329; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='OSPassphrase'; Type='DWord'; Data='0'; Title='Ensure ''Configure use of passwords for operating system drives'' is set to ''Disabled''.' }
    @{ Id=26330; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='UseAdvancedStartup'; Type='DWord'; Data='1'; Title='Ensure ''Require additional authentication at startup'' is set to ''Enabled''.' }
    @{ Id=26332; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPM'; Type='DWord'; Data='0'; Title='Ensure ''Require additional authentication at startup: Configure TPM startup:'' is set to ''Enabled: Do not allow TPM''.' }
    @{ Id=26333; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMPIN'; Type='DWord'; Data='1'; Title='Ensure ''Require additional authentication at startup: Configure TPM startup PIN:'' is set to ''Enabled: Require startup PIN with TPM''.' }
    @{ Id=26334; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMKey'; Type='DWord'; Data='0'; Title='Ensure ''Require additional authentication at startup: Configure TPM startup key:'' is set to ''Enabled: Do not allow startup key with TPM''.' }
    @{ Id=26335; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='UseTPMKeyPIN'; Type='DWord'; Data='0'; Title='Ensure ''Require additional authentication at startup: Configure TPM startup key and PIN:'' is set to ''Enabled: Do not allow startup key and PIN with TP' }
    @{ Id=26336; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVDiscoveryVolumeType'; Type='String'; Data=''; Title='Ensure ''Allow access to BitLocker-protected removable data drives from earlier versions of Windows'' is set to ''Disabled''.'; Note='idem lecteurs amovibles.' }
    @{ Id=26337; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVRecovery'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered'' is set to ''Enabled''.' }
    @{ Id=26338; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVManageDRA'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Allow data recovery agent'' is set to ''Enabled: True''.' }
    @{ Id=26339; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVRecoveryPassword'; Type='DWord'; Data='0'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Recovery Password'' is set to ''Enabled: Do not allow 48-digit recovery passwo' }
    @{ Id=26340; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVRecoveryKey'; Type='DWord'; Data='0'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Recovery Key'' is set to ''Enabled: Do not allow 256-bit recovery key''.' }
    @{ Id=26341; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVHideRecoveryPage'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Omit recovery options from the BitLocker setup wizard'' is set to ''Enabled: T' }
    @{ Id=26342; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVActiveDirectoryBackup'; Type='DWord'; Data='0'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Save BitLocker recovery information to AD DS for removable data drives'' is s' }
    @{ Id=26343; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVActiveDirectoryInfoToStore'; Type='DWord'; Data='1'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Configure storage of BitLocker recovery information to AD DS:'' is set to ''En' }
    @{ Id=26344; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVRequireActiveDirectoryBackup'; Type='DWord'; Data='0'; Title='Ensure ''Choose how BitLocker-protected removable drives can be recovered: Do not enable BitLocker until recovery information is stored to AD DS for re' }
    @{ Id=26345; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVHardwareEncryption'; Type='DWord'; Data='0'; Title='Ensure ''Configure use of hardware-based encryption for removable data drives'' is set to ''Disabled''.' }
    @{ Id=26346; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVPassphrase'; Type='DWord'; Data='0'; Title='Ensure ''Configure use of passwords for removable data drives'' is set to ''Disabled''.' }
    @{ Id=26347; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVAllowUserCert'; Type='DWord'; Data='1'; Title='Ensure ''Configure use of smart cards on removable data drives'' is set to ''Enabled''.' }
    @{ Id=26350; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='RDVDenyCrossOrg'; Type='DWord'; Data='0'; Title='Ensure ''Deny write access to removable drives not protected by BitLocker: Do not allow write access to devices configured in another organization'' is ' }
    @{ Id=26351; Tier=1; Fam='fve'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\FVE'; Name='DisableExternalDMAUnderLock'; Type='DWord'; Data='1'; Title='Ensure ''Disable new DMA devices when this computer is locked'' is set to ''Enabled''.' }
    @{ Id=26352; Tier=1; Fam='camera'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Camera'; Name='AllowCamera'; Type='DWord'; Data='0'; Title='Ensure ''Allow Use of Camera'' is set to ''Disabled''.'; Note='Famille "camera" pour passer sous le garde-fou : ecarte des qu''une webcam est reconnue. -IgnoreGuards l''applique quand meme.' }
    @{ Id=26353; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableConsumerAccountStateContent'; Type='DWord'; Data='1'; Title='Ensure ''Turn off cloud consumer account state content'' is set to ''Enabled''.' }
    @{ Id=26354; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableCloudOptimizedContent'; Type='DWord'; Data='1'; Title='Ensure ''Turn off cloud optimized content'' is set to ''Enabled''.' }
    @{ Id=26355; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name='DisableWindowsConsumerFeatures'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Microsoft consumer experiences'' is set to ''Enabled''.' }
    @{ Id=26356; Tier=2; Fam='bluetooth'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Connect'; Name='RequirePinForPairing'; Type='DWord'; Data='1'; Accept='1|2'; Title='Ensure ''Require pin for pairing'' is set to ''Enabled: First Time'' OR ''Enabled: Always''.'; Note='1 = code PIN a la premiere association.' }
    @{ Id=26357; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\CredUI'; Name='DisablePasswordReveal'; Type='DWord'; Data='1'; Title='Ensure ''Do not display the password reveal button'' is set to ''Enabled''.' }
    @{ Id=26358; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; Name='EnumerateAdministrators'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Enumerate administrator accounts on elevation'' is set to ''Disabled''.' }
    @{ Id=26359; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='NoLocalPasswordResetQuestions'; Type='DWord'; Data='1'; Title='Ensure ''Prevent the use of security questions for local accounts'' is set to ''Enabled''.' }
    @{ Id=26360; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='AllowTelemetry'; Type='DWord'; Data='0'; Accept='0|1'; Title='Ensure ''Allow Diagnostic Data'' is set to ''Enabled: Diagnostic data off (not recommended)'' or ''Enabled: Send required diagnostic data''.'; Note='0 = telemetrie desactivee (ramene a 1 sur les editions non Enterprise).' }
    @{ Id=26361; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DisableEnterpriseAuthProxy'; Type='DWord'; Data='1'; Title='Ensure ''Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service'' is set to ''Enabled: Disable Authenticated Proxy u' }
    @{ Id=26362; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DisableOneSettingsDownloads'; Type='DWord'; Data='1'; Title='Ensure ''Disable OneSettings Downloads'' is set to ''Enabled''.' }
    @{ Id=26363; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='DoNotShowFeedbackNotifications'; Type='DWord'; Data='1'; Title='Ensure ''Do not show feedback notifications'' is set to ''Enabled''.' }
    @{ Id=26364; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='EnableOneSettingsAuditing'; Type='DWord'; Data='1'; Title='Ensure ''Enable OneSettings Auditing'' is set to ''Enabled''.' }
    @{ Id=26365; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitDiagnosticLogCollection'; Type='DWord'; Data='1'; Title='Ensure ''Limit Diagnostic Log Collection'' is set to ''Enabled''.' }
    @{ Id=26366; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name='LimitDumpCollection'; Type='DWord'; Data='1'; Title='Ensure ''Limit Dump Collection'' is set to ''Enabled''.' }
    @{ Id=26367; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds'; Name='AllowBuildPreview'; Type='DWord'; Data='0'; Title='Ensure ''Toggle user control over Insider builds'' is set to ''Disabled''.' }
    @{ Id=26368; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Name='DODownloadMode'; Type='DWord'; Data='1'; AbsentOk=$true; Accept='0|1|2'; Title='Ensure ''Download Mode'' is NOT set to ''Enabled: Internet''.'; Note='1 = pair-a-pair limite au reseau local ; la regle interdit seulement 3 (Internet).' }
    @{ Id=26369; Tier=2; Fam='winget'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableAppInstaller'; Type='DWord'; Data='0'; Title='Ensure ''Enable App Installer'' is set to ''Disabled''.' }
    @{ Id=26370; Tier=2; Fam='winget'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableExperimentalFeatures'; Type='DWord'; Data='0'; Title='Ensure ''Enable App Installer Experimental Features'' is set to ''Disabled''.' }
    @{ Id=26371; Tier=2; Fam='winget'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableHashOverride'; Type='DWord'; Data='0'; Title='Ensure ''Enable App Installer Hash Override'' is set to ''Disabled''.' }
    @{ Id=26372; Tier=2; Fam='winget'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\AppInstaller'; Name='EnableMSAppInstallerProtocol'; Type='DWord'; Data='0'; Title='Ensure ''Enable App Installer ms-appinstaller protocol'' is set to ''Disabled''.' }
    @{ Id=26373; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name='Retention'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Application: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled''.' }
    @{ Id=26374; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'; Name='MaxSize'; Type='DWord'; Data='32768'; Title='Ensure ''Application: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater''.' }
    @{ Id=26375; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='Retention'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Security: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled''.' }
    @{ Id=26376; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; Name='MaxSize'; Type='DWord'; Data='196608'; Title='Ensure ''Security: Specify the maximum log file size (KB)'' is set to ''Enabled: 196,608 or greater''.' }
    @{ Id=26377; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'; Name='Retention'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Setup: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled''.' }
    @{ Id=26378; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup'; Name='MaxSize'; Type='DWord'; Data='32768'; Title='Ensure ''Setup: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater''.' }
    @{ Id=26379; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name='Retention'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''System: Control Event Log behavior when the log file reaches its maximum size'' is set to ''Disabled''.' }
    @{ Id=26380; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\EventLog\System'; Name='MaxSize'; Type='DWord'; Data='32768'; Title='Ensure ''System: Specify the maximum log file size (KB)'' is set to ''Enabled: 32,768 or greater''.' }
    @{ Id=26381; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='DisableGraphRecentItems'; Type='DWord'; Data='1'; Title='Ensure ''Turn off account-based insights, recent, favorite, and recommended files in File Explorer'' is set to ''Enabled''.' }
    @{ Id=26382; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoDataExecutionPrevention'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn off Data Execution Prevention for Explorer'' is set to ''Disabled''.' }
    @{ Id=26383; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Name='NoHeapTerminationOnCorruption'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn off heap termination on corruption'' is set to ''Disabled''.' }
    @{ Id=26384; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name='PreXPSP2ShellProtocolBehavior'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn off shell protocol protected mode'' is set to ''Disabled''.' }
    @{ Id=26385; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name='DisableLocation'; Type='DWord'; Data='1'; Title='Ensure ''Turn off location'' is set to ''Enabled''.' }
    @{ Id=26386; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Messaging'; Name='AllowMessageSync'; Type='DWord'; Data='0'; Title='Ensure ''Allow Message Service Cloud Sync'' is set to ''Disabled''.' }
    @{ Id=26387; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\MicrosoftAccount'; Name='DisableUserAuth'; Type='DWord'; Data='1'; Title='Ensure ''Block all consumer Microsoft account user authentication'' is set to ''Enabled''.' }
    @{ Id=26388; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name='LocalSettingOverrideSpynetReporting'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Configure local setting override for reporting to Microsoft MAPS'' is set to ''Disabled''.' }
    @{ Id=26390; Tier=1; Fam='base'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'; Name='ExploitGuard_ASR_Rules'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules'' is set to ''Enabled''.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='26190899-1602-49E8-8B27-eB1D0A1CE869'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='3B576869-A4EC-4529-8536-B80A7769E899'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='9E6C4E1F-7D60-472F-bA1A-A39EF669E4B2'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='D3E037E1-3EB8-44C8-A917-57927947596D'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26391; Tier=2; Fam='asr'; Hive='HKLM'; Path='Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'; Name='D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Type='DWord'; Data='1'; Title='Ensure ''Configure Attack Surface Reduction rules: Set the state for each ASR rule'' is configured.' }
    @{ Id=26392; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'; Name='EnableNetworkProtection'; Type='DWord'; Data='1'; Title='Ensure ''Prevent users and apps from accessing dangerous websites'' is set to ''Enabled: Block''.' }
    @{ Id=26393; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine'; Name='EnableFileHashComputation'; Type='DWord'; Data='1'; Title='Ensure ''Enable file hash computation feature'' is set to ''Enabled''.' }
    @{ Id=26394; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'; Name='DisableIOAVProtection'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Scan all downloaded files and attachments'' is set to ''Enabled''.' }
    @{ Id=26395; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'; Name='DisableRealtimeMonitoring'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn off real-time protection'' is set to ''Disabled''.' }
    @{ Id=26396; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'; Name='DisableBehaviorMonitoring'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn on behavior monitoring'' is set to ''Enabled''.' }
    @{ Id=26397; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Real-TimeProtection'; Name='DisableScriptScanning'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn on script scanning'' is set to ''Enabled''.' }
    @{ Id=26398; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Reporting'; Name='DisableGenericRePorts'; Type='DWord'; Data='1'; Title='Ensure ''Configure Watson events'' is set to ''Disabled''.' }
    @{ Id=26399; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DisablePackedExeScanning'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Scan packed executables'' is set to ''Enabled''.' }
    @{ Id=26400; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DisableRemovableDriveScanning'; Type='DWord'; Data='0'; Title='Ensure ''Scan removable drives'' is set to ''Enabled''.' }
    @{ Id=26401; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Scan'; Name='DisableEmailScanning'; Type='DWord'; Data='0'; Title='Ensure ''Turn on e-mail scanning'' is set to ''Enabled''.' }
    @{ Id=26402; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender'; Name='PUAProtection'; Type='DWord'; Data='1'; Title='Ensure ''Configure detection for potentially unwanted applications'' is set to ''Enabled: Block''.' }
    @{ Id=26403; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender'; Name='DisableAntiSpyware'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Turn off Microsoft Defender AntiVirus'' is set to ''Disabled''.' }
    @{ Id=26404; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\AppHVSI'; Name='AuditApplicationGuard'; Type='DWord'; Data='1'; Title='Ensure ''Allow auditing events in Microsoft Defender Application Guard'' is set to ''Enabled''.' }
    @{ Id=26405; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\AppHVSI'; Name='AllowCameraMicrophoneRedirection'; Type='DWord'; Data='0'; Title='Ensure ''Allow camera and microphone access in Microsoft Defender Application Guard'' is set to ''Disabled''.' }
    @{ Id=26406; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\AppHVSI'; Name='AllowPersistence'; Type='DWord'; Data='0'; Title='Ensure ''Allow data persistence for Microsoft Defender Application Guard'' is set to ''Disabled''.' }
    @{ Id=26407; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\AppHVSI'; Name='SaveFilesToHost'; Type='DWord'; Data='0'; Title='Ensure ''Allow files to download and save to the host operating system from Microsoft Defender Application Guard'' is set to ''Disabled''.' }
    @{ Id=26408; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\AppHVSI'; Name='AppHVSIClipboardSettings'; Type='DWord'; Data='1'; Title='Ensure ''Configure Microsoft Defender Application Guard clipboard settings: Clipboard behavior setting'' is set to ''Enabled: Enable clipboard operation ' }
    @{ Id=26409; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\AppHVSI'; Name='AllowAppHVSI_ProviderSet'; Type='DWord'; Data='1'; Title='Ensure ''Turn on Microsoft Defender Application Guard in Managed Mode'' is set to ''Enabled: 1''.' }
    @{ Id=26410; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Feeds'; Name='EnableFeeds'; Type='DWord'; Data='0'; Title='Ensure ''Enable news and interests on the taskbar'' is set to ''Disabled''.' }
    @{ Id=26411; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\OneDrive'; Name='DisableFileSyncNGSC'; Type='DWord'; Data='1'; Title='Ensure ''Prevent the usage of OneDrive for file storage'' is set to ''Enabled''.' }
    @{ Id=26412; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\PushToInstall'; Name='DisablePushToInstall'; Type='DWord'; Data='1'; Title='Ensure ''Turn off Push To Install service'' is set to ''Enabled''.' }
    @{ Id=26413; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client'; Name='DisableCloudClipboardIntegration'; Type='DWord'; Data='1'; Title='Ensure ''Disable Cloud Clipboard integration for server-to-client data transfer'' is set to ''Enabled''.' }
    @{ Id=26414; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DisablePasswordSaving'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow passwords to be saved'' is set to ''Enabled''.' }
    @{ Id=26415; Tier=2; Fam='rdp'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDenyTSConnections'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Allow users to connect remotely by using Remote Desktop Services'' is set to ''Disabled''.' }
    @{ Id=26416; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='EnableUiaRedirection'; Type='DWord'; Data='0'; Title='Ensure ''Allow UI Automation redirection'' is set to ''Disabled''.' }
    @{ Id=26417; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableCcm'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow COM port redirection'' is set to ''Enabled''.' }
    @{ Id=26418; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableCdm'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow drive redirection'' is set to ''Enabled''.' }
    @{ Id=26419; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableLocationRedir'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow location redirection'' is set to ''Enabled''.' }
    @{ Id=26420; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableLPT'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow LPT port redirection'' is set to ''Enabled''.' }
    @{ Id=26421; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisablePNPRedir'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow supported Plug and Play device redirection'' is set to ''Enabled''.' }
    @{ Id=26422; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fDisableWebAuthn'; Type='DWord'; Data='1'; Title='Ensure ''Do not allow WebAuthn redirection'' is set to ''Enabled''.' }
    @{ Id=26423; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fPromptForPassword'; Type='DWord'; Data='1'; Title='Ensure ''Always prompt for password upon connection'' is set to ''Enabled''.' }
    @{ Id=26424; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='fEncryptRPCTraffic'; Type='DWord'; Data='1'; Title='Ensure ''Require secure RPC communication'' is set to ''Enabled''.' }
    @{ Id=26425; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='SecurityLayer'; Type='DWord'; Data='2'; Title='Ensure ''Require use of specific security layer for remote (RDP) connections'' is set to ''Enabled: SSL''.' }
    @{ Id=26426; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='UserAuthentication'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Require user authentication for remote connections by using Network Level Authentication'' is set to ''Enabled''.' }
    @{ Id=26427; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MinEncryptionLevel'; Type='DWord'; Data='3'; AbsentOk=$true; Title='Ensure ''Set client connection encryption level'' is set to ''Enabled: High Level''.' }
    @{ Id=26428; Tier=2; Fam='rdp'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MaxIdleTime'; Type='DWord'; Data='900000'; Accept='range:1-900000'; Title='Ensure ''Set time limit for active but idle Remote Desktop Services sessions'' is set to ''Enabled: 15 minutes or less, but not Never (0)''.'; Note='15 min (Wazuh : <=900000 et !=0).' }
    @{ Id=26429; Tier=2; Fam='rdp'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='MaxDisconnectionTime'; Type='DWord'; Data='60000'; Title='Ensure ''Set time limit for disconnected sessions'' is set to ''Enabled: 1 minute''.' }
    @{ Id=26430; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; Name='DeleteTempDirsOnExit'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Do not delete temp folders upon exit'' is set to ''Disabled''.' }
    @{ Id=26431; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'; Name='DisableEnclosureDownload'; Type='DWord'; Data='1'; Title='Ensure ''Prevent downloading of enclosures'' is set to ''Enabled''.' }
    @{ Id=26432; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowCloudSearch'; Type='DWord'; Data='0'; Title='Ensure ''Allow Cloud Search'' is set to ''Enabled: Disable Cloud Search''.' }
    @{ Id=26433; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowCortana'; Type='DWord'; Data='0'; Title='Ensure ''Allow Cortana'' is set to ''Disabled''.' }
    @{ Id=26434; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowCortanaAboveLock'; Type='DWord'; Data='0'; Title='Ensure ''Allow Cortana above lock screen'' is set to ''Disabled''.' }
    @{ Id=26435; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowIndexingEncryptedStoresOrItems'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow indexing of encrypted files'' is set to ''Disabled''.' }
    @{ Id=26436; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='AllowSearchToUseLocation'; Type='DWord'; Data='0'; Title='Ensure ''Allow search and Cortana to use location'' is set to ''Disabled''.' }
    @{ Id=26437; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name='EnableDynamicContentInWSB'; Type='DWord'; Data='0'; Title='Ensure ''Allow search highlights'' is set to ''Disabled''.' }
    @{ Id=26438; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'; Name='NoGenTicket'; Type='DWord'; Data='1'; Title='Ensure ''Turn off KMS Client Online AVS Validation'' is set to ''Enabled''.' }
    @{ Id=26439; Tier=2; Fam='store'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsStore'; Name='DisableStoreApps'; Type='DWord'; Data='1'; Title='Ensure ''Disable all apps from Microsoft Store'' is set to ''Disabled''.' }
    @{ Id=26440; Tier=2; Fam='store'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsStore'; Name='RequirePrivateStoreOnly'; Type='DWord'; Data='1'; Title='Ensure ''Only display the private store within the Microsoft Store'' is set to ''Enabled''.' }
    @{ Id=26441; Tier=2; Fam='store'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsStore'; Name='AutoDownload'; Type='DWord'; Data='4'; AbsentOk=$true; Title='Ensure ''Turn off Automatic Download and Install of updates'' is set to ''Disabled''.' }
    @{ Id=26442; Tier=2; Fam='store'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsStore'; Name='DisableOSUpgrade'; Type='DWord'; Data='1'; Title='Ensure ''Turn off the offer to update to the latest version of Windows'' is set to ''Enabled''.' }
    @{ Id=26444; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Dsh'; Name='AllowNewsAndInterests'; Type='DWord'; Data='0'; Title='Ensure ''Allow widgets'' is set to ''Disabled''.' }
    @{ Id=26445; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Name='CaptureThreatWindow'; Type='DWord'; Data='1'; Title='Ensure ''Automatic Data Collection'' is set to ''Enabled''.' }
    @{ Id=26446; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Name='NotifyMalicious'; Type='DWord'; Data='1'; Title='Ensure ''Notify Malicious'' is set to ''Enabled''.' }
    @{ Id=26447; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Name='NotifyPasswordReuse'; Type='DWord'; Data='1'; Title='Ensure ''Notify Password Reuse'' is set to ''Enabled''.' }
    @{ Id=26448; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Name='NotifyUnsafeApp'; Type='DWord'; Data='1'; Title='Ensure ''Notify Unsafe App'' is set to ''Enabled''.' }
    @{ Id=26449; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WTDS\Components'; Name='ServiceEnabled'; Type='DWord'; Data='1'; Title='Ensure ''Service Enabled'' is set to ''Enabled''.' }
    @{ Id=26450; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='EnableSmartScreen'; Type='DWord'; Data='1'; Title='Ensure ''Configure Windows Defender SmartScreen'' is set to ''Enabled: Warn and prevent bypass''.' }
    @{ Id=26450; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\System'; Name='ShellSmartScreenLevel'; Type='String'; Data='Block'; Title='Ensure ''Configure Windows Defender SmartScreen'' is set to ''Enabled: Warn and prevent bypass''.' }
    @{ Id=26451; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='AllowGameDVR'; Type='DWord'; Data='0'; Title='Ensure ''Enables or disables Windows Game Recording and Broadcasting'' is set to ''Disabled''.' }
    @{ Id=26452; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Name='EnableESSwithSupportedPeripherals'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Enable ESS with Supported Peripherals'' is set to ''Enabled: 1''.' }
    @{ Id=26453; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name='AllowSuggestedAppsInWindowsInkWorkspace'; Type='DWord'; Data='0'; Title='Ensure ''Allow suggested apps in Windows Ink Workspace'' is set to ''Disabled''.' }
    @{ Id=26454; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; Name='AllowWindowsInkWorkspace'; Type='DWord'; Data='1'; Accept='0|1'; Title='Ensure ''Allow Windows Ink Workspace'' is set to ''Enabled: On, but disallow access above lock'' OR ''Enabled: Disabled''.'; Note='1 = actif mais inaccessible au-dessus de l''ecran de verrouillage.' }
    @{ Id=26455; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='EnableUserControl'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow user control over installs'' is set to ''Disabled''.' }
    @{ Id=26456; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='AlwaysInstallElevated'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Always install with elevated privileges'' is set to ''Disabled''.' }
    @{ Id=26457; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Installer'; Name='SafeForScripting'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Prevent Internet Explorer security prompt for Windows Installer scripts'' is set to ''Disabled''.' }
    @{ Id=26458; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='EnableMPR'; Type='DWord'; Data='0'; Title='Ensure ''Enable MPR notifications for the system'' is set to ''Disabled''.' }
    @{ Id=26459; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableAutomaticRestartSignOn'; Type='DWord'; Data='1'; Title='Ensure ''Sign-in and lock last interactive user automatically after a restart'' is set to ''Disabled''.' }
    @{ Id=26460; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Turn on PowerShell Script Block Logging'' is set to ''Enabled''.' }
    @{ Id=26461; Tier=2; Fam='pwsh-transcript'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name='EnableTranscripting'; Type='DWord'; Data='1'; Title='Ensure ''Turn on PowerShell Transcription'' is set to ''Enabled''.' }
    @{ Id=26462; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowBasic'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow Basic authentication'' is set to ''Disabled''.' }
    @{ Id=26463; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowUnencryptedTraffic'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow unencrypted traffic'' is set to ''Disabled''.' }
    @{ Id=26464; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'; Name='AllowDigest'; Type='DWord'; Data='0'; Title='Ensure ''Disallow Digest authentication'' is set to ''Enabled''.' }
    @{ Id=26465; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowBasic'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow Basic authentication'' is set to ''Disabled''.' }
    @{ Id=26466; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowAutoConfig'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow remote server management through WinRM'' is set to ''Disabled''.' }
    @{ Id=26467; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='AllowUnencryptedTraffic'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Allow unencrypted traffic'' is set to ''Disabled''.' }
    @{ Id=26468; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'; Name='DisableRunAs'; Type='DWord'; Data='1'; Title='Ensure ''Disallow WinRM from storing RunAs credentials'' is set to ''Enabled''.' }
    @{ Id=26469; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS'; Name='AllowRemoteShellAccess'; Type='DWord'; Data='0'; Title='Ensure ''Allow Remote Shell Access'' is set to ''Disabled''.' }
    @{ Id=26470; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Sandbox'; Name='AllowClipboardRedirection'; Type='DWord'; Data='0'; Title='Ensure ''Allow clipboard sharing with Windows Sandbox'' is set to ''Disabled''.' }
    @{ Id=26471; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\Sandbox'; Name='AllowNetworking'; Type='DWord'; Data='0'; Title='Ensure ''Allow networking in Windows Sandbox'' is set to ''Disabled''.' }
    @{ Id=26472; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender Security Center\App and Browser protection'; Name='DisallowExploitProtectionOverride'; Type='DWord'; Data='1'; Title='Ensure ''Prevent users from modifying settings'' is set to ''Enabled''.' }
    @{ Id=26473; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoRebootWithLoggedOnUsers'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''No auto-restart with logged on users for scheduled automatic updates installations'' is set to ''Disabled''.' }
    @{ Id=26474; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='NoAutoUpdate'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Configure Automatic Updates'' is set to ''Enabled''.' }
    @{ Id=26475; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name='ScheduledInstallDay'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Configure Automatic Updates: Scheduled install day'' is set to ''0 - Every day''.' }
    @{ Id=26476; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='AllowTemporaryEnterpriseFeatureControl'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Enable features introduced via servicing that are off by default'' is set to ''Disabled''.' }
    @{ Id=26477; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='SetDisablePauseUXAccess'; Type='DWord'; Data='1'; Title='Ensure ''Remove access to \"Pause updates\" feature'' is set to ''Enabled''.' }
    @{ Id=26478; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='ManagePreviewBuildsPolicyValue'; Type='DWord'; Data='1'; AbsentOk=$true; Title='Ensure ''Manage preview builds'' is set to ''Disabled''.' }
    @{ Id=26479; Tier=2; Fam='defer-updates'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='DeferFeatureUpdates'; Type='DWord'; Data='1'; Title='Ensure ''Select when Preview Builds and Feature Updates are received'' is set to ''Enabled: 180 or more days''.' }
    @{ Id=26479; Tier=2; Fam='defer-updates'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='DeferFeatureUpdatesPeriodInDays'; Type='DWord'; Data='180'; Title='Ensure ''Select when Preview Builds and Feature Updates are received'' is set to ''Enabled: 180 or more days''.' }
    @{ Id=26480; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='DeferQualityUpdates'; Type='DWord'; Data='1'; Title='Ensure ''Select when Quality Updates are received'' is set to ''Enabled: 0 days''.' }
    @{ Id=26480; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='DeferQualityUpdatesPeriodInDays'; Type='DWord'; Data='0'; Title='Ensure ''Select when Quality Updates are received'' is set to ''Enabled: 0 days''.' }
    @{ Id=26481; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Name='AllowOptionalContent'; Type='DWord'; Data='0'; AbsentOk=$true; Title='Ensure ''Enable optional updates'' is set to ''Disabled''.' }
)

$CisServices = @(
    @{ Id=26072; Tier=2; Service='BTAGService'; Guard='bluetooth'; Title='Ensure ''Bluetooth Audio Gateway Service (BTAGService)'' is set to ''Disabled''.' }
    @{ Id=26073; Tier=2; Service='bthserv'; Guard='bluetooth'; Title='Ensure ''Bluetooth Support Service (bthserv)'' is set to ''Disabled''.' }
    @{ Id=26074; Tier=2; Service='Browser'; Guard=''; Title='Ensure ''Computer Browser (Browser)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26075; Tier=2; Service='MapsBroker'; Guard=''; Title='Ensure ''Downloaded Maps Manager (MapsBroker)'' is set to ''Disabled''.' }
    @{ Id=26076; Tier=2; Service='lfsvc'; Guard='geoloc'; Title='Ensure ''Geolocation Service (lfsvc)'' is set to ''Disabled''.' }
    @{ Id=26077; Tier=2; Service='IISADMIN'; Guard=''; Title='Ensure ''IIS Admin Service (IISADMIN)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26078; Tier=2; Service='irmon'; Guard=''; Title='Ensure ''Infrared monitor service (irmon)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26079; Tier=2; Service='lltdsvc'; Guard=''; Title='Ensure ''Link-Layer Topology Discovery Mapper (lltdsvc)'' is set to ''Disabled''.' }
    @{ Id=26080; Tier=2; Service='LxssManager'; Guard='wsl'; Title='Ensure ''LxssManager (LxssManager)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26081; Tier=2; Service='FTPSVC'; Guard=''; Title='Ensure ''Microsoft FTP Service (FTPSVC)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26082; Tier=2; Service='MSiSCSI'; Guard=''; Title='Ensure ''Microsoft iSCSI Initiator Service (MSiSCSI)'' is set to ''Disabled''.' }
    @{ Id=26083; Tier=2; Service='sshd'; Guard='sshd'; Title='Ensure ''OpenSSH SSH Server (sshd)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26084; Tier=2; Service='PNRPsvc'; Guard=''; Title='Ensure ''Peer Name Resolution Protocol (PNRPsvc)'' is set to ''Disabled''.' }
    @{ Id=26085; Tier=2; Service='p2psvc'; Guard=''; Title='Ensure ''Peer Networking Grouping (p2psvc)'' is set to ''Disabled''.' }
    @{ Id=26086; Tier=2; Service='p2pimsvc'; Guard=''; Title='Ensure ''Peer Networking Identity Manager (p2pimsvc)'' is set to ''Disabled''.' }
    @{ Id=26087; Tier=2; Service='PNRPAutoReg'; Guard=''; Title='Ensure ''PNRP Machine Name Publication Service (PNRPAutoReg)'' is set to ''Disabled''.' }
    @{ Id=26088; Tier=2; Service='Spooler'; Guard='printers'; Title='Ensure ''Print Spooler (Spooler)'' is set to ''Disabled''.' }
    @{ Id=26089; Tier=2; Service='wercplsupport'; Guard=''; Title='Ensure ''Problem Reports and Solutions Control Panel Support (wercplsupport)'' is set to ''Disabled''.' }
    @{ Id=26090; Tier=2; Service='RasAuto'; Guard=''; Title='Ensure ''Remote Access Auto Connection Manager (RasAuto)'' is set to ''Disabled''.' }
    @{ Id=26091; Tier=2; Service='SessionEnv'; Guard='rdp'; Title='Ensure ''Remote Desktop Configuration (SessionEnv)'' is set to ''Disabled''.' }
    @{ Id=26092; Tier=2; Service='TermService'; Guard='rdp'; Title='Ensure ''Remote Desktop Services (TermService)'' is set to ''Disabled''.' }
    @{ Id=26093; Tier=2; Service='UmRdpService'; Guard='rdp'; Title='Ensure ''Remote Desktop Services UserMode Port Redirector (UmRdpService)'' is set to ''Disabled''.' }
    @{ Id=26094; Tier=2; Service='RpcLocator'; Guard=''; Title='Ensure ''Remote Procedure Call (RPC) Locator (RpcLocator)'' is set to ''Disabled''.' }
    @{ Id=26095; Tier=2; Service='RemoteRegistry'; Guard=''; Title='Ensure ''Remote Registry (RemoteRegistry)'' is set to ''Disabled''.' }
    @{ Id=26096; Tier=2; Service='RemoteAccess'; Guard=''; Title='Ensure ''Routing and Remote Access (RemoteAccess)'' is set to ''Disabled''.' }
    @{ Id=26097; Tier=2; Service='LanmanServer'; Guard='shares'; Title='Ensure ''Server (LanmanServer)'' is set to ''Disabled''.' }
    @{ Id=26098; Tier=2; Service='simptcp'; Guard=''; Title='Ensure ''Simple TCP/IP Services (simptcp)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26099; Tier=2; Service='SNMP'; Guard=''; Title='Ensure ''SNMP Service (SNMP)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26100; Tier=2; Service='sacsvr'; Guard=''; Title='Ensure ''Special Administration Console Helper (sacsvr)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26101; Tier=2; Service='SSDPSRV'; Guard=''; Title='Ensure ''SSDP Discovery (SSDPSRV)'' is set to ''Disabled''.' }
    @{ Id=26102; Tier=2; Service='upnphost'; Guard=''; Title='Ensure ''UPnP Device Host (upnphost)'' is set to ''Disabled''.' }
    @{ Id=26103; Tier=2; Service='WMSvc'; Guard=''; Title='Ensure ''Web Management Service (WMSvc)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26104; Tier=2; Service='WerSvc'; Guard=''; Title='Ensure ''Windows Error Reporting Service (WerSvc)'' is set to ''Disabled''.' }
    @{ Id=26105; Tier=2; Service='Wecsvc'; Guard=''; Title='Ensure ''Windows Event Collector (Wecsvc)'' is set to ''Disabled''.' }
    @{ Id=26106; Tier=2; Service='WMPNetworkSvc'; Guard=''; Title='Ensure ''Windows Media Player Network Sharing Service (WMPNetworkSvc)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26107; Tier=2; Service='icssvc'; Guard=''; Title='Ensure ''Windows Mobile Hotspot Service (icssvc)'' is set to ''Disabled''.' }
    @{ Id=26108; Tier=2; Service='WpnService'; Guard='notifications'; Title='Ensure ''Windows Push Notifications System Service (WpnService)'' is set to ''Disabled''.' }
    @{ Id=26109; Tier=2; Service='PushToInstall'; Guard=''; Title='Ensure ''Windows PushToInstall Service (PushToInstall)'' is set to ''Disabled''.' }
    @{ Id=26110; Tier=2; Service='WinRM'; Guard=''; Title='Ensure ''Windows Remote Management (WS- Management) (WinRM)'' is set to ''Disabled''.' }
    @{ Id=26111; Tier=2; Service='W3SVC'; Guard=''; Title='Ensure ''World Wide Web Publishing Service (W3SVC)'' is set to ''Disabled'' or ''Not Installed''.' }
    @{ Id=26112; Tier=2; Service='XboxGipSvc'; Guard='xbox'; Title='Ensure ''Xbox Accessory Management Service (XboxGipSvc)'' is set to ''Disabled''.' }
    @{ Id=26113; Tier=2; Service='XblAuthManager'; Guard='xbox'; Title='Ensure ''Xbox Live Auth Manager (XblAuthManager)'' is set to ''Disabled''.' }
    @{ Id=26114; Tier=2; Service='XblGameSave'; Guard='xbox'; Title='Ensure ''Xbox Live Game Save (XblGameSave)'' is set to ''Disabled''.' }
    @{ Id=26115; Tier=2; Service='XboxNetApiSvc'; Guard='xbox'; Title='Ensure ''Xbox Live Networking Service (XboxNetApiSvc)'' is set to ''Disabled''.' }
    @{ Id=26172; Tier=1; Service='mrxsmb10'; Guard=''; Title='Ensure ''Configure SMB v1 client driver'' is set to ''Enabled: Disable driver (recommended)''.' }
)

$CisDelete = @(
    @{ Id=26244; Tier=1; Fam='base'; Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name='DisableBkGndGroupPolicy'; Title='Ensure ''Turn off background refresh of Group Policy'' is set to ''Disabled''.'; Note='Wazuh exige l''ABSENCE de la valeur (rafraichissement GPO en arriere-plan actif).' }
    @{ Id=26389; Tier=9; Fam='score-only'; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows Defender\Spynet'; Name='SpynetReporting'; Title='Ensure ''Join Microsoft MAPS'' is set to ''Disabled''.'; Note='CIS veut Microsoft MAPS desactive. C''est une REGRESSION de securite reelle (protection cloud Defender) : applique uniquement avec -ScoreOnly.' }
)

$CisBlocked = @(
)

$CisManual = @(
    @{ Id=26011; Title='Configure ''Accounts: Rename administrator account''.'; Why='Renommer le compte administrateur -- nom a choisir par l''utilisateur.' }
    @{ Id=26012; Title='Configure ''Accounts: Rename guest account''.'; Why='Renommer le compte invite -- nom a choisir par l''utilisateur.' }
    @{ Id=26225; Title='Ensure ''Turn On Virtualization Based Security'' is set to ''Enabled''.'; Why='VBS/Credential Guard -- isole LSASS ; adjacent a la protection LSA, exclu par defaut (-EnableVBS).' }
    @{ Id=26226; Title='Ensure ''Turn On Virtualization Based Security: Select Platform Security Level'' is set to ''Secure Boot'' or higher.'; Why='VBS : niveau de securite plateforme (Secure Boot + DMA).' }
    @{ Id=26227; Title='Ensure ''Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity'' is set to ''Enabled with UEFI lock''.'; Why='VBS : integrite du code (HVCI) -- peut bloquer des pilotes non signes.' }
    @{ Id=26228; Title='Ensure ''Turn On Virtualization Based Security: Require UEFI Memory Attributes Table'' is set to ''True (checked)''.'; Why='VBS : table d''attributs memoire UEFI requise.' }
    @{ Id=26229; Title='Ensure ''Turn On Virtualization Based Security: Credential Guard Configuration'' is set to ''Enabled with UEFI lock''.'; Why='VBS : Credential Guard avec verrou UEFI -- desactivation ulterieure impossible sans acces physique.' }
    @{ Id=26230; Title='Ensure ''Turn On Virtualization Based Security: Kernel-mode Hardware-enforced Stack Protection'' is set to ''Enabled: Enabled in enforcement mode''.'; Why='VBS : protection materielle de la pile en mode noyau.' }
    @{ Id=26261; Title='Ensure ''Configure password backup directory'' is set to ''Enabled: Active Directory'' or ''Enabled: Azure Active Directory''.'; Why='LAPS : necessite Active Directory ou Entra ID.' }
    @{ Id=26268; Title='Ensure ''Post-authentication actions: Actions'' is set to ''Enabled: Reset the password and logoff the managed account'' or higher.'; Why='LAPS : action post-authentification.' }
    @{ Id=26269; Title='Ensure ''Allow Custom SSPs and APs to be loaded into LSASS'' is set to ''Disabled''.'; Why='Protection LSA : interdit tout package d''authentification TIERS dans LSASS (middleware de carte a puce, certains SSO). Liste noire si le poste ouvre sa session par carte.' }
    @{ Id=26270; Title='Ensure ''Configures LSASS to run as a protected process'' is set to ''Enabled: Enabled with UEFI Lock''.'; Why='Protection LSA : LSASS en processus protege avec verrou UEFI -- refuse tout module non signe PPL, et le verrou ne se retire pas sans acces physique. Liste noire si le poste ouvre sa session par carte.' }
    @{ Id=26317; Title='Ensure ''Configure use of smart cards on fixed data drives: Require use of smart cards on fixed data drives'' is set to ''Enabled: True''.'; Why='BitLocker : EXIGER une carte a puce sur les lecteurs fixes -- si la carte tombe en panne, volume inaccessible.' }
    @{ Id=26331; Title='Ensure ''Require additional authentication at startup: Allow BitLocker without a compatible TPM'' is set to ''Enabled: False''.'; Why='BitLocker sans TPM compatible interdit -- a decider selon le materiel.' }
    @{ Id=26348; Title='Ensure ''Configure use of smart cards on removable data drives: Require use of smart cards on removable data drives'' is set to ''Enabled: True''.'; Why='BitLocker : EXIGER une carte a puce sur les lecteurs amovibles -- meme risque.' }
    @{ Id=26349; Title='Ensure ''Deny write access to removable drives not protected by BitLocker'' is set to ''Enabled''.'; Why='BitLocker : cles USB non chiffrees en LECTURE SEULE -- impact quotidien fort.' }
    @{ Id=26443; Title='Ensure ''Turn off the Store application'' is set to ''Enabled''.'; Why='Store : le fait DISPARAITRE (plus d''installation ni de mise a jour d''applications du Store). Les autres controles ''store'' du TIER 2 le brident deja.' }
)

# -- Politique d'audit : 27 sous-categories, adressees par GUID -----------
# L'appel par NOM echoue en erreur 87 sur un Windows non anglais (verifie en
# direct : le nom anglais du contenu CIS n'existe pas, et le nom francais reel
# echoue aussi -- probleme d'encodage des accents en ligne de commande). Le
# GUID est en ASCII pur et identique sur toutes les langues depuis Vista.
$CisAudit = @(
    @{ Id=26139; Sub='Credential Validation';            Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26140; Sub='Application Group Management';     Guid='{0CCE9239-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26141; Sub='Security Group Management';        Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26142; Sub='User Account Management';          Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26143; Sub='Plug and Play Events';             Guid='{0CCE9248-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26144; Sub='Process Creation';                 Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26145; Sub='Account Lockout';                  Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; S=$false; F=$true  }
    @{ Id=26146; Sub='Group Membership';                 Guid='{0CCE9249-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26147; Sub='Logoff';                           Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26148; Sub='Logon';                            Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26149; Sub='Other Logon/Logoff Events';        Guid='{0CCE921C-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26150; Sub='Special Logon';                    Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26151; Sub='Detailed File Share';              Guid='{0CCE9244-69AE-11D9-BED3-505054503030}'; S=$false; F=$true  }
    @{ Id=26152; Sub='File Share';                       Guid='{0CCE9224-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26153; Sub='Other Object Access Events';       Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26154; Sub='Removable Storage';                Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26155; Sub='Audit Policy Change';              Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26156; Sub='Authentication Policy Change';     Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26157; Sub='Authorization Policy Change';      Guid='{0CCE9231-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26158; Sub='MPSSVC Rule-Level Policy Change';  Guid='{0CCE9232-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26159; Sub='Other Policy Change Events';       Guid='{0CCE9234-69AE-11D9-BED3-505054503030}'; S=$false; F=$true  }
    @{ Id=26160; Sub='Sensitive Privilege Use';          Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26161; Sub='IPsec Driver';                     Guid='{0CCE9213-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26162; Sub='Other System Events';              Guid='{0CCE9214-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
    @{ Id=26163; Sub='Security State Change';            Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26164; Sub='Security System Extension';        Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; S=$true;  F=$false }
    @{ Id=26165; Sub='System Integrity';                 Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; S=$true;  F=$true  }
)

# Politique de comptes (net accounts) -- les commutateurs sont en anglais quelle
# que soit la langue de Windows, contrairement aux noms de sous-categories.
$CisAccountPolicy = [ordered]@{
    'uniquepw'         = 24    # 26000
    'maxpwage'         = 365   # 26001
    'minpwage'         = 1     # 26002
    'minpwlen'         = 14    # 26003
    'lockoutduration'  = 15    # 26005
    'lockoutthreshold' = 5     # 26006
    'lockoutwindow'    = 15    # 26007
}

# ==================== 1. PROFIL DE LA MACHINE ============================
function Get-MachineProfile {
    $p = [ordered]@{}
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue

    $p.Host    = $env:COMPUTERNAME
    $p.OS      = if ($os) { $os.Caption } else { 'inconnu' }
    $p.Build   = if ($os) { $os.BuildNumber } else { '?' }
    $p.Culture = (Get-Culture).Name
    $p.English = (Get-Culture).TwoLetterISOLanguageName -eq 'en'
    $p.Laptop  = [bool](Get-CimInstance Win32_Battery -ErrorAction SilentlyContinue)
    $p.Domain  = [bool]($cs -and $cs.PartOfDomain)

    $p.AzureAD = $false
    try {
        $dsreg = & dsregcmd.exe /status 2>$null
        $p.AzureAD = [bool]($dsreg -match 'AzureAdJoined\s*:\s*YES')
    } catch { }

    # BitLocker actif sur au moins un volume.
    # Get-BitLockerVolume ET manage-bde exigent l'elevation : dans une session
    # ordinaire, les deux echouent et on ne peut pas conclure. Repondre "non"
    # serait le pire des choix -- la famille 'fve' (12 controles) et 'lockout'
    # sont gardees PAR ce booleen, une simulation non elevee annoncerait donc
    # qu'elle appliquerait des controles BitLocker qu'un -Apply (toujours
    # elevee) ecarterait. Faute de savoir, on suppose ACTIF : le garde-fou
    # reste ferme et la simulation ne promet rien qu'elle ne tiendrait pas.
    # Constate le 2026-08-04 : le meme poste affichait 'BitLocker ACTIF' en
    # session elevee et rien du tout en session ordinaire.
    $p.BitLocker      = $false
    $p.BitLockerKnown = $true
    try {
        $bde = Get-BitLockerVolume -ErrorAction Stop
        $p.BitLocker = [bool]($bde | Where-Object { $_.ProtectionStatus -eq 'On' })
    } catch {
        try { $p.BitLocker = [bool]((& manage-bde.exe -status 2>$null) -match 'Protection\s+On') } catch { }
        if (-not $isAdmin) { $p.BitLocker = $true; $p.BitLockerKnown = $false }
    }

    # Carte a puce : lecteur present ou service demarre
    $p.SmartCardReader = $false
    $p.ReaderNames     = @()
    try {
        $rd = @(Get-PnpDevice -Class SmartCardReader -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' })
        $p.SmartCardReader = [bool]$rd.Count
        $p.ReaderNames     = @($rd | ForEach-Object { $_.FriendlyName })
    } catch { }
    $p.SmartCardSvc = (Get-Service SCardSvr -ErrorAction SilentlyContinue).Status -eq 'Running'
    $p.SmartCard    = $p.SmartCardReader -or $p.SmartCardSvc

    # -- Pile de CONNEXION par carte sur un compte local ------------------
    # SCardSvr tourne sur presque tous les Windows : sa seule presence ne dit
    # pas que le poste OUVRE SA SESSION par carte. Le signal fort, c'est le
    # package d'authentification tiers reellement declare dans LSA, avec ses
    # DLL sur le disque.
    $p.EIDDlls = @($SmartCardDlls | Where-Object { Test-Path (Join-Path $env:SystemRoot "System32\$_") })
    $lsaKey = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $p.AuthPackages   = @(if ($lsaKey) { $lsaKey.'Authentication Packages' })
    $p.SecPackages    = @(if ($lsaKey) { $lsaKey.'Security Packages' })
    $p.NotifPackages  = @(if ($lsaKey) { $lsaKey.'Notification Packages' })
    $p.EIDRegistered  = [bool](($p.AuthPackages + $p.SecPackages + $p.NotifPackages) -match 'EID')
    $p.SmartCardLogonStack = ($p.EIDDlls.Count -eq $SmartCardDlls.Count) -and $p.EIDRegistered

    # Etat courant de l'isolation de LSA -- ce que le script s'interdit de changer
    $p.RunAsPPL = 0
    if ($lsaKey -and $null -ne $lsaKey.RunAsPPL) { $p.RunAsPPL = [int]$lsaKey.RunAsPPL }
    $p.CredGuardRunning = $false
    $p.HvciRunning      = $false
    try {
        $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
        # 1 = Credential Guard, 2 = integrite du code par l'hyperviseur (HVCI)
        $p.CredGuardRunning = ($dg.SecurityServicesRunning -contains 1)
        $p.HvciRunning      = ($dg.SecurityServicesRunning -contains 2)
    } catch { }

    # Compte Microsoft utilise pour ouvrir une session
    $p.MicrosoftAccount = $false
    try { $p.MicrosoftAccount = [bool](Get-LocalUser -ErrorAction Stop | Where-Object { $_.Enabled -and $_.PrincipalSource -eq 'MicrosoftAccount' }) } catch { }

    # Code PIN Windows Hello configure pour au moins un utilisateur
    $ngc = "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc"
    $p.HelloPin = [bool]((Get-ChildItem $ngc -Directory -ErrorAction SilentlyContinue | Measure-Object).Count)

    # Imprimante reelle (on ignore les imprimantes virtuelles de Windows).
    # Si le spouleur est deja arrete, Get-Printer echoue : il n'y a alors plus
    # rien a proteger, le garde-fou laisse passer.
    $p.Printers      = $false
    $p.SpoolerIsDown = ((Get-Service Spooler -ErrorAction SilentlyContinue).Status -ne 'Running')
    try {
        $p.Printers = [bool](Get-Printer -ErrorAction Stop | Where-Object {
            $_.Name -notmatch 'Microsoft Print to PDF|Microsoft XPS|OneNote|Fax' })
    } catch {
        try { $p.Printers = [bool](Get-CimInstance Win32_Printer -ErrorAction Stop | Where-Object { $_.PortName -like 'USB*' -or $_.PortName -like 'IP_*' -or $_.PortName -like 'WSD*' }) } catch { }
    }

    # Bluetooth : un adaptateur dont le pilote n'a pas demarre remonte en
    # 'Unknown'/'Error' des que bthserv est deja desactive -- ne pas s'y fier
    # seul. On considere le Bluetooth "en usage" si un peripherique repond OK
    # OU si le service de prise en charge est encore en demarrage automatique.
    $p.Bluetooth = $false
    try { $p.Bluetooth = [bool](Get-PnpDevice -Class Bluetooth -ErrorAction Stop | Where-Object { $_.Status -eq 'OK' }) } catch { }
    if (-not $p.Bluetooth) {
        $bt = Get-Service bthserv -ErrorAction SilentlyContinue
        if ($bt -and $bt.StartType -eq 'Automatic') { $p.Bluetooth = $true }
    }

    # Webcam. Le controle 26352 (AllowCamera = 0) coupe la camera pour TOUTES
    # les applications de la machine, sans message explicite : l'appli annonce
    # qu'aucune camera n'est disponible alors que le peripherique est en etat
    # OK et que la confidentialite est sur "Autoriser". Un poste qui a une
    # webcam reconnue a, par defaut, l'usage de sa webcam.
    # On enumere tout puis on filtre : -Class Camera,Image sous -ErrorAction
    # Stop leve des qu'une des classes est vide, et on conclurait "pas de
    # webcam" sur un poste qui en a une.
    $p.Camera      = $false
    $p.CameraNames = @()
    try {
        $cam = @(Get-PnpDevice -ErrorAction Stop | Where-Object {
            ($_.Class -eq 'Camera' -or $_.Service -eq 'usbvideo') -and $_.Status -eq 'OK' })
        $p.Camera      = [bool]$cam.Count
        $p.CameraNames = @($cam | ForEach-Object { $_.FriendlyName })
    } catch { }

    # Etats de veille. Les controles 26281-26284 (famille 'sleep') supposent
    # une machine a Modern Standby (S0), ou S1-S3 sont un chemin de repli mal
    # protege. Sur un portable S3 CLASSIQUE -- S0 non pris en charge par le
    # microprogramme -- 26283/26284 ne ferment pas une porte : ils suppriment
    # la DERNIERE, et renvoient toute mise en veille sur la veille prolongee.
    # Sur le poste qui l'a revele, ce chemin echouait une reprise sur trois en
    # 0xC00000D4, ce qui jette les ecritures en cache de TOUS les volumes.
    # On MESURE au lieu de supposer : powercfg /a. La sortie est localisee, on
    # se repere donc sur la coupure entre etats disponibles et indisponibles,
    # et on n'y cherche que 'S0' et 'S3'.
    $p.SleepRead     = $false
    $p.ModernStandby = $false
    $p.SleepS3       = $false
    try {
        $pa = (& powercfg /a 2>$null) -join "`n"
        if ($pa) {
            $p.SleepRead     = $true
            $dispo           = ($pa -split 'ne sont pas disponibles|are not available')[0]
            $p.SleepS3       = [bool]($dispo -match 'S3')
            $p.ModernStandby = [bool]($dispo -match 'S0')
        }
    } catch { }

    $lxss = Get-Service LxssManager -ErrorAction SilentlyContinue
    $p.WSL = [bool]($lxss -and $lxss.StartType -ne 'Disabled')

    $sshd = Get-Service sshd -ErrorAction SilentlyContinue
    $p.SSHD = [bool]($sshd -and $sshd.StartType -ne 'Disabled')

    $p.RDP = $false
    try { $p.RDP = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections -eq 0) } catch { }

    $p.Shares = $false
    try { $p.Shares = [bool](Get-SmbShare -ErrorAction Stop | Where-Object { -not $_.Special }) } catch { }

    $p.Xbox = [bool](Get-Service XblGameSave, XboxNetApiSvc -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Running' })

    $p.Wazuh        = [bool](Get-Service WazuhSvc -ErrorAction SilentlyContinue)
    $p.ScaPolicy    = 'C:\Program Files (x86)\ossec-agent\ruleset\sca\cis_win11_enterprise.yml'
    $p.HasScaPolicy = Test-Path $p.ScaPolicy

    return $p
}

function Show-MachineProfile($m) {
    Write-Host "`n-- Profil de la machine ------------------------------------" -ForegroundColor Cyan
    Write-Host ("  {0} -- {1} (build {2}), langue {3}" -f $m.Host, $m.OS, $m.Build, $m.Culture)
    $flags = @()
    if ($m.Laptop)           { $flags += 'portable' }
    if ($m.Domain)           { $flags += 'domaine AD' }
    if ($m.AzureAD)          { $flags += 'Entra ID' }
    if (-not ($m.Domain -or $m.AzureAD)) { $flags += 'WORKGROUP' }
    if ($m.BitLocker -and $m.BitLockerKnown)      { $flags += 'BitLocker ACTIF' }
    elseif ($m.BitLocker -and -not $m.BitLockerKnown) { $flags += 'BitLocker INDETERMINE (suppose actif)' }
    if ($m.SmartCardLogonStack) { $flags += 'CONNEXION PAR CARTE' }
    elseif ($m.SmartCard)       { $flags += 'carte a puce' }
    if ($m.MicrosoftAccount) { $flags += 'compte Microsoft' }
    if ($m.HelloPin)         { $flags += 'code PIN Hello' }
    if ($m.Printers)         { $flags += 'imprimante' }
    if ($m.Camera)           { $flags += 'webcam' }
    if ($m.SleepRead -and -not $m.ModernStandby) { $flags += 'veille S3 classique (pas de Modern Standby)' }
    if ($m.Bluetooth)        { $flags += 'Bluetooth' }
    if ($m.WSL)              { $flags += 'WSL' }
    if ($m.SSHD)             { $flags += 'serveur SSH' }
    if ($m.RDP)              { $flags += 'RDP actif' }
    if ($m.Shares)           { $flags += 'partages SMB' }
    if ($m.Xbox)             { $flags += 'services Xbox' }
    if ($m.Wazuh)            { $flags += 'agent Wazuh' }
    Write-Host ("  Detecte : " + ($flags -join ' | ')) -ForegroundColor White
    if (-not $m.English) {
        Write-Host "  Windows non anglais : les 27 controles d'audit (26139-26165) seront" -ForegroundColor Yellow
        Write-Host "  APPLIQUES mais resteront en echec cote Wazuh -- la regle SCA compare la" -ForegroundColor Yellow
        Write-Host "  sortie d'auditpol a la chaine anglaise 'Success and Failure'. Plafond de" -ForegroundColor Yellow
        Write-Host "  score connu, ce n'est pas un trou de securite." -ForegroundColor Yellow
    }
}

# ============ 1 bis. PROFIL CARTE A PUCE ET LISTE NOIRE ETENDUE ==========
# Decide si ce poste ouvre sa session par carte, puis etend la liste noire en
# consequence. Appele APRES le profil et AVANT toute selection de controles.
$script:CardMode   = $false
$script:CardReason = ''

function Set-SmartCardPolicy($m) {
    if ($NoSmartCard) {
        $script:CardMode   = $false
        $script:CardReason = "-NoSmartCard : declare par l'operateur comme poste sans connexion par carte"
    } elseif ($SmartCardLogon) {
        $script:CardMode   = $true
        $script:CardReason = "-SmartCardLogon : impose par l'operateur"
    } elseif ($m.SmartCardLogonStack) {
        $script:CardMode   = $true
        $script:CardReason = "package d'authentification tiers declare dans LSA + $($m.EIDDlls.Count)/$($SmartCardDlls.Count) DLL presentes"
    } elseif ($m.SmartCardReader) {
        $script:CardMode   = $true
        $script:CardReason = "lecteur de carte present ($($m.ReaderNames -join ', ')) -- prudence par defaut"
    } else {
        $script:CardMode   = $false
        $script:CardReason = 'aucun lecteur ni package de carte detecte'
    }

    if ($script:CardMode) {
        $script:ForbiddenIds    = @($ForbiddenIds + $SmartCardForbiddenIds | Select-Object -Unique)
        $script:ForbiddenValues = @($ForbiddenValues + $SmartCardForbiddenValues)
        $script:CisBlocked      = @($CisBlocked) + @($CisManual |
            Where-Object { $SmartCardForbiddenIds -contains $_.Id } |
            ForEach-Object { @{ Id=$_.Id; Title=$_.Title } })
        $script:CisManual       = @($CisManual | Where-Object { $SmartCardForbiddenIds -notcontains $_.Id })
    }
}

function Show-SmartCardStack($m) {
    Write-Host "`n-- Pile carte a puce ---------------------------------------" -ForegroundColor Cyan
    if ($script:CardMode) {
        Write-Host "  PROFIL CARTE A PUCE ACTIF -- $($script:CardReason)" -ForegroundColor Green
    } else {
        Write-Host "  Profil carte a puce inactif -- $($script:CardReason)" -ForegroundColor DarkGray
        Write-Host "  (-SmartCardLogon pour l'imposer quand meme)" -ForegroundColor DarkGray
    }
    Write-Host ("  Lecteur                   : {0}" -f $(if ($m.SmartCardReader) { $m.ReaderNames -join ', ' } else { 'aucun' }))
    Write-Host ("  Package d'authentification: {0}" -f $(if ($m.EIDRegistered) { 'declare dans LSA' } else { 'absent' })) `
        -ForegroundColor $(if ($m.EIDRegistered) { 'Green' } else { 'DarkGray' })
    $missing = @($SmartCardDlls | Where-Object { $m.EIDDlls -notcontains $_ })
    Write-Host ("  DLL dans System32         : {0}/{1}" -f $m.EIDDlls.Count, $SmartCardDlls.Count) `
        -ForegroundColor $(if ($missing.Count) { 'Red' } else { 'Green' })
    if ($missing.Count -and ($m.EIDRegistered -or $m.EIDDlls.Count)) {
        Write-Host ("    MANQUANTE(S) : {0}" -f ($missing -join ', ')) -ForegroundColor Red
        Write-Host "    LSA reclame un package dont la DLL n'est pas la : la connexion par" -ForegroundColor Red
        Write-Host "    carte echouera au prochain demarrage. Reparer AVANT de durcir." -ForegroundColor Red
    }
    # Rouge = dangereux pour la carte. Hors profil carte, ces protections sont
    # souhaitables : on les affiche sans jugement.
    $card = [bool]$script:CardMode
    Write-Host ("  Protection LSA (RunAsPPL) : {0}" -f $m.RunAsPPL) `
        -ForegroundColor $(if (-not $card) { 'Gray' } elseif ($m.RunAsPPL -eq 0) { 'Green' } else { 'Red' })
    Write-Host ("  Credential Guard          : {0}" -f $(if ($m.CredGuardRunning) { 'EN COURS' + $(if ($card) { ' -- incompatible' } else { '' }) } else { 'inactif' })) `
        -ForegroundColor $(if (-not $card) { 'Gray' } elseif ($m.CredGuardRunning) { 'Red' } else { 'Green' })
    Write-Host ("  HVCI (integrite du code)  : {0}" -f $(if ($m.HvciRunning) { 'en cours' } else { 'inactif' })) -ForegroundColor DarkGray
    if ($script:CardMode -and $EnableVBS) {
        Write-Host "`nARRET : -EnableVBS demande sur un poste a connexion par carte." -ForegroundColor Red
        Write-Host "  26229 (Credential Guard) isole LSA dans l'hyperviseur : aucun package" -ForegroundColor Red
        Write-Host "  d'authentification tiers n'y est charge -> plus d'ouverture de session" -ForegroundColor Red
        Write-Host "  par carte, et le verrou UEFI ne se retire pas sans acces physique." -ForegroundColor Red
        Write-Host "  Si ce poste n'ouvre PAS de session par carte : -NoSmartCard -EnableVBS." -ForegroundColor Yellow
        exit 2
    }
}

# ==================== 2. GARDE-FOUS ======================================
$script:Skipped = @()

function Test-GuardBlocks($guard, $fam, $m) {
    # Le garde-fou carte a puce passe AVANT -IgnoreGuards : -IgnoreGuards
    # accepte de casser un usage (imprimante, Bluetooth...), pas de perdre
    # l'acces a sa propre machine.
    if ($script:CardMode -and ($fam -eq 'vbs' -or $fam -eq 'smartcard' -or $guard -eq 'smartcard')) {
        return "profil carte a puce : isolerait LSA et casserait l'ouverture de session"
    }
    # Le garde-fou veille passe lui aussi AVANT -IgnoreGuards, et pour la meme
    # raison que la carte a puce : ce qu'il previent n'est pas une gene
    # d'usage, c'est une PERTE DE DONNEES silencieuse et irreversible. Sur un
    # poste sans Modern Standby, 26283/26284 suppriment le dernier etat de
    # veille et renvoient tout sur un chemin de reprise que personne n'a
    # verifie. -IgnoreGuards accepte de casser un usage, pas de jeter les
    # ecritures en cache de tous les volumes.
    if ($fam -eq 'sleep' -and -not $m.ModernStandby) {
        if ($m.SleepRead) {
            return "pas de Modern Standby (S0) sur ce poste : 26283/26284 supprimeraient le DERNIER etat de veille et renverraient toute mise en veille sur la veille prolongee"
        }
        return "etats de veille illisibles (powercfg /a muet) : on ne retire pas un etat de veille sans savoir lequel reste"
    }
    if ($IgnoreGuards) { return $null }
    switch ($guard) {
        'printers'      { if ($m.Printers)  { return "une imprimante est installee (le spouleur reste actif)" } }
        'bluetooth'     { if ($m.Bluetooth) { return "un peripherique Bluetooth est present" } }
        'wsl'           { if ($m.WSL)       { return "WSL est installe" } }
        'sshd'          { if ($m.SSHD)      { return "un serveur OpenSSH est configure" } }
        'rdp'           { if ($m.RDP)       { return "le Bureau a distance est actif sur ce poste" } }
        'shares'        { if ($m.Shares)    { return "des partages SMB non administratifs existent" } }
        'notifications' { return "desactiverait les notifications Windows (Teams, Outlook, alertes)" }
        'geoloc'        { if ($m.Laptop)    { return "service de geolocalisation, utile sur un portable" } }
        'xbox'          { if ($m.Xbox)      { return "les services Xbox tournent (jeux)" } }
    }
    switch ($fam) {
        'fve'       { if ($m.BitLocker)        { return $(if ($m.BitLockerKnown) { "BitLocker est ACTIF : changer la politique FVE se decide a la main" } else { "etat BitLocker indeterminable sans elevation : suppose actif, politique FVE non touchee" }) } }
        'lockout'   { if ($m.BitLocker)        { return $(if ($m.BitLockerKnown) { "BitLocker actif : un verrouillage d'appareil exigerait la cle de recuperation" } else { "etat BitLocker indeterminable sans elevation : suppose actif" }) } }
        'laps'      { if (-not ($m.Domain -or $m.AzureAD)) { return "LAPS sans objet : machine ni AD ni Entra ID" } }
        'camera'    { if ($m.Camera)           { return "une webcam est presente ($($m.CameraNames -join ', ')) : 26352 la couperait pour toutes les applications" } }
        'msaccount' { if ($m.MicrosoftAccount) { return "un compte Microsoft ouvre une session sur ce poste" } }
        'pin'       { if ($m.HelloPin)         { return "un code PIN Windows Hello est configure" } }
        'rdp'       { if ($m.RDP)              { return "le Bureau a distance est actif sur ce poste" } }
    }
    return $null
}

function Test-Forbidden($hive, $path, $name) {
    foreach ($f in $ForbiddenValues) {
        if ($f.Hive -eq $hive -and $f.Path -eq $path -and $f.Name -eq $name) { return $true }
    }
    return $false
}

# Bloc VBS / Credential Guard (26225-26230). Declare ici comme une table a
# part entiere -- et non plus construit a la volee dans le corps du script --
# pour qu'il passe, lui aussi, sous l'assertion de la liste noire. C'est par
# ce chemin que LsaCfgFlags pouvait etre ecrit sans que rien ne s'y oppose.
$CisVBS = @(
    @{ Id=26225; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='EnableVirtualizationBasedSecurity'; Type='DWord'; Data='1' }
    @{ Id=26226; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='RequirePlatformSecurityFeatures';   Type='DWord'; Data='3' }
    @{ Id=26227; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HypervisorEnforcedCodeIntegrity';   Type='DWord'; Data='1' }
    @{ Id=26228; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='HVCIMATRequired';                   Type='DWord'; Data='1' }
    @{ Id=26229; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='LsaCfgFlags';                       Type='DWord'; Data='1' }
    @{ Id=26230; Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'; Name='ConfigureKernelShadowStacksLaunch'; Type='DWord'; Data='1' }
)

# Assertion : aucune table ne doit contenir un controle de la liste noire.
# Elle est verifiee a CHAQUE execution -- une fois avec le socle, une seconde
# fois avec l'extension carte a puce -- pour qu'une regeneration future des
# tables ne puisse pas y reintroduire 26269/26270 ni 26225-26230 en silence.
function Assert-NoForbiddenWrite {
    $bad = @()
    $tables = @($CisRegistry) + @($CisDelete)
    if ($EnableVBS) { $tables += @($CisVBS) }   # ne s'applique que s'il serait ecrit
    foreach ($r in $tables) {
        if ($ForbiddenIds -contains $r.Id)          { $bad += "id $($r.Id)" }
        if (Test-Forbidden $r.Hive $r.Path $r.Name) { $bad += "$($r.Hive)\$($r.Path) :: $($r.Name)" }
    }
    foreach ($s in $CisServices) {
        if ($NeverTouchServices -contains $s.Service) { $bad += "service $($s.Service)" }
    }
    if ($bad.Count) {
        Write-Host "`nARRET : les tables du script violent la liste noire :" -ForegroundColor Red
        $bad | Select-Object -Unique | ForEach-Object { Write-Host "   $_" -ForegroundColor Red }
        Write-Host "  Rien n'a ete ecrit. Corriger les tables avant de relancer." -ForegroundColor Red
        exit 2
    }
}

# Etat des protections a preserver, releve avant et apres.
# Couvre TOUTE la pile de connexion par carte, pas seulement RunAsPPL : la
# version du 25/07 ne regardait ni Credential Guard ni les DLL ni les listes
# de packages, or c'est par la que la connexion peut tomber.
function Get-SafetySnapshot {
    $snap = [ordered]@{}
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $snap.RunAsPPL = if ($lsa -and $null -ne $lsa.RunAsPPL) { [int]$lsa.RunAsPPL } else { 0 }
    $sys = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue
    $snap.AllowCustomSSPsAPs = if ($sys -and $null -ne $sys.AllowCustomSSPsAPs) { [int]$sys.AllowCustomSSPsAPs } else { 1 }
    $dgk = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
    $snap.LsaCfgFlags = if ($dgk -and $null -ne $dgk.LsaCfgFlags) { [int]$dgk.LsaCfgFlags } else { 0 }
    $snap.VBS         = if ($dgk -and $null -ne $dgk.EnableVirtualizationBasedSecurity) { [int]$dgk.EnableVirtualizationBasedSecurity } else { 0 }
    $snap.AuthPackages  = (@(if ($lsa) { $lsa.'Authentication Packages' }) -join '|')
    $snap.SecPackages   = (@(if ($lsa) { $lsa.'Security Packages' })       -join '|')
    $snap.NotifPackages = (@(if ($lsa) { $lsa.'Notification Packages' })   -join '|')
    $snap.EIDDlls = (@($SmartCardDlls | Where-Object { Test-Path (Join-Path $env:SystemRoot "System32\$_") }) -join '|')
    foreach ($s in @('SCardSvr','ScDeviceEnum','SCPolicySvc','CertPropSvc')) {
        $svc = Get-Service $s -ErrorAction SilentlyContinue
        $snap["svc_$s"] = if ($svc) { "$($svc.StartType)/$($svc.Status)" } else { 'absent' }
    }
    return $snap
}

function Compare-SafetySnapshot($before, $after) {
    $drift = @()
    foreach ($k in $before.Keys) {
        if ($before[$k] -ne $after[$k]) { $drift += "$k : $($before[$k]) -> $($after[$k])" }
    }
    Write-Host "`n-- Verification des protections a preserver ----------------" -ForegroundColor Cyan
    # Les couleurs jugent l'etat du point de vue de la carte a puce ; hors de ce
    # profil, seul l'ecart avant/apres compte.
    $card = [bool]$script:CardMode
    Write-Host ("  Protection LSA (RunAsPPL)   : {0}" -f $after.RunAsPPL) -ForegroundColor $(if (-not $card) { 'Gray' } elseif ($after.RunAsPPL -eq 0) { 'Green' } else { 'Red' })
    Write-Host ("  SSP/AP tiers dans LSASS     : {0}" -f $after.AllowCustomSSPsAPs) -ForegroundColor $(if (-not $card) { 'Gray' } elseif ($after.AllowCustomSSPsAPs -ne 0) { 'Green' } else { 'Red' })
    Write-Host ("  Credential Guard (LsaCfgFl.): {0}" -f $after.LsaCfgFlags) -ForegroundColor $(if (-not $card) { 'Gray' } elseif ($after.LsaCfgFlags -eq 0) { 'Green' } else { 'Red' })
    Write-Host ("  Packages d'authentification : {0}" -f $after.AuthPackages)
    Write-Host ("  DLL de la carte presentes   : {0}" -f (@($after.EIDDlls -split '\|' | Where-Object { $_ }).Count))
    foreach ($s in @('SCardSvr','ScDeviceEnum','SCPolicySvc','CertPropSvc')) {
        Write-Host ("  {0,-27} : {1}" -f $s, $after["svc_$s"])
    }
    if ($drift.Count) {
        Write-Host "  ECART DETECTE pendant l'execution :" -ForegroundColor Red
        $drift | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
        Write-Host "  NE PAS REDEMARRER avant d'avoir compris cet ecart : LSA ne recharge" -ForegroundColor Red
        Write-Host "  ses packages qu'au demarrage, la casse ne se verrait qu'apres." -ForegroundColor Red
        Write-Host "  Retour arriere : $backupDir\Rollback.cmd" -ForegroundColor Red
    } else {
        Write-Host "  Aucun changement : l'ouverture de session par carte a puce est intacte." -ForegroundColor Green
    }
}

# ==================== 3. SELECTION DES CONTROLES =========================
function Select-Applicable($m) {
    $sel = @()
    foreach ($r in $CisRegistry) {
        if ($ForbiddenIds -contains $r.Id) { continue }
        if ($SkipFamily -contains $r.Fam) {
            $script:Skipped += @{ Id=$r.Id; What=$r.Name; Why="famille '$($r.Fam)' exclue par -SkipFamily" }
            continue
        }
        if ($r.Tier -eq 2 -and -not $IncludeOptional) { continue }
        if ($r.Tier -eq 9 -and -not $ScoreOnly)       { continue }
        $why = Test-GuardBlocks '' $r.Fam $m
        if ($why) { $script:Skipped += @{ Id=$r.Id; What=$r.Name; Why=$why }; continue }
        $row = $r.Clone()
        if ($StrictNTLM    -and $r.Id -eq 26061) { $row.Data = '2' }
        if ($StrictNetBIOS -and $r.Id -eq 26192) { $row.Data = '0' }
        $sel += $row
    }
    return $sel
}

function Select-ApplicableServices($m) {
    # mrxsmb10 (pilote client SMBv1) est le seul service du TIER 1 : SMBv1 est
    # mort depuis 2017, le desactiver ne casse aucun usage moderne.
    if (-not $IncludeOptional) {
        return @($CisServices | Where-Object { $_.Tier -eq 1 })
    }
    $sel = @()
    foreach ($s in $CisServices) {
        if ($NeverTouchServices -contains $s.Service) {
            $script:Skipped += @{ Id=$s.Id; What="service $($s.Service)"; Why="service protege (carte a puce / supervision)" }
            continue
        }
        if ($SkipFamily -contains 'service' -and $s.Tier -eq 2) { continue }
        $why = Test-GuardBlocks $s.Guard 'service' $m
        if ($why) { $script:Skipped += @{ Id=$s.Id; What="service $($s.Service)"; Why=$why }; continue }
        $sel += $s
    }
    return $sel
}

# ==================== 4. SAUVEGARDE ET RETOUR ARRIERE ====================
function Backup-BeforeChanges($rows, $services) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Write-Log "Sauvegarde -> $backupDir" "Cyan"

    try {
        Checkpoint-Computer -Description "Avant durcissement CIS ($ts)" -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Log "  Point de restauration systeme cree." "Green"
    } catch {
        Write-Log "  Point de restauration : $_ (protection systeme peut-etre desactivee -- on continue)" "Yellow"
    }

    $regDir = Join-Path $backupDir "registry"
    New-Item -ItemType Directory -Path $regDir -Force | Out-Null

    $keys = @($rows | ForEach-Object { "$($_.Hive)\$($_.Path)" }) +
            @($CisDelete | ForEach-Object { "$($_.Hive)\$($_.Path)" })
    $keys = $keys | Select-Object -Unique

    $ok = 0; $absent = 0
    foreach ($k in $keys) {
        $safe = ($k -replace '[\\:*?"<>|]', '_')
        # reg.exe est une commande NATIVE : sous ErrorActionPreference=Continue
        # elle ne leve pas d'exception sur une cle absente ; seul $LASTEXITCODE
        # dit si l'export a reellement fonctionne.
        try { & reg.exe export "$k" (Join-Path $regDir "$safe.reg") /y 2>$null 1>$null } catch { }
        if ($LASTEXITCODE -eq 0) { $ok++ } else { $absent++ }
    }
    Write-Log "  $ok cle(s) exportee(s), $absent absente(s) (normal : jamais configuree sur ce poste)" "Green"

    # Retour arriere REEL : reg import ne restaure que les valeurs qui
    # existaient deja. Les valeurs CREEES par ce script ne seraient pas
    # retirees -- on genere donc une ligne 'reg delete' pour chacune d'elles,
    # et on remet chaque service a son type de demarrage d'origine.
    $rb = @('@echo off',
            "REM Retour arriere du durcissement CIS du $ts",
            'REM A lancer dans une invite de commandes EN ADMINISTRATEUR.',
            'echo Restauration des cles de registre exportees...',
            'for %%f in ("%~dp0registry\*.reg") do reg import "%%f" >nul 2>&1',
            'echo Suppression des valeurs creees par le durcissement...')
    foreach ($r in $rows) {
        $existed = $false
        try { $existed = $null -ne (Get-ItemProperty -Path "$($r.Hive):\$($r.Path)" -Name $r.Name -ErrorAction Stop) } catch { }
        if (-not $existed) {
            $rb += ('reg delete "{0}\{1}" /v "{2}" /f >nul 2>&1' -f $r.Hive, $r.Path, $r.Name)
        }
    }
    if ($services) {
        $rb += 'echo Restauration du type de demarrage des services...'
        foreach ($s in $services) {
            $svc = Get-Service $s.Service -ErrorAction SilentlyContinue
            if ($svc) {
                $start = switch ($svc.StartType) {
                    'Automatic' { 'auto' }
                    'Manual'    { 'demand' }
                    'Disabled'  { 'disabled' }
                    default     { 'demand' }
                }
                $rb += ('sc config {0} start= {1} >nul 2>&1' -f $s.Service, $start)
            }
        }
    }
    $rb += 'echo Termine. REDEMARRER le poste pour que tout reprenne effet.'
    $rb += 'pause'
    Set-Content -Path (Join-Path $backupDir "Rollback.cmd") -Value $rb -Encoding ASCII

    & net.exe accounts             > (Join-Path $backupDir "net-accounts-avant.txt") 2>&1
    & auditpol.exe /get /category:* > (Join-Path $backupDir "auditpol-avant.txt") 2>&1
    Write-Log "  Retour arriere pret : $backupDir\Rollback.cmd" "Green"
}

# ==================== 5. APPLICATION =====================================
function Get-RegValue($hive, $path, $name) {
    try { return (Get-ItemProperty -Path "$($hive):\$path" -Name $name -ErrorAction Stop).$name } catch { return $null }
}

function Set-RegistryTable($table, $label) {
    $ok = 0; $fail = 0
    foreach ($row in $table) {
        if (Test-Forbidden $row.Hive $row.Path $row.Name) {
            Write-Log "  [$label] REFUS (liste noire) id=$($row.Id) $($row.Name)" "Red"
            continue
        }
        $full = "$($row.Hive):\$($row.Path)"
        try {
            if (-not (Test-Path $full)) { New-Item -Path $full -Force -ErrorAction Stop | Out-Null }
            switch ($row.Type) {
                'Multi' {
                    $val = if ([string]::IsNullOrEmpty($row.Data)) { [string[]]@() } else { [string[]]($row.Data -split '\|') }
                    New-ItemProperty -Path $full -Name $row.Name -Value $val -PropertyType MultiString -Force -ErrorAction Stop | Out-Null
                }
                'String' {
                    New-ItemProperty -Path $full -Name $row.Name -Value $row.Data -PropertyType String -Force -ErrorAction Stop | Out-Null
                }
                default {
                    New-ItemProperty -Path $full -Name $row.Name -Value ([int64]$row.Data) -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                }
            }
            $ok++
        } catch {
            $fail++
            Write-Log "  [$label] ECHEC id=$($row.Id) $($row.Hive)\$($row.Path) :: $($row.Name) -> $_" "Red"
        }
    }
    Write-Log "  [$label] $ok reglage(s) applique(s), $fail echec(s)." $(if ($fail -eq 0) { "Green" } else { "Yellow" })
    return @{ Ok = $ok; Fail = $fail }
}

function Remove-RegistryValues {
    $ok = 0; $fail = 0
    foreach ($d in $CisDelete) {
        if ($d.Tier -eq 9 -and -not $ScoreOnly) { continue }
        try {
            if ($null -ne (Get-RegValue $d.Hive $d.Path $d.Name)) {
                Remove-ItemProperty -Path "$($d.Hive):\$($d.Path)" -Name $d.Name -Force -ErrorAction Stop
            }
            $ok++
        } catch { $fail++; Write-Log "  [DEL] ECHEC id=$($d.Id) $($d.Name) -> $_" "Red" }
    }
    if ($ok -or $fail) {
        Write-Log "  [DEL] $ok valeur(s) traitee(s), $fail echec(s)." $(if ($fail -eq 0) { "Green" } else { "Yellow" })
    }
    return @{ Ok = $ok; Fail = $fail }
}

function Set-AccountPolicy {
    Write-Log "`n>> Politique de mots de passe et de verrouillage (net accounts)" "Cyan"
    $netArgs = ($CisAccountPolicy.GetEnumerator() | ForEach-Object { "/$($_.Key):$($_.Value)" }) -join ' '
    Write-Log "  net accounts $netArgs"
    $out = & cmd.exe /c "net accounts $netArgs" 2>&1
    if ($LASTEXITCODE -eq 0) { Write-Log "  Applique." "Green"; return @{ Ok = 7; Fail = 0 } }
    Write-Log "  ECHEC (code $LASTEXITCODE) : $out" "Red"
    return @{ Ok = 0; Fail = 7 }
}

# Compte invite : adresse par SID (-501) et non par le nom "Guest", traduit sur
# un Windows non anglais ("Invite"). Meme logique que les GUID d'auditpol.
function Disable-GuestAccount {
    Write-Log "`n>> Compte invite (SID -501) -> desactive" "Cyan"
    try {
        $guest = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-501$' }
        if (-not $guest) { Write-Log "  Compte absent." "DarkGray"; return @{ Ok = 0; Fail = 0 } }
        if (-not $guest.Enabled) { Write-Log "  Deja desactive ($($guest.Name))." "Green"; return @{ Ok = 1; Fail = 0 } }
        Disable-LocalUser -SID $guest.SID -ErrorAction Stop
        Write-Log "  Applique ($($guest.Name))." "Green"
        return @{ Ok = 1; Fail = 0 }
    } catch {
        & net.exe user guest /active:no 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Log "  Applique (repli net user)." "Green"; return @{ Ok = 1; Fail = 0 } }
        Write-Log "  Non applique : $_" "Yellow"
        return @{ Ok = 0; Fail = 0 }
    }
}

function Set-AuditPolicy {
    Write-Log "`n>> Politique d'audit ($($CisAudit.Count) sous-categories, adressees par GUID)" "Cyan"
    $ok = 0; $fail = 0
    foreach ($a in $CisAudit) {
        $s = if ($a.S) { "/success:enable" } else { "/success:disable" }
        $f = if ($a.F) { "/failure:enable" } else { "/failure:disable" }
        & auditpol.exe /set /subcategory:"$($a.Guid)" $s $f 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $ok++ } else { $fail++; Write-Log "  ECHEC id=$($a.Id) $($a.Sub) ($($a.Guid))" "Red" }
    }
    Write-Log "  $ok sous-categorie(s) appliquee(s), $fail echec(s)." $(if ($fail -eq 0) { "Green" } else { "Yellow" })
    return @{ Ok = $ok; Fail = $fail }
}

function Disable-OptionalServices($services) {
    if (-not $services -or -not $services.Count) { return @{ Ok = 0; Fail = 0 } }
    Write-Log "`n>> Services : $($services.Count) a desactiver" "Cyan"
    $ok = 0; $fail = 0
    foreach ($s in $services) {
        if ($NeverTouchServices -contains $s.Service) { continue }   # double verrou
        try {
            $svc = Get-Service -Name $s.Service -ErrorAction SilentlyContinue
            if (-not $svc) { Write-Log "  [absent] $($s.Service)" "DarkGray"; continue }
            Set-Service -Name $s.Service -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $s.Service -Force -ErrorAction SilentlyContinue
            $ok++
        } catch { $fail++; Write-Log "  ECHEC id=$($s.Id) service=$($s.Service) -> $_" "Red" }
    }
    Write-Log "  $ok service(s) desactive(s), $fail echec(s)." $(if ($fail -eq 0) { "Green" } else { "Yellow" })
    return @{ Ok = $ok; Fail = $fail }
}

function Set-LogonBanner {
    Write-Log "`n>> Banniere de connexion (26026 / 26027)" "Cyan"
    $p = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system"
    try {
        if (-not (Test-Path $p)) { New-Item -Path $p -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -Path $p -Name "legalnoticecaption" -Value $LegalNoticeTitle -PropertyType String -Force -ErrorAction Stop | Out-Null
        New-ItemProperty -Path $p -Name "legalnoticetext"    -Value $LegalNoticeText  -PropertyType String -Force -ErrorAction Stop | Out-Null
        Write-Log "  Applique (visible a la prochaine ouverture de session)." "Green"
        return @{ Ok = 2; Fail = 0 }
    } catch { Write-Log "  ECHEC : $_" "Red"; return @{ Ok = 0; Fail = 2 } }
}

# ==================== 6. VERIFICATION / SCORE ============================
# Conformite au sens de la REGLE WAZUH, pas au sens de "la valeur que ce script
# ecrirait". Deux tolerances sont necessaires pour ne pas signaler a tort :
#   AbsentOk : la regle est en 'condition: any' avec une alternative negative,
#              donc l'ABSENCE de la valeur suffit deja a la faire passer ;
#   Accept   : la regle tolere plusieurs valeurs ('1|2', 'range:1-30'...).
# Sans cela, un poste deja conforme apparaitrait en echec des que ce script
# aurait choisi une autre valeur acceptable que celle en place.
function Test-RowCompliant($row) {
    $cur = Get-RegValue $row.Hive $row.Path $row.Name
    if ($null -eq $cur) { return [bool]$row.AbsentOk }
    if ($row.Accept) {
        if ($row.Accept -like 'range:*') {
            $b = ($row.Accept -replace '^range:', '') -split '-'
            try { $n = [int64]$cur } catch { return $false }
            return ($n -ge [int64]$b[0] -and $n -le [int64]$b[1])
        }
        foreach ($a in ($row.Accept -split '\|')) {
            try { if ([int64]$cur -eq [int64]$a) { return $true } } catch { if ("$cur" -eq "$a") { return $true } }
        }
        return $false
    }
    switch ($row.Type) {
        'Multi' {
            $want = if ([string]::IsNullOrEmpty($row.Data)) { '' } else { (($row.Data -split '\|') -join '|') }
            return ((@($cur) -join '|') -eq $want)
        }
        'String' { return ("$cur" -eq "$($row.Data)") }
        default  { try { return ([int64]$cur -eq [int64]$row.Data) } catch { return $false } }
    }
}

function Invoke-VerifyPass {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  VERIFICATION -- lecture du poste, aucune modification" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan

    $applicable = @($CisRegistry | Where-Object { $ForbiddenIds -notcontains $_.Id -and $_.Tier -ne 9 })
    $failRows   = @($applicable  | Where-Object { -not (Test-RowCompliant $_) })
    $passCount  = $applicable.Count - $failRows.Count

    $svcPass = 0
    foreach ($s in $CisServices) {
        $svc = Get-Service $s.Service -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.StartType -eq 'Disabled') { $svcPass++ }
    }

    $total = $applicable.Count + $CisServices.Count
    $good  = $passCount + $svcPass
    $pct   = [math]::Round(100 * $good / [math]::Max($total, 1))
    Write-Host ("`n  Registre   : {0} conformes / {1}" -f $passCount, $applicable.Count)
    Write-Host ("  Services   : {0} conformes / {1}" -f $svcPass, $CisServices.Count)
    Write-Host ("  Estimation : {0} % ({1}/{2}) sur les controles couverts par ce script" -f $pct, $good, $total) -ForegroundColor White
    Write-Host "  (les 27 controles d'audit et le TIER 3 ne sont pas comptes ici)" -ForegroundColor DarkGray

    $byFam = $failRows | Group-Object { $_.Fam } | Sort-Object Count -Descending
    if ($byFam) {
        Write-Host "`n  Ecarts restants par famille :" -ForegroundColor Yellow
        foreach ($g in $byFam) { Write-Host ("    {0,-16} {1,4}" -f $g.Name, $g.Count) }
    }
    return @{ Pass = $good; Total = $total; Pct = $pct }
}

# ==================== 7. RAPPORTS ========================================
function Show-Skipped {
    if (-not $script:Skipped.Count) { return }
    Write-Host "`n-- Controles ignores sur ce poste (usage detecte) ----------" -ForegroundColor Yellow
    foreach ($s in ($script:Skipped | Sort-Object { $_.Id })) {
        Write-Host ("  [{0}] {1,-34} {2}" -f $s.Id, $s.What, $s.Why) -ForegroundColor DarkYellow
    }
    Write-Host "  Pour les appliquer quand meme : -IgnoreGuards." -ForegroundColor DarkGray
}

function Show-Blocked {
    Write-Host "`n-- LISTE NOIRE : jamais appliques, sous aucune option -------" -ForegroundColor Magenta
    if (-not @($CisBlocked).Count) {
        Write-Host "  Aucun controle : profil carte a puce inactif. La protection LSA et le" -ForegroundColor DarkGray
        Write-Host "  bloc VBS / Credential Guard sont en TIER 3, a decider a la main." -ForegroundColor DarkGray
        return
    }
    foreach ($b in ($CisBlocked | Sort-Object { $_.Id })) {
        Write-Host ("  [{0}] {1}" -f $b.Id, $b.Title) -ForegroundColor Magenta
        # Un motif propre au controle prime sur le motif collectif affiche plus
        # bas, qui ne concerne que la carte a puce.
        if ($b.Motif) { Write-Host ("         -> {0}" -f $b.Motif) -ForegroundColor DarkGray }
    }
    if ($script:CardMode) {
        Write-Host "  Motif : profil carte a puce actif. LSASS en processus protege (26269," -ForegroundColor DarkGray
        Write-Host "  26270) ou isole par l'hyperviseur (26225-26230) ne charge plus le package" -ForegroundColor DarkGray
        Write-Host "  d'authentification de la carte -> l'ouverture de session par carte" -ForegroundColor DarkGray
        Write-Host "  echoue, et le verrou UEFI ne se retire pas sans acces physique." -ForegroundColor DarkGray
    }
}

function Show-Manual {
    Write-Host "`n-- TIER 3 : $($CisManual.Count) controles a decider a la main -----------" -ForegroundColor Magenta
    foreach ($m in ($CisManual | Sort-Object { $_.Id })) {
        Write-Host ("  [{0}] {1}" -f $m.Id, $m.Title) -ForegroundColor White
        Write-Host ("        {0}" -f $m.Why) -ForegroundColor DarkGray
    }
    Write-Host "`n  Renommage des comptes integres (nom a choisir, jamais automatise) :" -ForegroundColor Magenta
    Write-Host '    Get-LocalUser | Where-Object { $_.SID -match "-500$" } | Rename-LocalUser -NewName <nom>   (26011)' -ForegroundColor DarkGray
    Write-Host '    Get-LocalUser | Where-Object { $_.SID -match "-501$" } | Rename-LocalUser -NewName <nom>   (26012)' -ForegroundColor DarkGray
    if (-not $EnableVBS -and -not $script:CardMode) {
        Write-Host "`n  VBS / Credential Guard (26225-26230) : -EnableVBS pour les appliquer." -ForegroundColor DarkGray
        Write-Host "  Exclus par defaut car adjacents a l'isolation de LSASS, et parce que le" -ForegroundColor DarkGray
        Write-Host "  verrou UEFI de Credential Guard ne se retire pas sans acces physique." -ForegroundColor DarkGray
    }
}

# =============================== EXECUTION ===============================
Assert-NoForbiddenWrite

Write-Host "============================================================" -ForegroundColor White
Write-Host "  DURCISSEMENT CIS WINDOWS 11 -- version generalisee" -ForegroundColor White
Write-Host "  Tables extraites de cis_win11_enterprise.yml (CIS v3.0.0)" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White

$machine = Get-MachineProfile
Show-MachineProfile $machine
if (-not $machine.HasScaPolicy) {
    Write-Host "  (agent Wazuh absent : les tables embarquees font foi ; utiliser -Verify" -ForegroundColor DarkGray
    Write-Host "   pour estimer le score sans passer par le dashboard)" -ForegroundColor DarkGray
}

# Profil carte a puce : etend la liste noire AVANT toute selection, puis on
# repasse l'assertion avec la liste etendue.
Set-SmartCardPolicy $machine
Show-SmartCardStack $machine
Assert-NoForbiddenWrite

if ($Verify -and -not $Apply) {
    [void](Invoke-VerifyPass)
    Show-Blocked
    Show-Manual
    exit 0
}

$rows     = Select-Applicable $machine
$services = Select-ApplicableServices $machine

Write-Host "`n-- Portee de ce passage ------------------------------------" -ForegroundColor White
Write-Host ("  TIER 1  : {0} reglages registre + {1} politique de comptes + {2} audit + 1 invite" -f `
    (@($rows | Where-Object { $_.Tier -eq 1 }).Count), $CisAccountPolicy.Count, $CisAudit.Count)
if ($IncludeOptional) {
    Write-Host ("  TIER 2  : ACTIF -> {0} reglages registre + {1} services + banniere" -f `
        (@($rows | Where-Object { $_.Tier -eq 2 }).Count), $services.Count) -ForegroundColor Yellow
} else {
    Write-Host "  TIER 2  : inactif (-IncludeOptional pour l'ajouter)" -ForegroundColor DarkGray
}
Write-Host ("  TIER 3  : {0} controles, jamais automatises" -f $CisManual.Count) -ForegroundColor DarkGray
Write-Host ("  Interdit: {0} controles en liste noire{1}" -f @($CisBlocked).Count, $(if ($script:CardMode) { ' (profil carte a puce)' } else { '' })) -ForegroundColor Magenta
Show-Skipped

if (-not $Apply) {
    Write-Host "`nMODE SIMULATION -- aucune modification n'a ete faite." -ForegroundColor Yellow
    Write-Host "  -Apply                    applique le TIER 1" -ForegroundColor Yellow
    Write-Host "  -Apply -IncludeOptional   applique aussi le TIER 2" -ForegroundColor Yellow
    Write-Host "  -Verify                   mesure l'etat actuel sans rien ecrire" -ForegroundColor Yellow
    Show-Blocked
    Show-Manual
    exit 0
}

$before = Get-SafetySnapshot
Backup-BeforeChanges $rows $services

$totalOk = 0; $totalFail = 0
$r = Set-AccountPolicy;     $totalOk += $r.Ok; $totalFail += $r.Fail
$r = Disable-GuestAccount;  $totalOk += $r.Ok; $totalFail += $r.Fail
$r = Set-AuditPolicy;       $totalOk += $r.Ok; $totalFail += $r.Fail
$r = Set-RegistryTable @($rows | Where-Object { $_.Tier -eq 1 }) "TIER1"; $totalOk += $r.Ok; $totalFail += $r.Fail
$r = Remove-RegistryValues; $totalOk += $r.Ok; $totalFail += $r.Fail
$r = Disable-OptionalServices $services; $totalOk += $r.Ok; $totalFail += $r.Fail

if ($IncludeOptional) {
    $r = Set-RegistryTable @($rows | Where-Object { $_.Tier -eq 2 }) "TIER2"; $totalOk += $r.Ok; $totalFail += $r.Fail
    $r = Set-LogonBanner;   $totalOk += $r.Ok; $totalFail += $r.Fail
}

if ($EnableVBS) {
    # Show-SmartCardStack a deja arrete le script si le profil carte est actif.
    Write-Log "`n>> VBS / Credential Guard demande explicitement (-EnableVBS)" "Yellow"
    Write-Log "   Poste declare SANS ouverture de session par carte." "Yellow"
    $r = Set-RegistryTable $CisVBS "VBS"; $totalOk += $r.Ok; $totalFail += $r.Fail
}

$after = Get-SafetySnapshot
Compare-SafetySnapshot $before $after

Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  TERMINE : $totalOk reglage(s) applique(s), $totalFail echec(s)." -ForegroundColor Green
Write-Host "  Journal        : $logPath" -ForegroundColor Green
Write-Host "  Sauvegarde     : $backupDir\registry\" -ForegroundColor Green
Write-Host "  Retour arriere : $backupDir\Rollback.cmd" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green

[void](Invoke-VerifyPass)
Show-Skipped
Show-Blocked
Show-Manual

Write-Host "`nA FAIRE MAINTENANT :" -ForegroundColor Yellow
if ($script:CardMode) {
    Write-Host "  1. AVANT DE REDEMARRER : s'assurer d'un acces de secours -- mot de passe" -ForegroundColor Yellow
    Write-Host "     Windows du compte, ou second compte administrateur. LSA ne recharge" -ForegroundColor Yellow
    Write-Host "     ses packages qu'au demarrage : si la carte devait ne plus ouvrir la" -ForegroundColor Yellow
    Write-Host "     session, cela ne se verrait qu'a ce moment-la." -ForegroundColor Yellow
    Write-Host "  2. Verifier la pile carte, ecran ci-dessus : RunAsPPL a 0, Credential" -ForegroundColor Yellow
    Write-Host "     Guard inactif, 3 DLL presentes, package declare dans LSA." -ForegroundColor Yellow
    Write-Host "     Controle complementaire : certutil -scinfo" -ForegroundColor Yellow
    Write-Host "  3. REDEMARRER -- LSA, Winlogon, services et audit ne sont pleinement" -ForegroundColor Yellow
    Write-Host "     effectifs qu'apres redemarrage. Puis ouvrir une session PAR CARTE." -ForegroundColor Yellow
    Write-Host "  4. Le score du dashboard ne bougera qu'au prochain scan SCA de Wazuh" -ForegroundColor Yellow
    Write-Host "     (environ toutes les heures apres le redemarrage)." -ForegroundColor Yellow
} else {
    Write-Host "  1. REDEMARRER le poste -- LSA, Winlogon, services et audit ne sont" -ForegroundColor Yellow
    Write-Host "     pleinement effectifs qu'apres redemarrage." -ForegroundColor Yellow
    Write-Host "  2. Le score du dashboard ne bougera qu'au prochain scan SCA de Wazuh" -ForegroundColor Yellow
    Write-Host "     (environ toutes les heures apres le redemarrage)." -ForegroundColor Yellow
}
Write-Host "  En cas de probleme : $backupDir\Rollback.cmd (invite EN ADMINISTRATEUR)." -ForegroundColor Yellow
