
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
    Write-Host ("  Protection LSA (RunAsPPL) : {0}" -f $m.RunAsPPL) -ForegroundColor $(if ($m.RunAsPPL -eq 0) { 'Green' } else { 'Red' })
    Write-Host ("  Credential Guard          : {0}" -f $(if ($m.CredGuardRunning) { 'EN COURS -- incompatible' } else { 'inactif' })) `
        -ForegroundColor $(if ($m.CredGuardRunning) { 'Red' } else { 'Green' })
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
# tables ne puisse pas reintroduire 26269/26270 (ni 26225-26230) en silence.
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
    Write-Host ("  Protection LSA (RunAsPPL)   : {0}" -f $after.RunAsPPL) -ForegroundColor $(if ($after.RunAsPPL -eq 0) { 'Green' } else { 'Red' })
    Write-Host ("  SSP/AP tiers dans LSASS     : {0}" -f $after.AllowCustomSSPsAPs) -ForegroundColor $(if ($after.AllowCustomSSPsAPs -ne 0) { 'Green' } else { 'Red' })
    Write-Host ("  Credential Guard (LsaCfgFl.): {0}" -f $after.LsaCfgFlags) -ForegroundColor $(if ($after.LsaCfgFlags -eq 0) { 'Green' } else { 'Red' })
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
    foreach ($b in ($CisBlocked | Sort-Object { $_.Id })) { Write-Host ("  [{0}] {1}" -f $b.Id, $b.Title) -ForegroundColor Magenta }
    Write-Host "  Motif : LSASS en Protected Process Light refuse de charger un CSP non" -ForegroundColor DarkGray
    Write-Host "  signe pour PPL -> l'ouverture de session par carte a puce echoue." -ForegroundColor DarkGray
    if ($script:CardMode) {
        Write-Host "  Le bloc VBS/Credential Guard (26225-26230) y est ajoute : profil carte" -ForegroundColor DarkGray
        Write-Host "  a puce actif. LSA isole ne charge aucun package d'authentification" -ForegroundColor DarkGray
        Write-Host "  tiers, et le verrou UEFI ne se retire pas sans acces physique." -ForegroundColor DarkGray
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
Write-Host ("  Interdit: {0} controles en liste noire (protection LSA)" -f $CisBlocked.Count) -ForegroundColor Magenta
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
