# -*- coding: utf-8 -*-
"""Genere les tables PowerShell du script de durcissement generalise.

Source de verite : cis_win11_enterprise.yml (le fichier que Wazuh utilise
lui-meme pour VERIFIER). Aucune valeur n'est devinee de memoire.
"""
import json, re, unicodedata

rows   = json.load(open("rows.json", encoding="utf-8"))
manual = json.load(open("manual.json", encoding="utf-8"))
checks = {c["id"]: c for c in json.load(open("checks.json", encoding="utf-8"))}

# ---------------------------------------------------------------- garde-fous
# Liste noire STATIQUE : jamais appliquee, quelles que soient les options, sur
# toute machine. Vide aujourd'hui. La protection LSA (26269, 26270) n'y est
# plus : elle est en TIER 3 ci-dessous, et le moteur la bascule en liste noire
# a l'execution quand le poste ouvre sa session par carte a puce
# ($SmartCardForbiddenIds), comme le bloc VBS.
BLOCKED = set()

# ------------------------------------------------- resolutions manuelles
# Chaque entree provient de la lecture directe de la regle Wazuh du YAML.
# (type, data) ; type 'Multi' = REG_MULTI_SZ (liste), 'Del' = supprimer.
OVERRIDES = {
    # id: (hive, path, name, type, data, tier, fam, why)
    26024: ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "MaxDevicePasswordFailedAttempts", "DWord", "10", 2, "lockout",
            "Wazuh accepte <=30 et !=0 ; 10 = valeur CIS. Verrouille l'appareil "
            "et peut exiger la cle de recuperation BitLocker -> ignore si BDE actif."),
    26029: ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "PasswordExpiryWarning", "DWord", "14", 1, "base",
            "Wazuh : >=5 et <=14."),
    26030: ("HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "ScRemoveOption", "String", "1", 1, "smartcard-ok",
            "1 = Verrouiller la station au retrait de la carte (REG_SZ). "
            "Coherent avec une authentification par carte a puce, ne la casse pas."),
    26043: ("HKLM", r"System\CurrentControlSet\Services\LanManServer\Parameters",
            "NullSessionPipes", "Multi", "", 1, "base",
            "Wazuh exige que la valeur ne contienne AUCUN caractere -> liste vide."),
    26044: ("HKLM", r"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths",
            "Machine", "Multi",
            r"System\CurrentControlSet\Control\ProductOptions|System\CurrentControlSet\Control\Server Applications|Software\Microsoft\Windows NT\CurrentVersion",
            1, "base", "Les 3 chemins exacts attendus par la regle Wazuh."),
    26045: ("HKLM", r"System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths",
            "Machine", "Multi",
            "|".join([r"System\CurrentControlSet\Control\Print\Printers",
                      r"System\CurrentControlSet\Services\Eventlog",
                      r"Software\Microsoft\OLAP Server",
                      r"Software\Microsoft\Windows NT\CurrentVersion\Print",
                      r"Software\Microsoft\Windows NT\CurrentVersion\Windows",
                      r"System\CurrentControlSet\Control\ContentIndex",
                      r"System\CurrentControlSet\Control\Terminal Server",
                      r"System\CurrentControlSet\Control\Terminal Server\UserConfig",
                      r"System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
                      r"Software\Microsoft\Windows NT\CurrentVersion\Perflib",
                      r"System\CurrentControlSet\Services\SysmonLog"]),
            1, "base", "Les 11 sous-chemins attendus par la regle Wazuh."),
    26047: ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa", "restrictremotesam",
            "String", "O:BAG:BAD:(A;;RC;;;BA)", 1, "base",
            "SDDL : seuls les administrateurs peuvent interroger SAM a distance."),
    26048: ("HKLM", r"System\CurrentControlSet\Services\LanManServer\Parameters",
            "NullSessionShares", "Multi", "", 1, "base",
            "Aucun partage accessible en session nulle."),
    26053: ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
            "SupportedEncryptionTypes", "DWord", "2147483644", 1, "base",
            "AES128+AES256+types futurs, RC4/DES exclus."),
    26061: ("HKLM", r"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
            "RestrictSendingNTLMTraffic", "DWord", "1", 1, "base",
            "1 = Auditer tout (accepte par Wazuh). 2 = Refuser tout : casse "
            "l'acces aux partages SMB/NAS -> reserve a -StrictNTLM."),
    26065: ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin", "DWord", "2", 1, "base",
            "Demander le consentement sur le bureau securise."),
    26119: ("HKLM", r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging",
            "LogFilePath", "String", r"%SystemRoot%\System32\logfiles\firewall\domainfw.log",
            1, "base", "Wazuh ne verifie qu'une sous-chaine ; on ecrit le vrai chemin Windows."),
    26126: ("HKLM", r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging",
            "LogFilePath", "String", r"%SystemRoot%\System32\logfiles\firewall\privatefw.log",
            1, "base", "idem profil prive."),
    26135: ("HKLM", r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging",
            "LogFilePath", "String", r"%SystemRoot%\System32\logfiles\firewall\publicfw.log",
            1, "base", "idem profil public."),
    26191: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "DoHPolicy",
            "DWord", "2", 1, "base",
            "2 = autoriser DoH (accepte). 3 = exiger DoH : coupe la resolution "
            "si le resolveur ne le gere pas."),
    26192: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableNetbios",
            "DWord", "2", 1, "base",
            "2 = NetBIOS desactive sur les reseaux publics (accepte par Wazuh). "
            "0 = partout : peut casser la decouverte NAS/imprimante -> -StrictNetBIOS."),
    26214: ("HKLM", r"Software\Policies\Microsoft\Windows NT\Printers\RPC",
            "ForceKerberosForRpc", "DWord", "0", 1, "print-rpc",
            "0 = Negocier (accepte). 1 = Kerberos obligatoire : casse "
            "l'impression reseau hors domaine."),
    26267: ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS",
            "PostAuthenticationResetDelay", "DWord", "8", 1, "laps",
            "Wazuh : >0 et <=8."),
    26305: ("HKLM", r"SOFTWARE\Policies\Microsoft\FVE", "FDVDiscoveryVolumeType",
            "String", "", 1, "fve",
            "Wazuh exige une valeur vide (pas d'agent de deverrouillage BitLocker To Go)."),
    26308: ("HKLM", r"SOFTWARE\Policies\Microsoft\FVE", "FDVRecoveryPassword",
            "DWord", "1", 1, "fve", "1 = autoriser le mot de passe de recuperation 48 chiffres."),
    26309: ("HKLM", r"SOFTWARE\Policies\Microsoft\FVE", "FDVRecoveryKey",
            "DWord", "1", 1, "fve", "1 = autoriser la cle de recuperation 256 bits."),
    26336: ("HKLM", r"SOFTWARE\Policies\Microsoft\FVE", "RDVDiscoveryVolumeType",
            "String", "", 1, "fve", "idem lecteurs amovibles."),
    # 26352 : hors du range 'fve' ci-dessous, il tombait en famille 'base' et
    # partait donc dans le TIER 1 sans garde-fou -- c'est ainsi qu'il avait
    # coupe la webcam d'un poste le 2026-07-21. Declare ici pour que la famille
    # 'camera' survive a une regeneration des tables depuis le YAML.
    26352: ("HKLM", r"SOFTWARE\Policies\Microsoft\Camera", "AllowCamera",
            "DWord", "0", 1, "camera",
            "Famille \"camera\" pour passer sous le garde-fou : ecarte des qu'une "
            "webcam est reconnue. -IgnoreGuards l'applique quand meme."),
    26356: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\Connect", "RequirePinForPairing",
            "DWord", "1", 2, "bluetooth", "1 = code PIN a la premiere association."),
    26360: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry",
            "DWord", "0", 1, "base", "0 = telemetrie desactivee (ramene a 1 sur les editions non Enterprise)."),
    26368: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
            "DODownloadMode", "DWord", "1", 1, "base",
            "1 = pair-a-pair limite au reseau local ; la regle interdit seulement 3 (Internet)."),
    26428: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
            "MaxIdleTime", "DWord", "900000", 2, "rdp", "15 min (Wazuh : <=900000 et !=0)."),
    26454: ("HKLM", r"SOFTWARE\Policies\Microsoft\WindowsInkWorkspace",
            "AllowWindowsInkWorkspace", "DWord", "1", 1, "base",
            "1 = actif mais inaccessible au-dessus de l'ecran de verrouillage."),
    # Restrictions d'installation de peripheriques -- reconstruites depuis la
    # remediation CIS presente dans le YAML (26232 / 26235).
    26231: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceIDs", "DWord", "1", 2, "deviceinstall",
            "Active le blocage par identifiant de peripherique."),
    26233: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceIDsRetroactive", "DWord", "1", 2, "deviceinstall",
            "Applique aussi aux peripheriques deja installes."),
    26232: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs",
            "1", "String", r"PCI\CC_0C0A", 2, "deviceinstall",
            "Identifiant CIS de la classe Bluetooth. NB : la regle Wazuh 26232 "
            "cherche une valeur NOMMEE 'PCI\\CC_0C0A' sous une sous-cle '1' -- "
            "ce n'est pas la facon dont Windows stocke la liste ; on ecrit la "
            "forme correcte pour Windows, le controle peut rester en echec."),
    26234: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceClasses", "DWord", "1", 2, "deviceinstall",
            "Active le blocage par classe de peripherique."),
    26236: ("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions",
            "DenyDeviceClassesRetroactive", "DWord", "1", 2, "deviceinstall",
            "Applique aussi aux peripheriques deja installes."),
}

# 26235 : les 4 GUID de classe IEEE 1394 / AVC, lus dans la remediation CIS du
# YAML (26235) -- la raison pour laquelle l'ancien script les excluait
# ("GUID non verifie") n'a plus lieu d'etre.
CLASS_GUIDS = ["{d48179be-ec20-11d1-b6b8-00c04fa372a7}",
               "{7ebefbc0-3200-11d2-b4c2-00a0C9697d07}",
               "{c06ff265-ae09-48f0-812c-16753d7cba83}",
               "{6bdd1fc1-810f-11d0-bec7-08002be2092f}"]
for i, g in enumerate(CLASS_GUIDS, 1):
    OVERRIDES[26235 + (i - 1) * 0.001] = (
        "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses",
        str(i), "String", g, 2, "deviceinstall",
        "Classe IEEE 1394 / AVC (DMA par FireWire) -- GUID issu de la remediation CIS du YAML.")

# 26202 : deux valeurs REG_SZ (chemins UNC durcis)
for nm in (r"\\*\NETLOGON", r"\\*\SYSVOL"):
    OVERRIDES[26202 + (0.001 if "SYS" in nm else 0)] = (
        "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths",
        nm, "String", "RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1",
        1, "base", "Chemins UNC durcis (sans effet hors domaine, sans risque).")

# --------------------------------------------------- valeurs a SUPPRIMER
DELETES = [
    (26244, "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
     "DisableBkGndGroupPolicy", 1, "base",
     "Wazuh exige l'ABSENCE de la valeur (rafraichissement GPO en arriere-plan actif)."),
    (26389, "HKLM", r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
     "SpynetReporting", 9, "score-only",
     "CIS veut Microsoft MAPS desactive. C'est une REGRESSION de securite reelle "
     "(protection cloud Defender) : applique uniquement avec -ScoreOnly."),
]

# ------------------------------------------------------------ classement
TIER3 = {
    26011: "Renommer le compte administrateur -- nom a choisir par l'utilisateur.",
    26012: "Renommer le compte invite -- nom a choisir par l'utilisateur.",
    26225: "VBS/Credential Guard -- isole LSASS ; adjacent a la protection LSA, exclu par defaut (-EnableVBS).",
    26226: "VBS : niveau de securite plateforme (Secure Boot + DMA).",
    26227: "VBS : integrite du code (HVCI) -- peut bloquer des pilotes non signes.",
    26228: "VBS : table d'attributs memoire UEFI requise.",
    26229: "VBS : Credential Guard avec verrou UEFI -- desactivation ulterieure impossible sans acces physique.",
    26230: "VBS : protection materielle de la pile en mode noyau.",
    26269: "Protection LSA : interdit tout package d'authentification TIERS dans LSASS (middleware de carte a puce, certains SSO). Liste noire si le poste ouvre sa session par carte.",
    26270: "Protection LSA : LSASS en processus protege avec verrou UEFI -- refuse tout module non signe PPL, et le verrou ne se retire pas sans acces physique. Liste noire si le poste ouvre sa session par carte.",
    26443: "Store : le fait DISPARAITRE (plus d'installation ni de mise a jour d'applications du Store). Les autres controles 'store' du TIER 2 le brident deja.",
    26261: "LAPS : necessite Active Directory ou Entra ID.",
    26268: "LAPS : action post-authentification.",
    26317: "BitLocker : EXIGER une carte a puce sur les lecteurs fixes -- si la carte tombe en panne, volume inaccessible.",
    26348: "BitLocker : EXIGER une carte a puce sur les lecteurs amovibles -- meme risque.",
    26349: "BitLocker : cles USB non chiffrees en LECTURE SEULE -- impact quotidien fort.",
    26331: "BitLocker sans TPM compatible interdit -- a decider selon le materiel.",
}

FAM = {}   # id -> (tier, fam)
def setfam(ids, tier, fam):
    for i in ids: FAM[i] = (tier, fam)

setfam(range(26072, 26116), 2, "service")
setfam([26172], 1, "service-smb1")
setfam([26008], 2, "msaccount")
setfam([26278], 2, "pin")
setfam([26025], 2, "inactivity")
setfam([26026, 26027], 2, "banner")
setfam([26243], 2, "cdp")
setfam([26281, 26282, 26283, 26284], 2, "sleep")
setfam([26369, 26370, 26371, 26372], 2, "winget")
setfam([26439, 26440, 26441, 26442, 26443, 26245], 2, "store")
setfam([26415, 26429], 2, "rdp")
setfam([26461], 2, "pwsh-transcript")
setfam([26391], 2, "asr")
setfam([26479], 2, "defer-updates")
setfam(range(26262, 26267), 1, "laps")
setfam(range(26306, 26352), 1, "fve")
setfam([26305, 26336], 1, "fve")
setfam(range(26211, 26217), 1, "print-rpc")
setfam([26210], 1, "print-rpc")

def tier_of(cid):
    if cid in TIER3: return 3, "manuel"
    if cid in FAM:   return FAM[cid]
    return 1, "base"

# ---------------------------------------------------------- tolerances
# Beaucoup de regles Wazuh sont en 'condition: any' avec une alternative
# NEGATIVE ("la cle n'existe pas") : l'absence de la valeur suffit alors a
# faire passer le controle. Sans cette information, le mode -Verify signalerait
# comme non conforme un poste qui passe deja le controle cote Wazuh.
def absent_ok(cid):
    c = checks.get(cid)
    if not c or not c["rules"]:
        return False
    neg = [r for r in c["rules"] if r.startswith("not ")]
    if not neg:
        return False
    # 'any' + une alternative negative : l'absence suffit.
    if c["condition"] == "any":
        return True
    # 'all' mais TOUTES les regles negatives (ex. 26368 "ne doit pas valoir 3") :
    # une valeur absente ne peut pas matcher, donc la negation est vraie.
    return len(neg) == len(c["rules"])

# Valeurs alternatives explicitement acceptees par la regle Wazuh, la ou elle
# tolere plusieurs etats (alternance regex ou comparaison numerique).
ACCEPT = {
    26024: "range:1-30",
    26029: "range:5-14",
    26030: "1|2|3",
    26053: "2147483644|2147483640",
    26061: "1|2",
    26191: "2|3",
    26192: "0|2",
    26214: "0|1",
    26267: "range:1-8",
    26308: "1|2",
    26309: "1|2",
    26356: "1|2",
    26360: "0|1",
    26368: "0|1|2",      # la regle interdit seulement 3 (Internet)
    26428: "range:1-900000",
    26454: "0|1",
}

# ------------------------------------------------------ assemblage final
out = []
seen = set()
for r in rows:
    cid = r["id"]
    if cid in BLOCKED or cid in TIER3 or cid in OVERRIDES:
        continue
    t, f = tier_of(cid)
    if t == 3: continue
    key = (r["hive"], r["path"].lower(), r["name"].lower())
    if key in seen: continue
    seen.add(key)
    out.append(dict(id=cid, tier=t, fam=f, hive=r["hive"], path=r["path"],
                    name=r["name"], type=r["type"], data=r["data"], title=r["title"]))

for cid, (hive, path, name, typ, data, tier, fam, why) in OVERRIDES.items():
    if int(cid) in BLOCKED or int(cid) in TIER3: continue
    out.append(dict(id=int(cid), tier=tier, fam=fam, hive=hive, path=path, name=name,
                    type=typ, data=data,
                    title=checks.get(int(cid), {}).get("title", "") or "", note=why))

out.sort(key=lambda x: (x["id"], x["name"]))

# services : on les sort de la table registre pour les traiter par service
services = [o for o in out if o["fam"].startswith("service")]
regs     = [o for o in out if not o["fam"].startswith("service")]

SVC_GUARD = {
    "Spooler": "printers", "bthserv": "bluetooth", "BTAGService": "bluetooth",
    "LxssManager": "wsl", "sshd": "sshd", "TermService": "rdp",
    "SessionEnv": "rdp", "UmRdpService": "rdp", "LanmanServer": "shares",
    "WpnService": "notifications", "MapsBroker": "", "lfsvc": "geoloc",
    "RemoteRegistry": "", "XboxGipSvc": "xbox", "XblAuthManager": "xbox",
    "XblGameSave": "xbox", "XboxNetApiSvc": "xbox",
}

def ps(s):
    return "'" + str(s).replace("'", "''") + "'"

def ascii_only(s):
    s = unicodedata.normalize("NFKD", s)
    return "".join(c for c in s if ord(c) < 128)

L = []
L.append("$CisRegistry = @(")
for o in regs:
    note  = ascii_only(o.get("note", ""))
    extra = "; AbsentOk=$true" if absent_ok(o["id"]) else ""
    if o["id"] in ACCEPT:
        extra += "; Accept=" + ps(ACCEPT[o["id"]])
    L.append("    @{{ Id={0}; Tier={1}; Fam={2}; Hive={3}; Path={4}; Name={5}; Type={6}; Data={7}{8}; Title={9}{10} }}".format(
        o["id"], o["tier"], ps(o["fam"]), ps(o["hive"]), ps(o["path"]), ps(o["name"]),
        ps(o["type"]), ps(o["data"]), extra, ps(ascii_only(o["title"])[:150]),
        ("; Note=" + ps(note)) if note else ""))
L.append(")")
L.append("")
L.append("$CisServices = @(")
for o in services:
    svc = o["path"].split("\\")[-1]
    L.append("    @{{ Id={0}; Tier={1}; Service={2}; Guard={3}; Title={4} }}".format(
        o["id"], o["tier"], ps(svc), ps(SVC_GUARD.get(svc, "")), ps(ascii_only(o["title"])[:120])))
L.append(")")
L.append("")
L.append("$CisDelete = @(")
for cid, hive, path, name, tier, fam, why in DELETES:
    L.append("    @{{ Id={0}; Tier={1}; Fam={2}; Hive={3}; Path={4}; Name={5}; Title={6}; Note={7} }}".format(
        cid, tier, ps(fam), ps(hive), ps(path), ps(name),
        ps(ascii_only(checks[cid]["title"])[:150]), ps(ascii_only(why))))
L.append(")")
L.append("")
L.append("$CisBlocked = @(")
for cid in sorted(BLOCKED):
    L.append("    @{{ Id={0}; Title={1} }}".format(cid, ps(ascii_only(checks[cid]["title"])[:150])))
L.append(")")
L.append("")
L.append("$CisManual = @(")
for cid, why in sorted(TIER3.items()):
    L.append("    @{{ Id={0}; Title={1}; Why={2} }}".format(
        cid, ps(ascii_only(checks[cid]["title"])[:150]), ps(ascii_only(why))))
L.append(")")

tables = "\n".join(L) + "\n"

# 26202 n'a pas de titre dans le YAML (champ vide en amont) : on le renseigne
# ici, apres la troncature a 150 caracteres. Ce correctif vivait dans
# assemble.py, ce qui rendait les deux assembleurs differents des qu'un
# tools/tables.ps1 existait.
tables = tables.replace(
    "Path='SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths'; Name='\\\\*\\NETLOGON'; Type='String'; Data='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Title=''",
    "Path='SOFTWARE\\Policies\\Microsoft\\Windows\\NetworkProvider\\HardenedPaths'; Name='\\\\*\\NETLOGON'; Type='String'; Data='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Title='Ensure ''Hardened UNC Paths'' is set to ''Enabled, with Require Mutual Authentication, Require Integrity and Require Privacy set for all NETLOGON and SYSVOL shares''.'")
tables = tables.replace(
    "Name='\\\\*\\SYSVOL'; Type='String'; Data='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Title=''",
    "Name='\\\\*\\SYSVOL'; Type='String'; Data='RequireMutualAuthentication=1, RequireIntegrity=1, RequirePrivacy=1'; Title='Ensure ''Hardened UNC Paths'' -- partage SYSVOL.'")

open("tables.ps1", "w", encoding="ascii", errors="replace", newline="\n").write(tables)

print("registre :", len(regs), "( tier1 =", sum(1 for o in regs if o["tier"] == 1),
      ", tier2 =", sum(1 for o in regs if o["tier"] == 2),
      ", score-only =", sum(1 for o in regs if o["tier"] == 9), ")")
print("services :", len(services))
print("suppressions :", len(DELETES))
print("bloques :", len(BLOCKED), " manuels :", len(TIER3))
ids = {o["id"] for o in out} | {d[0] for d in DELETES} | BLOCKED | set(TIER3)
print("controles couverts (registre) :", len(ids))
