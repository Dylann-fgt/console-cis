# Extraction des controles CIS depuis le fichier de regles SCA de Wazuh.
# Source de verite : le YAML que Wazuh utilise lui-meme pour VERIFIER.
import re, json, sys, collections

SRC = r"C:\Program Files (x86)\ossec-agent\ruleset\sca\cis_win11_enterprise.yml"

txt = open(SRC, encoding="utf-8", errors="replace").read()
lines = txt.splitlines()

checks = []
cur = None
mode = None

for ln in lines:
    m = re.match(r"^\s*-\s+id:\s*(\d+)\s*$", ln)
    if m:
        if cur: checks.append(cur)
        cur = {"id": int(m.group(1)), "title": "", "remediation": "", "condition": "", "rules": []}
        mode = None
        continue
    if cur is None:
        continue
    m = re.match(r'^\s+title:\s*"(.*)"\s*$', ln)
    if m: cur["title"] = m.group(1); mode = None; continue
    m = re.match(r'^\s+remediation:\s*"(.*)"\s*$', ln)
    if m: cur["remediation"] = m.group(1); mode = None; continue
    m = re.match(r'^\s+condition:\s*(\w+)\s*$', ln)
    if m: cur["condition"] = m.group(1); mode = None; continue
    if re.match(r'^\s+rules:\s*$', ln):
        mode = "rules"; continue
    if mode == "rules":
        m = re.match(r"^\s+-\s+'(.*)'\s*$", ln)
        if m:
            cur["rules"].append(m.group(1)); continue
        m = re.match(r'^\s+-\s+"(.*)"\s*$', ln)
        if m:
            cur["rules"].append(m.group(1)); continue
        if re.match(r"^\s+\w+:", ln):
            mode = None
if cur: checks.append(cur)

print("checks parses :", len(checks))
print("conditions :", collections.Counter(c["condition"] for c in checks))

# repartition des types de regles
kinds = collections.Counter()
for c in checks:
    for r in c["rules"]:
        kinds[r[:2]] += 1
print("prefixes de regles :", kinds)

# checks 100% registre
reg_only = [c for c in checks if c["rules"] and all(r.startswith("r:") for r in c["rules"])]
print("checks 100% registre :", len(reg_only))
cmd_only = [c for c in checks if c["rules"] and all(r.startswith("c:") for r in c["rules"])]
print("checks 100% commande :", len(cmd_only))
mixed = [c for c in checks if c not in reg_only and c not in cmd_only]
print("checks mixtes/autres :", len(mixed))

json.dump(checks, open("checks.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

# echantillon des valeurs attendues exotiques
exotic = collections.Counter()
for c in reg_only:
    for r in c["rules"]:
        parts = r[2:].split(" -> ")
        if len(parts) == 3:
            v = parts[2]
            if v.startswith("n:"): exotic["n:"] += 1
            elif v.startswith("r:"): exotic["r:"] += 1
            elif re.fullmatch(r"\d+", v): exotic["int"] += 1
            else: exotic["str"] += 1
        else:
            exotic["len%d" % len(parts)] += 1
print("formes de valeurs :", exotic)
