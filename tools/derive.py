# Etape 2 : deriver, pour chaque controle, l'ecriture de registre qui le fait PASSER.
import re, json, collections

checks = json.load(open("checks.json", encoding="utf-8"))
by_id = {c["id"]: c for c in checks}

HIVES = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKLM": "HKLM",
    "HKEY_USERS": "HKU",
    "HKU": "HKU",
    "HKEY_CURRENT_USER": "HKCU",
}

def split_rule(r):
    """Renvoie (negated, kind, parts) ; kind = 'r' registre, 'c' commande."""
    neg = False
    s = r
    if s.startswith("not "):
        neg = True
        s = s[4:]
    if s.startswith("r:"):
        return neg, "r", s[2:].split(" -> ")
    if s.startswith("c:"):
        return neg, "c", [s[2:]]
    return neg, "?", [s]

def parse_key(k):
    k = k.strip()
    for long, short in HIVES.items():
        if k.upper().startswith(long + "\\"):
            return short, k[len(long) + 1:]
    return None, None

NUM = re.compile(r"^n:\^?\(?\\d\+\)?\$?\s+compare\s+(<=|>=|==|<|>)\s+(-?\d+)$")

def value_from(expected):
    """(type, data, sur?) depuis la valeur attendue par Wazuh."""
    e = expected.strip()
    if re.fullmatch(r"-?\d+", e):
        return "DWord", e, True
    m = NUM.match(e)
    if m:
        op, n = m.group(1), int(m.group(2))
        if op in ("<=", "=="): return "DWord", str(n), True
        if op == "<":  return "DWord", str(n - 1), True
        if op == ">=": return "DWord", str(n), True
        if op == ">":  return "DWord", str(n + 1), True
    if e.startswith("r:"):
        return None, e[2:], False          # regex -> resolution manuelle
    if e.startswith("n:"):
        return None, e[2:], False
    return "String", e, True

rows = []          # ecritures derivees
manual = []        # controles non automatisables

for c in checks:
    cid, cond = c["id"], c["condition"]
    triples, pairs, others = [], [], []
    for r in c["rules"]:
        neg, kind, parts = split_rule(r)
        if kind != "r":
            others.append((neg, r)); continue
        if len(parts) == 3:
            triples.append((neg, parts))
        elif len(parts) == 2:
            pairs.append((neg, parts))   # "la valeur existe" -> implique par le triplet
        elif len(parts) == 1:
            pass                          # "la cle existe" -> implique par le triplet
        else:
            others.append((neg, r))

    if others:
        manual.append((cid, "regle non-registre", c["title"]))
        continue
    if not triples:
        manual.append((cid, "aucune valeur cible", c["title"]))
        continue

    # 'any' : plusieurs formulations acceptables -> on prend la 1re non negative
    sel = [t for t in triples if not t[0]]
    if cond == "any":
        sel = sel[:1]
    if not sel:
        manual.append((cid, "toutes les regles negatives", c["title"]))
        continue

    ok = True
    for neg, parts in sel:
        hive, path = parse_key(parts[0])
        name = parts[1].strip()
        typ, data, sure = value_from(parts[2])
        if hive is None or not sure:
            manual.append((cid, "valeur/ruche non resolue: %s" % parts[2], c["title"]))
            ok = False
            break
        rows.append({"id": cid, "title": c["title"], "hive": hive, "path": path,
                     "name": name, "type": typ, "data": data, "cond": cond,
                     "rem": c["remediation"]})
    del ok

print("ecritures derivees :", len(rows), "sur", len({r['id'] for r in rows}), "controles")
print("controles en revue manuelle :", len(manual))
print(collections.Counter(m[1].split(":")[0] for m in manual))

json.dump(rows, open("rows.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)
json.dump(manual, open("manual.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)

print("\n--- exemples de revue manuelle ---")
for m in manual[:40]:
    print(m[0], "|", m[1], "|", m[2][:90])
