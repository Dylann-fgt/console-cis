# -*- coding: utf-8 -*-
"""Assemble Harden-Windows-CIS.ps1 = engine-head + tables + engine-tail.

Se lance depuis ce dossier :   python assemble.py
Ecrit dans le dossier PARENT, en chemin relatif : le dossier peut etre
deplace sans que rien ne casse.
"""
import io, os

SCRATCH  = os.path.dirname(os.path.abspath(__file__))          # .../outils-cis/tools
DEST_DIR = os.path.dirname(SCRATCH)                            # .../outils-cis
SCRIPT   = os.path.join(DEST_DIR, "Harden-Windows-CIS.ps1")

BANNER_MARK = "# ============================ TABLES DE DONNEES"
TABLES_MARK = "$CisRegistry = @("
TAIL_MARK   = "# -- Politique d'audit :"


def rd(n):
    return io.open(os.path.join(SCRATCH, n), encoding="ascii", errors="replace").read()


def read_tables():
    """tables.ps1 s'il existe, sinon les tables du script deja assemble.

    gen_tables.py ne peut tourner que sur une machine portant le fichier de
    regles Wazuh (cis_win11_enterprise.yml). Ailleurs, les tables du script
    en place font foi : on remplace le moteur autour d'elles sans avoir
    besoin de les regenerer.
    """
    p = os.path.join(SCRATCH, "tables.ps1")
    if os.path.exists(p):
        return rd("tables.ps1"), "tools/tables.ps1"
    if not os.path.exists(SCRIPT):
        raise SystemExit("ni tools/tables.ps1 ni Harden-Windows-CIS.ps1 : rien a assembler")
    txt = io.open(SCRIPT, encoding="ascii", errors="replace").read()
    i = txt.index(TABLES_MARK, txt.index(BANNER_MARK))
    j = txt.index(TAIL_MARK, i)
    # rstrip + un seul saut de ligne : le tail apporte le sien, sinon une
    # ligne vide s'ajouterait a chaque reassemblage.
    return txt[i:j].rstrip("\r\n") + "\n", "tables reprises de Harden-Windows-CIS.ps1"


head = rd("engine-head.ps1")
tail = rd("engine-tail.ps1")
tables, tables_src = read_tables()
# Le titre de 26202 (vide dans le YAML) est renseigne par gen_tables.py.

banner = """
# ============================ TABLES DE DONNEES ==========================
#  Genere le 2026-10-12 par tools/ depuis
#    C:\\Program Files (x86)\\ossec-agent\\ruleset\\sca\\cis_win11_enterprise.yml
#  (CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0, 482 controles).
#  Ne pas editer a la main : regenerer les tables et reassembler.
#
#  Tier 1 = sur      Tier 2 = -IncludeOptional     Tier 9 = -ScoreOnly
#  Fam    = famille, sert aux garde-fous (fve, laps, service, store, rdp...)
# =========================================================================

"""

out = head + banner + tables + tail
# securite : le fichier doit rester en ASCII pur (une relecture par le codepage
# ANSI de PowerShell corromprait tout caractere multi-octet et casserait la
# tokenisation en cascade -- constate le 2026-07-21).
out.encode("ascii")

io.open(SCRIPT, "w", encoding="ascii", newline="\r\n").write(out)
print("tables      :", tables_src)
print("ecrit       :", SCRIPT, len(out), "octets,", out.count("\n") + 1, "lignes")
print("verifier    : $e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile("
      "(Resolve-Path .\\Harden-Windows-CIS.ps1).Path,[ref]$null,[ref]$e); $e.Count")
