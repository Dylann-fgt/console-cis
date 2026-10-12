# ============================================================================
#  assemble.ps1 -- equivalent PowerShell d'assemble.py
#
#  Reassemble Harden-Windows-CIS.ps1 = engine-head.ps1 + banniere + tables +
#  engine-tail.ps1, en ASCII pur et en CRLF, puis controle la syntaxe.
#
#  Pourquoi ce doublon : seule la GENERATION des tables (parse_sca.py,
#  derive.py, gen_tables.py) a besoin de Python et du fichier de regles Wazuh.
#  Modifier le MOTEUR ne demande que de recoller les morceaux, sans Python.
#  Les deux assembleurs produisent le meme fichier.
#
#  Les tables viennent de tools\tables.ps1 s'il existe, sinon du script deja
#  assemble : on remplace le moteur autour d'elles sans les regenerer.
# ============================================================================
$ErrorActionPreference = 'Stop'

$tools  = $PSScriptRoot
$dest   = Split-Path $tools -Parent
$script = Join-Path $dest 'Harden-Windows-CIS.ps1'

$BannerMark = '# ============================ TABLES DE DONNEES'
$TablesMark = '$CisRegistry = @('
$TailMark   = "# -- Politique d'audit :"

function Read-Ascii($path) { [IO.File]::ReadAllText($path, [Text.Encoding]::ASCII) }

$head = Read-Ascii (Join-Path $tools 'engine-head.ps1')
$tail = Read-Ascii (Join-Path $tools 'engine-tail.ps1')

$tablesFile = Join-Path $tools 'tables.ps1'
if (Test-Path $tablesFile) {
    $tables    = Read-Ascii $tablesFile
    $tablesSrc = 'tools\tables.ps1'
} elseif (Test-Path $script) {
    $txt = Read-Ascii $script
    $i   = $txt.IndexOf($TablesMark, $txt.IndexOf($BannerMark))
    $j   = $txt.IndexOf($TailMark, $i)
    if ($i -lt 0 -or $j -lt 0) { throw "reperes introuvables dans $script" }
    # rstrip + un seul saut de ligne : le tail apporte le sien, sinon une
    # ligne vide s'ajouterait a chaque reassemblage.
    $tables    = $txt.Substring($i, $j - $i).TrimEnd("`r", "`n") + "`n"
    $tablesSrc = 'tables reprises de Harden-Windows-CIS.ps1'
} else {
    throw 'ni tools\tables.ps1 ni Harden-Windows-CIS.ps1 : rien a assembler'
}

$banner = @"

# ============================ TABLES DE DONNEES ==========================
#  Genere le 2026-10-12 par tools/ depuis
#    C:\Program Files (x86)\ossec-agent\ruleset\sca\cis_win11_enterprise.yml
#  (CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0, 482 controles).
#  Ne pas editer a la main : regenerer les tables et reassembler.
#
#  Tier 1 = sur      Tier 2 = -IncludeOptional     Tier 9 = -ScoreOnly
#  Fam    = famille, sert aux garde-fous (fve, laps, service, store, rdp...)
# =========================================================================


"@ -replace "`r`n", "`n"

$out = ($head + $banner + $tables + $tail) -replace "`r`n", "`n"

# Le fichier doit rester en ASCII pur : PowerShell relit un UTF-8 sans BOM
# avec le codepage ANSI du systeme, ce qui corrompt tout caractere multi-octet
# et casse la tokenisation en cascade (constate le 2026-07-21).
$bad = [regex]::Matches($out, '[^\x00-\x7F]')
if ($bad.Count) {
    $ctx = $out.Substring([Math]::Max(0, $bad[0].Index - 60), 120)
    throw "caractere non-ASCII a l'offset $($bad[0].Index) : '$($bad[0].Value)'`n...$ctx..."
}

[IO.File]::WriteAllText($script, ($out -replace "`n", "`r`n"), [Text.Encoding]::ASCII)

$e = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($script, [ref]$null, [ref]$e)

Write-Host ("tables   : {0}" -f $tablesSrc)
Write-Host ("ecrit    : {0} -- {1} octets, {2} lignes" -f $script, (Get-Item $script).Length, (($out -split "`n").Count))
Write-Host ("syntaxe  : {0} erreur(s)" -f $e.Count) -ForegroundColor $(if ($e.Count) { 'Red' } else { 'Green' })
if ($e.Count) { $e | Select-Object -First 5 | ForEach-Object { Write-Host ("  L{0} : {1}" -f $_.Extent.StartLineNumber, $_.Message) -ForegroundColor Red }; exit 1 }
