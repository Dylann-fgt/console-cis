# ============================================================================
#  build-release.ps1 -- construit l'archive de publication de la Console CIS
#
#  Sortie : dist\Console-CIS-<version>.zip (+ .sha256), sous un dossier racine
#  du meme nom. Contenu : le depot moins son outillage (tools\, .github\) --
#  README, LICENSE, CHANGELOG, le moteur, console\ et docs\. La version est
#  lue dans console\Console-CIS.ps1 ($ConsoleVersion).
#
#  Controles AVANT d'ecrire :
#    - les deux scripts s'analysent sans erreur ;
#    - le moteur est exactement celui que tools\assemble.ps1 produit depuis
#      engine-head.ps1 et engine-tail.ps1. Sinon on publierait un moteur que
#      ses propres sources ne reproduisent pas -- et le prochain qui
#      reassemblerait perdrait ce qui n'est que dans l'assemble.
#  Jamais embarques : un dossier donnees\ ou un fichier PORTABLE, qui portent
#  l'historique d'un parc reel. La liste des fichiers est fermee, expres.
#
#  Se lance dans le depot publie (README, LICENSE et docs\ n'existent que la).
#  Une archive existante n'est jamais ecrasee : la deplacer avant.
# ============================================================================
param(
    [string]$OutDir
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $root 'dist' }

$m = Select-String -LiteralPath (Join-Path $root 'console\Console-CIS.ps1') -Pattern "^\`$ConsoleVersion\s*=\s*'([0-9.]+)'" |
     Select-Object -First 1
if (-not $m) { throw 'version introuvable dans console\Console-CIS.ps1 ($ConsoleVersion)' }
$ver  = $m.Matches[0].Groups[1].Value
$name = "Console-CIS-$ver"

$files = @(
    'README.md', 'LICENSE', 'CHANGELOG.md', 'Harden-Windows-CIS.ps1',
    'console\Console-CIS.cmd', 'console\Console-CIS.ps1',
    'console\LISEZ-MOI.md', 'console\LISEZ-MOI-PORTABLE.md',
    'docs\console.png'
)
foreach ($f in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $f))) { throw "fichier absent : $f" }
}

foreach ($f in 'Harden-Windows-CIS.ps1', 'console\Console-CIS.ps1') {
    $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $f), [ref]$null, [ref]$e)
    if ($e.Count) { throw "$f ne s'analyse pas : $($e[0].Message) (ligne $($e[0].Extent.StartLineNumber))" }
}

# Le moteur publie doit etre celui que ses sources assemblent. On assemble dans
# un dossier temporaire, avec les seules sources : les tables sont alors reprises
# du moteur en place, comme pour tout contributeur.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('cis-release-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $tmp 'tools') | Out-Null
try {
    Copy-Item -LiteralPath (Join-Path $root 'Harden-Windows-CIS.ps1') -Destination $tmp
    foreach ($t in 'assemble.ps1', 'engine-head.ps1', 'engine-tail.ps1') {
        Copy-Item -LiteralPath (Join-Path $root "tools\$t") -Destination (Join-Path $tmp 'tools')
    }
    $null = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tmp 'tools\assemble.ps1')
    if ($LASTEXITCODE) { throw "tools\assemble.ps1 a echoue (code $LASTEXITCODE)" }
    $a = (Get-FileHash -LiteralPath (Join-Path $root 'Harden-Windows-CIS.ps1') -Algorithm SHA256).Hash
    $b = (Get-FileHash -LiteralPath (Join-Path $tmp 'Harden-Windows-CIS.ps1') -Algorithm SHA256).Hash
    if ($a -ne $b) {
        throw "Harden-Windows-CIS.ps1 n'est pas ce que ses sources assemblent ($($a.Substring(0,16)) / $($b.Substring(0,16))) : modifier tools\engine-*.ps1, puis relancer tools\assemble.ps1"
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$zip = Join-Path $OutDir "$name.zip"
if (Test-Path -LiteralPath $zip) { throw "$zip existe deja : le deplacer avant de reconstruire" }

Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
# Entrees ecrites a la main avec des '/' et sous un dossier racine : l'extraction
# donne Console-CIS-<version>\, pas des fichiers en vrac.
$fs = [IO.File]::Open($zip, 'CreateNew')
$za = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create)
try {
    foreach ($f in $files) {
        $en = $za.CreateEntry("$name/" + $f.Replace('\', '/'), [IO.Compression.CompressionLevel]::Optimal)
        $w = $en.Open()
        try { $bytes = [IO.File]::ReadAllBytes((Join-Path $root $f)); $w.Write($bytes, 0, $bytes.Length) } finally { $w.Close() }
    }
} finally { $za.Dispose(); $fs.Close() }

# Relecture : ce qui est dans l'archive, pas ce qu'on croit y avoir mis.
$sha = [Security.Cryptography.SHA256]::Create()
$za  = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    foreach ($f in $files) {
        $en = $za.GetEntry("$name/" + $f.Replace('\', '/'))
        if (-not $en) { throw "entree absente de l'archive : $f" }
        $s = $en.Open()
        try { $h = [BitConverter]::ToString($sha.ComputeHash($s)).Replace('-', '') } finally { $s.Close() }
        if ($h -ne (Get-FileHash -LiteralPath (Join-Path $root $f) -Algorithm SHA256).Hash) { throw "copie infidele dans l'archive : $f" }
    }
    if ($za.Entries.Count -ne $files.Count) { throw "l'archive contient $($za.Entries.Count) entrees au lieu de $($files.Count)" }
} finally { $za.Dispose() }

$hz = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText("$zip.sha256", "$hz  $name.zip`n", (New-Object Text.UTF8Encoding($false)))
'{0}  {1} fichiers  {2} octets' -f (Split-Path $zip -Leaf), $files.Count, (Get-Item -LiteralPath $zip).Length
'SHA-256   {0}' -f $hz
