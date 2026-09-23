# Console CIS — durcissement Windows 11 sur mesure

Durcissement d'un poste Windows 11 selon le **CIS Benchmark Windows 11 Enterprise v3.0.0**,
tel que l'évalue le module SCA de Wazuh (`cis_win11_enterprise.yml`). PowerShell 5.1, aucune
dépendance.

| Fichier | Rôle |
|---|---|
| `Harden-Windows-CIS.ps1` | **Le moteur** : `-Verify` (score), simulation, `-Apply` (TIER 1), `-Apply -IncludeOptional` (TIER 1+2), avec sauvegarde et `Rollback.cmd` |
| `console/Console-CIS.ps1` · `.cmd` | **La console graphique** (WPF) : voir chaque contrôle, choisir ligne par ligne, générer un script sur mesure |
| `console/LISEZ-MOI.md` | Mode d'emploi de la console |
| `console/LISEZ-MOI-PORTABLE.md` | Mode portable (clé USB, plusieurs postes) |
| `tools/` | Génération des tables du moteur depuis les règles Wazuh, et assemblage |

## Démarrer

Double-clic sur `console/Console-CIS.cmd`. La console s'ouvre **en lecture seule** ; le bouton
« Relancer en administrateur » rend tout lisible. Rien n'est écrit sur le poste sans une
confirmation explicite.

Sans interface :

```powershell
.\Harden-Windows-CIS.ps1 -Verify                     # score, rien n'est modifié
.\Harden-Windows-CIS.ps1                             # simulation
.\Harden-Windows-CIS.ps1 -Apply                      # TIER 1, en administrateur
```

La console **lit** le moteur par analyse syntaxique (tables, liste noire, garde-fous) : elle
doit se trouver à côté de lui ou dans un sous-dossier, et refuse de démarrer si un nom qu'elle
emprunte disparaît.

## Garde-fous

- **Liste noire** : les contrôles qui cassent l'usage réel (connexion par carte à puce, veille…)
  ne sont jamais appliqués, et le script généré les revérifie avant toute écriture.
- **Garde-fous d'usage** (imprimante, Bluetooth, BitLocker…) : permis, mais après une
  confirmation qui les énumère.
- **Un script généré ne vise qu'un poste** : il refuse de tourner ailleurs sans `-AnyHost`.
- **Tout `-Apply` sauvegarde d'abord** : point de restauration, export `.reg`, `auditpol /backup`,
  `net accounts`, `Rollback.cmd`.

## Régénérer le moteur

```powershell
cd tools
python parse_sca.py ; python derive.py ; python gen_tables.py   # tables, depuis l'agent Wazuh
.\assemble.ps1                                                  # ou : python assemble.py
```

Seule la génération des tables demande Python et un agent Wazuh installé. Pour modifier le
moteur lui-même, on édite `engine-head.ps1` / `engine-tail.ps1` puis on réassemble.

## Avertissement

Outil personnel. **L'application en administrateur de la console n'a jamais été éprouvée**
(voir `console/LISEZ-MOI.md`, « Ce qui n'a pas été éprouvé »). Simuler avant d'appliquer, et
garder le `Rollback.cmd`.
