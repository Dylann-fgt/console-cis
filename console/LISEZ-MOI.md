# Console CIS — lire, choisir, générer

Console graphique (WPF, PowerShell 5.1, aucune dépendance) posée sur le moteur
`../Harden-Windows-CIS.ps1`. Vue d'ensemble : `../README.md`.

## Lancer

Double-clic sur **`Console-CIS.cmd`**. La console s'ouvre en **lecture seule** : sans élévation,
la politique d'audit et l'état BitLocker sont illisibles (BitLocker est alors supposé actif, comme
dans le moteur). Le bouton **« Relancer en administrateur »** rend tout lisible et garde les choix
en cours.

## Ce qu'on y fait

1. **Voir** chaque contrôle : valeur en place, conformité au sens de la règle Wazuh, garde-fou.
   Le score affiché est **exactement** celui de `Harden-Windows-CIS.ps1 -Verify`.
2. **Choisir**, ligne par ligne : `Appliquer`, `Retirer` (retour à « non configuré »), ou rien.
   La colonne **Cible** est modifiable pour les réglages simples ; une valeur hors tolérance CIS
   est acceptée, mais signalée avant la génération.
3. **Présélection** : ce que ferait `-Apply` (TIER 1) ou `-Apply -IncludeOptional` (TIER 1+2),
   limité aux contrôles **non conformes** et **sans garde-fou**.
4. **Enregistrer / charger un profil** (`.json`) : les choix se retrouvent d'une session à l'autre.
5. **Générer le script**, **Simuler** (fenêtre séparée, rien n'est écrit) ou **Appliquer en
   administrateur** (après confirmation ; la console relit le poste à la fermeture de la fenêtre).

## Ce qu'elle refuse

| Verrou | Dans la console | Dans le script généré |
|---|---|---|
| Liste noire (en profil carte à puce : protection LSA 26269/26270 et VBS 26225-26230) | affiché, jamais sélectionnable | revérifiée avant toute écriture, arrêt code 2 |
| Garde-fou dur (carte à puce, veille S3) | `Appliquer` absent ; `Retirer` seulement | — |
| Garde-fou d'usage (imprimante, Bluetooth, BitLocker…) | permis, **confirmation qui les énumère** | — |
| TIER 3 | affiché avec sa raison, pas d'action | — |
| Autre poste | — | refus code 3 sans `-AnyHost` |

## Le script généré

`%LOCALAPPDATA%\CIS-Console\CIS-sur-mesure-<POSTE>-<date>.ps1`, UTF-8 avec BOM.

- sans `-Apply` : **simulation** — état actuel et effet attendu, ligne à ligne ;
- avec `-Apply` (PowerShell **en administrateur**) : point de restauration, export `.reg` des clés
  touchées, `auditpol /backup`, `net accounts` avant, **`Rollback.cmd`** — puis application, puis
  **relecture de chaque réglage** et de la pile carte à puce ;
- sauvegarde et journal : `C:\ProgramData\CIS-Console-Backup\<date>\` (`execution.log`,
  `resultat.json`, `Rollback.cmd`, copie du script).

Écarts assumés par rapport au moteur : l'audit **ajoute** les indicateurs requis sans en retirer ;
`Retirer` n'est proposé que sous une clé `…\Policies\…` (hors stratégie, l'absence d'une valeur ne
veut pas dire « défaut ») ; retirer une valeur de stratégie déclenche `gpupdate /target:computer /force`.

## Ce qui a été éprouvé, et ce qui ne l'a pas été

- **Application réelle en administrateur** : un poste Windows 11 (build 26200, en français,
  session ouverte par carte à puce), en mode portable depuis un dossier local, les 26 et
  27/09/2026 — cinq applications puis un retrait, score passé de **326 à 440/447**. C'est ce
  passage qui a révélé le défaut corrigé en 1.2 (une console non élevée annonçait « aucune
  sauvegarde » au lieu de « sauvegarde non vérifiable »).
- **Sans élévation** : inventaire (481 contrôles), score identique au moteur, génération,
  simulation, refus de `-Apply` sans élévation, refus liste noire (script retouché à la main →
  code 2), refus d'un autre poste (code 3), aller-retour d'un profil, rendu de la fenêtre.
- **Pas encore éprouvé** : le lancement depuis une clé USB (copie des traces sur la clé) et
  depuis un lecteur réseau mappé (chemins traduits en UNC) ; et, plus largement, un **seul**
  poste a reçu une application réelle — ni Windows en anglais, ni poste sans carte à puce, ni
  poste membre d'un domaine.

## Vérifier sans fenêtre

```powershell
.\Console-CIS.ps1 -SelfTest <dossier>   # inventaire, présélection, profil, script d'essai
.\Console-CIS.ps1 -Snapshot <image.png> # rend la fenêtre hors écran
```

La console **lit** le moteur par analyse syntaxique (tables, liste noire, garde-fous, profil) : elle
refuse de démarrer si l'un des noms qu'elle emprunte disparaît. Modifier le moteur ne demande donc
rien ici — sauf s'il renomme ces tables ou fonctions.
