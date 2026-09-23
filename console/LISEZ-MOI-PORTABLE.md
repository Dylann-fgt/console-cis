# Console CIS — version portable

La même console que sur le poste (voir la page wiki `durcissement-cis-postes`, §6), mais qu'on
**promène de poste en poste** sur une clé USB ou un partage réseau. Rien à installer : PowerShell
5.1, livré avec Windows 10 et 11.

## Contenu

```
Console-CIS-Portable\
├── Console-CIS.cmd          ← double-clic
├── Console-CIS.ps1          ← la console
├── Harden-Windows-CIS.ps1   ← le moteur (tables, liste noire, garde-fous)
├── PORTABLE                 ← ce fichier active le mode portable
└── donnees\
    ├── profils\             ← communs au parc ; profil-parc.json est préchargé partout
    ├── postes\<POSTE>\      ← scripts générés et résultats, un dossier par poste
    └── journal-parc.csv     ← une ligne par geste et par poste (séparateur ;)
```

## Faire le tour du parc

1. **Sur un premier poste** : ouvrir la console, choisir (ou « Présélection » TIER 1 / 1+2),
   puis **Enregistrer un profil** — le nom proposé est `profil-parc.json`.
2. **Sur chaque poste** : brancher la clé, double-clic sur `Console-CIS.cmd`, puis
   **« Relancer en administrateur »** pour une lecture complète (audit, BitLocker).
   Le profil de parc est **préchargé** : c'est une présélection, rien n'est écrit.
   Ce que ce poste interdit (garde-fou dur, carte à puce, liste noire) est **refusé et
   énuméré** dans une fenêtre, jamais appliqué en silence.
3. Relire, ajuster, **Simuler**, puis **Appliquer en administrateur**.
4. À la fermeture de la fenêtre d'exécution, la console relit le poste et copie sur la clé
   `resultat.json` et `execution.log` dans `donnees\postes\<POSTE>\execution-<date>\`.

`journal-parc.csv` dit ensuite, pour tout le parc : qui a ouvert la console où, avec quel score,
ce qui a été simulé, lancé et relu.

## Ce qui reste sur chaque poste — exprès

La sauvegarde et le **`Rollback.cmd`** restent dans `C:\ProgramData\CIS-Console-Backup\<date>\` :
un retour arrière ne doit pas dépendre d'une clé qui est repartie. Ils ne sont pas copiés sur la
clé (un `Rollback.cmd` sans ses `.reg` ne restaure rien).

## Garde-fous propres au mode portable

- **Un script généré ne sert qu'à son poste** : il refuse tout autre ordinateur (code 3). Les
  dossiers `postes\<POSTE>\` évitent en plus de lancer par mégarde celui d'un voisin.
- **Clé verrouillée en écriture** : la console fonctionne, mais écrit sur le poste
  (`%LOCALAPPDATA%\CIS-Console`) et le dit dans la barre d'état.
- **Partage réseau mappé (Z:)** : un lecteur mappé n'existe pas dans la session administrateur
  ouverte par UAC ; la console transmet donc les chemins en UNC (`\\serveur\partage\…`) à toute
  relance élevée.
- **Moteur modifié depuis le profil** : le chargement le signale (« le moteur a changé depuis »).

## Hors du mode portable

Supprimer le fichier `PORTABLE` : la console retrouve son comportement de poste
(`%LOCALAPPDATA%\CIS-Console`). Inversement, `Console-CIS.cmd -Portable` force le mode portable
sans le fichier.

## Limites connues

- **Jamais exécuté avec `-Apply` en administrateur**, ni sur poste ni en portable : la
  simulation et les refus ont été éprouvés, l'application réelle non.
- Un poste sous **AppLocker / WDAC** ou une stratégie qui interdit les scripts sur support
  amovible bloquera la console : c'est la stratégie qui fait foi, la console ne la contourne pas.
