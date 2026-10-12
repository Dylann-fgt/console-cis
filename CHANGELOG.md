# Historique

Le moteur (`Harden-Windows-CIS.ps1`) et la console (`console/Console-CIS.ps1`) évoluent
ensemble ; les versions sont celles de la console. Chaque garde-fou a été ajouté **après** un
incident réel sur un poste durci — la raison est donnée avec lui.

## 1.3 — 2026-10-12

- **Protection LSA conditionnelle.** `26269` (`AllowCustomSSPsAPs`) et `26270` (`RunAsPPL`)
  ne sont plus en liste noire sur toute machine : ils y passent seulement quand le poste ouvre sa
  session par carte à puce, comme le bloc VBS / Credential Guard. Ailleurs, ils sont en TIER 3
  (affichés avec leur raison, jamais automatisés).
- **`26443` « Turn off the Store application » passe de la liste noire au TIER 3.** Il fait
  disparaître le Microsoft Store ; les autres contrôles `store` du TIER 2 le brident déjà.
- **Sources du moteur réalignées.** `tools/engine-head.ps1` et `engine-tail.ps1` avaient perdu
  le garde-fou veille et une entrée de liste noire, écrits directement dans le script assemblé :
  réassembler les aurait effacés. Réassembler redonne désormais exactement le script publié.
- **`tools/` reproduit les tables.** La régénération depuis le fichier de règles Wazuh redonne
  les tables embarquées ; le titre de `26202` est renseigné par `gen_tables.py`, si bien que
  `assemble.ps1` et `assemble.py` produisent le même fichier.
- **Aide intégrée** : `Get-Help .\Harden-Windows-CIS.ps1 -Full` et
  `Get-Help .\console\Console-CIS.ps1 -Full`.
- Hors profil carte à puce, l'état de la protection LSA et de Credential Guard est affiché sans
  le rouge qui signalait un danger pour la carte.

## 1.2 — 2026-10-05

- Après une application, une console **non élevée** ne peut pas lister
  `C:\ProgramData\CIS-Console-Backup` (réservé aux administrateurs, exprès). Le refus était
  avalé et devenait « aucune sauvegarde trouvée » — lu comme une application sans retour
  arrière. La console dit maintenant « sauvegarde non vérifiable : console non élevée ».

## 1.1 — 2026-09-23

- **Mode portable** : un fichier `PORTABLE` à côté de la console (ou `-Portable`) range profils,
  scripts et traces dans `donnees\` ; `profil-parc.json` est préchargé sur chaque poste ;
  `journal-parc.csv` trace chaque geste. Sauvegarde et `Rollback.cmd` restent sur le poste.
- Un lecteur réseau mappé n'existe pas dans la session élevée par UAC : toute relance en
  administrateur reçoit ses chemins en UNC.

## 1.0 — 2026-09-21

- **Console graphique** (WPF) : voir chaque contrôle, sa valeur, sa conformité au sens de la
  règle Wazuh et son garde-fou ; choisir ligne par ligne ; enregistrer des profils ; générer un
  script autonome lié au poste, qui simule par défaut, sauvegarde, applique et relit.
- La console **lit** le moteur par analyse syntaxique au lieu de le recopier.

## Moteur — avant la console

- **2026-09-16 — garde-fou veille.** Sur un portable sans Modern Standby (S0), `26283`/`26284`
  suppriment le dernier état de veille (S1-S3) et renvoient toute mise en veille sur la veille
  prolongée. Sur le poste qui l'a révélé, une reprise sur trois échouait (`0xC00000D4`) et
  jetait les écritures en cache des volumes. La famille `sleep` est écartée dès que le Modern
  Standby manque **ou que `powercfg /a` est illisible** ; `-IgnoreGuards` ne lève pas ce
  garde-fou. Pour réparer un poste déjà durci, retirer aussi `f15576e8` (`26281`/`26282`) —
  sinon `powercfg` refuse toute écriture —, puis `gpupdate /target:computer /force`.
- **2026-08-04 — BitLocker indéterminé.** Sans élévation, l'état BitLocker est illisible : le
  moteur le suppose désormais **actif** (et le dit), plutôt que d'annoncer des contrôles FVE
  qu'un `-Apply` élevé aurait écartés.
- **2026-08-03 — garde-fou webcam.** `26352` (`AllowCamera = 0`) coupe la caméra pour toutes
  les applications, et le symptôme ne désigne pas sa cause : l'application dit seulement
  qu'aucune caméra n'est disponible. Il est écarté dès qu'une webcam est reconnue.
- **2026-08-03 — profil carte à puce.** Trois réglages tuent une ouverture de session par
  carte reposant sur un package d'authentification tiers : `RunAsPPL`, `AllowCustomSSPsAPs` et
  `LsaCfgFlags` (Credential Guard, verrou UEFI). Le profil est détecté ; il met le bloc VBS en
  liste noire et fait refuser `-EnableVBS`. Instantané avant/après de toute la pile de la carte.
- **2026-07-25 — moteur généralisé.** Tables extraites des 482 contrôles du fichier de règles
  Wazuh, au lieu des seuls échecs d'un poste ; profil de machine et garde-fous d'usage ;
  `Rollback.cmd` ; mode `-Verify` ; `auditpol` par GUID et comptes intégrés par SID, pour
  fonctionner sur un Windows non anglais.
