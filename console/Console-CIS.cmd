@echo off
REM Console-CIS -- console graphique du durcissement CIS (lecture du poste, choix, generation).
REM La console n'ecrit rien sur le poste : elle ecrit des scripts. Voir LISEZ-MOI.md.
start "" powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Console-CIS.ps1" %*
