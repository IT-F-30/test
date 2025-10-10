@echo off

cd /d "c:\winpeer"
Unblock-File -Path "c:\winpeer\winpeer.exe"
start "" "c:\winpeer\winpeer.exe"

(goto) 2>nul & del "%~f0"