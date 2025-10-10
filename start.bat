@echo off
echo Starting winpeer.exe...

if not exist "c:\winpeer\winpeer.exe" (
    echo ERROR: winpeer.exe not found at c:\winpeer\winpeer.exe
    pause
    exit /b 1
)

echo Launching from c:\winpeer\
cd /d "c:\winpeer"
Unblock-File -Path "c:\winpeer\winpeer.exe"
start "" "c:\winpeer\winpeer.exe"
echo Exit code: %ERRORLEVEL%
pause