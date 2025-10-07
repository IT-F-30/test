@echo off
echo Starting winpeer.exe...

echo Launching from c:\winpeer\
"c:\winpeer\winpeer.exe"
echo Exit code: %ERRORLEVEL%
pause

if not exist "c:\winpeer\winpeer.exe" (
    echo ERROR: winpeer.exe not found at c:\winpeer\winpeer.exe
    pause
    exit /b 1
)

echo Launching from c:\winpeer\
start /d "c:\winpeer" "WinPeer Window" "c:\winpeer\winpeer.exe"

echo winpeer.exe started.
pause