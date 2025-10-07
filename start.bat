@echo off
echo Starting winpeer.exe...

if not exist "c:\winpeer\winpeer.exe" (
    echo ERROR: winpeer.exe not found at c:\winpeer\winpeer.exe
    pause
    exit /b 1
)

start "WinPeer" "c:\winpeer\winpeer.exe"

echo winpeer.exe started.
pause