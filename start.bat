@echo off
echo Starting winpeer.exe...

if not exist "c:\winpeer\winpeer.exe" (
    echo ERROR: winpeer.exe not found at c:\winpeer\winpeer.exe
    pause
    exit /b 1
)

echo Launching from c:\winpeer\
cd /d "c:\winpeer"
winpeer.exe tcp://10.40.241.126:1883 8959dc32e5536fd805df1034e99a77ce
echo Exit code: %ERRORLEVEL%
pause