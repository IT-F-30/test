@echo off
echo Starting winpeer.exe...

REM �p�X���m�F
if not exist "c:\winpeer\winpeer.exe" (
    echo ERROR: winpeer.exe not found at c:\winpeer\winpeer.exe
    pause
    exit /b 1
)

REM winpeer.exe�����s
start "WinPeer" "c:\winpeer\winpeer.exe"

REM �܂��́A���ڎ��s����ꍇ�i�E�B���h�E���ێ��j
REM "c:\winpeer\winpeer.exe"

echo winpeer.exe started.
pause