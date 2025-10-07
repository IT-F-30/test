@echo off
echo Starting winpeer.exe...

REM パスを確認
if not exist "c:\winpeer\winpeer.exe" (
    echo ERROR: winpeer.exe not found at c:\winpeer\winpeer.exe
    pause
    exit /b 1
)

REM winpeer.exeを実行
start "WinPeer" "c:\winpeer\winpeer.exe"

REM または、直接実行する場合（ウィンドウを維持）
REM "c:\winpeer\winpeer.exe"

echo winpeer.exe started.
pause