@echo off
REM Start Accord Desktop on Windows
REM Usage: start-desktop.bat [server_url]
REM Default: connects to http://localhost:8080
REM Example: start-desktop.bat http://192.168.1.100:8080

cd /d "%~dp0desktop\frontend"

IF "%~1"=="" (
    set VITE_ACCORD_SERVER_URL=http://localhost:8080
) ELSE (
    set VITE_ACCORD_SERVER_URL=%~1
)

echo Starting Accord Desktop...
echo Connecting to server: %VITE_ACCORD_SERVER_URL%
echo.

REM Install deps if needed
IF NOT EXIST node_modules (
    echo Installing dependencies...
    call npm install
)

REM Start dev server
call npm run dev
