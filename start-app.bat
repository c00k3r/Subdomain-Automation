@echo off
title ReconForge Desktop
echo ===================================================
echo Starting ReconForge Local Desktop App...
echo ===================================================
echo.

:: Check if node_modules exists
if not exist "node_modules\" (
    echo Installing dependencies...
    call npm install
)

:: Start server in background and open app window
start "ReconForge Server" cmd /c "node server.js"
timeout /t 3 /nobreak >nul

:: Launch browser in standalone app mode (frameless window without address bar)
where msedge >nul 2>nul
if %errorlevel% equ 0 (
    start msedge --app=http://localhost:3000
    exit
)

where chrome >nul 2>nul
if %errorlevel% equ 0 (
    start chrome --app=http://localhost:3000
    exit
)

:: Fallback standard browser opener
start http://localhost:3000
