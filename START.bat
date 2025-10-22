@echo off
title WhatsApp Clone - Real Messaging App
color 0A

echo.
echo ========================================
echo   WHATSAPP CLONE - REAL MESSAGING APP
echo ========================================
echo.

REM Check if Node.js is installed
echo [1/4] Checking for Node.js...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Node.js is NOT installed!
    echo.
    echo Please install Node.js from: https://nodejs.org
    echo After installation, restart this script.
    echo.
    pause
    exit /b 1
)

echo [OK] Node.js is installed!
node --version
echo.

REM Check if node_modules exists
if not exist "node_modules" (
    echo [2/4] Installing dependencies... This may take a minute...
    echo.
    call npm install
    if %errorlevel% neq 0 (
        echo.
        echo [ERROR] Failed to install dependencies!
        echo.
        pause
        exit /b 1
    )
    echo.
    echo [OK] Dependencies installed successfully!
) else (
    echo [2/4] Dependencies already installed!
)
echo.

REM Start the server
echo [3/4] Starting the server...
echo.
echo ========================================
echo   SERVER IS STARTING!
echo ========================================
echo.
echo Your WhatsApp Clone is running at:
echo.
echo    http://localhost:3000
echo.
echo [4/4] Instructions:
echo.
echo 1. Open your browser (Chrome, Firefox, Edge)
echo 2. Go to: http://localhost:3000
echo 3. Enter a username (e.g., "Alice")
echo 4. Open ANOTHER browser tab
echo 5. Go to: http://localhost:3000 again
echo 6. Enter a different username (e.g., "Bob")
echo 7. Click "New Chat" and select the other user
echo 8. START CHATTING! Messages appear in REAL-TIME!
echo.
echo ========================================
echo   Press Ctrl+C to stop the server
echo ========================================
echo.

node server.js
