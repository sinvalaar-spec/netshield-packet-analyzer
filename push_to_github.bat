@echo off
title Push NetShield to GitHub
cd /d "%~dp0"

echo =====================================================================
echo           NetShield: Push Repository to GitHub
echo =====================================================================
echo.

:: Ensure branch is main
git branch -M main

:: Stage all tracked and new files
echo [*] Staging files...
git add .

:: Commit
echo [*] Committing changes...
git commit -m "feat: Initial release of NetShield Network Packet Analyzer & Security Dashboard"

echo.
echo =====================================================================
echo   To push this project to GitHub:
echo   1. Go to https://github.com/new and create a new repository.
echo   2. Copy the HTTPS or SSH repository URL.
echo =====================================================================
echo.

set /p REPO_URL="Paste your GitHub repository URL (e.g. https://github.com/user/netshield.git): "

if "%REPO_URL%"=="" (
    echo [!] No URL provided. You can run this script again anytime.
    pause
    exit /b 0
)

:: Configure remote origin
git remote remove origin >nul 2>&1
git remote add origin %REPO_URL%

echo.
echo [*] Pushing code to %REPO_URL% on branch main...
git push -u origin main

if %ERRORLEVEL% EQU 0 (
    echo.
    echo =====================================================================
    echo [SUCCESS] NetShield has been successfully uploaded to GitHub!
    echo =====================================================================
) else (
    echo.
    echo [!] Push failed. Please check your GitHub credentials or repository URL.
)

echo.
pause
