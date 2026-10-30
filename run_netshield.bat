@echo off
title NetShield - Network Packet Analyzer ^& Security Monitor
cd /d "%~dp0"

echo =====================================================================
echo   Starting NetShield: Network Packet Analyzer ^& Security Dashboard
echo =====================================================================
echo.

set PYTHON_EXE=python
if exist "C:\Users\bazil\AppData\Local\Python\bin\python.exe" (
    set PYTHON_EXE="C:\Users\bazil\AppData\Local\Python\bin\python.exe"
)

echo Using Python: %PYTHON_EXE%
echo Starting Streamlit app on http://localhost:8501 ...
echo.

%PYTHON_EXE% -m streamlit run app.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] An error occurred while running the dashboard.
    pause
)
