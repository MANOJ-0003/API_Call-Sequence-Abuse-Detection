@echo off
setlocal enabledelayedexpansion
title API Sentinel - Behavioral API Security
color 0A

echo.
echo  =============================================================
echo    API Sentinel - Behavioral Sequence Abuse Detection Framework
echo  =============================================================
echo.

set "FOUND_PYTHON="

REM Check python in current directory venv first
IF EXIST "venv\Scripts\python.exe" (
    "venv\Scripts\python.exe" -c "import flask" >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        set "FOUND_PYTHON=venv\Scripts\python.exe"
        echo  [OK] Found virtual environment: venv\Scripts\python.exe
    )
)

REM Check .venv
IF NOT DEFINED FOUND_PYTHON IF EXIST ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import flask" >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        set "FOUND_PYTHON=.venv\Scripts\python.exe"
        echo  [OK] Found virtual environment: .venv\Scripts\python.exe
    )
)

REM Check global user myenv
IF NOT DEFINED FOUND_PYTHON IF EXIST "%USERPROFILE%\myenv\Scripts\python.exe" (
    "%USERPROFILE%\myenv\Scripts\python.exe" -c "import flask" >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        set "FOUND_PYTHON=%USERPROFILE%\myenv\Scripts\python.exe"
        echo  [OK] Found virtual environment: %USERPROFILE%\myenv\Scripts\python.exe
    )
)

REM Check system python
IF NOT DEFINED FOUND_PYTHON (
    python -c "import flask" >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        set "FOUND_PYTHON=python"
        echo  [OK] Found system Python with Flask
    )
)

REM Check py launcher
IF NOT DEFINED FOUND_PYTHON (
    py -3 -c "import flask" >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        set "FOUND_PYTHON=py -3"
        echo  [OK] Found py launcher with Flask
    )
)

REM If Flask is not installed in any environment, locate working Python and install requirements
IF NOT DEFINED FOUND_PYTHON (
    echo  [INFO] Checking Python installation to install dependencies...
    
    python --version >nul 2>&1
    IF !ERRORLEVEL! EQU 0 (
        set "FOUND_PYTHON=python"
    ) ELSE (
        py -3 --version >nul 2>&1
        IF !ERRORLEVEL! EQU 0 (
            set "FOUND_PYTHON=py -3"
        ) ELSE IF EXIST "%USERPROFILE%\myenv\Scripts\python.exe" (
            set "FOUND_PYTHON=%USERPROFILE%\myenv\Scripts\python.exe"
        )
    )

    IF DEFINED FOUND_PYTHON (
        echo  [INFO] Installing required dependencies (Flask)...
        !FOUND_PYTHON! -m pip install -r requirements.txt
        IF !ERRORLEVEL! NEQ 0 (
            echo  [WARNING] pip install had issues. Attempting direct Flask install...
            !FOUND_PYTHON! -m pip install "flask>=3.0"
        )
    ) ELSE (
        color 0C
        echo.
        echo  [ERROR] Python was not found on your system PATH!
        echo  Please install Python 3.9+ from https://www.python.org/downloads/
        echo  Make sure to check "Add Python to PATH" during installation.
        echo.
        pause
        exit /b 1
    )
)

echo.
echo  [OK] Server starting on http://127.0.0.1:5000
echo  [OK] Launching web interface in your browser...
echo.
echo  Press CTRL+C in this window to stop the server.
echo.

REM Open browser after 2 seconds
start /B cmd /C "timeout /T 2 /NOBREAK >nul && start http://127.0.0.1:5000"

REM Run Flask Application
!FOUND_PYTHON! app.py

echo.
echo  [Server stopped]
pause
