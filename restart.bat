@echo off
title API Sentinel - Restarting Server
color 0E

echo.
echo  =============================================================
echo    API Sentinel - Stopping Existing Server & Starting Fresh
echo  =============================================================
echo.

echo  [1/2] Stopping any existing process on port 5000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":5000" ^| findstr "LISTENING"') do (
    echo   - Terminating PID: %%a
    taskkill /F /PID %%a >nul 2>&1
)

echo  [2/2] Launching updated server...
echo.
timeout /T 1 /NOBREAK >nul
call run.bat
