@echo off
SETLOCAL

echo ==========================================
echo  NetAudit Agent - Windows Installer
echo ==========================================
echo.

REM Check Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: Python not found. Install from https://python.org
    pause
    exit /b 1
)

REM Install Python dependencies
echo Installing Python dependencies...
pip install httpx psutil structlog

REM Check ClamAV
IF NOT EXIST "C:\Program Files\ClamAV\clamscan.exe" (
    echo.
    echo WARNING: ClamAV not found.
    echo Virus scanning will be unavailable until ClamAV is installed.
    echo Download from: https://www.clamav.net/downloads
    echo.
)

REM Prompt for configuration
SET /P DASHBOARD_URL=Enter your NetAudit dashboard URL (e.g. http://192.168.1.50): 
SET /P AGENT_TOKEN=Enter your agent token (from Dashboard > My Account > Agent Token): 

REM Configure
python "%~dp0agent.py" configure --url %DASHBOARD_URL% --token %AGENT_TOKEN%

REM Install as service
python "%~dp0agent.py" install-service

echo.
echo Installation complete. The NetAudit agent is running in the background.
pause
