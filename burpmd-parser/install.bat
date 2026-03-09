@echo off
REM BurpMD Parser Pro — Windows Installation (Command Prompt)
REM Run this from the burpmd-parser-windows folder.
REM
REM For PowerShell users: use install.ps1 instead (recommended).

echo.
echo === BurpMD Parser Pro — Windows Installer ===
echo.

REM --- Check Python ---
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo         Download from https://www.python.org/downloads/
    echo         Make sure "Add Python to PATH" is checked during install.
    exit /b 1
)

python --version
echo.

REM --- Create virtual environment ---
if not exist ".venv" (
    echo [*] Creating virtual environment...
    python -m venv .venv
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment already exists.
)

REM --- Activate and install ---
echo [*] Activating virtual environment...
call .venv\Scripts\activate.bat

echo [*] Installing BurpMD Parser Pro...
pip install .

REM --- Verify ---
echo.
echo [*] Verifying installation...
burpmd --version 2>nul
if errorlevel 1 (
    echo [WARN] burpmd not found in PATH. Use: python -m burpmd --version
    python -m burpmd --version
)

echo.
echo === Installation Complete ===
echo.
echo Quick start:
echo   .venv\Scripts\activate.bat
echo   burpmd export.xml -o output --sitemap --full-analysis --dedupe -v
echo.
