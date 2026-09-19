@echo off
REM BurpMD Parser Pro — Windows Run Helper (Command Prompt)
REM Usage: run.bat <burp_export.xml> [output_folder]
REM
REM For PowerShell users: use run.ps1 instead (recommended).

if "%~1"=="" (
    echo Usage: run.bat ^<burp_export.xml^> [output_folder]
    echo.
    echo Examples:
    echo   run.bat C:\exports\burp_items.xml
    echo   run.bat C:\exports\burp_items.xml C:\my-audit\burpexplore
    exit /b 1
)

set "XML_FILE=%~1"

if not exist "%XML_FILE%" (
    echo [ERROR] XML file not found: %XML_FILE%
    exit /b 1
)

REM --- Output directory ---
if "%~2"=="" (
    set OUTPUT_DIR=output\burpmd_%date:~-4%%date:~4,2%%date:~7,2%
) else (
    set "OUTPUT_DIR=%~2"
)

REM --- Activate venv if present ---
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
)

echo.
echo === BurpMD Parser Pro ===
echo   Input:  %XML_FILE%
echo   Output: %OUTPUT_DIR%
echo.

burpmd "%XML_FILE%" -o "%OUTPUT_DIR%" --sitemap --full-analysis --dedupe -v 2>nul
if errorlevel 1 (
    echo [*] Trying python -m burpmd ...
    python -m burpmd "%XML_FILE%" -o "%OUTPUT_DIR%" --sitemap --full-analysis --dedupe -v
)

echo.
if errorlevel 1 exit /b 1
echo === Export Complete ===
echo Output: %OUTPUT_DIR%
echo.
echo Next steps:
echo   1. Open output folder in VS Code:  code "%OUTPUT_DIR%"
echo   2. Open AI_ANALYSIS_PROMPTS.md in Copilot Chat
echo   3. Follow the phased analysis plan
echo.
