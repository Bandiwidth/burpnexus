# BurpMD Parser Pro — Windows Installation Script
# Run this in PowerShell from the burpmd-parser-windows folder.
#
# Usage:
#   .\install.ps1
#
# What it does:
#   1. Checks Python 3.8+ is available
#   2. Creates a virtual environment (.venv)
#   3. Installs burpmd into it
#   4. Verifies the installation

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== BurpMD Parser Pro — Windows Installer ===" -ForegroundColor Cyan
Write-Host ""

# --- Locate Python ---
$pythonCmd = $null
foreach ($candidate in @("python", "py -3", "python3")) {
    try {
        $ver = & ($candidate.Split(" ")[0]) @($candidate.Split(" ") | Select-Object -Skip 1) --version 2>&1
        if ($ver -match "Python 3\.([8-9]|[1-9]\d)") {
            $pythonCmd = $candidate
            Write-Host "[OK] Found $ver using '$candidate'" -ForegroundColor Green
            break
        }
    } catch {}
}

if (-not $pythonCmd) {
    Write-Host "[ERROR] Python 3.8+ is required but not found." -ForegroundColor Red
    Write-Host "        Download from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "        Make sure 'Add Python to PATH' is checked during install." -ForegroundColor Yellow
    exit 1
}

# --- Create virtual environment ---
$venvPath = Join-Path $PSScriptRoot ".venv"
if (-not (Test-Path $venvPath)) {
    Write-Host ""
    Write-Host "[*] Creating virtual environment at .venv ..." -ForegroundColor Cyan
    $pyParts = $pythonCmd.Split(" ")
    & $pyParts[0] @($pyParts | Select-Object -Skip 1) -m venv $venvPath
    Write-Host "[OK] Virtual environment created." -ForegroundColor Green
} else {
    Write-Host "[OK] Virtual environment already exists at .venv" -ForegroundColor Green
}

# --- Activate and install ---
$activateScript = Join-Path $venvPath "Scripts\Activate.ps1"
if (-not (Test-Path $activateScript)) {
    Write-Host "[ERROR] Activate script not found: $activateScript" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[*] Activating virtual environment ..." -ForegroundColor Cyan
& $activateScript

Write-Host "[*] Installing BurpMD Parser Pro ..." -ForegroundColor Cyan
pip install $PSScriptRoot

# --- Verify ---
Write-Host ""
Write-Host "[*] Verifying installation ..." -ForegroundColor Cyan
try {
    $version = burpmd --version 2>&1
    Write-Host "[OK] $version" -ForegroundColor Green
} catch {
    Write-Host "[WARN] 'burpmd' command not found. Use: python -m burpmd --version" -ForegroundColor Yellow
    python -m burpmd --version
}

Write-Host ""
Write-Host "=== Installation Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Quick start:" -ForegroundColor Cyan
Write-Host "  .\.venv\Scripts\Activate.ps1" -ForegroundColor White
Write-Host "  burpmd export.xml -o output --sitemap --full-analysis --dedupe -v" -ForegroundColor White
Write-Host ""
Write-Host "Or use the run.ps1 helper:" -ForegroundColor Cyan
Write-Host "  .\run.ps1 C:\path\to\export.xml" -ForegroundColor White
Write-Host ""
