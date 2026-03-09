# BurpMD Parser Pro — Windows Run Helper
# Automatically activates the venv and runs burpmd with recommended settings.
#
# Usage:
#   .\run.ps1 <burp_export.xml> [output_folder]
#
# Examples:
#   .\run.ps1 C:\exports\burp_items.xml
#   .\run.ps1 C:\exports\burp_items.xml C:\my-audit\burpexplore
#   .\run.ps1 .\exports\burp_items.xml .\output

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$XmlFile,

    [Parameter(Position=1)]
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

# --- Validate input ---
if (-not (Test-Path $XmlFile)) {
    Write-Host "[ERROR] XML file not found: $XmlFile" -ForegroundColor Red
    exit 1
}

# --- Default output dir ---
if (-not $OutputDir) {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($XmlFile)
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputDir = Join-Path $PSScriptRoot "output\${baseName}_${timestamp}"
}

# --- Activate venv if present ---
$venvActivate = Join-Path $PSScriptRoot ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    & $venvActivate
}

# --- Run burpmd ---
Write-Host ""
Write-Host "=== BurpMD Parser Pro ===" -ForegroundColor Cyan
Write-Host "  Input:  $XmlFile" -ForegroundColor White
Write-Host "  Output: $OutputDir" -ForegroundColor White
Write-Host ""

$burpmdArgs = @(
    $XmlFile,
    "-o", $OutputDir,
    "--sitemap",
    "--full-analysis",
    "--dedupe",
    "-v"
)

try {
    burpmd @burpmdArgs
} catch {
    Write-Host "[*] 'burpmd' not in PATH, trying python -m burpmd ..." -ForegroundColor Yellow
    python -m burpmd @burpmdArgs
}

Write-Host ""
Write-Host "=== Export Complete ===" -ForegroundColor Green
Write-Host "Output: $OutputDir" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Open output folder in VS Code:  code `"$OutputDir`"" -ForegroundColor White
Write-Host "  2. Open AI_ANALYSIS_PROMPTS.md in Copilot Chat" -ForegroundColor White
Write-Host "  3. Follow the phased analysis plan" -ForegroundColor White
Write-Host ""
