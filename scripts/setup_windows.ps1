# One-time setup for the ASUS Windows laptop (Guardian).
# Run in PowerShell from the project folder:
#     powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "==> Checking Python"
python --version

Write-Host "==> Creating virtual environment (.venv)"
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --quiet --upgrade pip
Write-Host "==> Installing packages (FastAPI, Uvicorn, winotify)"
.\.venv\Scripts\python.exe -m pip install --quiet -r requirements-windows.txt

if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Write-Host "==> Created .env from .env.example (edit it with: notepad .env)"
} else {
    Write-Host "==> .env already exists - leaving it alone"
}
New-Item -ItemType Directory -Force -Path data | Out-Null

Write-Host ""
Write-Host "Done. Next steps:"
Write-Host "  1) .\.venv\Scripts\python.exe scripts\generate_token.py   (copy the result)"
Write-Host "  2) notepad .env     (paste SN_TOKEN=...)"
Write-Host "  3) Run PowerShell AS ADMINISTRATOR:  scripts\open_firewall_windows.ps1 -UbuntuIp 192.168.1.9"
Write-Host "  4) scripts\run_guardian.ps1"
