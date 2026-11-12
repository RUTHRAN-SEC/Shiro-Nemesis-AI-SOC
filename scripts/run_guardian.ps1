# Start Guardian on the ASUS laptop.   scripts\run_guardian.ps1
Set-Location (Join-Path $PSScriptRoot "..")
.\.venv\Scripts\python.exe -m guardian.main
