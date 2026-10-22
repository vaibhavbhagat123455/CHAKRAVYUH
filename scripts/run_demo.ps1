$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$python = Join-Path $root ".venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Virtual environment not found. Run .\scripts\setup.ps1 first."
}

$env:LOG_PATH = Join-Path $root "data\security_log.jsonl"
$env:DEMO_RESET_LOG = "1"
& $python -m ui.dashboard
