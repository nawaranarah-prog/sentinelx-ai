# Run SentinelX locally on Windows without Docker (SQLite development database unless DATABASE_URL is set).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Set-Location "$root\backend"
if (-not (Test-Path .venv)) { python -m venv .venv }
& .venv\Scripts\pip.exe install -q -r requirements.txt
if (-not $env:DATABASE_URL) { $env:DATABASE_URL = "sqlite:///./sentinelx.db" }
if (-not $env:SECRET_KEY) { $env:SECRET_KEY = "dev-only-secret-change-me-0123456789" }
& .venv\Scripts\alembic.exe upgrade head
$api = Start-Process -PassThru -NoNewWindow .venv\Scripts\python.exe -ArgumentList "-m", "uvicorn", "app.main:app", "--port", "8000"

try {
    Set-Location "$root\frontend"
    if (-not (Test-Path node_modules)) { npm install }
    npm run dev
} finally {
    Stop-Process -Id $api.Id -ErrorAction SilentlyContinue
}
