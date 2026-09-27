#!/usr/bin/env sh
# Run SentinelX locally without Docker (SQLite development database unless DATABASE_URL is set).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT/backend"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/pip install -q -r requirements.txt
export DATABASE_URL="${DATABASE_URL:-sqlite:///./sentinelx.db}"
export SECRET_KEY="${SECRET_KEY:-dev-only-secret-change-me-0123456789}"
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --port 8000 &
API_PID=$!
trap 'kill $API_PID' EXIT

cd "$ROOT/frontend"
[ -d node_modules ] || npm install
npm run dev
