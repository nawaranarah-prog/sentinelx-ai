"""Vercel Python function entrypoint: serves the SentinelX FastAPI app under /api/*."""

import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
os.environ.setdefault("AUTO_MIGRATE", "true")

from app.main import app  # noqa: E402

log = logging.getLogger("sentinelx.vercel")

# Cold start: make sure the schema and reference data exist before the first request.
try:
    from app.core.config import get_settings
    from app.database import session as dbs
    from app.services.workspace import bootstrap_reference_data

    if get_settings().auto_migrate:
        from app.database.migrate import upgrade_to_head

        upgrade_to_head()
    _db = dbs.SessionLocal()
    try:
        bootstrap_reference_data(_db)
    finally:
        _db.close()
except Exception:  # surfaced through /api/system/health and request errors, never swallowed silently
    log.exception("SentinelX cold-start initialisation failed")

__all__ = ["app"]
