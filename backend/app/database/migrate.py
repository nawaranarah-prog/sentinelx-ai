"""Programmatic `alembic upgrade head`, used at startup when AUTO_MIGRATE=true (e.g. on serverless platforms)."""

from pathlib import Path

from alembic.config import Config
from sqlalchemy import text

from alembic import command
from app.database import session as dbs

BACKEND_DIR = Path(__file__).resolve().parents[2]
MIGRATION_LOCK_ID = 7263540001


def upgrade_to_head() -> None:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    with dbs.engine.connect() as conn:
        postgres = conn.dialect.name == "postgresql"
        if postgres:
            conn.execute(text("SELECT pg_advisory_lock(:id)"), {"id": MIGRATION_LOCK_ID})
        try:
            cfg.attributes["connection"] = conn
            command.upgrade(cfg, "head")
            conn.commit()
        finally:
            if postgres:
                conn.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": MIGRATION_LOCK_ID})
                conn.commit()
