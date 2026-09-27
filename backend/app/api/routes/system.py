import time

import sklearn
from fastapi import APIRouter, Depends
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app import __version__
from app.ai.providers import provider_status
from app.api.deps import AdminCtx, ReadCtx, WorkspaceContext
from app.api.serializers import iso
from app.core.config import get_settings
from app.database import session as dbs
from app.database.session import get_db
from app.detection.rules import RULE_IMPLEMENTATIONS
from app.models import DetectionRule, KnowledgeChunk, KnowledgeDocument, ThreatIndicator

router = APIRouter(prefix="/api", tags=["health & system"])


@router.get("/health/live")
def live():
    """Liveness probe (no auth, no dependencies)."""
    return {"status": "ok", "version": __version__, "database_persistent": not get_settings().database_is_ephemeral}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)):
    """Readiness probe: verifies database connectivity."""
    db.execute(text("SELECT 1"))
    return {"status": "ok"}


def _component(name: str, status: str, detail: str, **extra) -> dict:
    return {"name": name, "status": status, "detail": detail, **extra}


@router.get("/system/health")
def health(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    settings = get_settings()
    comps = []
    t0 = time.perf_counter()
    try:
        db.execute(text("SELECT 1"))
        latency = round((time.perf_counter() - t0) * 1000, 1)
        dialect = dbs.engine.dialect.name
        if dialect == "postgresql":
            comps.append(_component("Database", "CONNECTED", f"PostgreSQL reachable ({latency} ms)", dialect=dialect))
        elif settings.database_is_ephemeral:
            comps.append(_component("Database", "DEGRADED", "EPHEMERAL SQLite in /tmp on a serverless function: data "
                                    "resets when the instance restarts. PostgreSQL: NOT CONFIGURED (set DATABASE_URL).",
                                    dialect=dialect))
        else:
            comps.append(_component("Database", "DEGRADED", f"SQLite fallback in use ({latency} ms). PostgreSQL: NOT "
                                    "CONFIGURED. Suitable for local development only.", dialect=dialect))
    except Exception as exc:  # report, never fake health
        comps.append(_component("Database", "ERROR", f"Database check failed ({type(exc).__name__})"))
    ws = ctx.workspace
    stats = ws.last_pipeline_stats or {}
    rules = db.query(DetectionRule).filter_by(workspace_id=ws.id).all()
    enabled = [r for r in rules if r.enabled]
    missing = [r.rule_key for r in rules if r.rule_key not in RULE_IMPLEMENTATIONS]
    if missing:
        comps.append(_component("Detection Engine", "ERROR", f"Rules without implementation: {', '.join(missing)}"))
    elif stats.get("rule_errors"):
        comps.append(_component("Detection Engine", "DEGRADED", f"Last run had rule errors: {stats['rule_errors']}"))
    else:
        comps.append(_component("Detection Engine", "CONNECTED", f"{len(enabled)}/{len(rules)} rules enabled; last run "
                                f"{iso(ws.last_pipeline_run_at) or 'never'} scanned {stats.get('events_scanned', 0)} events."))
    comps.append(_component("Correlation Engine", "CONNECTED" if ws.last_pipeline_run_at else "NOT CONFIGURED",
                            f"Last run created {stats.get('incidents_created', 0)} and updated {stats.get('incidents_updated', 0)} "
                            "incident(s)." if ws.last_pipeline_run_at else "No data has been analysed in this workspace yet."))
    if not ws.last_pipeline_run_at:
        comps.append(_component("ML Engine", "NOT CONFIGURED", f"scikit-learn {sklearn.__version__} loaded; no analysis run yet."))
    elif stats.get("isolation_forest_used"):
        comps.append(_component("ML Engine", "CONNECTED", f"IsolationForest (scikit-learn {sklearn.__version__}) scored "
                                f"{stats.get('anomaly_windows', 0)} entity-day windows; {stats.get('anomalies_flagged', 0)} anomalous."))
    else:
        comps.append(_component("ML Engine", "DEGRADED", "Statistical baseline only: " + "; ".join(stats.get("anomaly_notes") or ["population too small"])))
    ai = provider_status()
    comps.append(_component("AI Provider", ai["status"], ai["detail"], mode=ai["mode"], label=ai["label"],
                            model=ai.get("model")))
    docs = db.query(func.count(KnowledgeDocument.id)).filter_by(workspace_id=ws.id).scalar()
    chunks = db.query(func.count(KnowledgeChunk.id)).filter_by(workspace_id=ws.id).scalar()
    comps.append(_component("RAG", "CONNECTED" if chunks else "NOT CONFIGURED",
                            f"{docs} document(s), {chunks} indexed chunk(s); local hashing embeddings."))
    synth = db.query(func.count(ThreatIndicator.id)).filter_by(workspace_id=ws.id, is_synthetic=True).scalar()
    local = db.query(func.count(ThreatIndicator.id)).filter_by(workspace_id=ws.id, is_synthetic=False).scalar()
    ti_detail = f"{synth} synthetic demo indicator(s), {local} analyst indicator(s). External providers: NOT CONFIGURED."
    comps.append(_component("Threat Intelligence", "CONNECTED" if (synth or local) else "NOT CONFIGURED", ti_detail,
                            label="SYNTHETIC / DEMO INTELLIGENCE" if synth and not local else None))
    comps.insert(0, _component("Backend", "CONNECTED", f"SentinelX API {__version__} ({settings.environment})"))
    return {"components": comps, "checked_at": iso(dbs.utcnow())}


@router.get("/system/config")
def config(ctx: WorkspaceContext = AdminCtx):
    s = get_settings()
    return {
        "environment": s.environment, "version": __version__, "database_dialect": dbs.engine.dialect.name,
        "llm_provider": s.llm_provider, "llm_model": s.effective_llm_model or None, "llm_configured": s.llm_configured,
        "llm_api_key": "configured (hidden)" if s.llm_api_key else "not set", "llm_timeout_seconds": s.llm_timeout_seconds,
        "llm_max_tool_rounds": s.llm_max_tool_rounds, "cors_origins": s.cors_origin_list,
        "max_upload_mb": s.max_upload_mb, "max_upload_rows": s.max_upload_rows,
        "rate_limits_per_minute": {"auth": s.rate_limit_auth_per_minute, "ai": s.rate_limit_ai_per_minute,
                                   "upload": s.rate_limit_upload_per_minute},
        "allow_registration": s.allow_registration, "access_token_expire_minutes": s.access_token_expire_minutes,
        "cookie_secure": s.cookie_secure, "ai_context_max_events": s.ai_context_max_events,
        "ai_context_max_chars": s.ai_context_max_chars, "secret_key": "configured (hidden)",
        "workspace_settings": ctx.workspace.settings,
    }
