"""Data quality and pipeline observability, measured from stored events and ingestion jobs."""

from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Detection, Event, Incident, IngestionJob, Workspace

FIELDS = ("user", "host", "source_ip", "destination_ip", "process", "command", "action", "status", "bytes", "resource")
EXPECTED = {
    "authentication": ("user", "host", "source_ip", "status"),
    "process": ("user", "host", "process", "command"),
    "file": ("user", "host", "resource"),
    "network": ("host", "destination_ip", "bytes"),
    "privilege": ("user", "host", "resource"),
}


def data_quality(db: Session, ws: int) -> dict:
    total = db.scalar(select(func.count(Event.id)).where(Event.workspace_id == ws)) or 0
    if not total:
        return {"events": 0, "note": "No telemetry."}
    by_type = dict(db.execute(select(Event.event_type, func.count()).where(Event.workspace_id == ws)
                              .group_by(Event.event_type)).all())
    completeness = []
    for etype, fields in EXPECTED.items():
        n = by_type.get(etype, 0)
        if not n:
            continue
        for f in fields:
            col = getattr(Event, f)
            present = db.scalar(select(func.count()).where(Event.workspace_id == ws, Event.event_type == etype,
                                                           col.is_not(None))) or 0
            completeness.append({"event_type": etype, "field": f, "present": present, "total": n,
                                 "pct": round(present / n * 100, 1)})
    jobs = db.query(IngestionJob).filter_by(workspace_id=ws).all()
    rejected = sum(j.rejected_rows for j in jobs)
    dupes = sum(j.duplicate_rows for j in jobs)
    warnings = Counter()
    for j in jobs:
        for w in j.warnings or []:
            for msg in w.get("warnings", []):
                warnings[msg.split(":")[0]] += 1
    errors = Counter()
    for j in jobs:
        for e in j.errors or []:
            errors[e.get("error", "")[:60]] += 1
    rng = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp)).where(Event.workspace_id == ws)).one()
    hours = Counter(ts.replace(minute=0, second=0, microsecond=0) for (ts,) in
                    db.execute(select(Event.timestamp).where(Event.workspace_id == ws)))
    span_hours = int((rng[1] - rng[0]).total_seconds() // 3600) + 1 if rng[0] else 0
    silent = span_hours - len(hours)
    issues = [c for c in completeness if c["pct"] < 90]
    return {
        "events": total, "by_event_type": by_type, "unclassified_events": by_type.get("other", 0),
        "field_completeness": completeness, "low_completeness": issues,
        "rejected_rows": rejected, "duplicate_rows": dupes,
        "warning_types": [{"warning": k, "count": v} for k, v in warnings.most_common(10)],
        "rejection_reasons": [{"reason": k, "count": v} for k, v in errors.most_common(10)],
        "time_range": {"start": rng[0].isoformat() + "Z", "end": rng[1].isoformat() + "Z"},
        "hours_without_events": max(0, silent), "hours_in_range": span_hours,
    }


def pipeline_status(db: Session, workspace: Workspace) -> dict:
    ws = workspace.id
    jobs = db.query(IngestionJob).filter_by(workspace_id=ws).order_by(IngestionJob.id.desc()).limit(10).all()
    stats = workspace.last_pipeline_stats or {}
    events = db.scalar(select(func.count(Event.id)).where(Event.workspace_id == ws)) or 0
    dets = db.scalar(select(func.count(Detection.id)).where(Detection.workspace_id == ws)) or 0
    correlated = db.scalar(select(func.count(Detection.id)).where(Detection.workspace_id == ws,
                                                                  Detection.incident_id.is_not(None))) or 0
    incs = db.scalar(select(func.count(Incident.id)).where(Incident.workspace_id == ws)) or 0
    rows_in = sum(j.total_rows for j in jobs)
    return {
        "stages": [
            {"stage": "Ingest", "count": rows_in, "detail": f"rows received in the last {len(jobs)} upload(s)"},
            {"stage": "Parse", "count": rows_in - sum(j.rejected_rows for j in jobs), "detail": "rows parsed and validated"},
            {"stage": "Normalize", "count": sum(j.accepted_rows + j.duplicate_rows for j in jobs), "detail": "rows mapped to the event schema"},
            {"stage": "Store", "count": events, "detail": "events stored in the workspace (all sources)"},
            {"stage": "Enrich", "count": stats.get("graph_nodes", 0), "detail": "knowledge-graph nodes built from events"},
            {"stage": "Analyze", "count": stats.get("anomaly_windows", 0), "detail": "entity-day windows scored for anomalies"},
            {"stage": "Detect", "count": dets, "detail": "detections produced by rules"},
            {"stage": "Correlate", "count": correlated, "detail": "detections grouped into incidents"},
            {"stage": "Incident", "count": incs, "detail": "incidents"},
        ],
        "last_run": {**stats, "at": workspace.last_pipeline_run_at.isoformat() + "Z" if workspace.last_pipeline_run_at else None},
        "recent_jobs": [{"id": j.id, "filename": j.filename, "status": j.status, "rows": j.total_rows,
                         "accepted": j.accepted_rows, "rejected": j.rejected_rows, "timings_ms": j.stage_timings or {},
                         "created_at": j.created_at.isoformat() + "Z"} for j in jobs],
    }
