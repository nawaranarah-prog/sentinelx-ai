"""The SentinelX processing pipeline:
UPLOAD → VALIDATE → NORMALIZE → STORE → DETECT → ANOMALY ANALYSIS → CORRELATE → INCIDENTS (+ MITRE, risk).
"""

import logging
import re
import threading
from collections import defaultdict
from time import perf_counter

from sqlalchemy import func, insert, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.correlation.engine import correlate
from app.database import session as dbs
from app.database.session import utcnow
from app.detection.engine import load_events, run_detection
from app.ingestion.normalizer import NormalizedRow
from app.ingestion.parser import FileRejected, parse_upload
from app.ml.anomaly import run_anomaly_detection
from app.models import Asset, Event, Host, IngestionJob, Workspace
from app.services.notifications import notify_workspace

log = logging.getLogger(__name__)
_locks: dict[int, threading.Lock] = defaultdict(threading.Lock)
_locks_guard = threading.Lock()
INSERT_BATCH = 2000


def workspace_lock(workspace_id: int) -> threading.Lock:
    with _locks_guard:
        return _locks[workspace_id]


def store_events(db: Session, workspace_id: int, rows: list[NormalizedRow], job: IngestionJob | None = None,
                 source_label: str | None = None) -> tuple[int, int]:
    """Insert normalized rows, skipping events whose fingerprint already exists in the workspace."""
    fps = [r.fingerprint for r in rows]
    existing: set[str] = set()
    for i in range(0, len(fps), 1000):
        existing.update(db.scalars(select(Event.fingerprint).where(
            Event.workspace_id == workspace_id, Event.fingerprint.in_(fps[i:i + 1000]))))
    now = utcnow()
    payload, duplicates = [], 0
    for r in rows:
        if r.fingerprint in existing:
            duplicates += 1
            continue
        existing.add(r.fingerprint)
        f = r.fields
        payload.append({
            "workspace_id": workspace_id, "ingestion_job_id": job.id if job else None,
            "event_uid": f["event_uid"], "fingerprint": r.fingerprint, "timestamp": f["timestamp"],
            "event_type": f["event_type"], "user": f["user"], "source_ip": f["source_ip"],
            "destination_ip": f["destination_ip"], "host": f["host"], "process": f["process"],
            "command": f["command"], "action": f["action"], "status": f["status"], "severity": f["severity"],
            "bytes": f["bytes"], "resource": f["resource"], "source": f["source"] or source_label,
            "event_metadata": f["metadata"], "raw": r.raw, "ingested_at": now,
        })
    for i in range(0, len(payload), INSERT_BATCH):
        db.execute(insert(Event), payload[i:i + INSERT_BATCH])
        if job is not None:
            job.processed_rows = min(len(rows), i + INSERT_BATCH + duplicates)
            db.commit()
    return len(payload), duplicates


_CRITICAL_HOST = re.compile(r"\b(dc|pdc|ad|ntds)\d*\b|-dc\d*|dc\d+|swift|core|pay", re.I)
_HIGH_HOST = re.compile(r"sql|db|fs\d*|file|exch|mail|fin|vpn|jump|backup|bkp|web|app", re.I)
_SENSITIVE_ASSET = re.compile(r"finance|treasury|payroll|hr|customer|swift|confidential|restricted|board|legal", re.I)


def infer_host_criticality(hostname: str) -> tuple[str, str]:
    if _CRITICAL_HOST.search(hostname):
        return "critical", "domain controller / core banking naming"
    if _HIGH_HOST.search(hostname):
        return "high", "server role naming (database, file, mail, VPN, jump, web)"
    return "medium", "workstation or unclassified"


def update_inventory(db: Session, workspace_id: int) -> None:
    rows = db.execute(select(Event.host, func.min(Event.timestamp), func.max(Event.timestamp), func.count())
                      .where(Event.workspace_id == workspace_id, Event.host.is_not(None))
                      .group_by(Event.host)).all()
    hosts = {h.hostname: h for h in db.query(Host).filter_by(workspace_id=workspace_id)}
    for hostname, first, last, count in rows:
        h = hosts.get(hostname)
        if h is None:
            crit, why = infer_host_criticality(hostname)
            h = Host(workspace_id=workspace_id, hostname=hostname, criticality=crit, role_hint=why[:64])
            db.add(h)
        h.first_seen, h.last_seen, h.event_count = first, last, count
    shares = db.execute(select(Event.resource).where(Event.workspace_id == workspace_id,
                                                     Event.resource.like("\\\\%")).distinct().limit(5000)).scalars()
    assets = {a.name for a in db.query(Asset.name).filter_by(workspace_id=workspace_id)}
    for res in shares:
        parts = [p for p in res.split("\\") if p]
        if len(parts) < 2:
            continue
        name = "\\\\" + parts[0] + "\\" + parts[1]
        if name in assets:
            continue
        assets.add(name)
        sensitive = bool(_SENSITIVE_ASSET.search(name))
        db.add(Asset(workspace_id=workspace_id, name=name[:255], asset_type="file_share",
                     criticality="high" if sensitive else "medium",
                     description="Network share observed in telemetry" + (" (name suggests sensitive data)" if sensitive else "")))
    db.flush()


def run_pipeline(db: Session, workspace: Workspace, job: IngestionJob | None = None) -> dict:
    """Run detection → anomaly → correlation over the workspace. Caller commits."""
    t0 = perf_counter()

    def stage(name: str) -> None:
        if job is not None:
            job.stage = name
            db.commit()

    update_inventory(db, workspace.id)
    stage("DETECTING")
    events = load_events(db, workspace.id)
    det = run_detection(db, workspace, events)
    stage("ANOMALY_ANALYSIS")
    bh = (workspace.settings or {}).get("business_hours") or [7, 20]
    anomaly = run_anomaly_detection(db, workspace.id, events, (int(bh[0]), int(bh[1])),
                                    (workspace.settings or {}).get("anomaly_if_threshold"))
    stage("CORRELATING")
    corr = correlate(db, workspace)
    for d in det.new_detections:
        if d.severity == "critical":
            notify_workspace(db, workspace.id, "critical_detection", f"Critical detection: {d.title}",
                             d.explanation[:300], f"/detections/{d.id}", severity="critical")
    stats = {
        "events_scanned": det.events_scanned, "rules_run": det.rules_run,
        "detections_created": len(det.new_detections), "rule_errors": det.errors,
        "anomaly_windows": anomaly.windows, "anomalies_flagged": anomaly.flagged,
        "isolation_forest_used": anomaly.if_used, "anomaly_notes": anomaly.notes,
        "incidents_created": len(corr.new_incidents), "incidents_updated": len(corr.updated_incidents),
        "standalone_detections": corr.standalone_detections,
        "duration_ms": int((perf_counter() - t0) * 1000), "finished_at": utcnow().isoformat(),
    }
    workspace.last_pipeline_run_at = utcnow()
    workspace.last_pipeline_stats = stats
    return stats


def ingest_rows(db: Session, workspace: Workspace, rows: list[NormalizedRow], source_label: str,
                job: IngestionJob | None = None) -> dict:
    with workspace_lock(workspace.id):
        accepted, dups = store_events(db, workspace.id, rows, job, source_label)
        db.commit()
        stats = run_pipeline(db, workspace, job) if accepted else {
            "detections_created": 0, "incidents_created": 0, "incidents_updated": 0, "anomalies_flagged": 0,
            "note": "No new events were stored, so the analysis pipeline was not re-run."}
        db.commit()
    stats.update({"accepted": accepted, "duplicates": dups})
    return stats


def process_ingestion_job(job_id: int, filename: str, content: bytes) -> None:
    """Background task: parse, validate, normalize, store and analyze one uploaded file."""
    settings = get_settings()
    db = dbs.SessionLocal()
    try:
        job = db.get(IngestionJob, job_id)
        workspace = db.get(Workspace, job.workspace_id)
        job.status, job.stage, job.started_at = "RUNNING", "VALIDATING", utcnow()
        db.commit()
        try:
            parsed = parse_upload(filename, content, settings.max_upload_rows)
        except FileRejected as exc:
            job.status, job.stage, job.error_message, job.finished_at = "FAILED", "FAILED", str(exc), utcnow()
            notify_workspace(db, job.workspace_id, "ingestion_failed", f"Ingestion failed: {filename}", str(exc),
                             "/ingest", severity="medium", only_user_id=job.created_by_id)
            db.commit()
            return
        job.stage = "STORING"
        job.file_format = parsed.file_format
        job.total_rows = parsed.total_rows
        job.rejected_rows = parsed.rejected
        job.errors = parsed.errors
        job.warnings = parsed.warnings
        job.field_mapping = parsed.field_mapping
        db.commit()
        stats = ingest_rows(db, workspace, parsed.rows, source_label=f"upload:{filename[:40]}", job=job)
        job.accepted_rows = stats["accepted"]
        job.duplicate_rows = stats["duplicates"] + parsed.duplicates_in_file
        job.processed_rows = parsed.total_rows
        job.detections_created = stats.get("detections_created", 0)
        job.incidents_created = stats.get("incidents_created", 0)
        job.incidents_updated = stats.get("incidents_updated", 0)
        job.anomalies_flagged = stats.get("anomalies_flagged", 0)
        job.status = "COMPLETED" if job.rejected_rows == 0 else "COMPLETED_WITH_ERRORS"
        if not parsed.rows and not parsed.duplicates_in_file:
            job.status = "FAILED"
            job.error_message = "No valid rows: every row was rejected during validation."
        job.stage = "DONE" if job.status != "FAILED" else "FAILED"
        job.finished_at = utcnow()
        if job.status == "FAILED":
            notify_workspace(db, job.workspace_id, "ingestion_failed", f"Ingestion failed: {filename}",
                             job.error_message or "", "/ingest", severity="medium", only_user_id=job.created_by_id)
        else:
            notify_workspace(db, job.workspace_id, "ingestion_complete", f"Ingestion complete: {filename}",
                             f"{job.accepted_rows} events stored, {job.rejected_rows} rejected, "
                             f"{job.detections_created} detections, {job.incidents_created} new incidents.",
                             "/ingest", only_user_id=job.created_by_id)
        db.commit()
    except Exception:
        log.exception("Ingestion job %s failed", job_id)
        db.rollback()
        job = db.get(IngestionJob, job_id)
        if job:
            job.status, job.stage, job.finished_at = "FAILED", "FAILED", utcnow()
            job.error_message = "Internal processing error. The failure was logged for administrators."
            db.commit()
    finally:
        db.close()
