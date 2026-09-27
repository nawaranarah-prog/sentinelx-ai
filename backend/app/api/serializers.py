"""Model → JSON-safe dict conversion shared by routes, the AI toolbox and reporting."""

from datetime import datetime

from app.mitre.catalog import TECHNIQUE_INDEX


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() + "Z" if dt else None


def event_brief(e) -> dict:
    return {
        "id": e.id, "event_uid": e.event_uid, "timestamp": iso(e.timestamp), "event_type": e.event_type,
        "user": e.user, "source_ip": e.source_ip, "destination_ip": e.destination_ip, "host": e.host,
        "process": e.process, "command": e.command, "action": e.action, "status": e.status,
        "severity": e.severity, "bytes": e.bytes, "resource": e.resource, "source": e.source,
    }


def event_full(e) -> dict:
    d = event_brief(e)
    d.update({"metadata": e.event_metadata or {}, "raw": e.raw or {}, "ingestion_job_id": e.ingestion_job_id,
              "ingested_at": iso(e.ingested_at), "fingerprint": e.fingerprint})
    return d


def technique_info(tid: str) -> dict:
    info = TECHNIQUE_INDEX.get(tid)
    return dict(info) if info else {"id": tid, "name": "Unknown technique", "tactic": "", "url": ""}


def detection_brief(d) -> dict:
    return {
        "id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity, "confidence": d.confidence,
        "timestamp": iso(d.timestamp), "last_seen": iso(d.last_seen), "user": d.user, "host": d.host,
        "source_ip": d.source_ip, "destination_ip": d.destination_ip, "stage": d.stage, "status": d.status,
        "incident_id": d.incident_id, "event_count": (d.evidence_summary or {}).get("event_count", 0),
        "mitre_ids": [m["id"] for m in d.mitre or []],
    }


def detection_full(d) -> dict:
    out = detection_brief(d)
    summary = dict(d.evidence_summary or {})
    out.update({
        "description": d.description, "explanation": d.explanation, "evidence_summary": summary,
        "evidence_event_uids": summary.get("event_uids", []),
        "mitre": [{**technique_info(m["id"]), "reason": m["reason"],
                   "mapping_confidence": m.get("mapping_confidence", "high")} for m in d.mitre or []],
        "false_positives": d.false_positives or [], "recommendations": d.recommendations or [],
        "created_at": iso(d.created_at),
    })
    return out


def incident_brief(i, assignee_email: str | None = None) -> dict:
    return {
        "id": i.id, "number": i.number, "title": i.title, "status": i.status, "severity": i.severity,
        "confidence": i.confidence, "risk_score": i.risk_score, "risk_band": i.risk_band,
        "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "users": i.users or [],
        "hosts": i.hosts or [], "source_ips": i.source_ips or [], "destination_ips": i.destination_ips or [],
        "stages": i.stages or [], "tags": i.tags or [], "assigned_to_id": i.assigned_to_id,
        "assigned_to": assignee_email, "created_at": iso(i.created_at), "updated_at": iso(i.updated_at),
        "origin": i.origin,
    }


def incident_full(i, assignee_email: str | None = None) -> dict:
    out = incident_brief(i, assignee_email)
    out.update({
        "summary": i.summary, "risk_factors": i.risk_factors or [], "correlation_reason": i.correlation_reason,
        "correlation_keys": i.correlation_keys or {}, "anomaly_summary": i.anomaly_summary or {},
        "checklist": i.checklist or [], "resolved_at": iso(i.resolved_at),
    })
    return out


def user_brief(u) -> dict:
    return {"id": u.id, "email": u.email, "full_name": u.full_name}
