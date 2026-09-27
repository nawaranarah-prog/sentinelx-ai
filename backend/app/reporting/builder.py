from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.assistant import answer_question
from app.api.deps import WorkspaceContext
from app.api.serializers import iso, technique_info
from app.detection.base import fmt_bytes
from app.models import (
    Detection,
    Event,
    Host,
    Incident,
    IncidentEvent,
    IncidentStatusHistory,
    IncidentTechnique,
    InvestigationNote,
    User,
)

REPORT_TITLES = {"incident": "Incident Report", "technical": "Technical Investigation Report",
                 "executive": "Executive Summary"}
AI_PROMPTS = {"incident": "What happened? Summarize the incident, its evidence and recommended next steps.",
              "technical": "Give me a technical incident report.",
              "executive": "Summarize this for a CISO."}
TIMELINE_LIMIT = {"incident": 60, "technical": 250, "executive": 0}


def build_report(db: Session, ctx: WorkspaceContext, incident: Incident, report_type: str,
                 include_ai: bool = True) -> dict:
    dets = db.query(Detection).filter_by(incident_id=incident.id).order_by(Detection.timestamp).all()
    techs = db.query(IncidentTechnique).filter_by(incident_id=incident.id).all()
    hosts = {h.hostname: h for h in db.query(Host).filter(Host.workspace_id == ctx.workspace_id,
                                                          Host.hostname.in_(incident.hosts or [""]))}
    assignee = db.get(User, incident.assigned_to_id) if incident.assigned_to_id else None
    limit = TIMELINE_LIMIT[report_type]
    timeline = []
    if limit:
        rows = db.scalars(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(
            IncidentEvent.incident_id == incident.id, IncidentEvent.role == "evidence").order_by(Event.timestamp)
            .limit(limit)).all()
        timeline = [{"event_uid": e.event_uid, "timestamp": iso(e.timestamp), "event_type": e.event_type,
                     "action": e.action, "status": e.status, "user": e.user, "host": e.host,
                     "source_ip": e.source_ip, "destination_ip": e.destination_ip,
                     "detail": (e.command or e.resource or e.process or "")[:300],
                     "bytes": e.bytes} for e in rows]
    recs: list[str] = [c["item"] for c in incident.checklist or [] if not c.get("done")]
    for d in dets:
        for r in d.recommendations or []:
            if r not in recs:
                recs.append(r)
    exfil = sum(int((d.evidence_summary or {}).get("total_bytes") or 0) for d in dets if d.rule_key == "SX-009")
    files = sorted({f for d in dets if d.rule_key == "SX-008" for f in (d.evidence_summary or {}).get("files", [])})
    ai = None
    if include_ai:
        ans = answer_question(db, ctx, AI_PROMPTS[report_type], incident)
        ai = {"mode": ans["mode"], "provider": ans["provider"], "model": ans["model"], "markdown": ans["markdown"],
              "notices": ans["structured"].get("notices", []), "validation": ans["validation"]}
    content = {
        "title": f"{REPORT_TITLES[report_type]} — {incident.number}",
        "report_type": report_type, "generated_by": ctx.user.email, "workspace": ctx.workspace.name,
        "synthetic_data": ctx.workspace.mode == "DEMO",
        "incident": {"number": incident.number, "title": incident.title, "status": incident.status,
                     "severity": incident.severity, "confidence": incident.confidence,
                     "risk_score": incident.risk_score, "risk_band": incident.risk_band,
                     "first_seen": iso(incident.first_seen), "last_seen": iso(incident.last_seen),
                     "created_at": iso(incident.created_at), "assigned_to": assignee.email if assignee else None,
                     "stages": incident.stages, "tags": incident.tags},
        "summary": incident.summary, "correlation_reason": incident.correlation_reason,
        "impact": {"external_bytes": exfil, "external_bytes_human": fmt_bytes(exfil) if exfil else None,
                   "sensitive_files": files[:100], "privilege_escalation": any(d.rule_key == "SX-004" for d in dets)},
        "affected_assets": {"users": incident.users, "source_ips": incident.source_ips,
                            "destination_ips": incident.destination_ips,
                            "hosts": [{"hostname": h, "criticality": hosts[h].criticality if h in hosts else "unknown"}
                                      for h in incident.hosts]},
        "detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity,
                        "confidence": d.confidence, "timestamp": iso(d.timestamp), "stage": d.stage,
                        "explanation": d.explanation if report_type != "executive" else None,
                        "evidence_event_uids": (d.evidence_summary or {}).get("event_uids", [])[:10]} for d in dets],
        "techniques": [{**{k: technique_info(t.technique_id)[k] for k in ("id", "name", "tactic", "url")},
                        "reason": t.reason if report_type != "executive" else None,
                        "mapping_confidence": t.mapping_confidence} for t in techs],
        "risk": {"score": incident.risk_score, "band": incident.risk_band, "factors": incident.risk_factors,
                 "disclaimer": "SentinelX Risk Score is a transparent additive heuristic (0-100), not an industry "
                               "standard and not a probability."},
        "anomalies": incident.anomaly_summary if report_type != "executive" else
        {"anomalous_windows": (incident.anomaly_summary or {}).get("anomalous_windows", 0)},
        "timeline": timeline,
        "recommendations": recs[: (5 if report_type == "executive" else 15)],
        "ai_summary": ai,
    }
    if report_type == "technical":
        notes = db.query(InvestigationNote).filter_by(incident_id=incident.id).order_by(InvestigationNote.id).all()
        history = db.query(IncidentStatusHistory).filter_by(incident_id=incident.id).order_by(IncidentStatusHistory.id).all()
        authors = {u.id: u.email for u in db.query(User).filter(User.id.in_({n.author_id for n in notes} | {h.changed_by_id for h in history}))}
        content["notes"] = [{"author": authors.get(n.author_id, "unknown"), "kind": n.kind, "body": n.body,
                             "created_at": iso(n.created_at)} for n in notes]
        content["status_history"] = [{"from": h.from_status, "to": h.to_status, "by": authors.get(h.changed_by_id, "system"),
                                      "note": h.note, "at": iso(h.changed_at)} for h in history]
    return content
