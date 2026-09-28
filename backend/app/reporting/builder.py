from sqlalchemy import select
from sqlalchemy.orm import Session

from app.analysis.entities import unknown_unknowns
from app.analysis.investigations import memory_for
from app.api.serializers import iso, technique_info
from app.detection.base import fmt_bytes
from app.models import (
    AuditLog,
    Detection,
    Event,
    Host,
    Incident,
    IncidentEvent,
    IncidentStatusHistory,
    IncidentTechnique,
    InvestigationNote,
    User,
    Workspace,
)

REPORT_TITLES = {"incident": "Incident Report", "technical": "Technical Investigation Report",
                 "executive": "Executive Summary"}
TIMELINE_LIMIT = {"incident": 60, "technical": 250, "executive": 0}


def build_report(db: Session, workspace: Workspace, user_id: int, incident: Incident, report_type: str,
                 ai_narrative: dict | None = None) -> dict:
    """Report content from the incident's stored data. `ai_narrative` is included only when a model wrote it."""
    author = db.get(User, user_id)
    dets = db.query(Detection).filter_by(incident_id=incident.id).order_by(Detection.timestamp).all()
    techs = db.query(IncidentTechnique).filter_by(incident_id=incident.id).all()
    hosts = {h.hostname: h for h in db.query(Host).filter(Host.workspace_id == workspace.id,
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
                     "detail": (e.command or e.resource or e.process or "")[:300], "bytes": e.bytes} for e in rows]
    recs: list[str] = [c["item"] for c in incident.checklist or [] if not c.get("done")]
    for d in dets:
        for r in d.recommendations or []:
            if r not in recs:
                recs.append(r)
    exfil = sum(int((d.evidence_summary or {}).get("total_bytes") or 0) for d in dets if d.rule_key == "SX-009")
    files = sorted({f for d in dets if d.rule_key == "SX-008" for f in (d.evidence_summary or {}).get("files", [])})
    memory = memory_for(db, workspace.id, incident.id, limit=60)
    findings = {k: [m for m in memory if m["kind"] == k] for k in ("fact", "hypothesis", "conclusion", "question")}
    missing = [f["detail"] + f" ({f['entity']})" for f in unknown_unknowns(db, workspace.id)
               if f["type"] == "missing_telemetry" and f["entity"] in (incident.hosts or [])]
    uncertainty = [f"{t.technique_id} mapping confidence is {t.mapping_confidence}." for t in techs
                   if t.mapping_confidence in ("low", "medium")]
    uncertainty += [f"Missing telemetry: {m}" for m in missing]
    uncertainty += [f"Hypothesis with contradicting evidence: {h['text']}" for h in findings["hypothesis"] if h["contradicting"]]
    uncertainty.append("Only telemetry ingested into SentinelX was analysed; systems that do not send logs are not visible.")
    audit = db.query(AuditLog).filter(AuditLog.workspace_id == workspace.id, AuditLog.target_type == "incident",
                                      AuditLog.target_id == str(incident.id)).order_by(AuditLog.id).limit(80).all()
    method = [
        "Telemetry normalised to the SentinelX event schema and evaluated by rule-based detections (explanations "
        "generated from the matching events).",
        "Behavioral anomalies scored with a statistical baseline and a scikit-learn Isolation Forest.",
        "Related detections correlated by shared user, host or IP within the workspace correlation window.",
        "ATT&CK techniques mapped only when a detection's evidence supports the mapping.",
        "SentinelX Risk Score: transparent additive heuristic (0-100), not an industry standard or a probability.",
    ]
    if ai_narrative:
        method.append(f"Narrative section written by a language model ({ai_narrative['model']} via "
                      f"{ai_narrative['provider']}) using read-only SentinelX tools; every cited identifier was "
                      "verified against the database.")
    content = {
        "title": f"{REPORT_TITLES[report_type]} — {incident.number}",
        "report_type": report_type, "generated_by": author.email if author else "", "workspace": workspace.name,
        "synthetic_data": workspace.mode == "DEMO",
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
        "attack_dna": {k: (incident.dna or {}).get(k) for k in ("signature", "traits")} if incident.dna else None,
        "timeline": timeline,
        "findings": {k: [{"text": m["text"], "status": m["status"], "supporting": m["supporting"],
                          "contradicting": m["contradicting"], "source": m["source"], "investigation": m["investigation"]}
                         for m in v] for k, v in findings.items()},
        "uncertainty": uncertainty,
        "recommendations": recs[: (5 if report_type == "executive" else 15)],
        "analysis_method": method,
        "ai_summary": ai_narrative,
    }
    if report_type == "technical":
        notes = db.query(InvestigationNote).filter_by(incident_id=incident.id).order_by(InvestigationNote.id).all()
        history = db.query(IncidentStatusHistory).filter_by(incident_id=incident.id).order_by(IncidentStatusHistory.id).all()
        ids = {n.author_id for n in notes} | {h.changed_by_id for h in history}
        authors = {u.id: u.email for u in db.query(User).filter(User.id.in_(ids))} if ids else {}
        content["notes"] = [{"author": authors.get(n.author_id, "unknown"), "kind": n.kind, "body": n.body,
                             "created_at": iso(n.created_at)} for n in notes]
        content["status_history"] = [{"from": h.from_status, "to": h.to_status, "by": authors.get(h.changed_by_id, "system"),
                                      "note": h.note, "at": iso(h.changed_at)} for h in history]
        content["audit_history"] = [{"action": a.action, "user": a.user_email, "at": iso(a.created_at)} for a in audit]
    return content
