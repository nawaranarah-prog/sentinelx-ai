import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.session import utcnow
from app.detection.base import Ev, RuleContext
from app.detection.catalog import DEFAULT_RULES
from app.detection.rules import RULE_IMPLEMENTATIONS
from app.models import Detection, DetectionEvent, DetectionRule, Event, ThreatIndicator, Workspace

log = logging.getLogger(__name__)
MAX_EVIDENCE_LINKS = 500


@dataclass
class DetectionRunResult:
    new_detections: list[Detection] = field(default_factory=list)
    rules_run: int = 0
    events_scanned: int = 0
    errors: list[str] = field(default_factory=list)


def ensure_default_rules(db: Session, workspace_id: int) -> None:
    existing = {r.rule_key for r in db.query(DetectionRule).filter_by(workspace_id=workspace_id)}
    for spec in DEFAULT_RULES:
        if spec["rule_key"] not in existing:
            db.add(DetectionRule(workspace_id=workspace_id, **spec))
    db.flush()


def load_events(db: Session, workspace_id: int) -> list[Ev]:
    cols = (Event.id, Event.event_uid, Event.timestamp, Event.event_type, Event.user, Event.source_ip,
            Event.destination_ip, Event.host, Event.process, Event.command, Event.action, Event.status,
            Event.bytes, Event.resource, Event.event_metadata)
    rows = db.execute(select(*cols).where(Event.workspace_id == workspace_id).order_by(Event.timestamp, Event.id))
    return [Ev(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14] or {})
            for r in rows]


def build_context(db: Session, workspace: Workspace, events: list[Ev]) -> RuleContext:
    settings = workspace.settings or {}
    bh = settings.get("business_hours") or [7, 20]
    indicators = [
        {"value": i.value, "type": i.indicator_type, "source": i.source, "confidence": i.confidence,
         "severity": i.severity, "description": i.description, "is_synthetic": i.is_synthetic}
        for i in db.query(ThreatIndicator).filter_by(workspace_id=workspace.id, active=True)
    ]
    priv_users = {e.user for e in events if e.user and e.meta.get("privileged_logon")}
    return RuleContext(business_hours=(int(bh[0]), int(bh[1])), indicators=indicators,
                       privileged_logon_users=priv_users)


def run_detection(db: Session, workspace: Workspace, events: list[Ev] | None = None) -> DetectionRunResult:
    result = DetectionRunResult()
    ensure_default_rules(db, workspace.id)
    if events is None:
        events = load_events(db, workspace.id)
    result.events_scanned = len(events)
    if not events:
        return result
    ctx = build_context(db, workspace, events)
    rules = db.query(DetectionRule).filter_by(workspace_id=workspace.id, enabled=True).all()
    existing_keys = set(db.scalars(select(Detection.dedupe_key).where(Detection.workspace_id == workspace.id)))
    for rule in rules:
        impl = RULE_IMPLEMENTATIONS.get(rule.rule_key)
        if impl is None:
            continue
        result.rules_run += 1
        try:
            candidates = impl(events, rule.parameters or {}, ctx)
        except Exception as exc:  # a faulty rule must not stop the pipeline
            log.exception("Rule %s failed", rule.rule_key)
            result.errors.append(f"{rule.rule_key}: {type(exc).__name__}")
            continue
        for c in candidates:
            if c.dedupe_key in existing_keys:
                continue
            existing_keys.add(c.dedupe_key)
            det = Detection(
                workspace_id=workspace.id, rule_id=rule.id, rule_key=c.rule_key, dedupe_key=c.dedupe_key[:255],
                title=c.title[:255], description=rule.description, severity=c.severity, confidence=c.confidence,
                timestamp=c.ts, last_seen=c.last_seen, user=c.user, host=c.host, source_ip=c.source_ip,
                destination_ip=c.destination_ip, explanation=c.explanation,
                evidence_summary={**c.evidence_summary, "event_count": len(c.events),
                                  "event_uids": [e.uid for e in c.events[:MAX_EVIDENCE_LINKS]]},
                mitre=c.mitre, false_positives=c.false_positives, recommendations=c.recommendations,
                stage=c.stage, created_at=utcnow(),
            )
            db.add(det)
            db.flush()
            seen = set()
            for e in c.events[:MAX_EVIDENCE_LINKS]:
                if e.id not in seen:
                    seen.add(e.id)
                    db.add(DetectionEvent(detection_id=det.id, event_id=e.id))
            result.new_detections.append(det)
    db.flush()
    return result
