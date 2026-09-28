"""Structured investigation memory: facts, hypotheses (with supporting / contradicting evidence),
conclusions, notes and open questions — plus a scorecard computed from actual investigation state."""

from sqlalchemy.orm import Session

from app.database.session import utcnow
from app.models import Incident, IncidentEvent, Investigation, InvestigationItem

KINDS = ("fact", "hypothesis", "conclusion", "note", "question")
STATUSES = {"hypothesis": ("open", "supported", "refuted"), "question": ("open", "resolved"),
            "fact": ("open",), "conclusion": ("open",), "note": ("open",)}


def next_number(db: Session, ws: int) -> str:
    n = db.query(Investigation).filter_by(workspace_id=ws).count() + 1
    while db.query(Investigation).filter_by(workspace_id=ws, number=f"INV-{n:04d}").first():
        n += 1
    return f"INV-{n:04d}"


def create(db: Session, ws: int, user_id: int | None, title: str, incident: Incident | None = None,
           focus: dict | None = None) -> Investigation:
    inv = Investigation(workspace_id=ws, number=next_number(db, ws), title=title[:255],
                        incident_id=incident.id if incident else None, focus=focus or {}, created_by_id=user_id)
    db.add(inv)
    db.flush()
    return inv


def resolve(db: Session, ws: int, ref) -> Investigation | None:
    q = db.query(Investigation).filter(Investigation.workspace_id == ws)
    ref = str(ref).strip()
    if ref.upper().startswith("INV-"):
        return q.filter(Investigation.number == ref.upper()).first()
    return q.filter(Investigation.id == int(ref)).first() if ref.isdigit() else None


def add_item(db: Session, inv: Investigation, kind: str, text: str, *, source: str = "analyst",
             supporting: list | None = None, contradicting: list | None = None, status: str = "open",
             user_id: int | None = None) -> InvestigationItem:
    if kind not in KINDS:
        raise ValueError(f"kind must be one of {KINDS}")
    if status not in STATUSES[kind]:
        raise ValueError(f"status for {kind} must be one of {STATUSES[kind]}")
    item = InvestigationItem(investigation_id=inv.id, kind=kind, text=text[:4000], source=source, status=status,
                             supporting=[str(s)[:80] for s in supporting or []][:50],
                             contradicting=[str(s)[:80] for s in contradicting or []][:50], created_by_id=user_id)
    db.add(item)
    inv.updated_at = utcnow()
    db.flush()
    return item


def item_payload(i: InvestigationItem) -> dict:
    return {"id": i.id, "kind": i.kind, "text": i.text, "status": i.status, "supporting": i.supporting,
            "contradicting": i.contradicting, "source": i.source, "created_at": i.created_at.isoformat() + "Z"}


def payload(db: Session, inv: Investigation, with_items: bool = True) -> dict:
    items = db.query(InvestigationItem).filter_by(investigation_id=inv.id).order_by(InvestigationItem.id).all()
    inc = db.get(Incident, inv.incident_id) if inv.incident_id else None
    out = {"id": inv.id, "number": inv.number, "title": inv.title, "status": inv.status,
           "incident": {"id": inc.id, "number": inc.number, "title": inc.title} if inc else None,
           "focus": inv.focus, "scorecard": inv.scorecard, "created_at": inv.created_at.isoformat() + "Z",
           "updated_at": inv.updated_at.isoformat() + "Z",
           "counts": {k: sum(1 for i in items if i.kind == k) for k in KINDS}}
    if with_items:
        out["items"] = [item_payload(i) for i in items]
    return out


def memory_for(db: Session, ws: int, incident_id: int | None = None, limit: int = 40) -> list[dict]:
    """Prior analyst/AI conclusions, labeled as historical memory (not current evidence)."""
    q = db.query(InvestigationItem, Investigation).join(Investigation, Investigation.id == InvestigationItem.investigation_id)\
        .filter(Investigation.workspace_id == ws)
    if incident_id:
        q = q.filter(Investigation.incident_id == incident_id)
    rows = q.order_by(InvestigationItem.id.desc()).limit(limit).all()
    return [{**item_payload(i), "investigation": inv.number, "memory_type": "historical"} for i, inv in rows]


def scorecard(db: Session, inv: Investigation | None, reviewed_events: set[str], reviewed_entities: set[str],
              incident: Incident | None, missing_telemetry: list[str]) -> dict:
    items = db.query(InvestigationItem).filter_by(investigation_id=inv.id).all() if inv else []
    open_q = [i.text for i in items if i.kind == "question" and i.status == "open"]
    contradicting = sum(len(i.contradicting) for i in items if i.kind == "hypothesis")
    coverage = None
    if incident:
        from app.models import Event

        uids = {u for (u,) in db.query(Event.event_uid).join(IncidentEvent, IncidentEvent.event_id == Event.id)
                .filter(IncidentEvent.incident_id == incident.id, IncidentEvent.role == "evidence")}
        coverage = round(len(uids & reviewed_events) / len(uids), 2) if uids else None
    supported = sum(1 for i in items if i.kind == "hypothesis" and i.status == "supported")
    if coverage is not None and coverage >= 0.5 and not contradicting and supported:
        confidence = "high"
    elif (coverage or 0) >= 0.2 or supported:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "evidence_reviewed": len(reviewed_events), "entities_reviewed": len(reviewed_entities),
        "timeline_coverage": coverage, "open_questions": open_q, "contradicting_evidence": contradicting,
        "missing_telemetry": missing_telemetry, "confidence": confidence,
        "method": ("Coverage = share of the incident's evidence events retrieved during this investigation; "
                   "confidence is high only with ≥50% coverage, at least one supported hypothesis and no "
                   "contradicting evidence recorded."),
    }
