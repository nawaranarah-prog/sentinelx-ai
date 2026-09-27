from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AdminCtx, AnalystCtx, ReadCtx, WorkspaceContext
from app.api.serializers import detection_brief, detection_full, event_brief, iso
from app.audit.service import record
from app.correlation.engine import rebuild_incident
from app.database.session import get_db, utcnow
from app.detection.catalog import DEFAULT_RULES, RULE_GUIDANCE
from app.models import Detection, DetectionEvent, DetectionRule, Event, Incident, IncidentStatusHistory
from app.schemas import DetectionStatusIn, RuleUpdateIn

router = APIRouter(prefix="/api/detections", tags=["detections"])
rules_router = APIRouter(prefix="/api/rules", tags=["detection rules"])
DEFAULT_PARAMS = {r["rule_key"]: r["parameters"] for r in DEFAULT_RULES}


@router.get("")
def list_detections(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db),
                    severity: list[str] | None = Query(default=None), rule_key: str | None = None,
                    status: str | None = None, correlated: bool | None = None, q: str | None = None,
                    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = db.query(Detection).filter(Detection.workspace_id == ctx.workspace_id)
    if severity:
        query = query.filter(Detection.severity.in_(severity))
    if rule_key:
        query = query.filter(Detection.rule_key == rule_key)
    if status:
        query = query.filter(Detection.status == status)
    if correlated is True:
        query = query.filter(Detection.incident_id.is_not(None))
    elif correlated is False:
        query = query.filter(Detection.incident_id.is_(None))
    if q:
        like = f"%{q[:200]}%"
        query = query.filter(or_(Detection.title.ilike(like), Detection.user.ilike(like), Detection.host.ilike(like),
                                 Detection.source_ip.ilike(like)))
    total = query.count()
    rows = query.order_by(Detection.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [detection_brief(d) for d in rows], "total": total, "page": page, "page_size": page_size}


def _get(db: Session, ctx: WorkspaceContext, det_id: int) -> Detection:
    d = db.query(Detection).filter_by(id=det_id, workspace_id=ctx.workspace_id).first()
    if d is None:
        raise HTTPException(status_code=404, detail="Detection not found")
    return d


@router.get("/{det_id}")
def get_detection(det_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    d = _get(db, ctx, det_id)
    evs = db.scalars(select(Event).join(DetectionEvent, DetectionEvent.event_id == Event.id)
                     .where(DetectionEvent.detection_id == d.id).order_by(Event.timestamp).limit(300)).all()
    inc = db.get(Incident, d.incident_id) if d.incident_id else None
    return {**detection_full(d), "evidence_events": [event_brief(e) for e in evs],
            "incident": {"id": inc.id, "number": inc.number, "title": inc.title, "status": inc.status} if inc else None}


@router.patch("/{det_id}")
def update_detection(det_id: int, body: DetectionStatusIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                     db: Session = Depends(get_db)):
    d = _get(db, ctx, det_id)
    old = d.status
    d.status = body.status
    db.commit()
    record(db, "UPDATE_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="detection",
           target_id=d.id, details={"status": {"from": old, "to": body.status}}, request=request)
    return detection_brief(d)


@router.post("/{det_id}/promote", status_code=201)
def promote(det_id: int, request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    d = _get(db, ctx, det_id)
    if d.incident_id:
        raise HTTPException(status_code=409, detail="Detection already belongs to an incident.")
    ws = ctx.workspace
    ws.incident_seq = (ws.incident_seq or 0) + 1
    inc = Incident(workspace_id=ws.id, number=f"INC-{ws.incident_seq:04d}", title=d.title, severity=d.severity,
                   first_seen=d.timestamp, last_seen=d.last_seen, status="NEW", origin="manual",
                   created_by_id=ctx.user.id)
    db.add(inc)
    db.flush()
    d.incident_id = inc.id
    db.add(IncidentStatusHistory(incident_id=inc.id, to_status="NEW", changed_by_id=ctx.user.id,
                                 note=f"Promoted from detection #{d.id} by {ctx.user.email}"))
    db.flush()
    rebuild_incident(db, inc, ws)
    inc.correlation_reason = f"Manually promoted to an incident by {ctx.user.email} from detection #{d.id}."
    db.commit()
    record(db, "PROMOTE_DETECTION", user=ctx.user, workspace_id=ws.id, target_type="incident", target_id=inc.id,
           details={"detection_id": d.id}, request=request)
    return {"incident_id": inc.id, "number": inc.number}


# ------------------------------------------------------------------------------------------- rules
def rule_payload(r: DetectionRule, counts: dict) -> dict:
    return {"id": r.id, "rule_key": r.rule_key, "name": r.name, "description": r.description, "severity": r.severity,
            "enabled": r.enabled, "parameters": r.parameters, "default_parameters": DEFAULT_PARAMS.get(r.rule_key, {}),
            "mitre_techniques": r.mitre_techniques, "stage": r.stage, "version": r.version,
            "updated_at": iso(r.updated_at), "detection_count": counts.get(r.rule_key, 0),
            "false_positives": RULE_GUIDANCE.get(r.rule_key, {}).get("false_positives", [])}


@rules_router.get("")
def list_rules(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    counts = dict(db.execute(select(Detection.rule_key, func.count()).where(Detection.workspace_id == ctx.workspace_id)
                             .group_by(Detection.rule_key)).all())
    rules = db.query(DetectionRule).filter_by(workspace_id=ctx.workspace_id).order_by(DetectionRule.rule_key).all()
    return [rule_payload(r, counts) for r in rules]


def _validate_params(rule_key: str, params: dict) -> dict:
    defaults = DEFAULT_PARAMS.get(rule_key, {})
    clean = {}
    for k, v in params.items():
        if k not in defaults:
            raise HTTPException(status_code=422, detail=f"Unknown parameter '{k}' for {rule_key}")
        ref = defaults[k]
        if isinstance(ref, bool) or isinstance(v, bool):
            raise HTTPException(status_code=422, detail=f"Parameter '{k}' has an invalid type")
        if isinstance(ref, (int, float)):
            if not isinstance(v, (int, float)) or v <= 0 or v > 10_000_000_000_000:
                raise HTTPException(status_code=422, detail=f"Parameter '{k}' must be a positive number")
            clean[k] = type(ref)(v) if isinstance(ref, int) and float(v).is_integer() else float(v)
        elif isinstance(ref, list):
            if not isinstance(v, list) or len(v) > 200 or not all(isinstance(x, str) and 0 < len(x) <= 200 for x in v):
                raise HTTPException(status_code=422, detail=f"Parameter '{k}' must be a list of strings")
            clean[k] = [x.strip() for x in v]
        else:
            raise HTTPException(status_code=422, detail=f"Parameter '{k}' cannot be changed")
    return clean


@rules_router.patch("/{rule_id}")
def update_rule(rule_id: int, body: RuleUpdateIn, request: Request, ctx: WorkspaceContext = AdminCtx,
                db: Session = Depends(get_db)):
    r = db.query(DetectionRule).filter_by(id=rule_id, workspace_id=ctx.workspace_id).first()
    if r is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    before = {"enabled": r.enabled, "severity": r.severity, "parameters": dict(r.parameters or {})}
    if body.enabled is not None:
        r.enabled = body.enabled
    if body.severity is not None:
        r.severity = body.severity
    if body.parameters is not None:
        r.parameters = {**(r.parameters or {}), **_validate_params(r.rule_key, body.parameters)}
    r.version += 1
    r.updated_at = utcnow()
    r.updated_by_id = ctx.user.id
    db.commit()
    after = {"enabled": r.enabled, "severity": r.severity, "parameters": r.parameters}
    record(db, "CHANGE_RULE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="rule", target_id=r.rule_key,
           details={"before": before, "after": after}, request=request)
    return rule_payload(r, {})


@rules_router.post("/{rule_id}/reset")
def reset_rule(rule_id: int, request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    r = db.query(DetectionRule).filter_by(id=rule_id, workspace_id=ctx.workspace_id).first()
    if r is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    r.parameters = dict(DEFAULT_PARAMS.get(r.rule_key, {}))
    r.version += 1
    r.updated_at = utcnow()
    db.commit()
    record(db, "CHANGE_RULE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="rule", target_id=r.rule_key,
           details={"reset_to_defaults": True}, request=request)
    return rule_payload(r, {})
