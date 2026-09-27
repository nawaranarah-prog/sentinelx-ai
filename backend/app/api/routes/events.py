from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import ReadCtx, WorkspaceContext
from app.api.serializers import detection_brief, event_brief, event_full, incident_brief
from app.audit.service import record
from app.database.session import get_db
from app.ingestion.normalizer import parse_timestamp
from app.models import Detection, DetectionEvent, Event, Incident, IncidentEvent

router = APIRouter(prefix="/api/events", tags=["events"])
SORTABLE = {"timestamp": Event.timestamp, "severity": Event.severity, "user": Event.user, "host": Event.host,
            "event_type": Event.event_type, "source_ip": Event.source_ip}


def _parse_dt(value: str | None, name: str) -> datetime | None:
    if not value:
        return None
    dt = parse_timestamp(value)
    if dt is None:
        raise HTTPException(status_code=422, detail=f"Invalid {name} timestamp")
    return dt


def build_event_query(ws_id: int, q: str | None = None, start: str | None = None, end: str | None = None,
                      severity: list[str] | None = None, event_type: list[str] | None = None, user: str | None = None,
                      host: str | None = None, ip: str | None = None, source: str | None = None,
                      status: str | None = None, incident_id: int | None = None, detection_id: int | None = None):
    conds = [Event.workspace_id == ws_id]
    if start_dt := _parse_dt(start, "start"):
        conds.append(Event.timestamp >= start_dt)
    if end_dt := _parse_dt(end, "end"):
        conds.append(Event.timestamp <= end_dt)
    if severity:
        conds.append(Event.severity.in_(severity))
    if event_type:
        conds.append(Event.event_type.in_(event_type))
    if user:
        conds.append(Event.user == user.lower())
    if host:
        conds.append(Event.host == host.upper())
    if ip:
        conds.append(or_(Event.source_ip == ip, Event.destination_ip == ip))
    if source:
        conds.append(Event.source == source)
    if status:
        conds.append(Event.status == status)
    if incident_id is not None:
        conds.append(Event.id.in_(select(IncidentEvent.event_id).join(Incident, Incident.id == IncidentEvent.incident_id)
                                  .where(IncidentEvent.incident_id == incident_id, Incident.workspace_id == ws_id)))
    if detection_id is not None:
        conds.append(Event.id.in_(select(DetectionEvent.event_id).join(Detection, Detection.id == DetectionEvent.detection_id)
                                  .where(DetectionEvent.detection_id == detection_id, Detection.workspace_id == ws_id)))
    if q:
        like = f"%{q.strip()[:200]}%"
        conds.append(or_(Event.event_uid.ilike(like), Event.user.ilike(like), Event.host.ilike(like),
                         Event.source_ip.ilike(like), Event.destination_ip.ilike(like), Event.command.ilike(like),
                         Event.resource.ilike(like), Event.process.ilike(like), Event.action.ilike(like)))
    return and_(*conds)


@router.get("")
def list_events(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db),
                q: str | None = None, start: str | None = None, end: str | None = None,
                severity: list[str] | None = Query(default=None), event_type: list[str] | None = Query(default=None),
                user: str | None = None, host: str | None = None, ip: str | None = None, source: str | None = None,
                status: str | None = None, incident_id: int | None = None, detection_id: int | None = None,
                sort: str = "timestamp", order: str = "desc", page: int = Query(1, ge=1),
                page_size: int = Query(50, ge=1, le=200)):
    where = build_event_query(ctx.workspace_id, q, start, end, severity, event_type, user, host, ip, source, status,
                              incident_id, detection_id)
    total = db.scalar(select(func.count(Event.id)).where(where))
    col = SORTABLE.get(sort, Event.timestamp)
    direction = desc if order == "desc" else asc
    rows = db.scalars(select(Event).where(where).order_by(direction(col), direction(Event.id))
                      .offset((page - 1) * page_size).limit(page_size)).all()
    return {"items": [event_brief(e) for e in rows], "total": total, "page": page, "page_size": page_size}


@router.get("/facets")
def facets(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    ws = ctx.workspace_id

    def top(col, n=50):
        return [r[0] for r in db.execute(select(col, func.count()).where(Event.workspace_id == ws, col.is_not(None))
                                         .group_by(col).order_by(func.count().desc()).limit(n))]

    rng = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp)).where(Event.workspace_id == ws)).one()
    return {"event_types": top(Event.event_type), "sources": top(Event.source), "severities": top(Event.severity),
            "statuses": top(Event.status, 10),
            "time_range": {"min": rng[0].isoformat() + "Z" if rng[0] else None,
                           "max": rng[1].isoformat() + "Z" if rng[1] else None}}


@router.get("/{event_id}")
def get_event(event_id: int, request: Request, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    e = db.query(Event).filter_by(id=event_id, workspace_id=ctx.workspace_id).first()
    if e is None:
        raise HTTPException(status_code=404, detail="Event not found")
    dets = db.query(Detection).join(DetectionEvent, DetectionEvent.detection_id == Detection.id).filter(
        DetectionEvent.event_id == e.id, Detection.workspace_id == ctx.workspace_id).all()
    incs = db.query(Incident, IncidentEvent.role).join(IncidentEvent, IncidentEvent.incident_id == Incident.id).filter(
        IncidentEvent.event_id == e.id, Incident.workspace_id == ctx.workspace_id).all()
    record(db, "VIEW_EVENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="event", target_id=e.id,
           details={"event_uid": e.event_uid}, request=request)
    return {**event_full(e), "detections": [detection_brief(d) for d in dets],
            "incidents": [{**incident_brief(i), "role": role} for i, role in incs]}
