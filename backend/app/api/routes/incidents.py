from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AnalystCtx, ReadCtx, WorkspaceContext
from app.api.serializers import detection_full, event_brief, incident_brief, incident_full, iso, technique_info
from app.audit.service import record
from app.database.session import get_db, utcnow
from app.models import (
    AuditLog,
    Bookmark,
    CaseAssignment,
    Detection,
    DetectionEvent,
    Event,
    Incident,
    IncidentEvent,
    IncidentStatusHistory,
    IncidentTechnique,
    InvestigationNote,
    Membership,
    User,
)
from app.schemas import AssignIn, ChecklistIn, IncidentStatusIn, NoteIn, TagsIn
from app.services.graph import build_graph
from app.services.notifications import notify_workspace

router = APIRouter(prefix="/api/incidents", tags=["incidents"])
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def get_incident_or_404(db: Session, ctx: WorkspaceContext, incident_id: int | str) -> Incident:
    """Accept a numeric id or an incident number (INC-0006) so deep links work either way."""
    ref = str(incident_id).strip()
    q = db.query(Incident).filter_by(workspace_id=ctx.workspace_id)
    if ref.upper().startswith("INC-"):
        inc = q.filter_by(number=ref.upper()).first()
    else:
        inc = q.filter_by(id=int(ref)).first() if ref.isdigit() else None
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return inc


def _emails(db: Session, ids) -> dict[int, str]:
    ids = {i for i in ids if i}
    return {u.id: u.email for u in db.query(User).filter(User.id.in_(ids))} if ids else {}


@router.get("")
def list_incidents(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db),
                   status: list[str] | None = Query(default=None), severity: list[str] | None = Query(default=None),
                   assigned: str | None = None, q: str | None = None, sort: str = "risk",
                   page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = db.query(Incident).filter(Incident.workspace_id == ctx.workspace_id)
    if status:
        query = query.filter(Incident.status.in_(status))
    if severity:
        query = query.filter(Incident.severity.in_(severity))
    if assigned == "me":
        query = query.filter(Incident.assigned_to_id == ctx.user.id)
    elif assigned == "unassigned":
        query = query.filter(Incident.assigned_to_id.is_(None))
    if q:
        like = f"%{q[:200]}%"
        query = query.filter(or_(Incident.title.ilike(like), Incident.number.ilike(like)))
    order = {"risk": [Incident.risk_score.desc(), Incident.last_seen.desc()],
             "last_seen": [Incident.last_seen.desc()], "created": [Incident.created_at.desc()],
             "first_seen": [Incident.first_seen.desc()]}.get(sort, [Incident.risk_score.desc()])
    total = query.count()
    rows = query.order_by(*order).offset((page - 1) * page_size).limit(page_size).all()
    emails = _emails(db, [r.assigned_to_id for r in rows])
    bookmarks = {b.target_id for b in db.query(Bookmark).filter_by(user_id=ctx.user.id, workspace_id=ctx.workspace_id,
                                                                    target_type="incident")}
    counts = {}
    if rows:
        counts = dict(db.execute(select(Detection.incident_id, func.count(Detection.id)).where(
            Detection.incident_id.in_([r.id for r in rows])).group_by(Detection.incident_id)).all())
    items = [{**incident_brief(r, emails.get(r.assigned_to_id)), "detection_count": counts.get(r.id, 0),
              "bookmarked": r.id in bookmarks} for r in rows]
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@router.get("/compare")
def compare(ids: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    try:
        id_list = [int(x) for x in ids.split(",") if x.strip()][:5]
    except ValueError:
        raise HTTPException(status_code=422, detail="ids must be a comma-separated list of incident ids") from None
    incs = [get_incident_or_404(db, ctx, i) for i in id_list]
    if len(incs) < 2:
        raise HTTPException(status_code=422, detail="Provide at least two incident ids")
    tech = {i.id: {t.technique_id for t in db.query(IncidentTechnique).filter_by(incident_id=i.id)} for i in incs}
    common_users = set.intersection(*(set(i.users) for i in incs))
    common_hosts = set.intersection(*(set(i.hosts) for i in incs))
    common_ips = set.intersection(*(set(i.source_ips) for i in incs))
    common_tech = set.intersection(*tech.values())
    return {"incidents": [{**incident_brief(i), "techniques": sorted(tech[i.id])} for i in incs],
            "shared": {"users": sorted(common_users), "hosts": sorted(common_hosts), "source_ips": sorted(common_ips),
                       "techniques": sorted(common_tech)}}


@router.get("/{incident_id}")
def get_incident(incident_id: str, request: Request, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    dets = db.query(Detection).filter_by(incident_id=inc.id).order_by(Detection.timestamp).all()
    techs = db.query(IncidentTechnique).filter_by(incident_id=inc.id).all()
    history = db.query(IncidentStatusHistory).filter_by(incident_id=inc.id).order_by(IncidentStatusHistory.id).all()
    notes = db.query(InvestigationNote).filter_by(incident_id=inc.id).order_by(InvestigationNote.id).all()
    emails = _emails(db, [inc.assigned_to_id, inc.created_by_id] + [h.changed_by_id for h in history] +
                     [n.author_id for n in notes])
    evidence_count = db.query(IncidentEvent).filter_by(incident_id=inc.id, role="evidence").count()
    context_count = db.query(IncidentEvent).filter_by(incident_id=inc.id, role="context").count()
    bookmarked = db.query(Bookmark).filter_by(user_id=ctx.user.id, workspace_id=ctx.workspace_id,
                                              target_type="incident", target_id=inc.id).first() is not None
    record(db, "VIEW_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident",
           target_id=inc.id, details={"number": inc.number}, request=request)
    return {
        **incident_full(inc, emails.get(inc.assigned_to_id)),
        "created_by": emails.get(inc.created_by_id) or ("SentinelX correlation engine" if inc.origin == "correlation" else None),
        "detections": [detection_full(d) for d in dets],
        "techniques": sorted(
            [{**technique_info(t.technique_id), "reason": t.reason, "detection_ids": t.detection_ids,
              "event_uids": t.event_uids, "mapping_confidence": t.mapping_confidence} for t in techs],
            key=lambda t: t["tactic"]),
        "status_history": [{"from": h.from_status, "to": h.to_status, "by": emails.get(h.changed_by_id, "system"),
                            "note": h.note, "at": iso(h.changed_at)} for h in history],
        "notes": [{"id": n.id, "kind": n.kind, "body": n.body, "author": emails.get(n.author_id, "unknown"),
                   "created_at": iso(n.created_at)} for n in notes],
        "evidence_event_count": evidence_count, "context_event_count": context_count, "bookmarked": bookmarked,
    }


@router.get("/{incident_id}/timeline")
def timeline(incident_id: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db),
             include_context: bool = False, page: int = Query(1, ge=1), page_size: int = Query(200, ge=1, le=500)):
    inc = get_incident_or_404(db, ctx, incident_id)
    roles = ["evidence", "context"] if include_context else ["evidence"]
    base = select(Event, IncidentEvent.role).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(
        IncidentEvent.incident_id == inc.id, IncidentEvent.role.in_(roles))
    total = db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id, IncidentEvent.role.in_(roles)).count()
    rows = db.execute(base.order_by(Event.timestamp, Event.id).offset((page - 1) * page_size).limit(page_size)).all()
    det_rows = db.query(Detection).filter_by(incident_id=inc.id).all()
    det_map: dict[int, list[int]] = {}
    ids = [r[0].id for r in rows]
    if ids:
        for did, eid in db.execute(select(DetectionEvent.detection_id, DetectionEvent.event_id).where(
                DetectionEvent.event_id.in_(ids), DetectionEvent.detection_id.in_([d.id for d in det_rows] or [0]))):
            det_map.setdefault(eid, []).append(did)
    return {
        "items": [{**event_brief(e), "role": role, "detection_ids": det_map.get(e.id, [])} for e, role in rows],
        "detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity,
                        "timestamp": iso(d.timestamp), "last_seen": iso(d.last_seen), "stage": d.stage}
                       for d in sorted(det_rows, key=lambda d: d.timestamp)],
        "total": total, "page": page, "page_size": page_size,
    }


@router.get("/{incident_id}/graph")
def graph(incident_id: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return build_graph(db, get_incident_or_404(db, ctx, incident_id))


@router.get("/{incident_id}/history")
def case_history(incident_id: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    logs = db.query(AuditLog).filter(AuditLog.workspace_id == ctx.workspace_id, AuditLog.target_type == "incident",
                                     AuditLog.target_id == str(inc.id)).order_by(AuditLog.id.desc()).limit(200).all()
    return [{"id": a.id, "action": a.action, "user": a.user_email, "details": a.details, "at": iso(a.created_at)}
            for a in logs]


@router.patch("/{incident_id}")
def change_status(incident_id: str, body: IncidentStatusIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                  db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    if inc.status == body.status:
        raise HTTPException(status_code=409, detail=f"Incident is already {body.status}")
    old = inc.status
    inc.status = body.status
    inc.updated_at = utcnow()
    inc.resolved_at = utcnow() if body.status in ("RESOLVED", "FALSE_POSITIVE") else None
    db.add(IncidentStatusHistory(incident_id=inc.id, from_status=old, to_status=body.status,
                                 changed_by_id=ctx.user.id, note=body.note))
    db.commit()
    record(db, "CHANGE_INCIDENT_STATUS", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident",
           target_id=inc.id, details={"number": inc.number, "from": old, "to": body.status, "note": body.note},
           request=request)
    return incident_brief(inc)


@router.post("/{incident_id}/assign")
def assign(incident_id: str, body: AssignIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
           db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    assignee = None
    if body.user_id is not None:
        m = db.query(Membership).filter_by(workspace_id=ctx.workspace_id, user_id=body.user_id).first()
        if m is None:
            raise HTTPException(status_code=404, detail="Assignee is not a member of this workspace")
        if m.role.name == "VIEWER":
            raise HTTPException(status_code=422, detail="Viewers cannot own incidents")
        assignee = m.user
    db.query(CaseAssignment).filter_by(incident_id=inc.id, active=True).update({"active": False})
    db.add(CaseAssignment(incident_id=inc.id, assignee_id=body.user_id, assigned_by_id=ctx.user.id))
    inc.assigned_to_id = body.user_id
    inc.updated_at = utcnow()
    if assignee and inc.status == "NEW":
        db.add(IncidentStatusHistory(incident_id=inc.id, from_status="NEW", to_status="IN_PROGRESS",
                                     changed_by_id=ctx.user.id, note=f"Assigned to {assignee.email}"))
        inc.status = "IN_PROGRESS"
    if assignee and assignee.id != ctx.user.id:
        notify_workspace(db, ctx.workspace_id, "assignment", f"{inc.number} assigned to you", inc.title,
                         f"/incidents/{inc.id}", severity=inc.severity, only_user_id=assignee.id)
    db.commit()
    record(db, "ASSIGN_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident",
           target_id=inc.id, details={"assignee": assignee.email if assignee else None}, request=request)
    return incident_brief(inc, assignee.email if assignee else None)


@router.post("/{incident_id}/notes", status_code=201)
def add_note(incident_id: str, body: NoteIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
             db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    note = InvestigationNote(incident_id=inc.id, author_id=ctx.user.id, kind=body.kind, body=body.body.strip())
    db.add(note)
    inc.updated_at = utcnow()
    db.commit()
    record(db, "ADD_NOTE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident", target_id=inc.id,
           details={"kind": body.kind, "length": len(body.body)}, request=request)
    return {"id": note.id, "kind": note.kind, "body": note.body, "author": ctx.user.email,
            "created_at": iso(note.created_at)}


@router.patch("/{incident_id}/checklist")
def update_checklist(incident_id: str, body: ChecklistIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                     db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    items = [dict(c) for c in inc.checklist or []]
    if body.index >= len(items):
        raise HTTPException(status_code=404, detail="Checklist item not found")
    items[body.index]["done"] = body.done
    inc.checklist = items
    inc.updated_at = utcnow()
    db.commit()
    record(db, "UPDATE_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident",
           target_id=inc.id, details={"checklist_item": items[body.index]["item"], "done": body.done}, request=request)
    return {"checklist": items}


@router.put("/{incident_id}/tags")
def set_tags(incident_id: str, body: TagsIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
             db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    inc.tags = body.tags
    inc.updated_at = utcnow()
    db.commit()
    record(db, "UPDATE_INCIDENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="incident",
           target_id=inc.id, details={"tags": body.tags}, request=request)
    return {"tags": inc.tags}


@router.post("/{incident_id}/bookmark")
def toggle_bookmark(incident_id: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, incident_id)
    b = db.query(Bookmark).filter_by(user_id=ctx.user.id, workspace_id=ctx.workspace_id, target_type="incident",
                                     target_id=inc.id).first()
    if b:
        db.delete(b)
        state = False
    else:
        db.add(Bookmark(user_id=ctx.user.id, workspace_id=ctx.workspace_id, target_type="incident", target_id=inc.id,
                        label=inc.number))
        state = True
    db.commit()
    return {"bookmarked": state}
