"""Analytics, global search, entities, audit log, notifications and saved searches."""

import csv
import io
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import AdminCtx, ReadCtx, WorkspaceContext
from app.api.serializers import detection_brief, event_brief, incident_brief, iso
from app.audit.service import record
from app.database.session import get_db
from app.mitre.catalog import TECHNIQUE_INDEX
from app.ml.anomaly import describe_result
from app.models import (
    AnomalyResult,
    AuditLog,
    Detection,
    Event,
    Host,
    Hunt,
    Incident,
    Investigation,
    Notification,
    Report,
    SavedSearch,
    ThreatIndicator,
)
from app.schemas import HostUpdateIn, SavedSearchIn
from app.services.entity_risk import compute_entity_risks

analytics_router = APIRouter(prefix="/api/analytics", tags=["analytics"])
search_router = APIRouter(prefix="/api/search", tags=["search"])
entities_router = APIRouter(prefix="/api/entities", tags=["entities & risk"])
audit_router = APIRouter(prefix="/api/audit", tags=["audit"])
notif_router = APIRouter(prefix="/api/notifications", tags=["notifications"])
saved_router = APIRouter(prefix="/api/saved-searches", tags=["saved searches"])


# ---------------------------------------------------------------------------------------- analytics
@analytics_router.get("/summary")
def summary(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db), days: int | None = Query(None, ge=1, le=365)):
    ws = ctx.workspace_id
    rng = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp)).where(Event.workspace_id == ws)).one()
    start = rng[1] - timedelta(days=days) if (days and rng[1]) else rng[0]
    ev_filter = [Event.workspace_id == ws] + ([Event.timestamp >= start] if start else [])
    total_events = db.scalar(select(func.count(Event.id)).where(*ev_filter)) or 0

    def grouped(col, n=10, extra=()):
        return [{"key": k, "count": c} for k, c in db.execute(
            select(col, func.count()).where(*ev_filter, col.is_not(None), *extra).group_by(col)
            .order_by(func.count().desc()).limit(n))]

    series = []
    if rng[0] and rng[1]:
        span = rng[1] - (start or rng[0])
        bucket_hours = 1 if span <= timedelta(days=2) else 6 if span <= timedelta(days=14) else 24
        buckets: dict[str, dict] = {}
        for ts, sev in db.execute(select(Event.timestamp, Event.severity).where(*ev_filter)):
            b = ts.replace(minute=0, second=0, microsecond=0)
            b = b.replace(hour=(b.hour // bucket_hours) * bucket_hours)
            key = b.isoformat() + "Z"
            d = buckets.setdefault(key, {"bucket": key, "total": 0})
            d["total"] += 1
            d[sev] = d.get(sev, 0) + 1
        series = [buckets[k] for k in sorted(buckets)]
    else:
        bucket_hours = None

    det_q = db.query(Detection).filter(Detection.workspace_id == ws)
    if start:
        det_q = det_q.filter(Detection.timestamp >= start)
    dets = det_q.all()
    det_by_rule, det_by_sev, tech_counts = {}, {}, {}
    det_series: dict[str, int] = {}
    for d in dets:
        det_by_rule[d.rule_key] = det_by_rule.get(d.rule_key, 0) + 1
        det_by_sev[d.severity] = det_by_sev.get(d.severity, 0) + 1
        day = d.timestamp.strftime("%Y-%m-%d")
        det_series[day] = det_series.get(day, 0) + 1
        for m in d.mitre or []:
            tech_counts[m["id"]] = tech_counts.get(m["id"], 0) + 1
    incs = db.query(Incident).filter(Incident.workspace_id == ws).all()
    inc_by_status, inc_by_sev, inc_series = {}, {}, {}
    for i in incs:
        inc_by_status[i.status] = inc_by_status.get(i.status, 0) + 1
        inc_by_sev[i.severity] = inc_by_sev.get(i.severity, 0) + 1
        day = i.first_seen.strftime("%Y-%m-%d")
        inc_series[day] = inc_series.get(day, 0) + 1
    anomalies = db.query(AnomalyResult).filter_by(workspace_id=ws).all()
    hist = [0] * 10
    for a in anomalies:
        if a.if_score is not None:
            hist[min(9, max(0, int((a.if_score - 0.3) / 0.05)))] += 1
    open_incidents = [i for i in incs if i.status in ("NEW", "IN_PROGRESS", "CONTAINED")]
    return {
        "range": {"start": iso(start), "end": iso(rng[1]), "bucket_hours": bucket_hours},
        "kpis": {"events": total_events, "detections": len(dets), "incidents": len(incs),
                 "open_incidents": len(open_incidents),
                 "critical_open": sum(1 for i in open_incidents if i.severity == "critical"),
                 "anomalous_windows": sum(1 for a in anomalies if a.is_anomalous), "anomaly_windows": len(anomalies),
                 "users": db.scalar(select(func.count(func.distinct(Event.user))).where(*ev_filter)) or 0,
                 "hosts": db.scalar(select(func.count(func.distinct(Event.host))).where(*ev_filter)) or 0,
                 "mean_risk_open": round(sum(i.risk_score for i in open_incidents) / len(open_incidents)) if open_incidents else None},
        "events_over_time": series,
        "severity_distribution": grouped(Event.severity), "event_types": grouped(Event.event_type),
        "top_users": grouped(Event.user), "top_hosts": grouped(Event.host), "top_source_ips": grouped(Event.source_ip),
        "failed_logins_by_user": grouped(Event.user, 10, (Event.status == "failure", Event.event_type == "authentication")),
        "detections_by_rule": [{"key": k, "count": v} for k, v in sorted(det_by_rule.items(), key=lambda x: -x[1])],
        "detections_by_severity": [{"key": k, "count": v} for k, v in det_by_sev.items()],
        "detections_over_time": [{"day": k, "count": v} for k, v in sorted(det_series.items())],
        "incidents_by_status": [{"key": k, "count": v} for k, v in inc_by_status.items()],
        "incidents_by_severity": [{"key": k, "count": v} for k, v in inc_by_sev.items()],
        "incidents_over_time": [{"day": k, "count": v} for k, v in sorted(inc_series.items())],
        "techniques": [{"id": k, "name": TECHNIQUE_INDEX.get(k, {}).get("name", k),
                        "tactic": TECHNIQUE_INDEX.get(k, {}).get("tactic", ""), "count": v}
                       for k, v in sorted(tech_counts.items(), key=lambda x: -x[1])],
        "anomaly_score_histogram": [{"bin": f"{0.3 + 0.05 * i:.2f}", "count": c} for i, c in enumerate(hist)],
        "recent_incidents": [incident_brief(i) for i in sorted(incs, key=lambda i: -i.risk_score)[:6]],
    }


# ------------------------------------------------------------------------------------------- search
@search_router.get("")
def global_search(q: str = Query(min_length=1, max_length=200), ctx: WorkspaceContext = ReadCtx,
                  db: Session = Depends(get_db)):
    ws = ctx.workspace_id
    like = f"%{q.strip()}%"
    results = []
    for i in db.query(Incident).filter(Incident.workspace_id == ws, or_(Incident.title.ilike(like),
                                                                        Incident.number.ilike(like))).limit(8):
        results.append({"type": "incident", "id": i.id, "title": f"{i.number} · {i.title}", "subtitle": i.status,
                        "severity": i.severity, "link": f"/incidents/{i.number}"})
    for d in db.query(Detection).filter(Detection.workspace_id == ws, or_(Detection.title.ilike(like),
                                                                          Detection.rule_key.ilike(like))).limit(8):
        results.append({"type": "detection", "id": d.id, "title": d.title, "subtitle": d.rule_key,
                        "severity": d.severity, "link": f"/detections/{d.id}"})
    for (u,) in db.execute(select(Event.user).where(Event.workspace_id == ws, Event.user.ilike(like)).distinct().limit(6)):
        results.append({"type": "user", "id": u, "title": u, "subtitle": "User", "link": f"/entities/user/{u}"})
    for (h,) in db.execute(select(Event.host).where(Event.workspace_id == ws, Event.host.ilike(like)).distinct().limit(6)):
        results.append({"type": "host", "id": h, "title": h, "subtitle": "Host", "link": f"/entities/host/{h}"})
    for t in db.query(ThreatIndicator).filter(ThreatIndicator.workspace_id == ws,
                                              ThreatIndicator.value.ilike(like)).limit(6):
        results.append({"type": "indicator", "id": t.id, "title": t.value,
                        "subtitle": f"{t.indicator_type} · {t.source}", "severity": t.severity,
                        "link": f"/threat-intel?q={t.value}"})
    ql = q.strip().lower()
    for tid, info in TECHNIQUE_INDEX.items():
        if ql in tid.lower() or ql in info["name"].lower():
            results.append({"type": "technique", "id": tid, "title": f"{tid} · {info['name']}",
                            "subtitle": info["tactic"], "link": f"/mitre?technique={tid}"})
            if sum(1 for r in results if r["type"] == "technique") >= 6:
                break
    for e in db.scalars(select(Event).where(Event.workspace_id == ws, or_(
            Event.event_uid.ilike(like), Event.source_ip == q.strip(), Event.destination_ip == q.strip(),
            Event.command.ilike(like), Event.resource.ilike(like))).order_by(Event.timestamp.desc()).limit(8)):
        results.append({"type": "event", "id": e.id, "title": f"{e.event_uid} · {e.event_type}",
                        "subtitle": " ".join(x for x in [e.user or "", e.host or "", (e.command or e.resource or "")[:60]] if x),
                        "severity": e.severity, "link": f"/events/{e.event_uid}"})
    for inv in db.query(Investigation).filter(Investigation.workspace_id == ws, or_(
            Investigation.title.ilike(like), Investigation.number.ilike(like))).limit(6):
        results.append({"type": "investigation", "id": inv.id, "title": f"{inv.number} · {inv.title}",
                        "subtitle": inv.status, "link": f"/investigations/{inv.number}"})
    for h in db.query(Hunt).filter(Hunt.workspace_id == ws, or_(Hunt.name.ilike(like), Hunt.number.ilike(like),
                                                                Hunt.natural_language.ilike(like))).limit(6):
        results.append({"type": "hunt", "id": h.id, "title": f"{h.number} · {h.name}",
                        "subtitle": f"{h.last_result_count} matches", "link": f"/hunts/{h.number}"})
    for r in db.query(Report).filter(Report.workspace_id == ws, Report.title.ilike(like)).limit(6):
        results.append({"type": "report", "id": r.id, "title": r.title, "subtitle": r.report_type,
                        "link": f"/reports/{r.id}"})
    return {"query": q, "results": results}


# ----------------------------------------------------------------------------------------- entities
@entities_router.get("/{kind}")
def list_entities(kind: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db),
                  limit: int = Query(100, ge=1, le=1000)):
    if kind not in ("users", "hosts"):
        raise HTTPException(status_code=404, detail="Unknown entity type")
    return compute_entity_risks(db, ctx.workspace_id, kind[:-1])[:limit]


@entities_router.get("/{kind}/{name}")
def entity_profile(kind: str, name: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    if kind not in ("user", "host"):
        raise HTTPException(status_code=404, detail="Unknown entity type")
    risks = {r["name"]: r for r in compute_entity_risks(db, ctx.workspace_id, kind)}
    key = name.lower() if kind == "user" else name.upper()
    if key not in risks:
        raise HTTPException(status_code=404, detail=f"No telemetry for {kind} '{name}'")
    col = Event.user if kind == "user" else Event.host
    base = [Event.workspace_id == ctx.workspace_id, col == key]
    other = Event.host if kind == "user" else Event.user
    by_type = dict(db.execute(select(Event.event_type, func.count()).where(*base).group_by(Event.event_type)).all())
    related = [r[0] for r in db.execute(select(other, func.count()).where(*base, other.is_not(None)).group_by(other)
                                        .order_by(func.count().desc()).limit(15))]
    ips = [r[0] for r in db.execute(select(Event.source_ip, func.count()).where(*base, Event.source_ip.is_not(None))
                                    .group_by(Event.source_ip).order_by(func.count().desc()).limit(15))]
    dcol = Detection.user if kind == "user" else Detection.host
    dets = db.query(Detection).filter(Detection.workspace_id == ctx.workspace_id, dcol == key).order_by(Detection.timestamp.desc()).all()
    incs = [i for i in db.query(Incident).filter_by(workspace_id=ctx.workspace_id)
            if key in ((i.users if kind == "user" else i.hosts) or [])]
    anomalies = db.query(AnomalyResult).filter_by(workspace_id=ctx.workspace_id, entity_type=kind, entity=key)\
        .order_by(AnomalyResult.window_start).all()
    recent = db.scalars(select(Event).where(*base).order_by(Event.timestamp.desc()).limit(25)).all()
    rng = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp)).where(*base)).one()
    return {**risks[key], "first_seen": iso(rng[0]), "last_seen": iso(rng[1]), "events_by_type": by_type,
            ("hosts" if kind == "user" else "users"): related, "source_ips": ips,
            "detections": [detection_brief(d) for d in dets], "incidents": [incident_brief(i) for i in incs],
            "anomalies": [{"day": a.window_start.strftime("%Y-%m-%d"), "features": a.features,
                           "if_score": a.if_score, "if_threshold": a.if_threshold, "if_flagged": a.if_flagged,
                           "is_anomalous": a.is_anomalous, "top_deviations": a.top_deviations,
                           "explanation": describe_result(a), "method": a.method} for a in anomalies],
            "model_info": anomalies[0].model_info if anomalies else None,
            "recent_events": [event_brief(e) for e in recent]}


@entities_router.patch("/hosts/{host_id}")
def update_host(host_id: int, body: HostUpdateIn, request: Request, ctx: WorkspaceContext = AdminCtx,
                db: Session = Depends(get_db)):
    h = db.query(Host).filter_by(id=host_id, workspace_id=ctx.workspace_id).first()
    if h is None:
        raise HTTPException(status_code=404, detail="Host not found")
    old = h.criticality
    h.criticality, h.criticality_source, h.role_hint = body.criticality, "admin", "set by administrator"
    db.commit()
    record(db, "CHANGE_ASSET", user=ctx.user, workspace_id=ctx.workspace_id, target_type="host", target_id=h.id,
           details={"hostname": h.hostname, "from": old, "to": body.criticality}, request=request)
    return {"id": h.id, "hostname": h.hostname, "criticality": h.criticality}


# -------------------------------------------------------------------------------------------- audit
def _audit_query(db: Session, ws: int, action: str | None, user: str | None, target_type: str | None):
    q = db.query(AuditLog).filter(AuditLog.workspace_id == ws)
    if action:
        q = q.filter(AuditLog.action == action)
    if user:
        q = q.filter(AuditLog.user_email.ilike(f"%{user}%"))
    if target_type:
        q = q.filter(AuditLog.target_type == target_type)
    return q


def audit_payload(a: AuditLog) -> dict:
    return {"id": a.id, "action": a.action, "user": a.user_email, "user_id": a.user_id, "target_type": a.target_type,
            "target_id": a.target_id, "details": a.details, "ip_address": a.ip_address, "user_agent": a.user_agent,
            "created_at": iso(a.created_at)}


@audit_router.get("")
def list_audit(ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db), action: str | None = None,
               user: str | None = None, target_type: str | None = None, page: int = Query(1, ge=1),
               page_size: int = Query(50, ge=1, le=200)):
    q = _audit_query(db, ctx.workspace_id, action, user, target_type)
    total = q.count()
    rows = q.order_by(AuditLog.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    actions = [r[0] for r in db.execute(select(AuditLog.action).where(AuditLog.workspace_id == ctx.workspace_id).distinct())]
    return {"items": [audit_payload(a) for a in rows], "total": total, "page": page, "page_size": page_size,
            "actions": sorted(actions)}


@audit_router.get("/export.csv")
def export_audit(ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db), action: str | None = None,
                 user: str | None = None):
    rows = _audit_query(db, ctx.workspace_id, action, user, None).order_by(AuditLog.id.desc()).limit(50_000).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "created_at", "action", "user", "target_type", "target_id", "ip_address", "details"])
    for a in rows:
        w.writerow([a.id, iso(a.created_at), a.action, a.user_email, a.target_type, a.target_id, a.ip_address, a.details])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="sentinelx_audit_log.csv"'})


# ------------------------------------------------------------------------------------ notifications
@notif_router.get("")
def list_notifications(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db), unread_only: bool = False):
    q = db.query(Notification).filter_by(user_id=ctx.user.id, workspace_id=ctx.workspace_id)
    unread = q.filter_by(is_read=False).count()
    if unread_only:
        q = q.filter_by(is_read=False)
    rows = q.order_by(Notification.id.desc()).limit(50).all()
    return {"unread": unread, "items": [{"id": n.id, "kind": n.kind, "severity": n.severity, "title": n.title,
                                         "body": n.body, "link": n.link, "is_read": n.is_read,
                                         "created_at": iso(n.created_at)} for n in rows]}


@notif_router.post("/read-all")
def read_all(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    n = db.query(Notification).filter_by(user_id=ctx.user.id, workspace_id=ctx.workspace_id, is_read=False)\
        .update({"is_read": True})
    db.commit()
    return {"updated": n}


@notif_router.post("/{notif_id}/read")
def read_one(notif_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    n = db.query(Notification).filter_by(id=notif_id, user_id=ctx.user.id, workspace_id=ctx.workspace_id).first()
    if n is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.is_read = True
    db.commit()
    return {"ok": True}


# ------------------------------------------------------------------------------------ saved searches
@saved_router.get("")
def list_saved(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    rows = db.query(SavedSearch).filter_by(user_id=ctx.user.id, workspace_id=ctx.workspace_id).order_by(SavedSearch.id)
    return [{"id": s.id, "name": s.name, "query": s.query, "created_at": iso(s.created_at)} for s in rows]


@saved_router.post("", status_code=201)
def create_saved(body: SavedSearchIn, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    allowed = {"q", "start", "end", "severity", "event_type", "user", "host", "ip", "source", "status",
               "incident_id", "detection_id", "sort", "order"}
    query = {k: v for k, v in body.query.items() if k in allowed}
    s = SavedSearch(workspace_id=ctx.workspace_id, user_id=ctx.user.id, name=body.name, query=query)
    db.add(s)
    db.commit()
    return {"id": s.id, "name": s.name, "query": s.query, "created_at": iso(s.created_at)}


@saved_router.delete("/{search_id}")
def delete_saved(search_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    s = db.query(SavedSearch).filter_by(id=search_id, user_id=ctx.user.id, workspace_id=ctx.workspace_id).first()
    if s is None:
        raise HTTPException(status_code=404, detail="Saved search not found")
    db.delete(s)
    db.commit()
    return {"ok": True}
