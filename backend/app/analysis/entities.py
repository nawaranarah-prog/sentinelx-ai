"""Entity behavior analytics computed from stored telemetry (no pre-computed or invented values)."""

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.detection.base import is_off_hours
from app.ingestion.normalizer import is_external_ip
from app.models import AnomalyResult, Detection, Event, Incident

DET_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}


def _col(kind: str):
    return {"user": Event.user, "host": Event.host, "ip": Event.source_ip}[kind]


def _key(kind: str, name: str) -> str:
    return name.lower() if kind == "user" else name.upper() if kind == "host" else name.strip()


def _events(db: Session, ws: int, kind: str, name: str, start: datetime | None = None, end: datetime | None = None,
            limit: int = 20000) -> list[Event]:
    key = _key(kind, name)
    cond = or_(Event.source_ip == key, Event.destination_ip == key) if kind == "ip" else _col(kind) == key
    q = select(Event).where(Event.workspace_id == ws, cond)
    if start:
        q = q.where(Event.timestamp >= start)
    if end:
        q = q.where(Event.timestamp <= end)
    return list(db.scalars(q.order_by(Event.timestamp).limit(limit)))


def latest_ts(db: Session, ws: int) -> datetime | None:
    return db.scalar(select(func.max(Event.timestamp)).where(Event.workspace_id == ws))


def baseline(db: Session, ws: int, kind: str, name: str, exclude_after: datetime | None = None) -> dict:
    """Historical behavior: hour-of-day profile, usual sources/hosts/processes, daily volumes."""
    evs = _events(db, ws, kind, name)
    if not evs:
        return {"entity": name, "kind": kind, "events": 0, "note": "No telemetry for this entity."}
    hist = [e for e in evs if not exclude_after or e.timestamp < exclude_after]
    days = sorted({e.timestamp.date() for e in hist})
    hours = Counter(e.timestamp.hour for e in hist)
    auth_hours = Counter(e.timestamp.hour for e in hist if e.event_type == "authentication" and e.status == "success")
    per_day = Counter(e.timestamp.date() for e in hist)
    active = [h for h, c in sorted(hours.items()) if c >= max(1, 0.03 * len(hist))]
    return {
        "entity": _key(kind, name), "kind": kind, "events": len(hist), "days_observed": len(days),
        "first_seen": hist[0].timestamp.isoformat() + "Z" if hist else None,
        "last_seen": hist[-1].timestamp.isoformat() + "Z" if hist else None,
        "hour_histogram": [hours.get(h, 0) for h in range(24)],
        "login_hour_histogram": [auth_hours.get(h, 0) for h in range(24)],
        "usual_active_hours_utc": active,
        "median_events_per_day": sorted(per_day.values())[len(per_day) // 2] if per_day else 0,
        "event_types": dict(Counter(e.event_type for e in hist)),
        "source_ips": [k for k, _ in Counter(e.source_ip for e in hist if e.source_ip).most_common(10)],
        "hosts": [k for k, _ in Counter(e.host for e in hist if e.host).most_common(10)],
        "users": [k for k, _ in Counter(e.user for e in hist if e.user).most_common(10)],
        "processes": [k for k, _ in Counter(e.process for e in hist if e.process).most_common(10)],
        "external_destinations": [k for k, _ in Counter(e.destination_ip or e.resource for e in hist if e.event_type == "network"
                                  and (is_external_ip(e.destination_ip) or (not e.destination_ip and e.resource))).most_common(10)],
    }


def was_active_at(db: Session, ws: int, kind: str, name: str, when: datetime) -> dict:
    """Was the entity normally active at this hour (excluding the day in question)?"""
    b = baseline(db, ws, kind, name)
    evs = [e for e in _events(db, ws, kind, name) if e.timestamp.date() != when.date()]
    same_hour = sum(1 for e in evs if e.timestamp.hour == when.hour)
    days = len({e.timestamp.date() for e in evs})
    return {"entity": b["entity"], "hour_utc": when.hour, "events_in_that_hour_on_other_days": same_hour,
            "other_days_observed": days, "usual_active_hours_utc": b.get("usual_active_hours_utc", []),
            "normally_active": same_hour >= max(1, days // 2) if days else None,
            "note": "No other days of history to compare." if not days else None}


def behavior_history(db: Session, ws: int, kind: str, name: str, *, event_type: str | None = None,
                     text: str | None = None, source_ip: str | None = None, destination: str | None = None,
                     off_hours: bool = False, before: datetime | None = None, business_hours=(7, 20)) -> dict:
    """Has this entity done this before? Counts matching events and when they first/last happened."""
    evs = _events(db, ws, kind, name, end=before)
    matches = []
    for e in evs:
        if event_type and e.event_type != event_type:
            continue
        if text and text.lower() not in f"{e.process or ''} {e.command or ''} {e.resource or ''}".lower():
            continue
        if source_ip and e.source_ip != source_ip:
            continue
        if destination and destination not in (e.destination_ip, (e.resource or "").lower()):
            continue
        if off_hours and not is_off_hours(e.timestamp, business_hours):
            continue
        matches.append(e)
    days = sorted({e.timestamp.date().isoformat() for e in matches})
    return {"entity": _key(kind, name), "matching_events": len(matches), "distinct_days": len(days), "days": days[:30],
            "first": matches[0].timestamp.isoformat() + "Z" if matches else None,
            "last": matches[-1].timestamp.isoformat() + "Z" if matches else None,
            "examples": [e.event_uid for e in matches[:8]], "history_events_checked": len(evs)}


def primary_host(db: Session, ws: int, user: str) -> str | None:
    row = db.execute(select(Event.host, func.count()).where(Event.workspace_id == ws, Event.user == user.lower(),
                                                              Event.host.is_not(None), Event.event_type != "authentication")
                     .group_by(Event.host).order_by(func.count().desc()).limit(1)).first()
    return row[0] if row else None


def peer_group(db: Session, ws: int, user: str) -> dict:
    """Compare a user with peers sharing the same workstation naming group (e.g. NB-WS-TR*), else all users."""
    user = user.lower()
    host = primary_host(db, ws, user)
    prefix = re.sub(r"\d+$", "", host) if host else None
    users = [u for (u,) in db.execute(select(Event.user).where(Event.workspace_id == ws, Event.user.is_not(None)).distinct())]
    peers = [u for u in users if u != user and prefix and (primary_host(db, ws, u) or "").startswith(prefix)] if prefix else []
    basis = f"users whose main workstation starts with {prefix}" if len(peers) >= 2 else "all users in the workspace"
    if len(peers) < 2:
        peers = [u for u in users if u != user]

    def feats(u: str) -> dict:
        rows = db.execute(select(Event.event_type, Event.status, Event.bytes, Event.timestamp, Event.source_ip, Event.host,
                                 Event.destination_ip).where(Event.workspace_id == ws, Event.user == u)).all()
        days = max(1, len({r.timestamp.date() for r in rows}))
        return {"events_per_day": len(rows) / days,
                "failed_logins_per_day": sum(1 for r in rows if r.event_type == "authentication" and r.status == "failure") / days,
                "distinct_source_ips": len({r.source_ip for r in rows if r.source_ip}),
                "distinct_hosts": len({r.host for r in rows if r.host}),
                "external_mb": sum((r.bytes or 0) for r in rows if r.event_type == "network" and is_external_ip(r.destination_ip)) / 1e6,
                "privilege_events": sum(1 for r in rows if r.event_type == "privilege"),
                "off_hours_share": round(sum(1 for r in rows if is_off_hours(r.timestamp, (7, 20))) / max(1, len(rows)), 3)}

    mine = feats(user)
    peer_feats = [feats(p) for p in peers[:40]]
    comparison = []
    for k, v in mine.items():
        vals = sorted(p[k] for p in peer_feats) or [0]
        med = vals[len(vals) // 2]
        comparison.append({"feature": k, "value": round(v, 3), "peer_median": round(med, 3),
                           "ratio_to_peers": round(v / med, 2) if med else None,
                           "above_all_peers": bool(peer_feats) and v > max(vals)})
    return {"user": user, "primary_host": host, "peer_basis": basis, "peers": peers[:40], "comparison": comparison}


def risk_history(db: Session, ws: int, kind: str, name: str) -> list[dict]:
    """Daily SentinelX risk points from detections and anomalous behavior windows (transparent, additive)."""
    key = _key(kind, name)
    col = {"user": Detection.user, "host": Detection.host, "ip": Detection.source_ip}[kind]
    per_day: dict = defaultdict(lambda: {"points": 0, "detections": [], "anomalies": 0})
    for d in db.query(Detection).filter(Detection.workspace_id == ws, col == key):
        day = d.timestamp.date().isoformat()
        per_day[day]["points"] += DET_POINTS.get(d.severity, 0)
        per_day[day]["detections"].append(f"{d.rule_key} ({d.severity})")
    if kind in ("user", "host"):
        for a in db.query(AnomalyResult).filter_by(workspace_id=ws, entity_type=kind, entity=key, is_anomalous=True):
            day = a.window_start.date().isoformat()
            per_day[day]["points"] += 8
            per_day[day]["anomalies"] += 1
    days = sorted({e.timestamp.date().isoformat() for e in _events(db, ws, kind, name, limit=100000)} | set(per_day))
    return [{"day": d, "risk_points": min(100, per_day[d]["points"]), "detections": per_day[d]["detections"],
             "anomalous_windows": per_day[d]["anomalies"]} for d in days]


def risk_movers(db: Session, ws: int, kind: str = "user", limit: int = 10) -> list[dict]:
    """Entities whose daily risk points rose the most on the latest day compared with their earlier average."""
    col = _col(kind) if kind != "ip" else Event.source_ip
    names = [n for (n,) in db.execute(select(col).where(Event.workspace_id == ws, col.is_not(None)).distinct())]
    last = latest_ts(db, ws)
    if not last:
        return []
    last_day = last.date().isoformat()
    out = []
    for n in names:
        hist = risk_history(db, ws, kind, n)
        if not hist:
            continue
        latest = next((h for h in hist if h["day"] == last_day), {"risk_points": 0, "detections": [], "anomalous_windows": 0})
        prev = [h["risk_points"] for h in hist if h["day"] < last_day]
        avg = sum(prev) / len(prev) if prev else 0
        delta = latest["risk_points"] - avg
        if delta > 0:
            out.append({"entity": n, "kind": kind, "latest_day": last_day, "latest_points": latest["risk_points"],
                        "previous_daily_average": round(avg, 1), "increase": round(delta, 1),
                        "drivers": latest["detections"] + ([f"{latest['anomalous_windows']} anomalous window(s)"]
                                                           if latest["anomalous_windows"] else [])})
    out.sort(key=lambda x: -x["increase"])
    return out[:limit]


def life_story(db: Session, ws: int, kind: str, name: str) -> list[dict]:
    evs = _events(db, ws, kind, name, limit=100000)
    by_day: dict = defaultdict(list)
    for e in evs:
        by_day[e.timestamp.date().isoformat()].append(e)
    col = {"user": Detection.user, "host": Detection.host, "ip": Detection.source_ip}[kind]
    dets = defaultdict(list)
    for d in db.query(Detection).filter(Detection.workspace_id == ws, col == _key(kind, name)):
        dets[d.timestamp.date().isoformat()].append(f"{d.rule_key}: {d.title}")
    anomalies = {a.window_start.date().isoformat(): a for a in db.query(AnomalyResult).filter_by(
        workspace_id=ws, entity_type=kind, entity=_key(kind, name))} if kind in ("user", "host") else {}
    story = []
    for day in sorted(by_day):
        items = by_day[day]
        a = anomalies.get(day)
        story.append({
            "day": day, "events": len(items), "first": items[0].timestamp.strftime("%H:%M"),
            "last": items[-1].timestamp.strftime("%H:%M"),
            "event_types": dict(Counter(e.event_type for e in items)),
            "hosts" if kind == "user" else "users": sorted({(e.host if kind == "user" else e.user) or "" for e in items} - {""})[:8],
            "source_ips": sorted({e.source_ip for e in items if e.source_ip})[:8],
            "detections": dets.get(day, []),
            "anomalous": bool(a and a.is_anomalous), "anomaly_score": a.if_score if a else None,
        })
    return story


def environment_changes(db: Session, ws: int, hours: float = 24) -> dict:
    """Compare the latest window of data with everything before it."""
    last = latest_ts(db, ws)
    if not last:
        return {"note": "No telemetry."}
    cut = last - timedelta(hours=hours)
    rows = db.execute(select(Event.timestamp, Event.user, Event.host, Event.source_ip, Event.destination_ip,
                             Event.process, Event.event_type, Event.resource).where(Event.workspace_id == ws)).all()
    before, recent = [r for r in rows if r.timestamp < cut], [r for r in rows if r.timestamp >= cut]

    def firsts(attr):
        seen = {getattr(r, attr) for r in before if getattr(r, attr)}
        return sorted({getattr(r, attr) for r in recent if getattr(r, attr)} - seen)[:25]

    prior_days = max(1, len({r.timestamp.date() for r in before}))
    vol = []
    for t in sorted({r.event_type for r in rows}):
        now_n = sum(1 for r in recent if r.event_type == t)
        prev = sum(1 for r in before if r.event_type == t) / prior_days * (hours / 24)
        vol.append({"event_type": t, "recent": now_n, "expected_from_history": round(prev, 1),
                    "change_pct": round((now_n - prev) / prev * 100) if prev else None})
    new_dets = db.query(Detection).filter(Detection.workspace_id == ws, Detection.timestamp >= cut).all()
    new_incs = db.query(Incident).filter(Incident.workspace_id == ws, Incident.first_seen >= cut).all()
    return {"window": {"start": cut.isoformat() + "Z", "end": last.isoformat() + "Z", "hours": hours},
            "new_users": firsts("user"), "new_hosts": firsts("host"), "new_source_ips": firsts("source_ip"),
            "new_destinations": firsts("destination_ip"), "new_processes": firsts("process"),
            "volume_by_event_type": vol,
            "new_detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity} for d in new_dets[:25]],
            "new_incidents": [{"id": i.id, "number": i.number, "title": i.title, "severity": i.severity} for i in new_incs],
            "note": "Window is relative to the newest stored event, not wall-clock time."}


def events_around(db: Session, ws: int, event: Event, before_minutes: int = 30, after_minutes: int = 30,
                  same: str = "any", limit: int = 60) -> dict:
    lo, hi = event.timestamp - timedelta(minutes=before_minutes), event.timestamp + timedelta(minutes=after_minutes)
    conds = [Event.workspace_id == ws, Event.timestamp >= lo, Event.timestamp <= hi, Event.id != event.id]
    ors = []
    if same in ("any", "user") and event.user:
        ors.append(Event.user == event.user)
    if same in ("any", "host") and event.host:
        ors.append(Event.host == event.host)
    if same in ("any", "ip") and event.source_ip:
        ors.append(or_(Event.source_ip == event.source_ip, Event.destination_ip == event.source_ip))
    if ors:
        conds.append(or_(*ors))
    rows = list(db.scalars(select(Event).where(*conds).order_by(Event.timestamp).limit(limit * 2)))
    return {"anchor": event.event_uid, "anchor_time": event.timestamp.isoformat() + "Z",
            "before": [r for r in rows if r.timestamp <= event.timestamp][-limit:],
            "after": [r for r in rows if r.timestamp > event.timestamp][:limit]}


def unknown_unknowns(db: Session, ws: int) -> list[dict]:
    """Behavior no rule explains, and gaps in context."""
    findings = []
    det_days = {(d.user, d.timestamp.date()) for d in db.query(Detection).filter_by(workspace_id=ws)} | \
               {(d.host, d.timestamp.date()) for d in db.query(Detection).filter_by(workspace_id=ws)}
    for a in db.query(AnomalyResult).filter_by(workspace_id=ws, is_anomalous=True):
        if (a.entity, a.window_start.date()) not in det_days:
            findings.append({"type": "unexplained_anomaly", "entity_type": a.entity_type, "entity": a.entity,
                             "day": a.window_start.date().isoformat(), "score": a.if_score,
                             "detail": "Behavior flagged as anomalous with no detection explaining it: "
                                       + "; ".join(f"{d['label']}={d['value']:g}" for d in a.top_deviations[:3])})
    types_by_host = defaultdict(set)
    for host, t in db.execute(select(Event.host, Event.event_type).where(Event.workspace_id == ws, Event.host.is_not(None)).distinct()):
        types_by_host[host].add(t)
    for host, types in types_by_host.items():
        if "authentication" in types and "process" not in types and host.startswith(("NB-WS", "WS")):
            findings.append({"type": "missing_telemetry", "entity_type": "host", "entity": host,
                             "detail": "Logons are recorded but no process telemetry exists for this workstation."})
    other = db.scalar(select(func.count()).where(Event.workspace_id == ws, Event.event_type == "other")) or 0
    if other:
        findings.append({"type": "unclassified_events", "entity_type": "workspace", "entity": "",
                         "detail": f"{other} events could not be classified into a known event type."})
    return findings[:60]
