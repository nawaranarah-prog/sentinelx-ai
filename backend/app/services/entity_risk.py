"""SentinelX User Risk / Host Risk: transparent additive scores from observed activity (not probabilities)."""

from collections import defaultdict

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnomalyResult, Detection, Event, Host, Incident
from app.models.incident import OPEN_STATUSES
from app.services.risk import band

DET_POINTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
CRIT_POINTS = {"critical": 15, "high": 8, "medium": 0, "low": 0}
PRIV_PATTERNS = ("admin", "adm.", "adm_", "administrator", "root")


def _score(kind: str, name: str, dets: list, open_incidents: list, anomalies: list, extra: list[dict]) -> dict:
    factors = []
    det_pts = min(40, sum(DET_POINTS.get(d.severity, 0) for d in dets))
    factors.append({"factor": "Detections", "points": det_pts, "max": 40,
                    "detail": f"{len(dets)} detection(s) involving this {kind}" +
                              (f" (most severe: {max(dets, key=lambda d: DET_POINTS[d.severity]).severity})" if dets else "")})
    inc_pts = min(20, 10 * len(open_incidents))
    factors.append({"factor": "Open incidents", "points": inc_pts, "max": 20,
                    "detail": f"{len(open_incidents)} open incident(s): " + ", ".join(i.number for i in open_incidents[:5])
                    if open_incidents else "No open incidents"})
    flagged = [a for a in anomalies if a.is_anomalous]
    an_pts = min(16, 8 * len(flagged))
    factors.append({"factor": "Behavioral anomalies", "points": an_pts, "max": 16,
                    "detail": f"{len(flagged)} anomalous day(s) out of {len(anomalies)} analysed"})
    ti = [d for d in dets if d.rule_key == "SX-010"]
    factors.append({"factor": "Threat intelligence", "points": 8 if ti else 0, "max": 8,
                    "detail": f"{len(ti)} indicator match(es)" if ti else "No indicator matches"})
    factors.extend(extra)
    score = min(100, sum(f["points"] for f in factors))
    return {"entity_type": kind, "name": name, "risk_score": score, "risk_band": band(score), "factors": factors,
            "detection_count": len(dets), "open_incident_count": len(open_incidents),
            "anomalous_days": len(flagged)}


def compute_entity_risks(db: Session, workspace_id: int, kind: str) -> list[dict]:
    col = Event.user if kind == "user" else Event.host
    ev_counts = dict(db.execute(select(col, func.count()).where(Event.workspace_id == workspace_id, col.is_not(None))
                                .group_by(col)).all())
    dcol = Detection.user if kind == "user" else Detection.host
    dets_by: dict[str, list] = defaultdict(list)
    for d in db.query(Detection).filter(Detection.workspace_id == workspace_id, dcol.is_not(None)):
        dets_by[getattr(d, kind)].append(d)
    incs_by: dict[str, list] = defaultdict(list)
    for inc in db.query(Incident).filter(Incident.workspace_id == workspace_id, Incident.status.in_(OPEN_STATUSES)):
        for name in (inc.users if kind == "user" else inc.hosts) or []:
            incs_by[name].append(inc)
    an_by: dict[str, list] = defaultdict(list)
    for a in db.query(AnomalyResult).filter_by(workspace_id=workspace_id, entity_type=kind):
        an_by[a.entity].append(a)
    crit = {h.hostname: h for h in db.query(Host).filter_by(workspace_id=workspace_id)} if kind == "host" else {}
    out = []
    for name, count in ev_counts.items():
        extra = []
        if kind == "user":
            priv = any(p in name for p in PRIV_PATTERNS)
            extra.append({"factor": "Privileged account", "points": 8 if priv else 0, "max": 8,
                          "detail": "Account name indicates administrative privileges" if priv else "Standard account"})
        else:
            h = crit.get(name)
            level = h.criticality if h else "medium"
            extra.append({"factor": "Asset criticality", "points": CRIT_POINTS.get(level, 0), "max": 15,
                          "detail": f"Criticality {level} ({h.criticality_source}: {h.role_hint})" if h else "Unknown"})
        item = _score(kind, name, dets_by.get(name, []), incs_by.get(name, []), an_by.get(name, []), extra)
        item["event_count"] = count
        if kind == "host" and name in crit:
            item["criticality"] = crit[name].criticality
            item["host_id"] = crit[name].id
        out.append(item)
    out.sort(key=lambda x: (-x["risk_score"], -x["event_count"]))
    return out
