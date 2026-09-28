"""Turn hunt results into incidents (analyst-confirmed, created by the backend)."""

from sqlalchemy.orm import Session

from app.analysis import hunts as hunt_mod
from app.models import Event, Hunt, Incident, IncidentEvent, IncidentStatusHistory, Workspace
from app.services.notifications import notify_workspace


def incident_from_hunt(db: Session, workspace: Workspace, hunt: Hunt, title: str, event_ids: list[str] | None,
                       user_id: int) -> Incident:
    res = hunt_mod.run(db, workspace.id, {**hunt.spec, "limit": 500})
    uids = [e["event_uid"] for e in res["events"]]
    if event_ids:
        wanted = {str(x) for x in event_ids}
        uids = [u for u in uids if u in wanted]
    if not uids:
        raise LookupError("The hunt has no matching events to build an incident from.")
    events = db.query(Event).filter(Event.workspace_id == workspace.id, Event.event_uid.in_(uids[:200])).order_by(Event.timestamp).all()
    workspace.incident_seq = (workspace.incident_seq or 0) + 1
    inc = Incident(workspace_id=workspace.id, number=f"INC-{workspace.incident_seq:04d}", title=title[:255],
                   severity="medium", first_seen=events[0].timestamp, last_seen=events[-1].timestamp, status="NEW",
                   origin="hunt", created_by_id=user_id,
                   users=sorted({e.user for e in events if e.user})[:50], hosts=sorted({e.host for e in events if e.host})[:50],
                   source_ips=sorted({e.source_ip for e in events if e.source_ip})[:50],
                   destination_ips=sorted({e.destination_ip for e in events if e.destination_ip})[:50],
                   stages=["Hunt finding"], risk_score=0, risk_band="Low",
                   correlation_reason=f"Created from hunt {hunt.number} ('{hunt.name}'): {len(events)} matching event(s).",
                   summary=f"Hunt {hunt.number} matched {len(events)} event(s) between {events[0].timestamp:%Y-%m-%d %H:%M} "
                           f"and {events[-1].timestamp:%Y-%m-%d %H:%M} UTC.",
                   checklist=[{"item": "Review the hunt matches", "done": False},
                              {"item": "Decide whether the behavior is malicious or benign", "done": False},
                              {"item": "Create a candidate detection if the behavior should alert in future", "done": False}])
    db.add(inc)
    db.flush()
    for e in events:
        db.add(IncidentEvent(incident_id=inc.id, event_id=e.id, role="evidence"))
    db.add(IncidentStatusHistory(incident_id=inc.id, to_status="NEW", changed_by_id=user_id,
                                 note=f"Created from hunt {hunt.number}"))
    notify_workspace(db, workspace.id, "new_incident", f"New incident {inc.number} from hunt {hunt.number}", inc.title,
                     f"/incidents/{inc.id}", severity="medium")
    db.flush()
    return inc
