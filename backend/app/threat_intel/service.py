import csv
import io
import ipaddress
import json
import re

from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.serializers import event_brief, incident_brief, iso
from app.models import Event, Incident, ThreatIndicator

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{3,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$", re.I)


def detect_type(value: str) -> str:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(v):
        return "hash"
    if DOMAIN_RE.match(v):
        return "domain"
    if re.match(r"^[A-Z0-9][A-Z0-9-]{1,62}$", v) and "-" in v and v.upper() == v:
        return "hostname"
    return "username"


def normalize_value(value: str, itype: str) -> str:
    v = value.strip()
    if itype in ("domain", "username", "hash"):
        return v.lower()
    if itype == "hostname":
        return v.upper()
    return v


def indicator_payload(i: ThreatIndicator) -> dict:
    return {"id": i.id, "value": i.value, "indicator_type": i.indicator_type, "source": i.source,
            "is_synthetic": i.is_synthetic, "confidence": i.confidence, "severity": i.severity,
            "description": i.description, "tags": i.tags or [], "first_seen": iso(i.first_seen),
            "last_seen": iso(i.last_seen), "active": i.active, "created_at": iso(i.created_at)}


def sightings(db: Session, workspace_id: int, value: str, itype: str, limit: int = 25) -> dict:
    conds = {
        "ip": or_(Event.source_ip == value, Event.destination_ip == value),
        "hostname": Event.host == value.upper(),
        "username": Event.user == value.lower(),
        "domain": Event.resource.ilike(f"%{value}%"),
        "hash": cast(Event.raw, String).ilike(f"%{value}%"),
    }[itype]
    base = select(Event).where(Event.workspace_id == workspace_id, conds)
    total = db.scalar(select(func.count()).select_from(base.subquery()))
    events = db.scalars(base.order_by(Event.timestamp.desc()).limit(limit)).all()
    rng = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp)).where(
        Event.workspace_id == workspace_id, conds)).one()
    incidents = []
    for inc in db.query(Incident).filter(Incident.workspace_id == workspace_id).all():
        pool = {"ip": (inc.source_ips or []) + (inc.destination_ips or []), "hostname": inc.hosts or [],
                "username": inc.users or []}.get(itype, [])
        if normalize_value(value, itype) in pool:
            incidents.append(incident_brief(inc))
    return {"event_count": total, "events": [event_brief(e) for e in events], "incidents": incidents,
            "first_observed": iso(rng[0]), "last_observed": iso(rng[1])}


def search(db: Session, workspace_id: int, query: str) -> dict:
    q = query.strip()[:255]
    itype = detect_type(q)
    value = normalize_value(q, itype)
    exact = db.query(ThreatIndicator).filter(ThreatIndicator.workspace_id == workspace_id,
                                             func.lower(ThreatIndicator.value) == value.lower()).all()
    partial = db.query(ThreatIndicator).filter(ThreatIndicator.workspace_id == workspace_id,
                                               ThreatIndicator.value.ilike(f"%{q}%")).limit(20).all()
    seen = {i.id for i in exact}
    related = [i for i in partial if i.id not in seen]
    return {"query": q, "detected_type": itype, "value": value,
            "matches": [indicator_payload(i) for i in exact], "partial_matches": [indicator_payload(i) for i in related],
            "sightings": sightings(db, workspace_id, value, itype),
            "verdict": ("Known indicator" if exact else
                        "Not present in this workspace's threat intelligence")}


def parse_indicator_file(filename: str, content: bytes) -> list[dict]:
    text = content.decode("utf-8-sig", errors="replace")
    if filename.lower().endswith(".json"):
        data = json.loads(text)
        items = data.get("indicators", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ValueError("JSON must be a list of indicators or {\"indicators\": [...]}")
        return [i for i in items if isinstance(i, dict)]
    if filename.lower().endswith((".csv", ".txt")):
        reader = csv.DictReader(io.StringIO(text))
        if reader.fieldnames and "value" in [f.strip().lower() for f in reader.fieldnames]:
            return [{k.strip().lower(): v for k, v in row.items() if k} for row in reader]
        return [{"value": line.strip()} for line in text.splitlines() if line.strip() and not line.startswith("#")]
    raise ValueError("Upload a .csv, .txt or .json indicator file")
