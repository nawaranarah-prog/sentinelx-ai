"""Resolve SentinelX object references in free text, and verify citation tokens against the database.

Citation tokens used by the assistant look like [INC:INC-0006], [EVT:NB-000123], [USER:t.nguyen],
[HOST:NB-WS-TR07], [IP:203.0.113.45], [DET:12], [RULE:SX-001], [TECH:T1059.001], [IOC:mega.nz],
[INV:INV-0001], [HUNT:HUNT-0001], [DOMAIN:mega.nz], [PROC:powershell.exe].
"""

import ipaddress
import re

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.mitre.catalog import TECHNIQUE_INDEX
from app.models import Detection, DetectionRule, Event, GraphNode, Host, Hunt, Incident, Investigation, ThreatIndicator

CITATION = re.compile(r"\[(INC|EVT|USER|HOST|IP|DET|RULE|TECH|IOC|INV|HUNT|DOMAIN|PROC):([^\]\s][^\]]{0,120})\]")
_INC = re.compile(r"\bINC-\d{3,}\b", re.I)
_INV = re.compile(r"\bINV-\d{3,}\b", re.I)
_HUNT = re.compile(r"\bHUNT-\d{3,}\b", re.I)
_DET = re.compile(r"\bDET-(\d+)\b|\bdetection #?(\d+)\b", re.I)
_RULE = re.compile(r"\bSX-(?:C?\d{2,3})\b", re.I)
_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._\-\\]{2,127}")


def link_for(kind: str, ident: str) -> str:
    return {"INC": f"/incidents/{ident}", "EVT": f"/events/{ident}", "USER": f"/entities/user/{ident}",
            "HOST": f"/entities/host/{ident}", "IP": f"/threat-intel?q={ident}", "DET": f"/detections/{ident}",
            "RULE": f"/detection-lab?rule={ident}", "TECH": f"/mitre?technique={ident}", "IOC": f"/threat-intel?q={ident}",
            "INV": f"/investigations/{ident}", "HUNT": f"/hunts/{ident}", "DOMAIN": f"/threat-intel?q={ident}",
            "PROC": f"/events?q={ident}"}.get(kind, "#")


def exists(db: Session, ws: int, kind: str, ident: str) -> bool:
    ident = ident.strip()
    if kind == "INC":
        return db.query(Incident.id).filter_by(workspace_id=ws, number=ident.upper()).first() is not None
    if kind == "EVT":
        return db.query(Event.id).filter_by(workspace_id=ws, event_uid=ident).first() is not None
    if kind == "USER":
        return db.query(Event.id).filter_by(workspace_id=ws, user=ident.lower()).first() is not None
    if kind == "HOST":
        return (db.query(Host.id).filter_by(workspace_id=ws, hostname=ident.upper()).first() is not None or
                db.query(Event.id).filter_by(workspace_id=ws, host=ident.upper()).first() is not None)
    if kind == "IP":
        return db.query(Event.id).filter(Event.workspace_id == ws, or_(Event.source_ip == ident,
                                                                        Event.destination_ip == ident)).first() is not None
    if kind == "DET":
        num = ident.upper().removeprefix("DET-")
        return num.isdigit() and db.query(Detection.id).filter_by(workspace_id=ws, id=int(num)).first() is not None
    if kind == "RULE":
        return db.query(DetectionRule.id).filter_by(workspace_id=ws, rule_key=ident.upper()).first() is not None
    if kind == "TECH":
        return ident.upper() in TECHNIQUE_INDEX
    if kind == "IOC":
        return db.query(ThreatIndicator.id).filter(ThreatIndicator.workspace_id == ws,
                                                   ThreatIndicator.value.ilike(ident)).first() is not None
    if kind == "INV":
        return db.query(Investigation.id).filter_by(workspace_id=ws, number=ident.upper()).first() is not None
    if kind == "HUNT":
        return db.query(Hunt.id).filter_by(workspace_id=ws, number=ident.upper()).first() is not None
    if kind in ("DOMAIN", "PROC"):
        return db.query(GraphNode.id).filter_by(workspace_id=ws, kind="domain" if kind == "DOMAIN" else "process",
                                                key=ident.lower()).first() is not None
    return False


def verify_citations(db: Session, ws: int, text: str) -> tuple[str, list[dict], list[str]]:
    """Returns (text with unverifiable tokens marked, verified citations, invalid tokens)."""
    verified, invalid, cache = [], [], {}

    def repl(m: re.Match) -> str:
        kind, ident = m.group(1), m.group(2).strip()
        key = (kind, ident)
        if key not in cache:
            cache[key] = exists(db, ws, kind, ident)
        if cache[key]:
            if not any(c["type"] == kind and c["id"] == ident for c in verified):
                verified.append({"type": kind, "id": ident, "link": link_for(kind, ident)})
            return m.group(0)
        invalid.append(f"{kind}:{ident}")
        return f"⟨unverified reference {kind}:{ident} removed⟩"

    return CITATION.sub(repl, text or ""), verified, sorted(set(invalid))


def resolve_references(db: Session, ws: int, text: str, limit: int = 12) -> list[dict]:
    """Find SentinelX objects mentioned in free text (IDs, IPs, techniques, known users/hosts)."""
    refs: list[dict] = []

    def add(kind: str, ident: str, label: str | None = None):
        if len(refs) < limit and not any(r["type"] == kind and r["id"] == ident for r in refs):
            refs.append({"type": kind, "id": ident, "label": label or ident, "link": link_for(kind, ident)})

    for m in _INC.findall(text):
        inc = db.query(Incident).filter_by(workspace_id=ws, number=m.upper()).first()
        if inc:
            add("INC", inc.number, f"{inc.number} · {inc.title}")
    for m in _INV.findall(text):
        if exists(db, ws, "INV", m):
            add("INV", m.upper())
    for m in _HUNT.findall(text):
        if exists(db, ws, "HUNT", m):
            add("HUNT", m.upper())
    for a, b in _DET.findall(text):
        num = a or b
        if num and exists(db, ws, "DET", num):
            add("DET", num, f"Detection #{num}")
    for m in _RULE.findall(text):
        if exists(db, ws, "RULE", m):
            add("RULE", m.upper())
    for m in _TECH.findall(text):
        if m.upper() in TECHNIQUE_INDEX:
            add("TECH", m.upper(), f"{m.upper()} {TECHNIQUE_INDEX[m.upper()]['name']}")
    for m in _IP.findall(text):
        try:
            ipaddress.ip_address(m)
        except ValueError:
            continue
        if exists(db, ws, "IP", m):
            add("IP", m)
    tokens = {t.strip(".,;:!?()'\"") for t in _TOKEN.findall(text)}
    tokens = {t for t in tokens if len(t) >= 3}
    if tokens:
        lowered = [t.lower() for t in tokens]
        uppered = [t.upper() for t in tokens]
        for (uid,) in db.execute(select(Event.event_uid).where(Event.workspace_id == ws, Event.event_uid.in_(tokens)).limit(5)):
            add("EVT", uid)
        for (u,) in db.execute(select(Event.user).where(Event.workspace_id == ws, Event.user.in_(lowered)).distinct().limit(5)):
            add("USER", u)
        for (h,) in db.execute(select(Event.host).where(Event.workspace_id == ws, Event.host.in_(uppered)).distinct().limit(5)):
            add("HOST", h)
        for ind in db.query(ThreatIndicator).filter(ThreatIndicator.workspace_id == ws,
                                                    ThreatIndicator.value.in_(lowered + list(tokens))).limit(5):
            add("IOC", ind.value)
    return refs
