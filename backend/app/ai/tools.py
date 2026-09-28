"""Tools the SentinelX copilot can call. Every tool is scoped to the caller's workspace and checks the
caller's role server-side. No tool deletes data, executes commands, or contacts external systems.

Each tool returns JSON-serialisable data. Tools may append *artifacts* (rendered by the UI: hunt results,
graph paths, backtests, simulations, reports...) and record which evidence they returned, which feeds
citation checking and the investigation scorecard.
"""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.ai.guard import sanitize
from app.analysis import dna as dna_mod
from app.analysis import entities as ent
from app.analysis import hunts as hunt_mod
from app.analysis import investigations as inv_mod
from app.analysis import knowledge_graph as kg
from app.analysis import quality
from app.analysis import simulation as sim
from app.analysis.detection_lab import (
    RuleSpecError,
    backtest,
    next_custom_key,
    regression,
    rule_quality,
    validate_rule_spec,
)
from app.api.serializers import iso
from app.database.session import utcnow
from app.ingestion.normalizer import parse_timestamp
from app.mitre.catalog import TECHNIQUE_INDEX
from app.models import (
    AuditLog,
    Detection,
    DetectionEvent,
    DetectionRule,
    Event,
    Hunt,
    Incident,
    IncidentEvent,
    IncidentStatusHistory,
    IncidentTechnique,
    Investigation,
    Report,
    ThreatIndicator,
    Workspace,
)
from app.models.incident import OPEN_STATUSES
from app.rag import service as rag
from app.services.entity_risk import compute_entity_risks
from app.threat_intel import service as ti

log = logging.getLogger(__name__)
READ, ANALYST, ADMIN = "read", "analyst", "admin"
RESULT_LIMIT_CHARS = 14_000


@dataclass
class ToolContext:
    db: Session
    workspace: Workspace
    user_id: int
    role: str
    state: dict = field(default_factory=dict)
    reviewed_events: set = field(default_factory=set)
    reviewed_entities: set = field(default_factory=set)
    artifacts: list = field(default_factory=list)
    activity: list = field(default_factory=list)
    investigation: Investigation | None = None
    missing_telemetry: list = field(default_factory=list)

    @property
    def ws(self) -> int:
        return self.workspace.id

    @property
    def bh(self) -> tuple[int, int]:
        b = (self.workspace.settings or {}).get("business_hours") or [7, 20]
        return int(b[0]), int(b[1])

    def can(self, level: str) -> bool:
        if level == READ:
            return True
        if level == ANALYST:
            return self.role in ("ADMIN", "SOC_ANALYST")
        return self.role == "ADMIN"

    def focus(self, kind: str, value) -> None:
        self.state.setdefault("focus", {})[kind] = value


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    access: str
    fn: Callable
    summary: Callable[[dict, dict], str]


REGISTRY: dict[str, Tool] = {}


def tool(name: str, description: str, properties: dict | None = None, required: list[str] | None = None,
         access: str = READ, summary: Callable[[dict, dict], str] | None = None):
    def deco(fn):
        REGISTRY[name] = Tool(name, description, {"type": "object", "properties": properties or {},
                                                  "required": required or []}, access, fn,
                              summary or (lambda a, r: name.replace("_", " ").capitalize()))
        return fn
    return deco


def S(desc: str, **kw) -> dict:  # string property
    return {"type": "string", "description": desc, **kw}


def N(desc: str, **kw) -> dict:  # integer property
    return {"type": "integer", "description": desc, **kw}


KIND = {"type": "string", "enum": ["user", "host", "ip"], "description": "Entity kind"}


# ----------------------------------------------------------------------------------------------- helpers
def ev(e: Event, full: bool = False) -> dict:
    d = {"event_uid": e.event_uid, "time": iso(e.timestamp), "type": e.event_type, "action": e.action,
         "status": e.status, "user": e.user, "host": e.host, "src": e.source_ip, "dst": e.destination_ip,
         "process": e.process, "command": (e.command or "")[:300] or None, "resource": (e.resource or "")[:200] or None,
         "bytes": e.bytes, "severity": e.severity}
    if full:
        d["metadata"] = {k: v for k, v in (e.event_metadata or {}).items() if isinstance(v, (str, int, float, bool))}
        d["source"] = e.source
    return {k: v for k, v in d.items() if v not in (None, "")}


def _incident(ctx: ToolContext, ref) -> Incident:
    q = ctx.db.query(Incident).filter(Incident.workspace_id == ctx.ws)
    ref = str(ref or ctx.state.get("focus", {}).get("incident") or "").strip()
    inc = None
    if ref.upper().startswith("INC-"):
        inc = q.filter(Incident.number == ref.upper()).first()
    elif ref.isdigit():
        inc = q.filter(Incident.id == int(ref)).first()
    if inc is None:
        raise LookupError(f"Incident '{ref or '(none in focus)'}' not found in this workspace.")
    ctx.focus("incident", inc.number)
    return inc


def _event(ctx: ToolContext, ref) -> Event:
    ref = str(ref or ctx.state.get("focus", {}).get("event") or "").strip()
    e = ctx.db.query(Event).filter_by(workspace_id=ctx.ws, event_uid=ref).first()
    if e is None and ref.isdigit():
        e = ctx.db.query(Event).filter_by(workspace_id=ctx.ws, id=int(ref)).first()
    if e is None:
        raise LookupError(f"Event '{ref or '(none in focus)'}' not found in this workspace.")
    ctx.focus("event", e.event_uid)
    return e


def _entity(ctx: ToolContext, kind: str | None, name: str | None) -> tuple[str, str]:
    f = ctx.state.get("focus", {}).get("entity") or {}
    kind = kind or f.get("kind")
    name = name or f.get("name")
    if kind not in ("user", "host", "ip") or not name:
        raise LookupError("Specify the entity kind (user, host or ip) and name.")
    name = name.lower() if kind == "user" else name.upper() if kind == "host" else name
    ctx.focus("entity", {"kind": kind, "name": name})
    return kind, name


def _since(ctx: ToolContext, hours: float | None):
    if not hours:
        return None
    last = ent.latest_ts(ctx.db, ctx.ws)
    return (last or utcnow()) - timedelta(hours=float(hours))


# ----------------------------------------------------------------------------------------------- overview
@tool("get_environment_overview", "Current state of the workspace: data range, event/detection/incident counts, "
      "open incidents by risk, newest activity and biggest risk movers. Start here for broad questions.",
      summary=lambda a, r: "Reviewed environment overview")
def get_environment_overview(ctx: ToolContext) -> dict:
    db, ws = ctx.db, ctx.ws
    rng = db.execute(select(func.min(Event.timestamp), func.max(Event.timestamp)).where(Event.workspace_id == ws)).one()
    open_incs = db.query(Incident).filter(Incident.workspace_id == ws, Incident.status.in_(OPEN_STATUSES))\
        .order_by(Incident.risk_score.desc()).limit(8).all()
    return {
        "workspace": ctx.workspace.name, "mode": ctx.workspace.mode, "synthetic_demo_data": ctx.workspace.mode == "DEMO",
        "data_range": {"start": iso(rng[0]), "end": iso(rng[1])},
        "counts": {"events": db.scalar(select(func.count(Event.id)).where(Event.workspace_id == ws)),
                   "detections": db.scalar(select(func.count(Detection.id)).where(Detection.workspace_id == ws)),
                   "incidents": db.query(Incident).filter_by(workspace_id=ws).count(),
                   "open_incidents": db.query(Incident).filter(Incident.workspace_id == ws,
                                                               Incident.status.in_(OPEN_STATUSES)).count()},
        "open_incidents_by_risk": [{"number": i.number, "title": i.title, "severity": i.severity, "risk": i.risk_score,
                                    "status": i.status, "last_seen": iso(i.last_seen)} for i in open_incs],
        "risk_movers": ent.risk_movers(db, ws, "user", 5),
        "last_pipeline_run": iso(ctx.workspace.last_pipeline_run_at),
    }


# ----------------------------------------------------------------------------------------------- events
@tool("search_events", "Search normalized telemetry. Combine filters; times are ISO 8601 UTC. Use last_hours for "
      "relative windows (relative to the newest stored event). Returns newest first unless sort='asc'.",
      {"query": S("Text contained in command, process, resource, action or event ID"),
       "event_type": {"type": "string", "enum": ["authentication", "process", "file", "network", "privilege", "other"]},
       "user": S("Exact user name"), "host": S("Exact host name"), "ip": S("Source or destination IP"),
       "status": {"type": "string", "enum": ["success", "failure"]}, "action": S("Action contains"),
       "start": S("ISO start time"), "end": S("ISO end time"), "last_hours": {"type": "number"},
       "sort": {"type": "string", "enum": ["asc", "desc"]}, "limit": N("Max events (default 40, max 100)")},
      summary=lambda a, r: f"Searched events ({r.get('total', 0)} matched)")
def search_events(ctx: ToolContext, query=None, event_type=None, user=None, host=None, ip=None, status=None, action=None,
                  start=None, end=None, last_hours=None, sort="desc", limit=40) -> dict:
    c = [Event.workspace_id == ctx.ws]
    if query:
        like = f"%{query[:120]}%"
        c.append(or_(Event.command.ilike(like), Event.process.ilike(like), Event.resource.ilike(like),
                     Event.action.ilike(like), Event.event_uid.ilike(like)))
    for col, val in ((Event.event_type, event_type), (Event.status, status)):
        if val:
            c.append(col == val)
    if user:
        c.append(Event.user == user.lower())
    if host:
        c.append(Event.host == host.upper())
    if ip:
        c.append(or_(Event.source_ip == ip, Event.destination_ip == ip))
    if action:
        c.append(Event.action.ilike(f"%{action}%"))
    s = parse_timestamp(start) if start else _since(ctx, last_hours)
    if s:
        c.append(Event.timestamp >= s)
    if end and (e_ := parse_timestamp(end)):
        c.append(Event.timestamp <= e_)
    total = ctx.db.scalar(select(func.count(Event.id)).where(*c))
    order = Event.timestamp.asc() if sort == "asc" else Event.timestamp.desc()
    rows = ctx.db.scalars(select(Event).where(*c).order_by(order).limit(min(int(limit or 40), 100))).all()
    return {"total": total, "returned": len(rows), "events": [ev(e) for e in rows]}


@tool("get_event", "Full details of one event by its event ID, including metadata and the detections/incidents "
      "that reference it.", {"event_id": S("Event ID (event_uid)")}, ["event_id"],
      summary=lambda a, r: f"Retrieved event {a.get('event_id')}")
def get_event(ctx: ToolContext, event_id) -> dict:
    e = _event(ctx, event_id)
    dets = ctx.db.query(Detection).join(DetectionEvent, DetectionEvent.detection_id == Detection.id)\
        .filter(DetectionEvent.event_id == e.id).all()
    incs = ctx.db.query(Incident, IncidentEvent.role).join(IncidentEvent, IncidentEvent.incident_id == Incident.id)\
        .filter(IncidentEvent.event_id == e.id).all()
    return {**ev(e, full=True), "detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title} for d in dets],
            "incidents": [{"number": i.number, "role": role} for i, role in incs]}


@tool("events_around", "Events immediately before and after an event (same user, host or IP). Use for 'what "
      "happened before/after this'.",
      {"event_id": S("Anchor event ID (defaults to the event in focus)"), "before_minutes": N("Minutes before (default 30)"),
       "after_minutes": N("Minutes after (default 30)"), "same": {"type": "string", "enum": ["any", "user", "host", "ip"]}},
      summary=lambda a, r: f"Retrieved {len(r.get('before', []))} events before / {len(r.get('after', []))} after")
def events_around(ctx: ToolContext, event_id=None, before_minutes=30, after_minutes=30, same="any") -> dict:
    e = _event(ctx, event_id)
    res = ent.events_around(ctx.db, ctx.ws, e, int(before_minutes), int(after_minutes), same, limit=40)
    return {"anchor": ev(e), "before": [ev(x) for x in res["before"]], "after": [ev(x) for x in res["after"]]}


# ----------------------------------------------------------------------------------------------- incidents
@tool("search_incidents", "List incidents with filters. Sort by risk (default), last_seen or first_seen.",
      {"status": {"type": "string", "enum": ["NEW", "IN_PROGRESS", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]},
       "open_only": {"type": "boolean"}, "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
       "entity": S("User, host or IP involved"), "text": S("Title contains"), "technique": S("ATT&CK technique ID"),
       "sort": {"type": "string", "enum": ["risk", "last_seen", "first_seen"]}, "limit": N("Max (default 15)")},
      summary=lambda a, r: f"Searched incidents ({len(r.get('incidents', []))} found)")
def search_incidents(ctx: ToolContext, status=None, open_only=False, severity=None, entity=None, text=None,
                     technique=None, sort="risk", limit=15) -> dict:
    q = ctx.db.query(Incident).filter(Incident.workspace_id == ctx.ws)
    if status:
        q = q.filter(Incident.status == status)
    if open_only:
        q = q.filter(Incident.status.in_(OPEN_STATUSES))
    if severity:
        q = q.filter(Incident.severity == severity)
    if text:
        q = q.filter(Incident.title.ilike(f"%{text}%"))
    order = {"last_seen": Incident.last_seen.desc(), "first_seen": Incident.first_seen.desc()}.get(sort, Incident.risk_score.desc())
    rows = q.order_by(order).all()
    if entity:
        e = entity.strip()
        rows = [i for i in rows if e.lower() in [u.lower() for u in i.users] or e.upper() in i.hosts
                or e in (i.source_ips or []) + (i.destination_ips or [])]
    if technique:
        ids = {t.incident_id for t in ctx.db.query(IncidentTechnique).filter_by(technique_id=technique.upper())}
        rows = [i for i in rows if i.id in ids]
    return {"incidents": [{"number": i.number, "title": i.title, "status": i.status, "severity": i.severity,
                           "risk": i.risk_score, "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen),
                           "users": i.users[:5], "hosts": i.hosts[:5], "stages": i.stages} for i in rows[:min(int(limit or 15), 40)]]}


@tool("get_incident", "Facts of one incident: entities, detections with explanations and evidence IDs, techniques "
      "with mapping reasons, risk factors, anomalies, correlation reason, status history and Attack DNA.",
      {"incident": S("Incident number like INC-0006 (defaults to the incident in focus)")},
      summary=lambda a, r: f"Retrieved incident {r.get('number', a.get('incident'))}")
def get_incident(ctx: ToolContext, incident=None) -> dict:
    inc = _incident(ctx, incident)
    dets = ctx.db.query(Detection).filter_by(incident_id=inc.id).order_by(Detection.timestamp).all()
    techs = ctx.db.query(IncidentTechnique).filter_by(incident_id=inc.id).all()
    hist = ctx.db.query(IncidentStatusHistory).filter_by(incident_id=inc.id).order_by(IncidentStatusHistory.id).all()
    return {
        "number": inc.number, "title": inc.title, "status": inc.status, "severity": inc.severity,
        "confidence": inc.confidence, "risk_score": inc.risk_score, "risk_band": inc.risk_band,
        "risk_factors": [f for f in inc.risk_factors if f["points"] > 0], "first_seen": iso(inc.first_seen),
        "last_seen": iso(inc.last_seen), "users": inc.users, "hosts": inc.hosts, "source_ips": inc.source_ips,
        "destination_ips": inc.destination_ips, "stages": inc.stages, "correlation_reason": inc.correlation_reason,
        "detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity,
                        "confidence": d.confidence, "time": iso(d.timestamp), "stage": d.stage, "user": d.user,
                        "host": d.host, "explanation": d.explanation,
                        "evidence_event_uids": (d.evidence_summary or {}).get("event_uids", [])[:10],
                        "false_positives": d.false_positives[:2]} for d in dets],
        "techniques": [{"id": t.technique_id, "name": TECHNIQUE_INDEX.get(t.technique_id, {}).get("name"),
                        "reason": t.reason, "confidence": t.mapping_confidence, "evidence": t.event_uids[:5]} for t in techs],
        "anomalies": inc.anomaly_summary, "attack_dna": {k: inc.dna.get(k) for k in ("signature", "traits")} if inc.dna else None,
        "status_history": [{"to": h.to_status, "at": iso(h.changed_at), "note": h.note} for h in hist],
        "checklist": inc.checklist,
    }


@tool("get_incident_timeline", "Chronological evidence events of an incident (optionally including surrounding "
      "context events).", {"incident": S("Incident number"), "include_context": {"type": "boolean"},
                           "limit": N("Max events (default 80)")},
      summary=lambda a, r: f"Reconstructed timeline ({r.get('returned', 0)} events)")
def get_incident_timeline(ctx: ToolContext, incident=None, include_context=False, limit=80) -> dict:
    inc = _incident(ctx, incident)
    roles = ["evidence", "context"] if include_context else ["evidence"]
    rows = ctx.db.execute(select(Event, IncidentEvent.role).join(IncidentEvent, IncidentEvent.event_id == Event.id)
                          .where(IncidentEvent.incident_id == inc.id, IncidentEvent.role.in_(roles))
                          .order_by(Event.timestamp)).all()
    limit = min(int(limit or 80), 150)
    if len(rows) > limit:
        step = len(rows) / limit
        rows = [rows[int(i * step)] for i in range(limit)]
    det_map: dict[int, list[str]] = {}
    for eid, rk in ctx.db.execute(select(DetectionEvent.event_id, Detection.rule_key).join(
            Detection, Detection.id == DetectionEvent.detection_id).where(Detection.incident_id == inc.id)):
        det_map.setdefault(eid, []).append(rk)
    phases, prev = [], None
    for e, _role in rows:
        gap = (e.timestamp - prev).total_seconds() if prev else 0
        if not phases or gap > 900:
            phases.append({"start": iso(e.timestamp), "events": 0})
        phases[-1]["events"] += 1
        phases[-1]["end"] = iso(e.timestamp)
        prev = e.timestamp
    return {"incident": inc.number, "returned": len(rows),
            "phases": phases,
            "events": [{**ev(e), "role": role, "rules": sorted(set(det_map.get(e.id, [])))} for e, role in rows]}


@tool("search_evidence", "Search an incident's evidence and context events for text or an entity.",
      {"incident": S("Incident number"), "text": S("Text to look for"), "entity": S("User, host or IP")},
      summary=lambda a, r: f"Searched incident evidence ({len(r.get('events', []))} matches)")
def search_evidence(ctx: ToolContext, incident=None, text=None, entity=None) -> dict:
    inc = _incident(ctx, incident)
    rows = ctx.db.scalars(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id)
                          .where(IncidentEvent.incident_id == inc.id).order_by(Event.timestamp)).all()
    out = []
    for e in rows:
        blob = " ".join(filter(None, [e.command, e.process, e.resource, e.action, e.user, e.host, e.source_ip,
                                      e.destination_ip, e.event_uid])).lower()
        if (not text or text.lower() in blob) and (not entity or entity.lower() in blob):
            out.append(ev(e))
    return {"incident": inc.number, "events": out[:60], "total": len(out)}


# ----------------------------------------------------------------------------------------------- detections
@tool("search_detections", "Search detections by rule, severity, entity, incident or recency.",
      {"rule_key": S("Rule key like SX-005"), "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
       "entity": S("User, host or IP"), "incident": S("Incident number"), "last_hours": {"type": "number"},
       "standalone_only": {"type": "boolean"}, "limit": N("Max (default 25)")},
      summary=lambda a, r: f"Searched detections ({len(r.get('detections', []))} found)")
def search_detections(ctx: ToolContext, rule_key=None, severity=None, entity=None, incident=None, last_hours=None,
                      standalone_only=False, limit=25) -> dict:
    q = ctx.db.query(Detection).filter(Detection.workspace_id == ctx.ws)
    if rule_key:
        q = q.filter(Detection.rule_key == rule_key.upper())
    if severity:
        q = q.filter(Detection.severity == severity)
    if entity:
        q = q.filter(or_(Detection.user == entity.lower(), Detection.host == entity.upper(), Detection.source_ip == entity))
    if incident:
        q = q.filter(Detection.incident_id == _incident(ctx, incident).id)
    if standalone_only:
        q = q.filter(Detection.incident_id.is_(None))
    if s := _since(ctx, last_hours):
        q = q.filter(Detection.timestamp >= s)
    rows = q.order_by(Detection.timestamp.desc()).limit(min(int(limit or 25), 60)).all()
    incs = {i.id: i.number for i in ctx.db.query(Incident).filter(Incident.id.in_({d.incident_id for d in rows} or {0}))}
    return {"detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity,
                            "time": iso(d.timestamp), "user": d.user, "host": d.host, "source_ip": d.source_ip,
                            "incident": incs.get(d.incident_id)} for d in rows]}


@tool("get_detection", "Why a detection fired: rule definition and thresholds, the explanation built from matched "
      "events, matched event IDs, entities, ATT&CK mappings and false-positive guidance.",
      {"detection_id": N("Detection ID (DET-<id>)")}, ["detection_id"],
      summary=lambda a, r: f"Retrieved detection DET-{a.get('detection_id')}")
def get_detection(ctx: ToolContext, detection_id) -> dict:
    did = int(str(detection_id).upper().removeprefix("DET-"))
    d = ctx.db.query(Detection).filter_by(workspace_id=ctx.ws, id=did).first()
    if d is None:
        raise LookupError(f"Detection {detection_id} not found in this workspace.")
    ctx.focus("detection", d.id)
    rule = ctx.db.get(DetectionRule, d.rule_id) if d.rule_id else None
    evs = ctx.db.scalars(select(Event).join(DetectionEvent, DetectionEvent.event_id == Event.id)
                         .where(DetectionEvent.detection_id == d.id).order_by(Event.timestamp).limit(25)).all()
    inc = ctx.db.get(Incident, d.incident_id) if d.incident_id else None
    return {"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity, "confidence": d.confidence,
            "time": iso(d.timestamp), "last_seen": iso(d.last_seen), "explanation": d.explanation,
            "rule": {"name": rule.name, "description": rule.description, "parameters": {k: v for k, v in (rule.parameters or {}).items()
                                                                                        if not isinstance(v, list) or len(v) < 20},
                     "version": rule.version} if rule else None,
            "evidence_summary": {k: v for k, v in (d.evidence_summary or {}).items() if k != "event_uids"},
            "matched_events": [ev(e) for e in evs], "mitre": d.mitre, "false_positives": d.false_positives,
            "recommendations": d.recommendations, "incident": inc.number if inc else None}


@tool("rule_quality", "Detection rule health: detections produced, false-positive/dismissed share, regression "
      "failures on known scenarios, and evasion tests against realistic attack variations. Use for 'which rules "
      "are weak' or coverage questions.", summary=lambda a, r: "Evaluated rule quality (regression + evasion tests)")
def tool_rule_quality(ctx: ToolContext) -> dict:
    rows = rule_quality(ctx.db, ctx.workspace)
    ctx.artifacts.append({"type": "rule_quality", "rows": rows})
    return {"rules": rows}


@tool("test_detection", "Detection sandbox: run a rule (or all rules) against a synthetic attack scenario with "
      "optional variations, without storing anything.",
      {"scenario": S("Scenario id: credential_compromise, password_spray, insider_cloud_exfil, internal_scan, "
                     "admin_credential_dumping, macro_powershell, domain_admin_escalation"),
       "variations": {"type": "object", "description": "Scenario parameters, e.g. {\"attempt_interval_s\": 90}"},
       "rule_key": S("Optional rule key to focus on")}, ["scenario"],
      summary=lambda a, r: f"Ran detection sandbox on {a.get('scenario')}")
def test_detection(ctx: ToolContext, scenario, variations=None, rule_key=None) -> dict:
    res = sim.sandbox(ctx.db, ctx.workspace, scenario, variations or {})
    base = res["baseline"]
    out = {"scenario": scenario, "variations": variations or {}, "rules_fired": base["rules_fired"],
           "stages_detected": base["stages_detected"], "detections": base["detections"]}
    if rule_key:
        out["rule_detected"] = rule_key.upper() in base["rules_fired"]
    ctx.artifacts.append({"type": "sandbox", **out})
    return out


@tool("propose_detection", "Create a CANDIDATE detection rule (disabled until an admin activates it) from a "
      "structured spec: {name, description, severity, stage, mitre[], match:{event_types[], status, actions[], "
      "text_any[], text_all[], users[], hosts[], behaviors[off_hours|external_destination|large_transfer]}, "
      "threshold:{count, window_minutes, group_by(user|host|source_ip|destination_ip), distinct?}}. Backtest it next.",
      {"spec": {"type": "object"}}, ["spec"], access=ANALYST,
      summary=lambda a, r: f"Created candidate rule {r.get('rule_key', '')}")
def propose_detection(ctx: ToolContext, spec) -> dict:
    try:
        clean = validate_rule_spec(spec)
    except (RuleSpecError, ValueError, TypeError) as exc:
        raise LookupError(f"Invalid rule spec: {exc}") from None
    key = next_custom_key(ctx.db, ctx.ws)
    rule = DetectionRule(workspace_id=ctx.ws, rule_key=key, name=clean["name"], description=clean["description"] or clean["name"],
                         severity=clean["severity"], enabled=False, kind="candidate", parameters={"spec": clean},
                         mitre_techniques=clean["mitre"], stage=clean["stage"], updated_by_id=ctx.user_id)
    ctx.db.add(rule)
    ctx.db.flush()
    ctx.artifacts.append({"type": "candidate_rule", "rule_key": key, "spec": clean})
    return {"rule_key": key, "status": "candidate (disabled)", "spec": clean}


@tool("run_detection_backtest", "Backtest a rule (candidate or active) against all stored telemetry, the benign "
      "baseline dataset and each attack dataset. Reports alerts, overlap with incidents and false-positive signals.",
      {"rule_key": S("Rule key, e.g. SX-C01 or SX-001")}, ["rule_key"],
      summary=lambda a, r: f"Backtested {a.get('rule_key')} ({r.get('alerts', 0)} alerts)")
def run_detection_backtest(ctx: ToolContext, rule_key) -> dict:
    rule = ctx.db.query(DetectionRule).filter_by(workspace_id=ctx.ws, rule_key=str(rule_key).upper()).first()
    if rule is None:
        raise LookupError(f"Rule {rule_key} not found.")
    res = backtest(ctx.db, ctx.workspace, rule)
    params = dict(rule.parameters or {})
    params["last_backtest"] = {k: res[k] for k in ("alerts", "alerts_overlapping_incidents", "alerts_outside_incidents",
                                                    "benign_baseline_alerts", "scenario_coverage", "ran_at")}
    rule.parameters = params
    ctx.artifacts.append({"type": "backtest", **res})
    return res


@tool("run_regression_tests", "Run all enabled rules against every known scenario dataset to verify expected "
      "detections still fire and the benign dataset stays quiet.",
      summary=lambda a, r: f"Ran regression suite ({'passed' if r.get('passed') else 'failures found'})")
def run_regression_tests(ctx: ToolContext) -> dict:
    res = regression(ctx.db, ctx.workspace)
    ctx.artifacts.append({"type": "regression", **res})
    return res


# ----------------------------------------------------------------------------------------------- entities
@tool("search_entities", "Find users, hosts, IPs, processes, domains, file shares or groups by name.",
      {"query": S("Name or part of a name"), "kind": {"type": "string", "enum": list(kg.NODE_KINDS)}}, ["query"],
      summary=lambda a, r: f"Searched entities for '{a.get('query')}'")
def search_entities(ctx: ToolContext, query, kind=None) -> dict:
    nodes = kg.search_nodes(ctx.db, ctx.ws, query, kind, limit=25)
    return {"entities": [{"kind": n.kind, "name": n.label, "key": n.key, "first_seen": iso(n.first_seen),
                          "last_seen": iso(n.last_seen), **{k: v for k, v in n.props.items() if k in ("criticality", "severity")}}
                         for n in nodes]}


@tool("get_entity", "Summarize a user, host or IP: SentinelX risk score with factors, normal behavior (baseline), "
      "recent activity, detections, incidents and relationships.",
      {"kind": KIND, "name": S("User name, host name or IP")},
      summary=lambda a, r: f"Summarized {a.get('kind')} {a.get('name')}")
def get_entity(ctx: ToolContext, kind=None, name=None) -> dict:
    kind, name = _entity(ctx, kind, name)
    out: dict = {"kind": kind, "name": name}
    if kind in ("user", "host"):
        risks = {r["name"]: r for r in compute_entity_risks(ctx.db, ctx.ws, kind)}
        r = risks.get(name)
        if r is None:
            raise LookupError(f"No telemetry for {kind} '{name}'.")
        out["risk"] = {"score": r["risk_score"], "band": r["risk_band"],
                       "factors": [f for f in r["factors"] if f["points"] > 0]}
    base = ent.baseline(ctx.db, ctx.ws, kind, name)
    out["baseline"] = {k: base.get(k) for k in ("events", "days_observed", "first_seen", "last_seen",
                                                "usual_active_hours_utc", "event_types", "source_ips", "hosts",
                                                "users", "processes", "external_destinations")}
    col = {"user": Detection.user, "host": Detection.host, "ip": Detection.source_ip}[kind]
    dets = ctx.db.query(Detection).filter(Detection.workspace_id == ctx.ws, col == name).order_by(Detection.timestamp.desc()).limit(10).all()
    out["recent_detections"] = [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "time": iso(d.timestamp)} for d in dets]
    incs = search_incidents(ctx, entity=name, limit=8)["incidents"]
    out["incidents"] = [{"number": i["number"], "title": i["title"], "status": i["status"]} for i in incs]
    node = kg.find_node(ctx.db, ctx.ws, name, kind)
    if node:
        nb = kg.neighbors(ctx.db, ctx.ws, node.id, limit=25)
        labels = {n["id"]: f"{n['kind']}:{n['label']}" for n in nb["nodes"]}
        out["relationships"] = [{"rel": e["rel"], "with": labels.get(e["target"] if e["source"] == node.id else e["source"]),
                                 "count": e["count"]} for e in nb["edges"]]
    if base.get("events"):
        ctx.reviewed_entities.add(f"{kind}:{name}")
    return out


@tool("get_entity_timeline", "Chronological activity of an entity, or its day-by-day 'life story' when no time "
      "range is given.", {"kind": KIND, "name": S("Entity name"), "start": S("ISO start"), "end": S("ISO end"),
                          "limit": N("Max events (default 60)")},
      summary=lambda a, r: f"Retrieved timeline for {a.get('name') or 'entity'}")
def get_entity_timeline(ctx: ToolContext, kind=None, name=None, start=None, end=None, limit=60) -> dict:
    kind, name = _entity(ctx, kind, name)
    if not start and not end:
        return {"entity": name, "life_story": ent.life_story(ctx.db, ctx.ws, kind, name)}
    evs = ent._events(ctx.db, ctx.ws, kind, name, parse_timestamp(start) if start else None,
                      parse_timestamp(end) if end else None, limit=min(int(limit or 60), 150))
    return {"entity": name, "events": [ev(e) for e in evs]}


@tool("compare_to_baseline", "Is this normal for the entity? Compares an event or time against the entity's own "
      "history (hour-of-day profile, usual sources, hosts and volumes).",
      {"kind": KIND, "name": S("Entity name"), "at": S("ISO time to evaluate (defaults to the event in focus)")},
      summary=lambda a, r: f"Compared {a.get('name') or 'entity'} with its baseline")
def compare_to_baseline(ctx: ToolContext, kind=None, name=None, at=None) -> dict:
    kind, name = _entity(ctx, kind, name)
    when = parse_timestamp(at) if at else None
    if when is None and ctx.state.get("focus", {}).get("event"):
        e = ctx.db.query(Event).filter_by(workspace_id=ctx.ws, event_uid=ctx.state["focus"]["event"]).first()
        when = e.timestamp if e else None
    base = ent.baseline(ctx.db, ctx.ws, kind, name)
    out = {"baseline": base}
    if when:
        out["at"] = ent.was_active_at(ctx.db, ctx.ws, kind, name, when)
    from app.models import AnomalyResult

    rows = ctx.db.query(AnomalyResult).filter_by(workspace_id=ctx.ws, entity_type=kind, entity=name).all() if kind != "ip" else []
    out["anomalous_days"] = [{"day": a.window_start.date().isoformat(), "score": a.if_score, "threshold": a.if_threshold,
                              "deviations": a.top_deviations[:3]} for a in rows if a.is_anomalous]
    return out


@tool("behavior_history", "Has this entity done this before? Counts earlier matching behavior (event type, text, "
      "source IP, destination, off-hours).",
      {"kind": KIND, "name": S("Entity name"), "event_type": S("Event type"), "text": S("Command/process/resource text"),
       "source_ip": S("Source IP"), "destination": S("Destination IP or domain"), "off_hours": {"type": "boolean"},
       "before": S("Only count events before this ISO time")},
      summary=lambda a, r: f"Checked behavior history ({r.get('matching_events', 0)} earlier matches)")
def behavior_history(ctx: ToolContext, kind=None, name=None, event_type=None, text=None, source_ip=None,
                     destination=None, off_hours=False, before=None) -> dict:
    kind, name = _entity(ctx, kind, name)
    return ent.behavior_history(ctx.db, ctx.ws, kind, name, event_type=event_type, text=text, source_ip=source_ip,
                                destination=destination, off_hours=off_hours,
                                before=parse_timestamp(before) if before else None, business_hours=ctx.bh)


@tool("peer_comparison", "Compare a user's behavior with peers (users sharing the same workstation group, or all "
      "users).", {"name": S("User name")}, summary=lambda a, r: f"Compared {a.get('name') or 'user'} with peers")
def peer_comparison(ctx: ToolContext, name=None) -> dict:
    _, name = _entity(ctx, "user", name)
    return ent.peer_group(ctx.db, ctx.ws, name)


@tool("get_risk_history", "Daily SentinelX risk points for an entity with the detections/anomalies behind each day.",
      {"kind": KIND, "name": S("Entity name")}, summary=lambda a, r: f"Retrieved risk history for {a.get('name') or 'entity'}")
def get_risk_history(ctx: ToolContext, kind=None, name=None) -> dict:
    kind, name = _entity(ctx, kind, name)
    return {"entity": name, "history": ent.risk_history(ctx.db, ctx.ws, kind, name)}


@tool("risk_movers", "Entities whose risk increased most on the latest day of data versus their earlier average.",
      {"kind": KIND}, summary=lambda a, r: "Ranked risk increases")
def risk_movers(ctx: ToolContext, kind="user") -> dict:
    return {"movers": ent.risk_movers(ctx.db, ctx.ws, kind or "user", 10),
            "method": "Daily risk points = detection severity points + 8 per anomalous window; increase = latest day minus earlier daily average."}


@tool("environment_changes", "What changed recently: first-seen users, hosts, IPs, destinations and processes, "
      "event volume versus history, and new detections/incidents.",
      {"hours": {"type": "number", "description": "Window size in hours (default 24)"}},
      summary=lambda a, r: "Compared recent activity with history")
def environment_changes(ctx: ToolContext, hours=24) -> dict:
    return ent.environment_changes(ctx.db, ctx.ws, float(hours or 24))


# ----------------------------------------------------------------------------------------------- intel / mitre
@tool("search_threat_intel", "Look up an IP, domain, hash, hostname or username in threat intelligence and find "
      "where it was observed in telemetry and incidents.", {"value": S("Indicator value")}, ["value"],
      summary=lambda a, r: f"Checked threat intelligence for {a.get('value')}")
def search_threat_intel(ctx: ToolContext, value) -> dict:
    res = ti.search(ctx.db, ctx.ws, str(value))
    s = res["sightings"]
    return {"value": res["value"], "type": res["detected_type"], "verdict": res["verdict"],
            "indicators": [{k: i[k] for k in ("value", "indicator_type", "source", "is_synthetic", "confidence",
                                              "severity", "description")} for i in res["matches"]],
            "sightings": {"events": s["event_count"], "first": s["first_observed"], "last": s["last_observed"],
                          "sample": [{"event_uid": e["event_uid"], "time": e["timestamp"], "type": e["event_type"],
                                      "user": e["user"], "host": e["host"]} for e in s["events"][:10]],
                          "incidents": [i["number"] for i in s["incidents"]]}}


@tool("search_iocs", "List threat indicators (optionally filtered by type or text).",
      {"text": S("Contains"), "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "hostname", "username"]}},
      summary=lambda a, r: f"Listed indicators ({len(r.get('indicators', []))})")
def search_iocs(ctx: ToolContext, text=None, indicator_type=None) -> dict:
    q = ctx.db.query(ThreatIndicator).filter_by(workspace_id=ctx.ws)
    if text:
        q = q.filter(ThreatIndicator.value.ilike(f"%{text}%"))
    if indicator_type:
        q = q.filter_by(indicator_type=indicator_type)
    return {"indicators": [{"value": i.value, "type": i.indicator_type, "severity": i.severity, "confidence": i.confidence,
                            "source": i.source, "synthetic": i.is_synthetic} for i in q.limit(50)]}


@tool("search_mitre", "Explain an ATT&CK technique (by ID or name) and list where it was observed in this workspace.",
      {"query": S("Technique ID like T1059.001 or a name")}, ["query"],
      summary=lambda a, r: f"Looked up ATT&CK {a.get('query')}")
def search_mitre(ctx: ToolContext, query) -> dict:
    q = str(query).strip()
    matches = [v for k, v in TECHNIQUE_INDEX.items() if q.upper() == k or q.lower() in v["name"].lower()][:5]
    if not matches:
        return {"matches": [], "note": f"'{q}' is not in the SentinelX technique catalogue."}
    out = []
    for m in matches:
        rows = ctx.db.query(IncidentTechnique, Incident).join(Incident, Incident.id == IncidentTechnique.incident_id)\
            .filter(Incident.workspace_id == ctx.ws, IncidentTechnique.technique_id == m["id"]).all()
        out.append({**m, "observed_in": [{"incident": i.number, "reason": t.reason, "evidence": t.event_uids[:5]} for t, i in rows]})
    return {"matches": out}


# ----------------------------------------------------------------------------------------------- graph
@tool("get_attack_graph", "The knowledge-graph neighbourhood of an incident: entities, detections, techniques and "
      "how they connect (with evidence event IDs on edges).", {"incident": S("Incident number")},
      summary=lambda a, r: f"Retrieved attack graph ({len(r.get('nodes', []))} nodes)")
def get_attack_graph(ctx: ToolContext, incident=None) -> dict:
    inc = _incident(ctx, incident)
    g = kg.incident_subgraph(ctx.db, ctx.ws, inc)
    labels = {n["id"]: f"{n['kind']}:{n['label']}" for n in g["nodes"]}
    ctx.artifacts.append({"type": "graph", "incident": inc.number, **g})
    return {"incident": inc.number, "nodes": [labels[n["id"]] for n in g["nodes"]],
            "edges": [{"from": labels.get(e["source"]), "rel": e["rel"], "to": labels.get(e["target"]),
                       "count": e["count"], "evidence": e["evidence"][:3]} for e in g["edges"]][:120]}


@tool("graph_neighbors", "Relationships of any graph entity (user, host, ip, process, domain, share, group, "
      "incident, detection, technique, ioc).",
      {"entity": S("Name, optionally prefixed with kind, e.g. 'host:NB-DC01'"), "relation": S("Optional relation filter")},
      ["entity"], summary=lambda a, r: f"Explored relationships of {a.get('entity')}")
def graph_neighbors(ctx: ToolContext, entity, relation=None) -> dict:
    node = kg.find_node(ctx.db, ctx.ws, entity)
    if node is None:
        raise LookupError(f"'{entity}' is not in the knowledge graph.")
    nb = kg.neighbors(ctx.db, ctx.ws, node.id, [relation] if relation else None, limit=60)
    labels = {n["id"]: f"{n['kind']}:{n['label']}" for n in nb["nodes"]}
    return {"entity": f"{node.kind}:{node.label}", "relations": [
        {"from": labels.get(e["source"]), "rel": e["rel"], "to": labels.get(e["target"]), "count": e["count"],
         "first_seen": e["first_seen"], "last_seen": e["last_seen"], "evidence": e["evidence"][:3]} for e in nb["edges"]]}


@tool("find_attack_paths", "Find how two entities are connected in the knowledge graph (shortest observed paths).",
      {"source": S("From entity, e.g. 'user:t.nguyen'"), "target": S("To entity, e.g. 'host:NB-FS01'"),
       "max_depth": N("Max hops (default 5)")}, ["source", "target"],
      summary=lambda a, r: f"Searched paths {a.get('source')} → {a.get('target')} ({r.get('found', 0)} found)")
def find_attack_paths(ctx: ToolContext, source, target, max_depth=5) -> dict:
    a, b = kg.find_node(ctx.db, ctx.ws, source), kg.find_node(ctx.db, ctx.ws, target)
    if a is None or b is None:
        raise LookupError(f"Could not find {'source' if a is None else 'target'} in the knowledge graph.")
    res = kg.find_paths(ctx.db, ctx.ws, a.id, b.id, max_depth=min(int(max_depth or 5), 7))
    ctx.artifacts.append({"type": "paths", "source": f"{a.kind}:{a.label}", "target": f"{b.kind}:{b.label}", **res})
    return {"found": res["found"], "paths": [" → ".join(
        (f"[{s['via']['rel']}] " if s["via"] else "") + f"{s['node']['kind']}:{s['node']['label']}" for s in p)
        for p in res["paths"]], "note": res["note"]}


@tool("find_similar_incidents", "Have we seen this attack before? Compares Attack DNA (techniques, stage sequence, "
      "rules, entities, traits) with every other incident.", {"incident": S("Incident number")},
      summary=lambda a, r: f"Compared Attack DNA ({len(r.get('similar', []))} candidates)")
def find_similar_incidents(ctx: ToolContext, incident=None) -> dict:
    inc = _incident(ctx, incident)
    sims = dna_mod.similar_incidents(ctx.db, ctx.ws, inc, 6)
    ctx.artifacts.append({"type": "similar", "incident": inc.number, "dna": inc.dna, "similar": sims})
    return {"incident": inc.number, "dna_signature": inc.dna.get("signature") if inc.dna else None,
            "similar": sims, "weights": dna_mod.WEIGHTS}


@tool("attack_families", "Group incidents into attack families by Attack DNA similarity and show how behavior "
      "evolved within each family.", summary=lambda a, r: f"Clustered incidents into {len(r.get('families', []))} families")
def attack_families(ctx: ToolContext) -> dict:
    return {"families": dna_mod.families(ctx.db, ctx.ws), "threshold": dna_mod.FAMILY_THRESHOLD}


# ----------------------------------------------------------------------------------------------- hunting
@tool("run_hunt", "Run a threat hunt over stored telemetry. Provide a structured spec: {time:{last_hours|start,end|"
      "all, hour_from?, hour_to?}, event_types[], actions[], status, users[], hosts[], ips[], text_any[], text_all[], "
      "processes[], entity_scope:{privileged_users, servers}, behaviors[new_source_for_user|off_hours|rare_destination|"
      "new_destination_for_host|first_seen_process|external_destination|large_transfer], followed_by:{event_types[], "
      "text_any[], internal_destination, within_minutes, same}, above_baseline, group_by, limit}. Saved as HUNT-n.",
      {"spec": {"type": "object"}, "name": S("Short hunt name"), "natural_language": S("The analyst's request")},
      ["spec"], summary=lambda a, r: f"Ran hunt {r.get('hunt', '')} ({r.get('total', 0)} matches)")
def run_hunt(ctx: ToolContext, spec, name=None, natural_language=None, translation="llm") -> dict:
    try:
        res = hunt_mod.run(ctx.db, ctx.ws, spec, ctx.bh)
    except (hunt_mod.HuntError, ValueError, TypeError) as exc:
        raise LookupError(f"Invalid hunt: {exc}") from None
    number = f"HUNT-{ctx.db.query(Hunt).filter_by(workspace_id=ctx.ws).count() + 1:04d}"
    h = Hunt(workspace_id=ctx.ws, number=number, name=(name or natural_language or "Hunt")[:255],
             natural_language=natural_language or "", spec=res["spec"], translation=translation,
             last_run_at=utcnow(), last_result_count=res["total"], created_by_id=ctx.user_id)
    ctx.db.add(h)
    ctx.db.flush()
    ctx.focus("hunt", number)
    ctx.artifacts.append({"type": "hunt", "hunt": number, "natural_language": natural_language or "",
                          "translation": translation, **res})
    return {"hunt": number, "description": res["description"], "total": res["total"], "entities": res["entities"],
            "groups": res["groups"], "events": res["events"][:30], "sequences": res["sequences"][:10]}


@tool("create_incident_from_hunt", "Create an incident from a hunt's matching events (analyst action). The backend "
      "creates the incident; the title should summarise the evidence.",
      {"hunt": S("Hunt number"), "title": S("Incident title"), "event_ids": {"type": "array", "items": {"type": "string"},
                                                                               "description": "Event IDs to include (default: all hunt matches, max 200)"}},
      ["hunt", "title"], access=ANALYST, summary=lambda a, r: f"Created incident {r.get('number', '')}")
def create_incident_from_hunt(ctx: ToolContext, hunt, title, event_ids=None) -> dict:
    from app.services.hunt_actions import incident_from_hunt

    h = ctx.db.query(Hunt).filter_by(workspace_id=ctx.ws, number=str(hunt).upper()).first()
    if h is None:
        raise LookupError(f"Hunt {hunt} not found.")
    inc = incident_from_hunt(ctx.db, ctx.workspace, h, title, event_ids, ctx.user_id)
    ctx.focus("incident", inc.number)
    ctx.artifacts.append({"type": "incident_created", "number": inc.number, "id": inc.id, "title": inc.title})
    return {"number": inc.number, "title": inc.title, "link": f"/incidents/{inc.number}"}


# ----------------------------------------------------------------------------------------------- investigations
def _investigation(ctx: ToolContext, ref=None, create_title: str | None = None) -> Investigation:
    inv = inv_mod.resolve(ctx.db, ctx.ws, ref) if ref else ctx.investigation
    if inv is None and create_title and ctx.can(ANALYST):
        focus_inc = ctx.state.get("focus", {}).get("incident")
        inc = ctx.db.query(Incident).filter_by(workspace_id=ctx.ws, number=focus_inc).first() if focus_inc else None
        inv = inv_mod.create(ctx.db, ctx.ws, ctx.user_id, create_title, inc, ctx.state.get("focus"))
        ctx.investigation = inv
    if inv is None:
        raise LookupError("No investigation in focus. Create one first.")
    ctx.investigation = inv
    ctx.focus("investigation", inv.number)
    return inv


@tool("create_investigation", "Open an investigation (INV-n) to record facts, hypotheses, questions and conclusions.",
      {"title": S("Investigation title"), "incident": S("Related incident number")}, ["title"], access=ANALYST,
      summary=lambda a, r: f"Opened investigation {r.get('number', '')}")
def create_investigation(ctx: ToolContext, title, incident=None) -> dict:
    inc = _incident(ctx, incident) if incident or ctx.state.get("focus", {}).get("incident") else None
    inv = inv_mod.create(ctx.db, ctx.ws, ctx.user_id, title, inc, ctx.state.get("focus"))
    ctx.investigation = inv
    ctx.focus("investigation", inv.number)
    return {"number": inv.number, "title": inv.title, "incident": inc.number if inc else None}


@tool("add_investigation_note", "Record a fact, note, open question or conclusion in the investigation memory. "
      "Facts and conclusions must cite evidence IDs in 'refs'.",
      {"kind": {"type": "string", "enum": ["fact", "note", "question", "conclusion"]}, "text": S("Content"),
       "refs": {"type": "array", "items": {"type": "string"}, "description": "Evidence citations like EVT:NB-000123"},
       "investigation": S("Investigation number (defaults to the one in focus)")}, ["kind", "text"], access=ANALYST,
      summary=lambda a, r: f"Recorded {a.get('kind')} in {r.get('investigation', '')}")
def add_investigation_note(ctx: ToolContext, kind, text, refs=None, investigation=None) -> dict:
    inv = _investigation(ctx, investigation, create_title=f"Investigation of {ctx.state.get('focus', {}).get('incident') or 'current activity'}")
    item = inv_mod.add_item(ctx.db, inv, kind, text, source="ai", supporting=refs or [], user_id=ctx.user_id)
    return {"investigation": inv.number, "item": inv_mod.item_payload(item)}


@tool("create_hypothesis", "Record a hypothesis with supporting and contradicting evidence (citations) and a status "
      "(open, supported, refuted). Use to track competing explanations.",
      {"statement": S("Hypothesis"), "supporting": {"type": "array", "items": {"type": "string"}},
       "contradicting": {"type": "array", "items": {"type": "string"}},
       "status": {"type": "string", "enum": ["open", "supported", "refuted"]}, "investigation": S("Investigation number")},
      ["statement"], access=ANALYST, summary=lambda a, r: f"Recorded hypothesis in {r.get('investigation', '')}")
def create_hypothesis(ctx: ToolContext, statement, supporting=None, contradicting=None, status="open", investigation=None) -> dict:
    inv = _investigation(ctx, investigation, create_title=f"Investigation of {ctx.state.get('focus', {}).get('incident') or 'current activity'}")
    item = inv_mod.add_item(ctx.db, inv, "hypothesis", statement, source="ai", supporting=supporting, contradicting=contradicting,
                            status=status if status in ("open", "supported", "refuted") else "open", user_id=ctx.user_id)
    return {"investigation": inv.number, "item": inv_mod.item_payload(item)}


@tool("get_investigation_memory", "Previously recorded facts, hypotheses, conclusions and open questions (from "
      "analysts or earlier AI sessions). These are HISTORICAL records, not current evidence.",
      {"incident": S("Incident number"), "investigation": S("Investigation number")},
      summary=lambda a, r: f"Read investigation memory ({len(r.get('items', []))} items)")
def get_investigation_memory(ctx: ToolContext, incident=None, investigation=None) -> dict:
    if investigation:
        inv = _investigation(ctx, investigation)
        return {"items": inv_mod.payload(ctx.db, inv)["items"], "memory_type": "historical"}
    inc_id = _incident(ctx, incident).id if (incident or ctx.state.get("focus", {}).get("incident")) else None
    return {"items": inv_mod.memory_for(ctx.db, ctx.ws, inc_id), "memory_type": "historical"}


# ----------------------------------------------------------------------------------------------- simulation
@tool("run_attack_simulation", "Simulate an attack scenario (with optional variations and defensive controls) "
      "through the real detection rules. Sandbox by default; persist=true injects it into a DEMO workspace through "
      "the full pipeline. Controls: mfa, powershell_constrained, privileged_group_approval, credential_guard, "
      "dlp_egress, network_segmentation.",
      {"scenario": S("Scenario id"), "variations": {"type": "object"}, "controls": {"type": "array", "items": {"type": "string"}},
       "persist": {"type": "boolean"}}, ["scenario"], access=ANALYST,
      summary=lambda a, r: f"Simulated {a.get('scenario')}" + (" with controls" if a.get("controls") else ""))
def run_attack_simulation(ctx: ToolContext, scenario, variations=None, controls=None, persist=False) -> dict:
    try:
        if persist:
            res = sim.persist(ctx.db, ctx.workspace, scenario, variations)
        else:
            res = sim.sandbox(ctx.db, ctx.workspace, scenario, variations, controls)
    except (sim.SimulationError, ValueError) as exc:
        raise LookupError(str(exc)) from None
    run = sim.record_run(ctx.db, ctx.ws, ctx.user_id, "persisted" if persist else "sandbox", scenario, variations or {},
                         controls or [], bool(persist), res)
    ctx.artifacts.append({"type": "simulation", "run_id": run.id, **res})
    return res


@tool("defense_what_if", "What would change for an existing incident if defensive controls had been in place? "
      "Controls: mfa, powershell_constrained, privileged_group_approval, credential_guard, dlp_egress, network_segmentation.",
      {"incident": S("Incident number"), "controls": {"type": "array", "items": {"type": "string"}}}, ["controls"],
      summary=lambda a, r: f"Modeled controls {', '.join(a.get('controls') or [])}")
def defense_what_if(ctx: ToolContext, controls, incident=None) -> dict:
    inc = _incident(ctx, incident)
    bad = [c for c in controls or [] if c not in sim.CONTROLS]
    if bad:
        raise LookupError(f"Unknown controls {bad}; allowed: {list(sim.CONTROLS)}")
    res = sim.incident_what_if(ctx.db, inc, controls)
    ctx.artifacts.append({"type": "what_if", **res})
    return res


@tool("counterfactual_analysis", "Remove detections from an incident and recompute risk, stages and whether the "
      "rest would still correlate. Use to test how much a conclusion depends on specific evidence.",
      {"incident": S("Incident number"), "remove_detection_ids": {"type": "array", "items": {"type": "integer"}}},
      ["remove_detection_ids"], summary=lambda a, r: "Ran counterfactual analysis")
def counterfactual_analysis(ctx: ToolContext, remove_detection_ids, incident=None) -> dict:
    inc = _incident(ctx, incident)
    res = sim.counterfactual(ctx.db, inc, [int(x) for x in remove_detection_ids])
    ctx.artifacts.append({"type": "counterfactual", **res})
    return res


# ----------------------------------------------------------------------------------------------- reporting / ops
@tool("generate_report", "Generate a report from an incident's actual data (incident, technical or executive). "
      "Returns a report link.", {"incident": S("Incident number"), "report_type": {"type": "string", "enum":
                                                                                 ["incident", "technical", "executive"]}},
      access=ANALYST, summary=lambda a, r: f"Generated {a.get('report_type', 'incident')} report")
def generate_report(ctx: ToolContext, incident=None, report_type="incident") -> dict:
    from app.reporting.builder import build_report

    inc = _incident(ctx, incident)
    content = build_report(ctx.db, ctx.workspace, ctx.user_id, inc, report_type or "incident", ai_narrative=None)
    rep = Report(workspace_id=ctx.ws, incident_id=inc.id, report_type=report_type or "incident", title=content["title"],
                 content=content, ai_mode="NONE", created_by_id=ctx.user_id)
    ctx.db.add(rep)
    ctx.db.flush()
    ctx.artifacts.append({"type": "report", "id": rep.id, "title": rep.title})
    return {"report_id": rep.id, "title": rep.title, "link": f"/reports/{rep.id}"}


@tool("search_reports", "List generated reports.", {"incident": S("Incident number")},
      summary=lambda a, r: f"Listed reports ({len(r.get('reports', []))})")
def search_reports(ctx: ToolContext, incident=None) -> dict:
    q = ctx.db.query(Report).filter_by(workspace_id=ctx.ws)
    if incident:
        q = q.filter_by(incident_id=_incident(ctx, incident).id)
    return {"reports": [{"id": r.id, "title": r.title, "type": r.report_type, "created": iso(r.created_at)}
                        for r in q.order_by(Report.id.desc()).limit(20)]}


@tool("search_hunts", "List saved hunts and their last results.", summary=lambda a, r: "Listed hunts")
def search_hunts(ctx: ToolContext) -> dict:
    return {"hunts": [{"number": h.number, "name": h.name, "results": h.last_result_count, "last_run": iso(h.last_run_at)}
                      for h in ctx.db.query(Hunt).filter_by(workspace_id=ctx.ws).order_by(Hunt.id.desc()).limit(25)]}


@tool("search_audit_log", "Search the audit log (administrators only).",
      {"action": S("Action such as LOGIN, UPLOAD_DATA, QUERY_AI"), "user": S("User email contains"), "limit": N("Max (default 30)")},
      access=ADMIN, summary=lambda a, r: f"Searched audit log ({len(r.get('entries', []))})")
def search_audit_log(ctx: ToolContext, action=None, user=None, limit=30) -> dict:
    q = ctx.db.query(AuditLog).filter(AuditLog.workspace_id == ctx.ws)
    if action:
        q = q.filter(AuditLog.action == action.upper())
    if user:
        q = q.filter(AuditLog.user_email.ilike(f"%{user}%"))
    return {"entries": [{"action": a.action, "user": a.user_email, "target": f"{a.target_type} {a.target_id}",
                         "at": iso(a.created_at)} for a in q.order_by(AuditLog.id.desc()).limit(min(int(limit or 30), 100))]}


@tool("get_system_health", "Status of SentinelX components, data quality and pipeline stages.",
      summary=lambda a, r: "Checked system health and data quality")
def get_system_health(ctx: ToolContext) -> dict:
    return {"pipeline": quality.pipeline_status(ctx.db, ctx.workspace), "data_quality": quality.data_quality(ctx.db, ctx.ws)}


@tool("find_unexplained_behavior", "Unknown-unknowns: anomalous behavior no detection explains, missing telemetry "
      "and unclassified data.", summary=lambda a, r: f"Looked for unexplained behavior ({len(r.get('findings', []))})")
def find_unexplained_behavior(ctx: ToolContext) -> dict:
    return {"findings": ent.unknown_unknowns(ctx.db, ctx.ws)}


@tool("search_knowledge_base", "Retrieve passages from the organization's knowledge base (playbooks, policies, "
      "procedures). Cite them by document title.", {"query": S("Question or keywords")}, ["query"],
      summary=lambda a, r: f"Searched knowledge base ({len(r.get('passages', []))} passages)")
def search_knowledge_base(ctx: ToolContext, query) -> dict:
    hits = rag.search(ctx.db, ctx.ws, str(query), 4)
    ctx.state.setdefault("sources", [])
    for h in hits:
        ctx.artifacts.append({"type": "source", "document": h["document_title"], "heading": h["heading"], "score": h["score"]})
    return {"passages": [{"document": h["document_title"], "section": h["heading"], "text": h["content"][:900]} for h in hits]}


# ----------------------------------------------------------------------------------------------- dispatch
def specs_for(ctx: ToolContext) -> list[dict]:
    return [{"name": t.name, "description": t.description, "parameters": t.parameters}
            for t in REGISTRY.values() if ctx.can(t.access)]


def _collect(ctx: ToolContext, obj) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "event_uid" and isinstance(v, str):
                ctx.reviewed_events.add(v)
            elif k in ("evidence_event_uids", "evidence", "examples") and isinstance(v, list):
                ctx.reviewed_events.update(x for x in v if isinstance(x, str))
            elif k == "user" and isinstance(v, str):
                ctx.reviewed_entities.add(f"user:{v}")
            elif k == "host" and isinstance(v, str):
                ctx.reviewed_entities.add(f"host:{v}")
            else:
                _collect(ctx, v)
    elif isinstance(obj, list):
        for v in obj:
            _collect(ctx, v)


def call(ctx: ToolContext, name: str, args: dict) -> tuple[dict, str]:
    """Execute a tool with authorization. Returns (result, activity summary)."""
    t = REGISTRY.get(name)
    if t is None:
        result = {"error": f"Unknown tool '{name}'."}
    elif not ctx.can(t.access):
        result = {"error": f"Your role does not permit '{name}'."}
    else:
        try:
            result = t.fn(ctx, **{k: v for k, v in (args or {}).items() if v is not None})
        except LookupError as exc:
            result = {"error": str(exc)}
        except TypeError as exc:
            result = {"error": f"Invalid arguments for {name}: {exc}"}
        except ValueError as exc:  # validation errors from hunts, rule specs, simulations
            result = {"error": str(exc)[:300]}
        except Exception:  # a failing tool must not end the investigation; the model sees a generic error
            log.exception("Tool %s failed", name)
            result = {"error": f"The {name} tool failed internally. The error was logged."}
    ok = "error" not in result
    summary = t.summary(args or {}, result) if (t and ok) else f"{name.replace('_', ' ')}: {result.get('error', 'failed')}"
    if ok:
        _collect(ctx, result)
    ctx.activity.append({"tool": name, "summary": summary, "ok": ok})
    return result, summary


def result_text(result: dict) -> str:
    text = json.dumps(sanitize(result, max_str=900), default=str, ensure_ascii=False)
    if len(text) > RESULT_LIMIT_CHARS:
        text = text[:RESULT_LIMIT_CHARS] + "…[truncated; narrow the query for more]"
    return f'<untrusted_data source="tool_result">{text}</untrusted_data>'
