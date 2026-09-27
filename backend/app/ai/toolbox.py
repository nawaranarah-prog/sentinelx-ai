"""Read-only investigation tools available to the AI assistant.

Every tool is scoped to the caller's workspace (authorization is enforced here, not by the model).
There are deliberately no tools that write data, execute commands, or reach external systems.
The toolbox records every reference it returns so model output can be validated against it.
"""

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.serializers import iso
from app.mitre.catalog import TECHNIQUE_INDEX
from app.models import Detection, DetectionEvent, Event, Incident, IncidentEvent, IncidentTechnique
from app.rag import service as rag
from app.services.entity_risk import compute_entity_risks
from app.threat_intel import service as ti

TOOL_SPECS = [
    {"name": "list_incidents", "description": "List incidents in the current workspace (most risky first).",
     "parameters": {"type": "object", "properties": {"status": {"type": "string", "enum": ["NEW", "IN_PROGRESS", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"]},
                                                     "limit": {"type": "integer", "minimum": 1, "maximum": 25}}}},
    {"name": "get_incident", "description": "Get an incident's facts: entities, detections, techniques, risk factors, anomalies.",
     "parameters": {"type": "object", "properties": {"incident": {"type": "string", "description": "Incident id or number such as INC-0006"}},
                    "required": ["incident"]}},
    {"name": "get_timeline", "description": "Chronological evidence events of an incident.",
     "parameters": {"type": "object", "properties": {"incident": {"type": "string"},
                                                     "limit": {"type": "integer", "minimum": 1, "maximum": 150}},
                    "required": ["incident"]}},
    {"name": "get_detection", "description": "Get one detection with its explanation and evidence event IDs.",
     "parameters": {"type": "object", "properties": {"detection_id": {"type": "integer"}}, "required": ["detection_id"]}},
    {"name": "search_events", "description": "Search normalized events by text and/or exact user, host, IP or type.",
     "parameters": {"type": "object", "properties": {
         "query": {"type": "string"}, "user": {"type": "string"}, "host": {"type": "string"}, "ip": {"type": "string"},
         "event_type": {"type": "string", "enum": ["authentication", "process", "file", "network", "privilege", "other"]},
         "limit": {"type": "integer", "minimum": 1, "maximum": 50}}}},
    {"name": "get_event", "description": "Get one event (normalized fields and metadata) by its event ID.",
     "parameters": {"type": "object", "properties": {"event_id": {"type": "string"}}, "required": ["event_id"]}},
    {"name": "get_host", "description": "Risk profile and activity summary for a host.",
     "parameters": {"type": "object", "properties": {"hostname": {"type": "string"}}, "required": ["hostname"]}},
    {"name": "get_user_activity", "description": "Risk profile and recent activity for a user account.",
     "parameters": {"type": "object", "properties": {"username": {"type": "string"}}, "required": ["username"]}},
    {"name": "search_threat_intel", "description": "Look up an IP, domain, hash, hostname or username in workspace threat intelligence.",
     "parameters": {"type": "object", "properties": {"value": {"type": "string"}}, "required": ["value"]}},
    {"name": "get_mitre", "description": "Describe a MITRE ATT&CK technique from the SentinelX catalogue.",
     "parameters": {"type": "object", "properties": {"technique_id": {"type": "string"}}, "required": ["technique_id"]}},
    {"name": "search_knowledge_base", "description": "Retrieve relevant passages from the organization's knowledge base (playbooks, policies).",
     "parameters": {"type": "object", "properties": {"query": {"type": "string"},
                                                     "k": {"type": "integer", "minimum": 1, "maximum": 6}},
                    "required": ["query"]}},
]


def _ev(e: Event, cmd_len: int = 300) -> dict:
    meta = {k: (str(v)[:200] if isinstance(v, str) else v) for k, v in list((e.event_metadata or {}).items())[:10]
            if isinstance(v, (str, int, float, bool))}
    return {"event_uid": e.event_uid, "timestamp": iso(e.timestamp), "type": e.event_type, "user": e.user,
            "host": e.host, "source_ip": e.source_ip, "destination_ip": e.destination_ip, "process": e.process,
            "command": (e.command or "")[:cmd_len] or None, "action": e.action, "status": e.status,
            "bytes": e.bytes, "resource": (e.resource or "")[:200] or None, "metadata": meta or None}


class Toolbox:
    def __init__(self, db: Session, workspace_id: int, max_events: int = 120):
        self.db = db
        self.ws = workspace_id
        self.max_events = max_events
        self.event_uids: set[str] = set()
        self.detection_ids: set[int] = set()
        self.techniques: set[str] = set()
        self.incident_numbers: set[str] = set()
        self.sources: list[dict] = []
        self.calls: list[dict] = []

    # ---------------------------------------------------------------- reference tracking
    def _track_events(self, events: list[dict]) -> None:
        self.event_uids.update(e["event_uid"] for e in events if e.get("event_uid"))

    def _resolve_incident(self, ref) -> Incident | None:
        ref = str(ref).strip()
        q = self.db.query(Incident).filter(Incident.workspace_id == self.ws)
        if ref.upper().startswith("INC-"):
            return q.filter(Incident.number == ref.upper()).first()
        try:
            return q.filter(Incident.id == int(ref.lstrip("#"))).first()
        except ValueError:
            return None

    # ---------------------------------------------------------------- tools
    def list_incidents(self, status: str | None = None, limit: int = 15) -> dict:
        q = self.db.query(Incident).filter(Incident.workspace_id == self.ws)
        if status:
            q = q.filter(Incident.status == status)
        rows = q.order_by(Incident.risk_score.desc()).limit(min(int(limit or 15), 25)).all()
        self.incident_numbers.update(i.number for i in rows)
        return {"incidents": [{"id": i.id, "number": i.number, "title": i.title, "status": i.status,
                               "severity": i.severity, "risk_score": i.risk_score, "first_seen": iso(i.first_seen),
                               "last_seen": iso(i.last_seen), "users": i.users[:5], "hosts": i.hosts[:5]} for i in rows]}

    def get_incident(self, incident) -> dict:
        inc = self._resolve_incident(incident)
        if inc is None:
            return {"error": f"Incident '{incident}' not found in this workspace."}
        dets = self.db.query(Detection).filter_by(incident_id=inc.id).order_by(Detection.timestamp).all()
        techs = self.db.query(IncidentTechnique).filter_by(incident_id=inc.id).all()
        self.incident_numbers.add(inc.number)
        self.detection_ids.update(d.id for d in dets)
        for d in dets:
            self.event_uids.update((d.evidence_summary or {}).get("event_uids", [])[:500])
            self.techniques.update(m["id"] for m in d.mitre or [])
        self.techniques.update(t.technique_id for t in techs)
        return {
            "incident": {"id": inc.id, "number": inc.number, "title": inc.title, "status": inc.status,
                         "severity": inc.severity, "confidence": inc.confidence, "risk_score": inc.risk_score,
                         "risk_band": inc.risk_band, "first_seen": iso(inc.first_seen), "last_seen": iso(inc.last_seen),
                         "users": inc.users, "hosts": inc.hosts, "source_ips": inc.source_ips,
                         "destination_ips": inc.destination_ips, "stages": inc.stages,
                         "correlation_reason": inc.correlation_reason, "summary": inc.summary, "tags": inc.tags},
            "risk_factors": inc.risk_factors,
            "detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity,
                            "confidence": d.confidence, "stage": d.stage, "timestamp": iso(d.timestamp),
                            "last_seen": iso(d.last_seen), "user": d.user, "host": d.host, "source_ip": d.source_ip,
                            "destination_ip": d.destination_ip, "explanation": d.explanation,
                            "evidence_event_uids": (d.evidence_summary or {}).get("event_uids", [])[:12],
                            "evidence_event_count": (d.evidence_summary or {}).get("event_count", 0),
                            "evidence_summary": {k: v for k, v in (d.evidence_summary or {}).items()
                                                 if k not in ("event_uids",)},
                            "mitre": [{"id": m["id"], "reason": m["reason"],
                                       "mapping_confidence": m.get("mapping_confidence")} for m in d.mitre or []],
                            "false_positives": d.false_positives, "recommendations": d.recommendations}
                           for d in dets],
            "techniques": [{"id": t.technique_id, "name": TECHNIQUE_INDEX.get(t.technique_id, {}).get("name"),
                            "tactic": TECHNIQUE_INDEX.get(t.technique_id, {}).get("tactic"), "reason": t.reason,
                            "mapping_confidence": t.mapping_confidence, "event_uids": t.event_uids[:8]} for t in techs],
            "anomalies": inc.anomaly_summary, "checklist": inc.checklist,
        }

    def get_timeline(self, incident, limit: int | None = None) -> dict:
        inc = self._resolve_incident(incident)
        if inc is None:
            return {"error": f"Incident '{incident}' not found in this workspace."}
        limit = min(int(limit or self.max_events), self.max_events)
        rows = self.db.scalars(select(Event).join(IncidentEvent, IncidentEvent.event_id == Event.id).where(
            IncidentEvent.incident_id == inc.id, IncidentEvent.role == "evidence").order_by(Event.timestamp)).all()
        det_by_event: dict[int, list[str]] = {}
        for eid, rk in self.db.execute(select(DetectionEvent.event_id, Detection.rule_key)
                                            .join(Detection, Detection.id == DetectionEvent.detection_id)
                                            .where(Detection.incident_id == inc.id)):
            det_by_event.setdefault(eid, []).append(rk)
        if len(rows) > limit:
            # Keep the start and end of long bursts: first/last events of each detection plus an even sample.
            step = len(rows) / limit
            rows = [rows[int(i * step)] for i in range(limit)]
        events = [{**_ev(e), "detections": sorted(set(det_by_event.get(e.id, [])))} for e in rows]
        self._track_events(events)
        return {"incident": inc.number, "total_evidence_events": self.db.query(IncidentEvent).filter_by(
            incident_id=inc.id, role="evidence").count(), "returned": len(events), "events": events}

    def get_detection(self, detection_id: int) -> dict:
        d = self.db.query(Detection).filter_by(id=int(detection_id), workspace_id=self.ws).first()
        if d is None:
            return {"error": f"Detection {detection_id} not found in this workspace."}
        self.detection_ids.add(d.id)
        uids = (d.evidence_summary or {}).get("event_uids", [])
        self.event_uids.update(uids)
        self.techniques.update(m["id"] for m in d.mitre or [])
        return {"id": d.id, "rule_key": d.rule_key, "title": d.title, "severity": d.severity,
                "confidence": d.confidence, "timestamp": iso(d.timestamp), "user": d.user, "host": d.host,
                "source_ip": d.source_ip, "explanation": d.explanation, "mitre": d.mitre,
                "evidence_event_uids": uids[:50], "false_positives": d.false_positives,
                "recommendations": d.recommendations, "incident_id": d.incident_id}

    def search_events(self, query: str | None = None, user: str | None = None, host: str | None = None,
                      ip: str | None = None, event_type: str | None = None, limit: int = 25) -> dict:
        conds = [Event.workspace_id == self.ws]
        if user:
            conds.append(Event.user == user.lower())
        if host:
            conds.append(Event.host == host.upper())
        if ip:
            conds.append(or_(Event.source_ip == ip, Event.destination_ip == ip))
        if event_type:
            conds.append(Event.event_type == event_type)
        if query:
            like = f"%{query[:100]}%"
            conds.append(or_(Event.command.ilike(like), Event.resource.ilike(like), Event.process.ilike(like),
                             Event.event_uid.ilike(like), Event.action.ilike(like)))
        rows = self.db.scalars(select(Event).where(*conds).order_by(Event.timestamp.desc()).limit(min(int(limit or 25), 50))).all()
        events = [_ev(e) for e in rows]
        self._track_events(events)
        return {"returned": len(events), "events": events}

    def get_event(self, event_id: str) -> dict:
        e = self.db.query(Event).filter_by(workspace_id=self.ws, event_uid=str(event_id)).first()
        if e is None:
            return {"error": f"Event '{event_id}' not found in this workspace."}
        self.event_uids.add(e.event_uid)
        dets = self.db.query(Detection).join(DetectionEvent, DetectionEvent.detection_id == Detection.id).filter(
            DetectionEvent.event_id == e.id).all()
        self.detection_ids.update(d.id for d in dets)
        return {**_ev(e, 2000), "metadata": e.event_metadata, "source": e.source,
                "detections": [{"id": d.id, "rule_key": d.rule_key, "title": d.title} for d in dets]}

    def get_host(self, hostname: str) -> dict:
        risks = {r["name"]: r for r in compute_entity_risks(self.db, self.ws, "host")}
        r = risks.get(str(hostname).upper())
        return r or {"error": f"No telemetry for host '{hostname}'."}

    def get_user_activity(self, username: str) -> dict:
        risks = {r["name"]: r for r in compute_entity_risks(self.db, self.ws, "user")}
        r = risks.get(str(username).lower())
        if not r:
            return {"error": f"No telemetry for user '{username}'."}
        recent = self.search_events(user=username, limit=15)
        return {**r, "recent_events": recent["events"]}

    def search_threat_intel(self, value: str) -> dict:
        res = ti.search(self.db, self.ws, str(value))
        s = res["sightings"]
        events = [{k: e[k] for k in ("event_uid", "timestamp", "event_type", "user", "host", "source_ip",
                                     "destination_ip", "resource")} for e in s["events"][:10]]
        self._track_events(events)
        return {"query": res["query"], "type": res["detected_type"], "verdict": res["verdict"],
                "indicators": [{k: i[k] for k in ("value", "indicator_type", "source", "is_synthetic", "confidence",
                                                  "severity", "description")} for i in res["matches"]],
                "sightings": {"event_count": s["event_count"], "first_observed": s["first_observed"],
                              "last_observed": s["last_observed"], "sample_events": events,
                              "incidents": [i["number"] for i in s["incidents"]]}}

    def get_mitre(self, technique_id: str) -> dict:
        tid = str(technique_id).strip().upper()
        info = TECHNIQUE_INDEX.get(tid)
        if not info:
            return {"error": f"{tid} is not in the SentinelX technique catalogue."}
        self.techniques.add(tid)
        return info

    def search_knowledge_base(self, query: str, k: int = 4) -> dict:
        hits = rag.search(self.db, self.ws, str(query), min(int(k or 4), 6))
        for h in hits:
            if h["chunk_id"] not in {s["chunk_id"] for s in self.sources}:
                self.sources.append({k2: h[k2] for k2 in ("chunk_id", "document_id", "document_title", "heading", "score")})
        return {"passages": [{"source": f"{h['document_title']} › {h['heading']}" if h["heading"] else h["document_title"],
                              "chunk_id": h["chunk_id"], "score": h["score"], "text": h["content"]} for h in hits]}

    # ---------------------------------------------------------------- dispatch
    def call(self, name: str, args: dict) -> dict:
        fn = getattr(self, name, None) if name in {t["name"] for t in TOOL_SPECS} else None
        if fn is None:
            result = {"error": f"Unknown tool '{name}'."}
        else:
            try:
                result = fn(**{k: v for k, v in (args or {}).items() if v is not None})
            except (TypeError, ValueError) as exc:
                result = {"error": f"Invalid arguments for {name}: {type(exc).__name__}"}
        self.calls.append({"tool": name, "args": args, "ok": "error" not in result})
        return result
