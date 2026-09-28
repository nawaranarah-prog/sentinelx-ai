"""Persistent security knowledge graph built from telemetry, detections and incidents.

Every node and edge is derived from stored data (each edge keeps sample event IDs as evidence).
The graph is rebuilt for a workspace at the end of each pipeline run.
"""

from collections import defaultdict, deque
from datetime import datetime

from sqlalchemy import delete, insert, or_, select
from sqlalchemy.orm import Session

from app.detection.base import Ev
from app.ingestion.normalizer import is_external_ip
from app.models import Detection, GraphEdge, GraphNode, Host, Incident, IncidentTechnique, ThreatIndicator

NODE_KINDS = ("user", "host", "ip", "process", "domain", "share", "group", "incident", "detection", "technique", "ioc")
RELATIONS = {
    "authenticated_to": "user logged on to host",
    "authenticated_from": "user authenticated from IP address",
    "connected_to": "host or IP connected to destination",
    "executed": "user executed process",
    "executed_on": "process ran on host",
    "accessed": "user accessed file share",
    "resolved_to": "domain resolved to IP (observed together)",
    "modified_group": "user added an account to a group",
    "involved_in": "entity involved in incident",
    "triggered": "entity triggered detection",
    "observed_on": "detection observed on host",
    "part_of": "detection part of incident",
    "uses": "incident uses ATT&CK technique",
    "precedes": "detection happened before the next detection of the same incident",
    "associated_with": "indicator matched an entity",
}
SAMPLES = 5


def _share_root(path: str) -> str | None:
    if not path.startswith("\\\\"):
        return None
    parts = [p for p in path.split("\\") if p]
    return "\\\\" + "\\".join(parts[:2]) if len(parts) >= 2 else None


def _domain(resource: str | None) -> str | None:
    if not resource or resource.startswith("\\"):
        return None
    r = resource.lower()
    if r.startswith("http"):
        r = r.split("/")[2] if r.count("/") >= 2 else r
    r = r.split(":")[0]
    if "." in r and " " not in r and not r.replace(".", "").isdigit():
        return r
    return None


class _Builder:
    def __init__(self):
        self.nodes: dict[tuple[str, str], dict] = {}
        self.edges: dict[tuple, dict] = {}

    def node(self, kind: str, key: str, label: str | None = None, ts: datetime | None = None, **props) -> tuple[str, str]:
        k = (kind, key[:255])
        n = self.nodes.get(k)
        if n is None:
            n = self.nodes[k] = {"kind": kind, "key": key[:255], "label": (label or key)[:255], "props": {},
                                 "first_seen": ts, "last_seen": ts}
        n["props"].update({p: v for p, v in props.items() if v is not None})
        if ts:
            n["first_seen"] = min(filter(None, [n["first_seen"], ts]))
            n["last_seen"] = max(filter(None, [n["last_seen"], ts]))
        return k

    def edge(self, src: tuple, dst: tuple, rel: str, ts: datetime | None = None, uid: str | None = None, **props):
        k = (src, dst, rel)
        e = self.edges.get(k)
        if e is None:
            e = self.edges[k] = {"count": 0, "first_seen": ts, "last_seen": ts, "samples": [], "props": defaultdict(int)}
        e["count"] += 1
        if ts:
            e["first_seen"] = min(filter(None, [e["first_seen"], ts]))
            e["last_seen"] = max(filter(None, [e["last_seen"], ts]))
        if uid and len(e["samples"]) < SAMPLES:
            e["samples"].append(uid)
        for p, v in props.items():
            if isinstance(v, (int, float)):
                e["props"][p] += v


def rebuild(db: Session, workspace_id: int, events: list[Ev]) -> dict:
    b = _Builder()
    hosts = {h.hostname: h for h in db.query(Host).filter_by(workspace_id=workspace_id)}
    for e in events:
        user = b.node("user", e.user, ts=e.ts) if e.user else None
        host = None
        if e.host:
            h = hosts.get(e.host)
            host = b.node("host", e.host, ts=e.ts, criticality=h.criticality if h else None,
                          role=h.role_hint if h else None)
        src = b.node("ip", e.src, ts=e.ts, external=is_external_ip(e.src)) if e.src else None
        if e.type == "authentication":
            ok = 1 if e.status == "success" else 0
            if user and host:
                b.edge(user, host, "authenticated_to", e.ts, e.uid, success=ok, failure=1 - ok)
            if user and src:
                b.edge(user, src, "authenticated_from", e.ts, e.uid, success=ok, failure=1 - ok)
        elif e.type == "process" and e.process:
            proc = b.node("process", e.process.lower(), ts=e.ts)
            if host:
                b.edge(proc, host, "executed_on", e.ts, e.uid)
            if user:
                b.edge(user, proc, "executed", e.ts, e.uid)
        elif e.type == "network":
            origin = host or src
            dom = _domain(e.resource)
            if e.dst:
                dst = b.node("ip", e.dst, ts=e.ts, external=is_external_ip(e.dst))
                if origin:
                    b.edge(origin, dst, "connected_to", e.ts, e.uid, bytes=e.bytes or 0)
                if dom:
                    b.edge(b.node("domain", dom, ts=e.ts), dst, "resolved_to", e.ts, e.uid)
            elif dom and origin:
                b.edge(origin, b.node("domain", dom, ts=e.ts), "connected_to", e.ts, e.uid, bytes=e.bytes or 0)
        elif e.type == "file" and e.resource:
            root = _share_root(e.resource)
            if root and user:
                b.edge(user, b.node("share", root.lower(), label=root, ts=e.ts), "accessed", e.ts, e.uid)
        elif e.type == "privilege" and user:
            grp = e.meta.get("group") or e.resource
            if grp:
                b.edge(user, b.node("group", str(grp).lower(), label=str(grp), ts=e.ts), "modified_group", e.ts, e.uid)

    # Incidents, detections, techniques
    dets = db.query(Detection).filter_by(workspace_id=workspace_id).all()
    incidents = {i.id: i for i in db.query(Incident).filter_by(workspace_id=workspace_id)}
    by_incident: dict[int, list[Detection]] = defaultdict(list)
    for d in dets:
        dn = b.node("detection", str(d.id), label=f"{d.rule_key} · {d.title}", ts=d.timestamp, severity=d.severity,
                    rule_key=d.rule_key, detection_id=d.id)
        if d.user:
            b.edge(b.node("user", d.user), dn, "triggered", d.timestamp)
        if d.host:
            b.edge(dn, b.node("host", d.host), "observed_on", d.timestamp)
        if d.incident_id and d.incident_id in incidents:
            by_incident[d.incident_id].append(d)
        if d.rule_key == "SX-010":
            s = d.evidence_summary or {}
            ioc = b.node("ioc", f"{s.get('indicator_type')}:{s.get('indicator')}", label=str(s.get("indicator")),
                         ts=d.timestamp, indicator_type=s.get("indicator_type"), synthetic=s.get("synthetic"))
            kind = {"ip": "ip", "domain": "domain", "hostname": "host", "username": "user"}.get(s.get("indicator_type"))
            if kind:
                key = str(s.get("indicator"))
                key = key.upper() if kind == "host" else key.lower() if kind in ("user", "domain") else key
                b.edge(ioc, b.node(kind, key), "associated_with", d.timestamp)
    for inc in incidents.values():
        inode = b.node("incident", inc.number, label=f"{inc.number} · {inc.title}", ts=inc.first_seen,
                       severity=inc.severity, status=inc.status, incident_id=inc.id, risk_score=inc.risk_score)
        for u in inc.users or []:
            b.edge(b.node("user", u), inode, "involved_in", inc.first_seen)
        for h in inc.hosts or []:
            b.edge(b.node("host", h), inode, "involved_in", inc.first_seen)
        for ip in (inc.source_ips or []) + (inc.destination_ips or []):
            b.edge(b.node("ip", ip), inode, "involved_in", inc.first_seen)
        ordered = sorted(by_incident.get(inc.id, []), key=lambda d: d.timestamp)
        for d in ordered:
            b.edge(b.node("detection", str(d.id)), inode, "part_of", d.timestamp)
        for a, c in zip(ordered, ordered[1:], strict=False):
            b.edge(b.node("detection", str(a.id)), b.node("detection", str(c.id)), "precedes", c.timestamp)
    for t in db.query(IncidentTechnique).join(Incident, Incident.id == IncidentTechnique.incident_id).filter(
            Incident.workspace_id == workspace_id):
        inc = incidents.get(t.incident_id)
        if inc:
            b.edge(b.node("incident", inc.number), b.node("technique", t.technique_id), "uses", inc.first_seen)
    for ind in db.query(ThreatIndicator).filter_by(workspace_id=workspace_id, active=True):
        b.node("ioc", f"{ind.indicator_type}:{ind.value}", label=ind.value, indicator_type=ind.indicator_type,
               synthetic=ind.is_synthetic, severity=ind.severity)

    db.execute(delete(GraphEdge).where(GraphEdge.workspace_id == workspace_id))
    db.execute(delete(GraphNode).where(GraphNode.workspace_id == workspace_id))
    rows = [GraphNode(workspace_id=workspace_id, kind=n["kind"], key=n["key"], label=n["label"], props=n["props"],
                      first_seen=n["first_seen"], last_seen=n["last_seen"]) for n in b.nodes.values()]
    db.add_all(rows)
    db.flush()
    ids = {(r.kind, r.key): r.id for r in rows}
    payload = [{"workspace_id": workspace_id, "src_id": ids[s], "dst_id": ids[d], "rel": rel, "count": e["count"],
                "first_seen": e["first_seen"], "last_seen": e["last_seen"], "sample_event_uids": e["samples"],
                "props": dict(e["props"])} for (s, d, rel), e in b.edges.items() if s in ids and d in ids]
    for i in range(0, len(payload), 2000):
        db.execute(insert(GraphEdge), payload[i:i + 2000])
    db.flush()
    return {"nodes": len(rows), "edges": len(payload)}


# ------------------------------------------------------------------------------------------ queries
def node_payload(n: GraphNode) -> dict:
    return {"id": n.id, "kind": n.kind, "key": n.key, "label": n.label, "props": n.props,
            "first_seen": n.first_seen.isoformat() + "Z" if n.first_seen else None,
            "last_seen": n.last_seen.isoformat() + "Z" if n.last_seen else None}


def edge_payload(e: GraphEdge) -> dict:
    return {"id": e.id, "source": e.src_id, "target": e.dst_id, "rel": e.rel, "count": e.count,
            "first_seen": e.first_seen.isoformat() + "Z" if e.first_seen else None,
            "last_seen": e.last_seen.isoformat() + "Z" if e.last_seen else None,
            "evidence": e.sample_event_uids, "props": e.props}


def normalize_key(kind: str, key: str) -> str:
    key = key.strip()
    if kind == "host":
        return key.upper()
    if kind in ("user", "domain", "process", "share", "group"):
        return key.lower()
    return key


def find_node(db: Session, workspace_id: int, ref: str, kind: str | None = None) -> GraphNode | None:
    ref = ref.strip()
    if ":" in ref and ref.split(":", 1)[0] in NODE_KINDS and kind is None:
        kind, ref = ref.split(":", 1)
    q = db.query(GraphNode).filter(GraphNode.workspace_id == workspace_id)
    kinds = [kind] if kind else list(NODE_KINDS)
    for k in kinds:
        n = q.filter(GraphNode.kind == k, GraphNode.key == normalize_key(k, ref)).first()
        if n:
            return n
    return q.filter(GraphNode.label.ilike(f"%{ref}%")).order_by(GraphNode.kind).first()


def search_nodes(db: Session, workspace_id: int, text: str, kind: str | None = None, limit: int = 25) -> list[GraphNode]:
    q = db.query(GraphNode).filter(GraphNode.workspace_id == workspace_id,
                                   or_(GraphNode.key.ilike(f"%{text}%"), GraphNode.label.ilike(f"%{text}%")))
    if kind:
        q = q.filter(GraphNode.kind == kind)
    rows = q.limit(500).all()
    t = text.lower()
    entity_kinds = ("user", "host", "ip", "domain", "process", "share", "group")
    # Exact key first, then prefix matches, then entities before incidents/detections, then alphabetical.
    rows.sort(key=lambda n: (n.key.lower() != t, not n.key.lower().startswith(t), n.kind not in entity_kinds,
                             n.kind, n.label))
    return rows[:limit]


def neighbors(db: Session, workspace_id: int, node_id: int, rels: list[str] | None = None, limit: int = 60) -> dict:
    q = db.query(GraphEdge).filter(GraphEdge.workspace_id == workspace_id,
                                   or_(GraphEdge.src_id == node_id, GraphEdge.dst_id == node_id))
    if rels:
        q = q.filter(GraphEdge.rel.in_(rels))
    edges = q.order_by(GraphEdge.count.desc()).limit(limit).all()
    ids = {node_id} | {e.src_id for e in edges} | {e.dst_id for e in edges}
    nodes = db.query(GraphNode).filter(GraphNode.id.in_(ids)).all()
    return {"nodes": [node_payload(n) for n in nodes], "edges": [edge_payload(e) for e in edges]}


def find_paths(db: Session, workspace_id: int, src_id: int, dst_id: int, max_depth: int = 5, max_paths: int = 5,
               exclude_kinds: tuple[str, ...] = ()) -> dict:
    """Breadth-first search over the undirected graph; returns up to `max_paths` shortest simple paths."""
    edges = db.execute(select(GraphEdge.id, GraphEdge.src_id, GraphEdge.dst_id, GraphEdge.rel)
                       .where(GraphEdge.workspace_id == workspace_id)).all()
    kinds = dict(db.execute(select(GraphNode.id, GraphNode.kind).where(GraphNode.workspace_id == workspace_id)).all())
    adj: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for eid, s, d, _ in edges:
        adj[s].append((d, eid))
        adj[d].append((s, eid))
    paths: list[list[tuple[int, int | None]]] = []
    queue = deque([[(src_id, None)]])
    best = None
    while queue and len(paths) < max_paths:
        path = queue.popleft()
        if best is not None and len(path) > best:
            break
        last = path[-1][0]
        if last == dst_id:
            paths.append(path)
            best = len(path)
            continue
        if len(path) > max_depth:
            continue
        visited = {p[0] for p in path}
        for nxt, eid in adj.get(last, []):
            if nxt in visited or (kinds.get(nxt) in exclude_kinds and nxt != dst_id):
                continue
            queue.append(path + [(nxt, eid)])
    node_ids = {n for p in paths for n, _ in p}
    edge_ids = {e for p in paths for _, e in p if e}
    nodes = {n.id: n for n in db.query(GraphNode).filter(GraphNode.id.in_(node_ids or {0}))}
    edge_rows = {e.id: e for e in db.query(GraphEdge).filter(GraphEdge.id.in_(edge_ids or {0}))}
    return {
        "paths": [[{"node": node_payload(nodes[n]), "via": edge_payload(edge_rows[e]) if e else None} for n, e in p]
                  for p in paths],
        "found": len(paths), "max_depth": max_depth,
        "note": "Paths are observed relationships in stored telemetry, detections and incidents; a path shows "
                "connection, not proof of attacker movement.",
    }


def incident_subgraph(db: Session, workspace_id: int, incident: Incident) -> dict:
    inode = db.query(GraphNode).filter_by(workspace_id=workspace_id, kind="incident", key=incident.number).first()
    if inode is None:
        return {"nodes": [], "edges": []}
    first = neighbors(db, workspace_id, inode.id, limit=200)
    ids = {n["id"] for n in first["nodes"]}
    entity_ids = [n["id"] for n in first["nodes"] if n["kind"] in ("user", "host", "ip")]
    extra = db.query(GraphEdge).filter(GraphEdge.workspace_id == workspace_id, GraphEdge.src_id.in_(entity_ids or [0]),
                                       GraphEdge.dst_id.in_(ids)).all()
    edges = {e["id"]: e for e in first["edges"]}
    for e in extra:
        edges[e.id] = edge_payload(e)
    return {"nodes": first["nodes"], "edges": list(edges.values())}
