"""Attack graph built strictly from an incident's detections and evidence events."""

from collections import Counter, defaultdict

from sqlalchemy.orm import Session

from app.correlation.engine import STAGE_LABELS
from app.detection.base import fmt_bytes
from app.ingestion.normalizer import is_external_ip
from app.models import Detection, DetectionEvent, Event, Incident

LAYERS = {"ip": 0, "user": 1, "host": 2, "activity": 3, "target": 4}


def build_graph(db: Session, incident: Incident) -> dict:
    dets = db.query(Detection).filter_by(incident_id=incident.id).order_by(Detection.timestamp).all()
    det_ids = [d.id for d in dets]
    links = db.query(DetectionEvent.detection_id, Event).join(Event, Event.id == DetectionEvent.event_id).filter(
        DetectionEvent.detection_id.in_(det_ids or [0])).all()
    events_by_det: dict[int, list[Event]] = defaultdict(list)
    for did, ev in links:
        events_by_det[did].append(ev)

    nodes: dict[str, dict] = {}
    edges: dict[tuple, dict] = {}

    def node(nid: str, ntype: str, label: str, layer: str, **extra) -> str:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label, "layer": LAYERS[layer], **extra}
        return nid

    def edge(src: str, dst: str, label: str, **extra) -> None:
        key = (src, dst, label)
        if key not in edges:
            edges[key] = {"id": f"e{len(edges)}", "source": src, "target": dst, "label": label, **extra}

    # Authentication relationships: source IP → user (failures / successes), user → host (logons).
    auth_counts: Counter = Counter()
    logons: set[tuple[str, str]] = set()
    all_events = {e.id: e for evs in events_by_det.values() for e in evs}
    for e in all_events.values():
        if e.event_type == "authentication":
            if e.source_ip and e.user:
                auth_counts[(e.source_ip, e.user, e.status or "unknown")] += 1
            if e.status == "success" and e.user and e.host:
                logons.add((e.user, e.host))
    pairs: dict[tuple[str, str], dict[str, int]] = defaultdict(dict)
    for (ip, user, status), n in auth_counts.items():
        pairs[(ip, user)][status] = n
    for (ip, user), by_status in pairs.items():
        node(f"ip:{ip}", "ip", ip, "ip", external=is_external_ip(ip))
        node(f"user:{user}", "user", user, "user")
        parts = [f"{n} {'failed' if s == 'failure' else 'successful' if s == 'success' else s}"
                 for s, n in sorted(by_status.items(), key=lambda x: x[0] != "failure")]
        edge(f"ip:{ip}", f"user:{user}", ", ".join(parts) + " login" + ("s" if sum(by_status.values()) != 1 else ""),
             kind="auth_failure" if "failure" in by_status else "auth")
    for user, host in logons:
        node(f"user:{user}", "user", user, "user")
        node(f"host:{host}", "host", host, "host")
        edge(f"user:{user}", f"host:{host}", "logged on", kind="logon")

    prev = None
    for order, d in enumerate(dets):
        did = node(f"det:{d.id}", "detection", STAGE_LABELS.get(d.rule_key, d.rule_key), "activity",
                   sublabel=d.title, severity=d.severity, detection_id=d.id, rule_key=d.rule_key, order=order,
                   timestamp=d.timestamp.isoformat() + "Z", stage=d.stage)
        if d.host:
            node(f"host:{d.host}", "host", d.host, "host")
            edge(f"host:{d.host}", did, "observed on", kind="observed")
        elif d.user:
            node(f"user:{d.user}", "user", d.user, "user")
            edge(f"user:{d.user}", did, "performed by", kind="observed")
        elif d.source_ip:
            node(f"ip:{d.source_ip}", "ip", d.source_ip, "ip", external=is_external_ip(d.source_ip))
            edge(f"ip:{d.source_ip}", did, "originated from", kind="observed")
        if d.user and d.host:
            node(f"user:{d.user}", "user", d.user, "user")
            if (d.user, d.host) not in logons:
                edge(f"user:{d.user}", f"host:{d.host}", "active on", kind="activity")
        if prev:
            edge(prev, did, "followed by", kind="sequence")
        prev = did
        summary = d.evidence_summary or {}
        if d.rule_key == "SX-008":
            files = summary.get("files", [])
            tid = node(f"files:{d.id}", "files", f"{len(files)} sensitive file(s)", "target", items=files[:30])
            edge(did, tid, "accessed", kind="target")
        elif d.rule_key == "SX-009":
            dest = summary.get("destination") or d.destination_ip or "external destination"
            tid = node(f"dest:{dest}", "destination", dest, "target", external=True)
            edge(did, tid, f"sent {fmt_bytes(summary.get('total_bytes', 0))}", kind="exfil")
        elif d.rule_key == "SX-010":
            val = summary.get("indicator")
            tid = node(f"ioc:{val}", "indicator", str(val), "target",
                       sublabel=f"{summary.get('indicator_type')} · {summary.get('indicator_source')}")
            edge(did, tid, "matches indicator", kind="intel")
        elif d.rule_key == "SX-004":
            grp = summary.get("group")
            if grp:
                tid = node(f"group:{grp}", "group", str(grp), "target")
                edge(did, tid, "membership added", kind="target")

    ordered = sorted(nodes.values(), key=lambda n: (n["layer"], n.get("order", 0), n["label"]))
    counters: Counter = Counter()
    for n in ordered:
        n["row"] = counters[n["layer"]]
        counters[n["layer"]] += 1
    return {"nodes": ordered, "edges": list(edges.values()),
            "layers": [{"index": v, "name": k} for k, v in LAYERS.items()],
            "note": "Every node and edge is derived from this incident's detections and their evidence events."}
