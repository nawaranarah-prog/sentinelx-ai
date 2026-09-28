"""Correlation engine: groups related detections into incidents and explains why."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy import and_, delete, or_, select
from sqlalchemy.orm import Session

from app.analysis.dna import compute_dna
from app.database.session import utcnow
from app.detection.base import SEVERITY_RANK, fmt_duration, fmt_ts, join_limited, max_severity
from app.ingestion.normalizer import is_external_ip
from app.mitre.catalog import TECHNIQUE_INDEX, tactic_rank
from app.models import (
    AnomalyResult,
    Detection,
    DetectionEvent,
    Event,
    Host,
    Incident,
    IncidentEvent,
    IncidentStatusHistory,
    IncidentTechnique,
    Workspace,
)
from app.models.incident import OPEN_STATUSES
from app.services.notifications import notify_workspace
from app.services.risk import compute_incident_risk

CONTEXT_MARGIN = timedelta(minutes=15)
MAX_CONTEXT_EVENTS = 1000
STAGE_LABELS = {
    "SX-001": "Brute force", "SX-002": "Successful login after failures", "SX-003": "Suspicious privileged login",
    "SX-004": "Privilege escalation", "SX-005": "Suspicious PowerShell", "SX-006": "Discovery",
    "SX-007": "Suspicious process", "SX-008": "Sensitive file access", "SX-009": "Data exfiltration",
    "SX-010": "Threat-intel match",
}


@dataclass
class CorrelationResult:
    new_incidents: list[Incident] = field(default_factory=list)
    updated_incidents: list[Incident] = field(default_factory=list)
    standalone_detections: int = 0


def entity_keys(d: Detection) -> set[str]:
    keys = set()
    if d.user:
        keys.add(f"user:{d.user}")
    if d.source_ip:
        keys.add(f"ip:{d.source_ip}")
    if d.destination_ip and is_external_ip(d.destination_ip):
        keys.add(f"ip:{d.destination_ip}")
    # The host on an authentication-failure burst is the *targeted* service (e.g. a VPN gateway) which many
    # unrelated attacks share, so it is not used as a correlation key for SX-001.
    if d.host and d.rule_key != "SX-001":
        keys.add(f"host:{d.host}")
    return keys


def _key_label(k: str) -> str:
    kind, _, val = k.partition(":")
    return {"user": f"user '{val}'", "ip": f"IP {val}", "host": f"host '{val}'"}[kind]


def _ordered_stages(dets: list[Detection]) -> list[str]:
    firsts: dict[str, object] = {}
    for d in sorted(dets, key=lambda x: x.timestamp):
        firsts.setdefault(d.stage or "Other", d.timestamp)
    return sorted(firsts, key=lambda s: (firsts[s], tactic_rank(s)))


def correlation_reason(dets: list[Detection], window: timedelta) -> tuple[str, dict]:
    counter: Counter = Counter()
    for d in dets:
        for k in entity_keys(d):
            counter[k] += 1
    shared = [(k, c) for k, c in counter.most_common() if c >= 2]
    dets_sorted = sorted(dets, key=lambda x: x.timestamp)
    span = max(d.last_seen for d in dets) - dets_sorted[0].timestamp
    seq = []
    for d in dets_sorted:
        lbl = STAGE_LABELS.get(d.rule_key, d.rule_key)
        if not seq or seq[-1] != lbl:
            seq.append(lbl)
    if len(dets) == 1:
        d = dets[0]
        reason = (f"Single {d.severity.upper()} detection escalated to an incident because its severity is high "
                  f"enough to warrant investigation on its own ({d.title}).")
    else:
        reason = (
            f"{len(dets)} detections were correlated because they share "
            + join_limited([f"{_key_label(k)} ({c} detections)" for k, c in shared], 4)
            + f" and occur within {fmt_duration(span)} (correlation window: consecutive related detections at most "
            f"{fmt_duration(window)} apart). Observed sequence: " + " → ".join(seq) + "."
        )
    return reason, {"shared_entities": [{"key": k, "detections": c} for k, c in shared], "sequence": seq,
                    "span_seconds": int(span.total_seconds()), "window_minutes": int(window.total_seconds() // 60)}


def _title(dets: list[Detection], users: list[str], hosts: list[str]) -> str:
    behavioral = [d for d in dets if d.rule_key != "SX-010"] or dets
    ordered = sorted(behavioral, key=lambda d: (d.timestamp, tactic_rank(d.stage)))
    first = STAGE_LABELS.get(ordered[0].rule_key, ordered[0].stage)
    later = ordered[1:] or ordered
    # The headline outcome is the most severe later stage (ties go to the most recent one).
    worst = max(later, key=lambda d: (SEVERITY_RANK.get(d.severity, 0), d.timestamp))
    last = STAGE_LABELS.get(worst.rule_key, worst.stage)
    chain = first if first == last else f"{first} leading to {last.lower()}"
    subject = []
    if users:
        subject.append(users[0] if len(users) == 1 else f"{len(users)} users")
    if hosts:
        subject.append(hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts")
    return (chain + (" — " + " on ".join(subject) if subject else ""))[:255]


def _checklist(dets: list[Detection], users: list[str], hosts: list[str], ips: list[str], dests: list[str]) -> list[dict]:
    rules = {d.rule_key for d in dets}
    items = ["Review the timeline and confirm the evidence events"]
    if users:
        items.append(f"Contact {join_limited(users, 3)} out-of-band to validate the activity")
    if rules & {"SX-001", "SX-002"}:
        items.append(f"Review authentication history for {join_limited(ips, 3) or 'the source addresses'}")
    if rules & {"SX-002", "SX-003", "SX-005", "SX-007"} and users:
        items.append(f"Reset credentials and revoke sessions for {join_limited(users, 3)}")
    if "SX-004" in rules:
        items.append("Remove unauthorized privileged group membership")
    if rules & {"SX-005", "SX-006", "SX-007"} and hosts:
        items.append(f"Isolate and triage {join_limited(hosts, 3)}")
    if "SX-008" in rules:
        items.append("Identify the data accessed and its classification")
    if "SX-009" in rules:
        items.append(f"Block exfiltration destination(s) {join_limited(dests, 3)} and assess notification obligations")
    items.append("Document findings, root cause and lessons learned")
    return [{"item": t, "done": False} for t in items]


def rebuild_incident(db: Session, incident: Incident, workspace: Workspace) -> None:
    dets = db.query(Detection).filter_by(incident_id=incident.id).order_by(Detection.timestamp).all()
    if not dets:
        return
    window = timedelta(minutes=int((workspace.settings or {}).get("correlation_window_minutes", 120)))
    ev_ids = set(db.scalars(select(DetectionEvent.event_id).where(
        DetectionEvent.detection_id.in_([d.id for d in dets]))))

    users = [u for u, _ in Counter(d.user for d in dets if d.user).most_common()]
    for d in dets:
        if d.rule_key == "SX-001":
            for acct in (d.evidence_summary or {}).get("accounts", [])[:25]:
                if acct not in users:
                    users.append(acct)
    hosts = [h for h, _ in Counter(d.host for d in dets if d.host).most_common()]
    src_ips = [i for i, _ in Counter(d.source_ip for d in dets if d.source_ip).most_common()]
    dst_ips = [i for i, _ in Counter(d.destination_ip for d in dets if d.destination_ip).most_common()]
    ev_rows = db.execute(select(Event.id, Event.host, Event.source_ip, Event.destination_ip)
                         .where(Event.id.in_(ev_ids))).all() if ev_ids else []
    for _, h, s, dst in ev_rows:
        if h and h not in hosts and len(hosts) < 25:
            hosts.append(h)
        if s and s not in src_ips and len(src_ips) < 25:
            src_ips.append(s)
        if dst and dst not in dst_ips and len(dst_ips) < 25 and is_external_ip(dst):
            dst_ips.append(dst)

    incident.first_seen = min(d.timestamp for d in dets)
    incident.last_seen = max(d.last_seen for d in dets)
    incident.severity = max_severity(*(d.severity for d in dets))
    top_conf = max(d.confidence for d in dets)
    incident.confidence = round(min(0.99, top_conf + 0.03 * (len(dets) - 1)), 2)
    incident.users, incident.hosts = users[:50], hosts[:50]
    incident.source_ips, incident.destination_ips = src_ips[:50], dst_ips[:50]
    incident.stages = _ordered_stages(dets)
    if incident.origin == "correlation":
        det_users = list(dict.fromkeys(d.user for d in dets if d.user)) or users
        det_hosts = list(dict.fromkeys(d.host for d in dets if d.host))
        incident.title = _title(dets, det_users, det_hosts)
    reason, keys = correlation_reason(dets, window)
    incident.correlation_reason = reason
    incident.correlation_keys = keys

    # Evidence + context events
    db.execute(delete(IncidentEvent).where(IncidentEvent.incident_id == incident.id))
    for eid in ev_ids:
        db.add(IncidentEvent(incident_id=incident.id, event_id=eid, role="evidence"))
    conds = []
    if users:
        conds.append(Event.user.in_(users[:50]))
    if hosts:
        conds.append(Event.host.in_(hosts[:50]))
    if src_ips:
        conds.append(Event.source_ip.in_(src_ips[:50]))
    if conds:
        ctx_ids = db.scalars(
            select(Event.id).where(and_(
                Event.workspace_id == incident.workspace_id,
                Event.timestamp >= incident.first_seen - CONTEXT_MARGIN,
                Event.timestamp <= incident.last_seen + CONTEXT_MARGIN,
                or_(*conds))).order_by(Event.timestamp).limit(MAX_CONTEXT_EVENTS + len(ev_ids)))
        n = 0
        for cid in ctx_ids:
            if cid not in ev_ids and n < MAX_CONTEXT_EVENTS:
                db.add(IncidentEvent(incident_id=incident.id, event_id=cid, role="context"))
                n += 1

    # MITRE techniques aggregated from detections
    db.execute(delete(IncidentTechnique).where(IncidentTechnique.incident_id == incident.id))
    agg: dict[str, dict] = defaultdict(lambda: {"reasons": [], "dets": [], "uids": [], "conf": []})
    for d in dets:
        uids = (d.evidence_summary or {}).get("event_uids", [])
        for m in d.mitre or []:
            if m["id"] not in TECHNIQUE_INDEX:
                continue
            a = agg[m["id"]]
            if m["reason"] not in a["reasons"]:
                a["reasons"].append(m["reason"])
            a["dets"].append(d.id)
            a["uids"].extend(u for u in uids[:10] if u not in a["uids"])
            a["conf"].append(m.get("mapping_confidence", "high"))
    rank = {"low": 0, "medium": 1, "high": 2}
    for tid, a in agg.items():
        db.add(IncidentTechnique(
            incident_id=incident.id, technique_id=tid, reason=" ".join(a["reasons"])[:4000],
            detection_ids=sorted(set(a["dets"])), event_uids=a["uids"][:30],
            mapping_confidence=max(a["conf"], key=lambda c: rank.get(c, 0)),
        ))

    # Anomaly results for the involved entities during the incident days
    day_start = incident.first_seen.replace(hour=0, minute=0, second=0, microsecond=0)
    anomalies = db.query(AnomalyResult).filter(
        AnomalyResult.workspace_id == incident.workspace_id,
        AnomalyResult.window_start >= day_start,
        AnomalyResult.window_start <= incident.last_seen,
        or_(and_(AnomalyResult.entity_type == "user", AnomalyResult.entity.in_(users[:50] or [""])),
            and_(AnomalyResult.entity_type == "host", AnomalyResult.entity.in_(hosts[:50] or [""])))).all()
    flagged = [a for a in anomalies if a.is_anomalous]
    incident.anomaly_summary = {
        "windows_checked": len(anomalies), "anomalous_windows": len(flagged),
        "items": [{"entity_type": a.entity_type, "entity": a.entity, "day": a.window_start.strftime("%Y-%m-%d"),
                   "if_score": a.if_score, "if_threshold": a.if_threshold, "if_flagged": a.if_flagged,
                   "is_anomalous": a.is_anomalous, "top_deviations": a.top_deviations[:3], "method": a.method}
                  for a in sorted(anomalies, key=lambda a: -(a.if_score or 0))[:10]],
    }
    host_crit = {h.hostname: h.criticality for h in db.query(Host).filter(
        Host.workspace_id == incident.workspace_id, Host.hostname.in_(hosts[:50] or [""]))}
    score, band_, factors = compute_incident_risk(dets, list(agg), users, hosts, len(ev_ids), anomalies, host_crit)
    incident.risk_score, incident.risk_band, incident.risk_factors = score, band_, factors
    bh = (workspace.settings or {}).get("business_hours") or [7, 20]
    incident.dna = compute_dna(incident, dets, list(agg), (int(bh[0]), int(bh[1])))

    old = {c["item"]: c["done"] for c in (incident.checklist or [])}
    incident.checklist = [{"item": c["item"], "done": old.get(c["item"], False)}
                          for c in _checklist(dets, users, hosts, src_ips, dst_ips)]
    stages_txt = " → ".join(incident.stages)
    incident.summary = (
        f"Between {fmt_ts(incident.first_seen)} and {fmt_ts(incident.last_seen)}, SentinelX recorded {len(dets)} "
        f"detection(s) spanning {len(incident.stages)} stage(s) ({stages_txt})"
        + (f" involving user(s) {join_limited(users, 3)}" if users else "")
        + (f" on host(s) {join_limited(hosts, 3)}" if hosts else "")
        + (f" with source IP(s) {join_limited(src_ips, 3)}" if src_ips else "") + ". "
        + f"SentinelX Risk Score {score}/100 ({band_})."
    )
    incident.updated_at = utcnow()


def correlate(db: Session, workspace: Workspace) -> CorrelationResult:
    result = CorrelationResult()
    window = timedelta(minutes=int((workspace.settings or {}).get("correlation_window_minutes", 120)))
    dets = db.query(Detection).filter(Detection.workspace_id == workspace.id, Detection.incident_id.is_(None),
                                      Detection.status == "OPEN").order_by(Detection.timestamp).all()
    if not dets:
        return result
    parent = list(range(len(dets)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    last_by_key: dict[str, int] = {}
    for i, d in enumerate(dets):
        for k in entity_keys(d):
            j = last_by_key.get(k)
            if j is not None and d.timestamp - dets[j].last_seen <= window:
                parent[find(i)] = find(j)
            if j is None or d.last_seen >= dets[j].last_seen:
                last_by_key[k] = i
    clusters: dict[int, list[Detection]] = defaultdict(list)
    for i, d in enumerate(dets):
        clusters[find(i)].append(d)

    open_incidents = db.query(Incident).filter(Incident.workspace_id == workspace.id,
                                               Incident.status.in_(OPEN_STATUSES)).all()
    inc_keys = {}
    for inc in open_incidents:
        keys = {f"user:{u}" for u in inc.users or []} | {f"host:{h}" for h in inc.hosts or []} | \
               {f"ip:{i}" for i in inc.source_ips or []}
        inc_keys[inc.id] = keys

    touched: dict[int, Incident] = {}
    for members in sorted(clusters.values(), key=lambda m: m[0].timestamp):
        keys = set().union(*(entity_keys(d) for d in members))
        first = min(d.timestamp for d in members)
        last = max(d.last_seen for d in members)
        target = None
        for inc in open_incidents:
            if keys & inc_keys[inc.id] and first - inc.last_seen <= window and last >= inc.first_seen - window:
                target = inc
                break
        if target is None:
            qualifies = len(members) >= 2 or any(d.severity in ("high", "critical") for d in members)
            if not qualifies:
                result.standalone_detections += len(members)
                continue
            workspace.incident_seq = (workspace.incident_seq or 0) + 1
            target = Incident(workspace_id=workspace.id, number=f"INC-{workspace.incident_seq:04d}", title="pending",
                              severity="low", first_seen=first, last_seen=last, status="NEW", origin="correlation")
            db.add(target)
            db.flush()
            db.add(IncidentStatusHistory(incident_id=target.id, from_status=None, to_status="NEW",
                                         note="Created by the SentinelX correlation engine"))
            result.new_incidents.append(target)
            open_incidents.append(target)
        else:
            if target.id not in touched and target not in result.new_incidents:
                result.updated_incidents.append(target)
        prev_sev = target.severity
        for d in members:
            d.incident_id = target.id
        db.flush()
        rebuild_incident(db, target, workspace)
        inc_keys[target.id] = {f"user:{u}" for u in target.users} | {f"host:{h}" for h in target.hosts} | \
                              {f"ip:{i}" for i in target.source_ips}
        touched[target.id] = target
        if target not in result.new_incidents and SEVERITY_RANK.get(target.severity, 0) > SEVERITY_RANK.get(prev_sev, 0):
            notify_workspace(db, workspace.id, "incident_escalation",
                             f"{target.number} escalated to {target.severity.upper()}",
                             f"New correlated activity raised the severity of '{target.title}'.",
                             f"/incidents/{target.id}", severity=target.severity)
    for inc in result.new_incidents:
        notify_workspace(db, workspace.id, "new_incident", f"New {inc.severity.upper()} incident {inc.number}",
                         inc.title, f"/incidents/{inc.id}", severity=inc.severity)
    db.flush()
    return result
