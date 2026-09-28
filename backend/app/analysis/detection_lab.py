"""Detection engineering lab: custom rules, sandbox evaluation, backtesting, regression and evasion tests.

Everything here runs the real rule implementations against real or synthetic events. Sandbox runs are
evaluated in memory and never write detections, so experiments cannot pollute an analyst's data.
"""

import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.demo.generator import DATASETS, dataset_records, scenario_records
from app.detection.base import Candidate, Ev, RuleContext, cluster_by_gap, fmt_duration, fmt_ts, is_off_hours
from app.detection.catalog import DEFAULT_RULES
from app.detection.engine import build_context, load_events
from app.detection.rules import RULE_IMPLEMENTATIONS
from app.ingestion.normalizer import RowError, is_external_ip, normalize_record
from app.mitre.catalog import TECHNIQUE_INDEX
from app.models import DetectionEvent, DetectionRule, Incident, IncidentEvent, Workspace

GROUP_FIELDS = {"user": "user", "host": "host", "source_ip": "src", "destination_ip": "dst"}
STATELESS_BEHAVIORS = ("off_hours", "external_destination", "large_transfer")
EXPECTED_BY_DATASET = {
    "normal": set(),
    "brute_force": {"SX-001", "SX-002"},
    "privilege_escalation": {"SX-004", "SX-007"},
    "powershell": {"SX-005"},
    "exfiltration": {"SX-008", "SX-009"},
    "mixed": {"SX-001", "SX-002", "SX-003", "SX-004", "SX-005", "SX-006", "SX-007", "SX-008", "SX-009"},
}
# Realistic attack variations used to probe each built-in rule's robustness.
EVASION_TESTS = [
    {"rule": "SX-001", "name": "Low-and-slow brute force (1 attempt / 90 s)", "scenario": "credential_compromise",
     "variations": {"attempt_interval_s": 90, "failed_attempts": 40}},
    {"rule": "SX-001", "name": "Short burst (8 attempts)", "scenario": "credential_compromise",
     "variations": {"failed_attempts": 8}},
    {"rule": "SX-002", "name": "Low-and-slow brute force (1 attempt / 90 s)", "scenario": "credential_compromise",
     "variations": {"attempt_interval_s": 90, "failed_attempts": 40}},
    {"rule": "SX-005", "name": "PowerShell without encoding", "scenario": "credential_compromise",
     "variations": {"encoded_powershell": False}},
    {"rule": "SX-009", "name": "Small exfiltration (90 MB)", "scenario": "credential_compromise",
     "variations": {"exfil_mb": 90}},
    {"rule": "SX-009", "name": "Exfiltration to cloud storage", "scenario": "insider_cloud_exfil",
     "variations": {"upload_mb": 600, "destination": "dropbox.com"}},
    {"rule": "SX-006", "name": "Slow network scan (1 host / 20 s)", "scenario": "internal_scan",
     "variations": {"interval_s": 20}},
    {"rule": "SX-008", "name": "Fewer sensitive files (4)", "scenario": "insider_cloud_exfil",
     "variations": {"file_count": 4}},
]


class RuleSpecError(ValueError):
    pass


# ------------------------------------------------------------------------------------------ custom rules
def validate_rule_spec(spec: dict) -> dict:
    if not isinstance(spec, dict):
        raise RuleSpecError("Rule specification must be an object")
    name = str(spec.get("name", "")).strip()
    if not 3 <= len(name) <= 120:
        raise RuleSpecError("name must be 3-120 characters")
    sev = spec.get("severity", "medium")
    if sev not in ("low", "medium", "high", "critical"):
        raise RuleSpecError("severity must be low, medium, high or critical")
    m = spec.get("match") or {}
    if not isinstance(m, dict):
        raise RuleSpecError("match must be an object")
    types = [t for t in m.get("event_types") or [] if isinstance(t, str)]
    allowed_types = {"authentication", "process", "file", "network", "privilege", "other"}
    if set(types) - allowed_types:
        raise RuleSpecError(f"Unknown event types: {sorted(set(types) - allowed_types)}")
    behaviors = [b for b in m.get("behaviors") or [] if isinstance(b, str)]
    if set(behaviors) - set(STATELESS_BEHAVIORS):
        raise RuleSpecError(f"Rule behaviors must be among {STATELESS_BEHAVIORS}")
    match = {
        "event_types": types, "behaviors": behaviors,
        "status": m.get("status") if m.get("status") in ("success", "failure") else None,
        "actions": [str(a)[:60] for a in m.get("actions") or []][:20],
        "text_any": [str(a)[:120] for a in m.get("text_any") or []][:30],
        "text_all": [str(a)[:120] for a in m.get("text_all") or []][:10],
        "users": [str(a).lower() for a in m.get("users") or []][:50],
        "hosts": [str(a).upper() for a in m.get("hosts") or []][:50],
    }
    if not any([types, behaviors, match["status"], match["actions"], match["text_any"], match["text_all"]]):
        raise RuleSpecError("match must constrain at least one of event_types, status, actions, text or behaviors")
    th = spec.get("threshold") or {}
    count = int(th.get("count", 1))
    window = int(th.get("window_minutes", 60))
    group = th.get("group_by", "host")
    if not 1 <= count <= 10000 or not 1 <= window <= 7 * 1440:
        raise RuleSpecError("threshold.count must be 1-10000 and window_minutes 1-10080")
    if group not in GROUP_FIELDS:
        raise RuleSpecError(f"threshold.group_by must be one of {list(GROUP_FIELDS)}")
    distinct = th.get("distinct")
    if distinct and distinct not in ("user", "host", "source_ip", "destination_ip", "resource", "process"):
        raise RuleSpecError("threshold.distinct must be user, host, source_ip, destination_ip, resource or process")
    mitre = [t for t in spec.get("mitre") or [] if t in TECHNIQUE_INDEX]
    return {"name": name, "description": str(spec.get("description", ""))[:600], "severity": sev,
            "stage": str(spec.get("stage") or "Custom")[:48], "mitre": mitre, "match": match,
            "threshold": {"count": count, "window_minutes": window, "group_by": group, "distinct": distinct or None}}


def _ev_matches(e: Ev, m: dict, bh: tuple[int, int]) -> bool:
    if m["event_types"] and e.type not in m["event_types"]:
        return False
    if m["status"] and e.status != m["status"]:
        return False
    if m["actions"] and not any(a.lower() in (e.action or "") for a in m["actions"]):
        return False
    text = f"{e.process or ''} {e.command or ''} {e.resource or ''}".lower()
    if m["text_any"] and not any(t.lower() in text for t in m["text_any"]):
        return False
    if m["text_all"] and not all(t.lower() in text for t in m["text_all"]):
        return False
    if m["users"] and e.user not in m["users"]:
        return False
    if m["hosts"] and e.host not in m["hosts"]:
        return False
    for b in m["behaviors"]:
        if b == "off_hours" and not is_off_hours(e.ts, bh):
            return False
        if b == "external_destination" and not (is_external_ip(e.dst) or (not e.dst and e.resource and "." in e.resource
                                                                          and not e.resource.startswith("\\"))):
            return False
        if b == "large_transfer" and not (e.bytes and e.bytes >= 10_000_000):
            return False
    return True


def _distinct_value(e: Ev, field: str | None):
    if not field:
        return e.id
    return {"user": e.user, "host": e.host, "source_ip": e.src, "destination_ip": e.dst, "resource": e.resource,
            "process": e.process}[field]


def custom_rule(events: list[Ev], params: dict, ctx: RuleContext) -> list[Candidate]:
    spec = params["spec"]
    key = params.get("rule_key", "SX-C00")
    th = spec["threshold"]
    window = timedelta(minutes=th["window_minutes"])
    gfield = GROUP_FIELDS[th["group_by"]]
    groups: dict[str, list[Ev]] = defaultdict(list)
    for e in events:
        if _ev_matches(e, spec["match"], ctx.business_hours):
            g = getattr(e, gfield)
            if g:
                groups[g].append(e)
    out = []
    for g, evs in groups.items():
        for cl in cluster_by_gap(evs, window):
            # Densest sliding window, measured in distinct values (or events when no distinct field is set).
            counts: dict = defaultdict(int)
            j, n, span = 0, 0, (0, 0)
            for i, e in enumerate(cl):
                counts[_distinct_value(e, th["distinct"])] += 1
                while cl[i].ts - cl[j].ts > window:
                    v = _distinct_value(cl[j], th["distinct"])
                    counts[v] -= 1
                    if counts[v] == 0:
                        del counts[v]
                    j += 1
                if len(counts) > n:
                    n, span = len(counts), (j, i)
            if n < th["count"]:
                continue
            best = cl[span[0]:span[1] + 1]
            what = f"{n} distinct {th['distinct'].replace('_', ' ')} value(s)" if th["distinct"] else f"{n} matching events"
            explanation = (f"Triggered because {th['group_by'].replace('_', ' ')} {g} produced {what} within "
                           f"{fmt_duration(best[-1].ts - best[0].ts)} ({fmt_ts(best[0].ts)} to {fmt_ts(best[-1].ts)}). "
                           f"Custom rule threshold: {th['count']} within {fmt_duration(window)}.")
            out.append(Candidate(
                rule_key=key, dedupe_key=f"{key}:{g}:{cl[0].ts.isoformat()}", title=f"{spec['name']}: {g}",
                description=spec["description"] or spec["name"], severity=spec["severity"], confidence=0.6,
                ts=cl[0].ts, last_seen=cl[-1].ts, events=cl, explanation=explanation,
                mitre=[{"id": t, "reason": f"Assigned by the custom rule author: {spec['name']}.", "mapping_confidence": "medium"}
                       for t in spec["mitre"]],
                false_positives=["Custom rule: review matches before relying on it."],
                recommendations=[f"Review the {len(cl)} matching events for {g}."], stage=spec["stage"],
                user=best[0].user, host=best[0].host, source_ip=best[0].src, destination_ip=best[0].dst,
                evidence_summary={"matched": len(cl), "peak": n, "group": g},
            ))
    return out


def implementation_for(rule: DetectionRule):
    if rule.kind in ("custom", "candidate"):
        return custom_rule, {"spec": (rule.parameters or {}).get("spec"), "rule_key": rule.rule_key}
    return RULE_IMPLEMENTATIONS.get(rule.rule_key), rule.parameters or {}


def next_custom_key(db: Session, workspace_id: int) -> str:
    keys = [k for (k,) in db.execute(select(DetectionRule.rule_key).where(DetectionRule.workspace_id == workspace_id,
                                                                            DetectionRule.rule_key.like("SX-C%")))]
    nums = [int(k[4:]) for k in keys if k[4:].isdigit()]
    return f"SX-C{(max(nums) + 1) if nums else 1:02d}"


# ------------------------------------------------------------------------------------------ in-memory evaluation
def records_to_evs(records: list[dict], id_offset: int = 10_000_000) -> list[Ev]:
    evs = []
    for i, r in enumerate(records):
        try:
            f = normalize_record(r).fields
        except RowError:
            continue
        evs.append(Ev(id_offset + i, f["event_uid"], f["timestamp"], f["event_type"], f["user"], f["source_ip"],
                      f["destination_ip"], f["host"], f["process"], f["command"], f["action"], f["status"], f["bytes"],
                      f["resource"], f["metadata"]))
    evs.sort(key=lambda e: (e.ts, e.id))
    return evs


def evaluate(evs: list[Ev], rules: list[tuple[str, object, dict]], ctx: RuleContext) -> dict[str, list[Candidate]]:
    out: dict[str, list[Candidate]] = {}
    for key, impl, params in rules:
        if impl is None:
            continue
        out[key] = impl(evs, params, ctx)
    return out


def workspace_rules(db: Session, workspace_id: int, include_disabled: bool = False,
                    extra: list[DetectionRule] | None = None) -> list[tuple[str, object, dict]]:
    q = db.query(DetectionRule).filter_by(workspace_id=workspace_id)
    rows = [r for r in q if (include_disabled or r.enabled) and r.kind != "candidate"] + list(extra or [])
    out = []
    for r in rows:
        impl, params = implementation_for(r)
        out.append((r.rule_key, impl, params))
    return out


def default_rules() -> list[tuple[str, object, dict]]:
    return [(r["rule_key"], RULE_IMPLEMENTATIONS[r["rule_key"]], r["parameters"]) for r in DEFAULT_RULES]


def summarize(results: dict[str, list[Candidate]]) -> dict:
    return {k: {"alerts": len(v), "samples": [{"title": c.title, "severity": c.severity, "explanation": c.explanation,
                                               "first": c.ts.isoformat() + "Z", "event_uids": [e.uid for e in c.events[:8]]}
                                              for c in v[:3]]}
            for k, v in results.items() if v}


# ------------------------------------------------------------------------------------------ backtest
def backtest(db: Session, workspace: Workspace, rule: DetectionRule) -> dict:
    impl, params = implementation_for(rule)
    events = load_events(db, workspace.id)
    ctx = build_context(db, workspace, events)
    cands = impl(events, params, ctx) if events else []
    incident_events = {eid for (eid,) in db.execute(select(IncidentEvent.event_id).join(
        Incident, Incident.id == IncidentEvent.incident_id).where(Incident.workspace_id == workspace.id))}
    overlap = [c for c in cands if any(e.id in incident_events for e in c.events)]
    # Benign baseline: the rule should stay quiet on synthetic normal activity.
    normal = records_to_evs(dataset_records("normal"))
    benign = impl(normal, params, RuleContext(business_hours=ctx.business_hours)) if normal else []
    coverage = {}
    for name in DATASETS:
        if name in ("normal", "mixed"):
            continue
        evs = records_to_evs(dataset_records(name))
        coverage[name] = len(impl(evs, params, RuleContext(business_hours=ctx.business_hours)))
    entities = sorted({x for c in cands for x in (c.user, c.host) if x})[:30]
    return {
        "rule_key": rule.rule_key, "events_scanned": len(events), "alerts": len(cands),
        "alerts_overlapping_incidents": len(overlap), "alerts_outside_incidents": len(cands) - len(overlap),
        "benign_baseline_alerts": len(benign), "benign_baseline_events": len(normal),
        "scenario_coverage": coverage, "entities": entities,
        "samples": [{"title": c.title, "explanation": c.explanation, "first": c.ts.isoformat() + "Z",
                     "event_uids": [e.uid for e in c.events[:8]], "in_incident": c in overlap} for c in cands[:10]],
        "interpretation": ("Alerts outside existing incidents and alerts on the benign baseline are candidate false "
                           "positives to review; scenario coverage counts alerts on the synthetic attack datasets."),
        "ran_at": datetime.now(UTC).isoformat(),
    }


def regression(db: Session, workspace: Workspace, candidate: DetectionRule | None = None) -> dict:
    rules = workspace_rules(db, workspace.id, extra=[candidate] if candidate else None)
    bh = tuple((workspace.settings or {}).get("business_hours") or [7, 20])
    ctx = RuleContext(business_hours=(int(bh[0]), int(bh[1])))
    results = []
    for name in DATASETS:
        evs = records_to_evs(dataset_records(name))
        fired = {k for k, v in evaluate(evs, rules, ctx).items() if v}
        expected = EXPECTED_BY_DATASET.get(name, set())
        missing = sorted(expected - fired)
        unexpected = sorted(fired) if name == "normal" else []
        results.append({"dataset": name, "expected": sorted(expected), "fired": sorted(fired), "missing": missing,
                        "unexpected_on_benign": unexpected, "passed": not missing and not unexpected})
    return {"passed": all(r["passed"] for r in results), "datasets": results,
            "rules_evaluated": [k for k, _, _ in rules], "ran_at": datetime.now(UTC).isoformat()}


def evasion_tests(db: Session, workspace: Workspace) -> list[dict]:
    rules = {k: (impl, p) for k, impl, p in workspace_rules(db, workspace.id)}
    all_rules = workspace_rules(db, workspace.id)
    out = []
    start = datetime.now(UTC).replace(tzinfo=None, microsecond=0) - timedelta(days=2)
    for t in EVASION_TESTS:
        if t["rule"] not in rules:
            continue
        evs = records_to_evs(scenario_records(t["scenario"], start.replace(hour=13), t["variations"]))
        impl, params = rules[t["rule"]]
        hits = impl(evs, params, RuleContext())
        others = sorted(k for k, v in evaluate(evs, all_rules, RuleContext()).items() if v and k != t["rule"])
        out.append({"rule": t["rule"], "test": t["name"], "scenario": t["scenario"], "variations": t["variations"],
                    "detected": bool(hits), "other_rules_fired": others})
    return out


def rule_quality(db: Session, workspace: Workspace) -> list[dict]:
    from app.models import Detection

    reg = regression(db, workspace)
    evasions = evasion_tests(db, workspace)
    rows = []
    for r in db.query(DetectionRule).filter_by(workspace_id=workspace.id).order_by(DetectionRule.rule_key):
        dets = db.query(Detection).filter_by(workspace_id=workspace.id, rule_key=r.rule_key).all()
        fp = [d for d in dets if d.incident_id and db.get(Incident, d.incident_id).status == "FALSE_POSITIVE"]
        dismissed = [d for d in dets if d.status == "DISMISSED"]
        missed = [x["dataset"] for x in reg["datasets"] if r.rule_key in x["missing"]]
        ev = [e for e in evasions if e["rule"] == r.rule_key]
        evaded = [e["test"] for e in ev if not e["detected"]]
        weaknesses = []
        if not r.enabled:
            weaknesses.append("disabled")
        if missed:
            weaknesses.append(f"fails regression on {', '.join(missed)}")
        if evaded:
            weaknesses.append(f"evaded by: {'; '.join(evaded)}")
        if dets and (len(fp) + len(dismissed)) / len(dets) >= 0.5:
            weaknesses.append(f"{len(fp) + len(dismissed)} of {len(dets)} detections marked false positive or dismissed")
        rows.append({"rule_key": r.rule_key, "name": r.name, "kind": r.kind, "enabled": r.enabled,
                     "detections": len(dets), "false_positive_or_dismissed": len(fp) + len(dismissed),
                     "regression_failures": missed, "evasion_tests": len(ev), "evaded": evaded,
                     "weaknesses": weaknesses, "mitre": r.mitre_techniques})
    return rows


def detection_events(db: Session, detection_id: int) -> set[int]:
    return {eid for (eid,) in db.execute(select(DetectionEvent.event_id).where(DetectionEvent.detection_id == detection_id))}


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40]
