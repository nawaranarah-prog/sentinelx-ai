"""Attack simulation, attack variations, defense what-if and counterfactual analysis.

Simulations run synthetic scenarios (from the Nova Bank generator) through the real detection rules.
Controls are modeled explicitly: each control blocks specific attack steps; blocked steps are recorded
as failed/denied events and the steps that depend on them do not happen. Results are clearly labeled as
simulations of a modeled environment, not predictions about a real network.
"""

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.analysis.detection_lab import evaluate, records_to_evs, workspace_rules
from app.correlation.engine import STAGE_LABELS
from app.demo.generator import SCENARIO_PARAMETERS, SCENARIOS, scenario_records
from app.detection.base import RuleContext, fmt_bytes
from app.ingestion.normalizer import is_external_ip, normalize_record
from app.mitre.catalog import tactic_rank
from app.models import Detection, Incident, IncidentTechnique, SimulationRun, Workspace
from app.services.risk import compute_incident_risk

CONTROLS = {
    "mfa": {"label": "MFA on remote access (VPN)", "gate": True,
            "blocks": "successful password-only logins to NB-VPN01 from external addresses"},
    "powershell_constrained": {"label": "Block encoded / download-cradle PowerShell (EDR)", "gate": True,
                               "blocks": "PowerShell with -enc, FromBase64String, DownloadString or IEX"},
    "privileged_group_approval": {"label": "Approval workflow for privileged group changes", "gate": False,
                                  "blocks": "additions to Administrators / Domain Admins without approval"},
    "credential_guard": {"label": "Credential Guard / LSASS protection", "gate": False,
                         "blocks": "LSASS memory dumps and NTDS.dit extraction"},
    "dlp_egress": {"label": "DLP / egress filtering for uploads", "gate": False,
                   "blocks": "uploads of 10 MB or more to external destinations"},
    "network_segmentation": {"label": "Segmentation of workstation SMB traffic", "gate": False,
                             "blocks": "workstation-to-workstation SMB connections after the first 5"},
}
_PS_BLOCK = re.compile(r"-enc|frombase64string|downloadstring|\biex\b|invoke-expression", re.I)
RULE_GATES = {"mfa": {"SX-002", "SX-003"}, "powershell_constrained": {"SX-005"},
              "privileged_group_approval": {"SX-004"}, "credential_guard": {"SX-007"}, "dlp_egress": {"SX-009"},
              "network_segmentation": {"SX-006"}}


class SimulationError(ValueError):
    pass


def _blocked_by(rec: dict, controls: set[str], state: dict) -> str | None:
    cmd = f"{rec.get('process', '')} {rec.get('command', '')}"
    if "mfa" in controls and rec.get("event_type") == "authentication" and rec.get("status") == "success" \
            and rec.get("host") == "NB-VPN01" and is_external_ip(rec.get("source_ip")):
        return "mfa"
    if "powershell_constrained" in controls and "powershell" in cmd.lower() and _PS_BLOCK.search(cmd):
        return "powershell_constrained"
    if "privileged_group_approval" in controls and rec.get("event_type") == "privilege" and \
            str(rec.get("group") or rec.get("resource") or "").lower() in ("administrators", "domain admins"):
        return "privileged_group_approval"
    if "privileged_group_approval" in controls and re.search(r"net1?(\.exe)?\s+(local)?group\s+.*/add", cmd, re.I):
        return "privileged_group_approval"
    if "credential_guard" in controls and re.search(r"lsass|ntdsutil|ntds\.dit", cmd + str(rec.get("resource", "")), re.I):
        return "credential_guard"
    if "dlp_egress" in controls and rec.get("event_type") == "network" and (rec.get("bytes") or 0) >= 10_000_000 \
            and (is_external_ip(rec.get("destination_ip")) or not rec.get("destination_ip")):
        return "dlp_egress"
    if "network_segmentation" in controls and rec.get("event_type") == "network" and str(rec.get("dest_port")) == "445":
        state["smb"] = state.get("smb", 0) + 1
        if state["smb"] > 5 and str(rec.get("destination_ip", "")).startswith("10.20.") and rec.get("host", "").startswith("NB-WS"):
            return "network_segmentation"
    return None


def apply_controls(records: list[dict], controls: set[str]) -> tuple[list[dict], list[dict]]:
    """Returns (transformed records, blocked steps). Gate controls stop the rest of the attack chain."""
    out, blocked, state = [], [], {}
    for rec in records:
        ctl = _blocked_by(rec, controls, state)
        if ctl is None:
            out.append(rec)
            continue
        denied = {**rec, "status": "failure", "action": f"{rec.get('action') or 'activity'}_blocked", "bytes": 0,
                  "blocked_by": ctl, "event_id": rec["event_id"] + "-B"}
        out.append(denied)
        blocked.append({"control": ctl, "event_uid": rec["event_id"], "timestamp": rec["timestamp"],
                        "event_type": rec.get("event_type"), "detail": (rec.get("command") or rec.get("resource") or
                                                                          rec.get("action") or "")[:160]})
        if CONTROLS[ctl]["gate"]:
            break
    return out, blocked


@dataclass
class _LiteDet:
    rule_key: str
    title: str
    severity: str
    confidence: float
    stage: str
    evidence_summary: dict
    timestamp: datetime


def _analyse(evs, rules, ctx) -> dict:
    results = evaluate(evs, rules, ctx)
    dets = [_LiteDet(k, c.title, c.severity, c.confidence, c.stage, c.evidence_summary, c.ts)
            for k, cands in results.items() for c in cands]
    dets.sort(key=lambda d: d.timestamp)
    stages = []
    for d in dets:
        if d.stage != "Threat Intelligence" and (not stages or stages[-1] != d.stage):
            stages.append(d.stage)
    techniques = sorted({m["id"] for cands in results.values() for c in cands for m in c.mitre})
    users = sorted({c.user for cands in results.values() for c in cands if c.user})
    hosts = sorted({c.host for cands in results.values() for c in cands if c.host})
    exfil = sum(int(d.evidence_summary.get("total_bytes") or 0) for d in dets if d.rule_key == "SX-009")
    risk = compute_incident_risk(dets, techniques, users, hosts, sum(len(c.events) for v in results.values() for c in v),
                                 [], {})[0] if dets else 0
    uploaded = sum(e.bytes or 0 for e in evs if e.type == "network" and (e.bytes or 0) >= 1_000_000
                   and (is_external_ip(e.dst) or (not e.dst and e.resource)) and e.status != "failure")
    return {
        "detections": [{"rule_key": d.rule_key, "title": d.title, "severity": d.severity, "stage": d.stage,
                        "label": STAGE_LABELS.get(d.rule_key, d.rule_key), "timestamp": d.timestamp.isoformat() + "Z"}
                       for d in dets],
        "rules_fired": sorted({d.rule_key for d in dets}), "stages_detected": stages, "techniques": techniques,
        "estimated_risk": risk, "exfiltrated_bytes_detected": exfil, "attack_bytes_uploaded": uploaded,
        "attack_events": len(evs),
    }


def sandbox(db: Session, workspace: Workspace, scenario: str, variations: dict | None = None,
            controls: list[str] | None = None, extra_rules: list | None = None) -> dict:
    if scenario not in SCENARIOS:
        raise SimulationError(f"Unknown scenario '{scenario}'")
    controls = [c for c in controls or []]
    unknown = [c for c in controls if c not in CONTROLS]
    if unknown:
        raise SimulationError(f"Unknown controls: {unknown}")
    start = (datetime.now(UTC).replace(tzinfo=None, microsecond=0) - timedelta(days=1)).replace(hour=13, minute=0, second=0)
    records = scenario_records(scenario, start, variations)
    rules = workspace_rules(db, workspace.id, extra=extra_rules)
    bh = tuple((workspace.settings or {}).get("business_hours") or [7, 20])
    ctx = RuleContext(business_hours=(int(bh[0]), int(bh[1])))
    base = _analyse(records_to_evs(records), rules, ctx)
    result = {"scenario": scenario, "scenario_description": SCENARIOS[scenario], "variations": variations or {},
              "baseline": base, "label": "Simulation on synthetic telemetry with modeled controls."}
    if controls:
        transformed, blocked = apply_controls(records, set(controls))
        with_controls = _analyse(records_to_evs(transformed), rules, ctx)
        result["controls"] = [{"id": c, **CONTROLS[c]} for c in controls]
        result["with_controls"] = with_controls
        result["blocked_steps"] = blocked
        result["attack_steps_prevented"] = len(records) - len(transformed) + len(blocked)
        result["summary"] = (
            f"With {', '.join(CONTROLS[c]['label'] for c in controls)}: {len(blocked)} attack step(s) blocked, "
            f"{result['attack_steps_prevented']} of {len(records)} simulated attack events did not happen. "
            f"Detected stages went from {len(base['stages_detected'])} to {len(with_controls['stages_detected'])}; "
            f"data uploaded externally went from {fmt_bytes(base['attack_bytes_uploaded'])} to "
            f"{fmt_bytes(with_controls['attack_bytes_uploaded'])}; estimated risk {base['estimated_risk']} → "
            f"{with_controls['estimated_risk']}.")
    return result


def gap_analysis(db: Session, workspace: Workspace, scenario: str, variations: dict) -> dict:
    """Compare the default scenario with a variation to find stages the rules no longer detect."""
    default = sandbox(db, workspace, scenario)["baseline"]
    varied = sandbox(db, workspace, scenario, variations)["baseline"]
    lost = sorted(set(default["rules_fired"]) - set(varied["rules_fired"]))
    return {"scenario": scenario, "variations": variations, "default_rules": default["rules_fired"],
            "variation_rules": varied["rules_fired"], "rules_evaded": lost,
            "stages_lost": [s for s in default["stages_detected"] if s not in varied["stages_detected"]],
            "gap_found": bool(lost)}


def persist(db: Session, workspace: Workspace, scenario: str, variations: dict | None = None) -> dict:
    """Inject a scenario into a DEMO workspace through the real ingestion pipeline."""
    from app.services.pipeline import ingest_rows

    if workspace.mode != "DEMO":
        raise SimulationError("Persisted simulations are only allowed in DEMO workspaces (they add synthetic telemetry).")
    now = datetime.now(UTC).replace(tzinfo=None, microsecond=0)
    prefix = f"SIM{int(now.timestamp()) % 100000}"
    start = now - timedelta(hours=3)
    records = scenario_records(scenario, start, variations, prefix=prefix)
    # Slow variations can span hours: shift the start back so the whole chain has happened by "now".
    last = max((r["timestamp"] for r in records), default=None)
    if last:
        overrun = datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ") - now
        if overrun > timedelta(0):
            records = scenario_records(scenario, start - overrun - timedelta(minutes=5), variations, prefix=prefix)
    cutoff = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    records = [r for r in records if r["timestamp"] <= cutoff]
    before = {i.id for i in db.query(Incident.id).filter_by(workspace_id=workspace.id)}
    rows = [normalize_record(r) for r in records]
    stats = ingest_rows(db, workspace, rows, source_label=f"simulation:{scenario}")
    uids = {r["event_id"] for r in records}
    touched = []
    for inc in db.query(Incident).filter_by(workspace_id=workspace.id):
        from app.models import Event, IncidentEvent

        hit = db.query(IncidentEvent).join(Event, Event.id == IncidentEvent.event_id).filter(
            IncidentEvent.incident_id == inc.id, Event.event_uid.in_(uids)).first()
        if hit:
            touched.append({"id": inc.id, "number": inc.number, "title": inc.title, "new": inc.id not in before,
                            "risk_score": inc.risk_score, "severity": inc.severity})
    return {"scenario": scenario, "variations": variations or {}, "events": len(records), "pipeline": stats,
            "incidents": touched}


def record_run(db: Session, workspace_id: int, user_id: int, kind: str, scenario: str, variations: dict,
               controls: list, persisted: bool, results: dict) -> SimulationRun:
    run = SimulationRun(workspace_id=workspace_id, kind=kind, scenario=scenario, variations=variations or {},
                        controls=controls or [], persisted=int(persisted), results=results, created_by_id=user_id)
    db.add(run)
    db.flush()
    return run


# ------------------------------------------------------------------------------------------ real incidents
def incident_what_if(db: Session, incident: Incident, controls: list[str]) -> dict:
    dets = db.query(Detection).filter_by(incident_id=incident.id).order_by(Detection.timestamp).all()
    if not dets:
        raise SimulationError("Incident has no detections")
    blocked_at = None
    outcome = []
    for d in dets:
        ctl = next((c for c in controls if d.rule_key in RULE_GATES.get(c, set())), None)
        if blocked_at is not None:
            outcome.append({"detection_id": d.id, "title": d.title, "stage": d.stage, "status": "prevented",
                            "reason": f"occurs after the step blocked by {CONTROLS[blocked_at]['label']}"})
            continue
        if ctl:
            outcome.append({"detection_id": d.id, "title": d.title, "stage": d.stage, "status": "blocked",
                            "reason": f"{CONTROLS[ctl]['label']} blocks {CONTROLS[ctl]['blocks']}"})
            if CONTROLS[ctl]["gate"]:
                blocked_at = ctl
        else:
            outcome.append({"detection_id": d.id, "title": d.title, "stage": d.stage, "status": "unaffected",
                            "reason": "no selected control addresses this step"})
    remaining = [d for d, o in zip(dets, outcome, strict=True) if o["status"] == "unaffected"]
    techs = [t.technique_id for t in db.query(IncidentTechnique).filter_by(incident_id=incident.id)]
    new_risk = compute_incident_risk(remaining, techs if remaining else [], incident.users, incident.hosts,
                                     0, [], {})[0] if remaining else 0
    return {"incident": incident.number, "controls": [{"id": c, **CONTROLS[c]} for c in controls], "steps": outcome,
            "original_risk": incident.risk_score, "residual_risk_estimate": new_risk,
            "note": "Modeled what-if: assumes each control works as described and that steps after a blocked "
                    "gate (MFA, PowerShell blocking) would not have happened. Not a guarantee."}


def counterfactual(db: Session, incident: Incident, remove_detection_ids: list[int]) -> dict:
    from app.correlation.engine import entity_keys

    dets = db.query(Detection).filter_by(incident_id=incident.id).order_by(Detection.timestamp).all()
    remaining = [d for d in dets if d.id not in set(remove_detection_ids)]
    if not remaining:
        return {"incident": incident.number, "remaining": 0, "risk": 0, "still_one_incident": False,
                "explanation": "With all detections removed there is no incident."}
    parent = {d.id: d.id for d in remaining}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for i, a in enumerate(remaining):
        for b in remaining[i + 1:]:
            if entity_keys(a) & entity_keys(b):
                parent[find(b.id)] = find(a.id)
    groups = defaultdict(list)
    for d in remaining:
        groups[find(d.id)].append(d.rule_key)
    techs = sorted({m["id"] for d in remaining for m in d.mitre or []})
    users = sorted({d.user for d in remaining if d.user})
    hosts = sorted({d.host for d in remaining if d.host})
    score, band, factors = compute_incident_risk(remaining, techs, users, hosts, 0, [], {})
    stages = sorted({d.stage for d in remaining if d.stage != "Threat Intelligence"}, key=tactic_rank)
    return {"incident": incident.number, "removed": sorted(remove_detection_ids), "remaining": len(remaining),
            "original_risk": incident.risk_score, "recomputed_risk": score, "recomputed_band": band,
            "factors": factors, "stages": stages, "correlation_groups": list(groups.values()),
            "still_one_incident": len(groups) == 1,
            "explanation": (f"Without the removed evidence the remaining {len(remaining)} detection(s) "
                            + ("still share entities and would correlate into one incident"
                               if len(groups) == 1 else f"split into {len(groups)} unrelated groups")
                            + f"; risk would be {score}/100 ({band}) instead of {incident.risk_score}.")}


def scenario_catalogue() -> list[dict]:
    return [{"id": k, "description": v, "parameters": SCENARIO_PARAMETERS.get(k, {})} for k, v in SCENARIOS.items()]
