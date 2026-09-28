"""Attack DNA: a behavioral fingerprint of an incident, plus similarity, families and evolution.

The fingerprint only contains properties observed in the incident's detections and evidence.
Similarity is a transparent weighted blend of component similarities (shown to the analyst).
"""

from difflib import SequenceMatcher

from sqlalchemy.orm import Session

from app.detection.base import is_off_hours
from app.ingestion.normalizer import is_external_ip
from app.mitre.catalog import TECHNIQUE_INDEX
from app.models import Incident

STAGE_CODES = {"Credential Access": "CA", "Initial Access": "IA", "Execution": "EX", "Persistence": "PE",
               "Privilege Escalation": "PR", "Defense Evasion": "DE", "Discovery": "DI", "Lateral Movement": "LM",
               "Collection": "CO", "Command and Control": "C2", "Exfiltration": "EF", "Impact": "IM",
               "Threat Intelligence": "TI"}
WEIGHTS = {"techniques": 0.30, "sequence": 0.25, "rules": 0.15, "entities": 0.10, "traits": 0.20}
FAMILY_THRESHOLD = 0.55


def _bucket_duration(seconds: float) -> str:
    if seconds < 600:
        return "<10m"
    if seconds < 7200:
        return "10m-2h"
    if seconds < 86400:
        return "2h-1d"
    return ">1d"


def _bucket_bytes(n: int) -> str:
    if n <= 0:
        return "none"
    if n < 100_000_000:
        return "<100MB"
    if n < 1_000_000_000:
        return "100MB-1GB"
    return ">1GB"


def compute_dna(incident: Incident, detections: list, technique_ids: list[str],
                business_hours: tuple[int, int] = (7, 20)) -> dict:
    dets = sorted(detections, key=lambda d: d.timestamp)
    stages = []
    for d in dets:
        if d.stage and d.stage != "Threat Intelligence" and (not stages or stages[-1] != d.stage):
            stages.append(d.stage)
    exfil = sum(int((d.evidence_summary or {}).get("total_bytes") or 0) for d in dets if d.rule_key == "SX-009")
    duration = (incident.last_seen - incident.first_seen).total_seconds()
    tactics = sorted({TECHNIQUE_INDEX[t]["tactic"] for t in technique_ids if t in TECHNIQUE_INDEX})
    traits = {
        "external_source": any(is_external_ip(ip) for ip in incident.source_ips or []),
        "external_destination": bool(incident.destination_ips),
        "off_hours_start": is_off_hours(incident.first_seen, business_hours),
        "privilege_escalation": any(d.rule_key == "SX-004" for d in dets),
        "credential_theft": any(t.startswith("T1003") or t.startswith("T1110") for t in technique_ids),
        "duration": _bucket_duration(duration),
        "exfil_volume": _bucket_bytes(exfil),
        "multi_host": len(incident.hosts or []) > 1,
    }
    return {
        "version": 1,
        "signature": ">".join(STAGE_CODES.get(s, "??") for s in stages) or "—",
        "stages": stages, "techniques": sorted(set(technique_ids)), "tactics": tactics,
        "rules": sorted({d.rule_key for d in dets}),
        "entities": {"users": sorted(incident.users or [])[:30], "hosts": sorted(incident.hosts or [])[:30],
                     "ips": sorted((incident.source_ips or []) + (incident.destination_ips or []))[:30]},
        "traits": traits, "duration_seconds": int(duration), "exfil_bytes": exfil,
        "first_hour_utc": incident.first_seen.hour, "detection_count": len(dets),
    }


def _jaccard(a, b) -> float:
    a, b = set(a), set(b)
    if not a and not b:
        return 1.0
    return len(a & b) / len(a | b)


def similarity(a: dict, b: dict) -> dict:
    if not a or not b:
        return {"score": 0.0, "components": {}}
    ent_a = set(a["entities"]["users"] + a["entities"]["hosts"] + a["entities"]["ips"])
    ent_b = set(b["entities"]["users"] + b["entities"]["hosts"] + b["entities"]["ips"])
    ta, tb = a["traits"], b["traits"]
    comps = {
        "techniques": _jaccard(a["techniques"], b["techniques"]),
        "sequence": SequenceMatcher(None, a["stages"], b["stages"]).ratio() if (a["stages"] or b["stages"]) else 1.0,
        "rules": _jaccard(a["rules"], b["rules"]),
        "entities": _jaccard(ent_a, ent_b) if (ent_a or ent_b) else 0.0,
        "traits": sum(1 for k in ta if ta.get(k) == tb.get(k)) / max(1, len(ta)),
    }
    score = sum(WEIGHTS[k] * v for k, v in comps.items())
    return {"score": round(score, 3), "components": {k: round(v, 3) for k, v in comps.items()},
            "shared_techniques": sorted(set(a["techniques"]) & set(b["techniques"])),
            "shared_entities": sorted(ent_a & ent_b)[:20]}


def similar_incidents(db: Session, workspace_id: int, incident: Incident, limit: int = 5) -> list[dict]:
    out = []
    for other in db.query(Incident).filter(Incident.workspace_id == workspace_id, Incident.id != incident.id):
        if not other.dna:
            continue
        s = similarity(incident.dna, other.dna)
        out.append({"incident_id": other.id, "number": other.number, "title": other.title, "status": other.status,
                    "severity": other.severity, "first_seen": other.first_seen.isoformat() + "Z",
                    "signature": other.dna.get("signature"), **s})
    out.sort(key=lambda x: -x["score"])
    return out[:limit]


def families(db: Session, workspace_id: int, threshold: float = FAMILY_THRESHOLD) -> list[dict]:
    incs = [i for i in db.query(Incident).filter_by(workspace_id=workspace_id).order_by(Incident.first_seen) if i.dna]
    parent = list(range(len(incs)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(incs)):
        for j in range(i + 1, len(incs)):
            if similarity(incs[i].dna, incs[j].dna)["score"] >= threshold:
                parent[find(j)] = find(i)
    groups: dict[int, list[Incident]] = {}
    for i, inc in enumerate(incs):
        groups.setdefault(find(i), []).append(inc)
    result = []
    for n, members in enumerate(sorted(groups.values(), key=lambda m: m[0].first_seen), start=1):
        evolution = []
        for prev, cur in zip(members, members[1:], strict=False):
            evolution.append({
                "from": prev.number, "to": cur.number,
                "added_techniques": sorted(set(cur.dna["techniques"]) - set(prev.dna["techniques"])),
                "removed_techniques": sorted(set(prev.dna["techniques"]) - set(cur.dna["techniques"])),
                "sequence_change": f"{prev.dna['signature']} → {cur.dna['signature']}",
            })
        shared = set(members[0].dna["techniques"])
        for m in members[1:]:
            shared &= set(m.dna["techniques"])
        result.append({"family": f"FAM-{n:02d}", "size": len(members),
                       "incidents": [{"id": m.id, "number": m.number, "title": m.title, "signature": m.dna["signature"],
                                      "first_seen": m.first_seen.isoformat() + "Z"} for m in members],
                       "shared_techniques": sorted(shared), "evolution": evolution})
    return result
