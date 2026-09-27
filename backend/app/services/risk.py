"""SentinelX Risk Score: a transparent, additive heuristic (0-100).

It is NOT an industry standard and NOT a probability. Each factor contributes bounded points and
the breakdown is shown to analysts so the score can be challenged.
"""

from app.detection.base import fmt_bytes

SEVERITY_POINTS = {"critical": 30, "high": 22, "medium": 12, "low": 5, "info": 0}
HOST_CRITICALITY_POINTS = {"critical": 6, "high": 4, "medium": 0, "low": 0}


def band(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def compute_incident_risk(detections: list, technique_ids: list[str], users: list, hosts: list,
                          evidence_event_count: int, anomalies: list, host_criticality: dict[str, str]) -> tuple[int, str, list[dict]]:
    factors: list[dict] = []

    def add(name: str, points: float, maximum: int, detail: str) -> None:
        factors.append({"factor": name, "points": int(round(points)), "max": maximum, "detail": detail})

    top = max(detections, key=lambda d: SEVERITY_POINTS.get(d.severity, 0))
    add("Highest detection severity", SEVERITY_POINTS.get(top.severity, 0), 30,
        f"Most severe detection is {top.severity.upper()}: {top.title}")

    avg_conf = sum(d.confidence for d in detections) / len(detections)
    add("Detection confidence", 10 * avg_conf, 10, f"Average rule confidence {avg_conf:.2f} across {len(detections)} detection(s)")

    stages = sorted({d.stage for d in detections if d.stage and d.stage != "Threat Intelligence"})
    add("Attack-chain breadth", min(16, 4 * max(0, len(stages) - 1)), 16,
        f"{len(stages)} distinct stage(s): {', '.join(stages) or 'none'} (4 points per stage beyond the first)")

    priv = [d for d in detections if d.rule_key == "SX-004"]
    priv_login = [d for d in detections if d.rule_key == "SX-003"]
    if priv:
        add("Privilege escalation", 10, 10, f"{len(priv)} privilege-escalation detection(s)")
    elif priv_login:
        add("Privilege escalation", 5, 10, "Suspicious privileged-account login, but no escalation observed")
    else:
        add("Privilege escalation", 0, 10, "No privilege escalation observed")

    exfil_bytes = sum(int((d.evidence_summary or {}).get("total_bytes") or 0) for d in detections if d.rule_key == "SX-009")
    pts = 10 if exfil_bytes >= 1_000_000_000 else 7 if exfil_bytes >= 100_000_000 else 0
    add("External data transfer", pts, 10,
        f"{fmt_bytes(exfil_bytes)} sent to external destinations" if exfil_bytes else "No large external transfer detected")

    add("MITRE ATT&CK techniques", min(6, len(technique_ids)), 6,
        f"{len(technique_ids)} distinct technique(s) mapped from evidence" if technique_ids else "No techniques mapped")

    crit_pts = max((HOST_CRITICALITY_POINTS.get(host_criticality.get(h, "medium"), 0) for h in hosts), default=0)
    ent_pts = min(8, 2 * (len(users) + len(hosts)))
    crit_hosts = [h for h in hosts if host_criticality.get(h) in ("high", "critical")]
    add("Affected entities", min(12, ent_pts + crit_pts), 12,
        f"{len(users)} user(s), {len(hosts)} host(s)" + (f"; high-criticality hosts: {', '.join(crit_hosts)}" if crit_hosts else ""))

    if_hits = [a for a in anomalies if a.is_anomalous and a.if_flagged]
    base_hits = [a for a in anomalies if a.is_anomalous and not a.if_flagged]
    if if_hits:
        add("Behavioral anomaly", 8, 8, f"{len(if_hits)} entity-day window(s) flagged by Isolation Forest and baseline")
    elif base_hits:
        add("Behavioral anomaly", 4, 8, f"{len(base_hits)} entity-day window(s) deviate from the statistical baseline")
    else:
        add("Behavioral anomaly", 0, 8, "No anomalous behavior windows for involved entities")

    ti = [d for d in detections if d.rule_key == "SX-010"]
    add("Threat intelligence", 6 if ti else 0, 6,
        f"{len(ti)} threat-intelligence match(es)" if ti else "No threat-intelligence matches")

    vol_pts = 4 if evidence_event_count >= 100 else 2 if evidence_event_count >= 20 else 0
    add("Evidence volume", vol_pts, 4, f"{evidence_event_count} evidence event(s)")

    score = min(100, sum(f["points"] for f in factors))
    return score, band(score), factors
