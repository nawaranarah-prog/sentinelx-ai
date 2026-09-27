"""Behavioral anomaly detection.

Layer 1 - statistical baseline: robust z-scores (median / MAD) of per-entity daily features against the
population of all entity-days, plus against the entity's own history when enough history exists.

Layer 2 - scikit-learn IsolationForest trained on the same log-transformed feature matrix. The model
itself does not attribute scores to features, so explanations use the Layer 1 deviations.
"""

import math
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.detection.base import Ev, is_off_hours
from app.ingestion.normalizer import is_external_ip
from app.models import AnomalyResult

USER_FEATURES = ["login_count", "failed_login_count", "unique_source_ips", "unique_hosts", "event_count",
                 "external_bytes_out", "process_count", "suspicious_command_count", "privilege_events",
                 "sensitive_file_count", "off_hours_ratio"]
HOST_FEATURES = ["login_count", "failed_login_count", "unique_source_ips", "unique_users", "event_count",
                 "external_bytes_out", "process_count", "suspicious_command_count", "privilege_events",
                 "sensitive_file_count", "off_hours_ratio"]
FEATURE_LABELS = {
    "login_count": "successful logins", "failed_login_count": "failed logins",
    "unique_source_ips": "distinct source IPs", "unique_hosts": "distinct hosts used",
    "unique_users": "distinct users", "event_count": "total events",
    "external_bytes_out": "bytes sent to external destinations", "process_count": "process executions",
    "suspicious_command_count": "suspicious commands", "privilege_events": "privilege changes",
    "sensitive_file_count": "sensitive file accesses", "off_hours_ratio": "share of activity outside business hours",
}
MIN_POPULATION_FOR_IF = 10
BASELINE_Z = 3.5
CORROBORATION_Z = 3.0
# sklearn's contamination="auto" uses the original paper's offset (score 0.5). SentinelX applies a stricter,
# configurable decision threshold and additionally requires a corroborating feature deviation.
DEFAULT_IF_THRESHOLD = 0.60
SUSPICIOUS_CMD = re.compile(
    r"-enc\b|-encodedcommand|downloadstring|invoke-webrequest|\biex\b|mimikatz|sekurlsa|procdump|psexec|"
    r"vssadmin|certutil|whoami|nltest|net\s+group|net\s+user|net\s+localgroup|systeminfo|\bnmap\b|bypass|"
    r"hidden|7z\s+a|rar\s+a|wmic", re.I)
SENSITIVE = re.compile(r"confidential|restricted|payroll|salary|customer|pii|wire_transfer|swift|ntds\.dit|"
                       r"\.kdbx|id_rsa|passwords|credentials|\\finance\\|\\hr\\", re.I)


@dataclass
class AnomalyRunResult:
    run_id: str
    windows: int = 0
    flagged: int = 0
    if_used: bool = False
    notes: list[str] = field(default_factory=list)
    model_info: dict = field(default_factory=dict)


def _features(evs: list[Ev], kind: str, business_hours: tuple[int, int]) -> dict[str, float]:
    f = defaultdict(float)
    srcs, hosts, users = set(), set(), set()
    off = 0
    for e in evs:
        f["event_count"] += 1
        if e.type == "authentication" and "logout" not in (e.action or "") and "logoff" not in (e.action or ""):
            if e.status == "success":
                f["login_count"] += 1
            elif e.status == "failure":
                f["failed_login_count"] += 1
        if e.src:
            srcs.add(e.src)
        if e.host:
            hosts.add(e.host)
        if e.user:
            users.add(e.user)
        if e.type == "process":
            f["process_count"] += 1
        if e.command and SUSPICIOUS_CMD.search(e.command):
            f["suspicious_command_count"] += 1
        if e.type == "privilege":
            f["privilege_events"] += 1
        if e.type == "file" and e.resource and SENSITIVE.search(e.resource):
            f["sensitive_file_count"] += 1
        if e.bytes and e.type == "network" and (is_external_ip(e.dst) or (not e.dst and e.resource and "." in e.resource)):
            if str(e.meta.get("direction") or "").lower() not in ("inbound", "in", "download"):
                f["external_bytes_out"] += e.bytes
        if is_off_hours(e.ts, business_hours):
            off += 1
    f["unique_source_ips"] = len(srcs)
    f["unique_hosts"] = len(hosts)
    f["unique_users"] = len(users)
    f["off_hours_ratio"] = round(off / len(evs), 3) if evs else 0.0
    names = USER_FEATURES if kind == "user" else HOST_FEATURES
    return {n: float(f[n]) for n in names}


def _transform(value: float, name: str) -> float:
    return value if name == "off_hours_ratio" else math.log1p(value)


def _robust_z(col: np.ndarray) -> tuple[np.ndarray, float, float]:
    med = float(np.median(col))
    mad = float(np.median(np.abs(col - med)))
    scale = 1.4826 * mad
    if scale == 0:
        std = float(np.std(col))
        scale = std if std > 0 else 0.0
    if scale == 0:
        return np.zeros_like(col), med, 0.0
    return (col - med) / scale, med, scale


def run_anomaly_detection(db: Session, workspace_id: int, events: list[Ev], business_hours: tuple[int, int] = (7, 20),
                          if_threshold_override: float | None = None) -> AnomalyRunResult:
    run_id = uuid.uuid4().hex
    result = AnomalyRunResult(run_id=run_id)
    db.execute(delete(AnomalyResult).where(AnomalyResult.workspace_id == workspace_id))
    if not events:
        result.notes.append("No events to analyze.")
        return result

    for kind in ("user", "host"):
        buckets: dict[tuple[str, str], list[Ev]] = defaultdict(list)
        for e in events:
            ent = e.user if kind == "user" else e.host
            if ent:
                buckets[(ent, e.ts.strftime("%Y-%m-%d"))].append(e)
        if not buckets:
            continue
        keys = list(buckets)
        names = USER_FEATURES if kind == "user" else HOST_FEATURES
        raw = [_features(buckets[k], kind, business_hours) for k in keys]
        X = np.array([[_transform(r[n], n) for n in names] for r in raw], dtype=float)
        n = len(keys)
        result.windows += n

        z_cols, medians = [], []
        for j in range(X.shape[1]):
            z, med, _ = _robust_z(X[:, j])
            z_cols.append(z)
            medians.append(med)
        Z = np.stack(z_cols, axis=1)
        pop_medians_raw = {names[j]: float(np.median([r[names[j]] for r in raw])) for j in range(len(names))}

        # Entity's own history (other days) for self-baselining.
        by_entity: dict[str, list[int]] = defaultdict(list)
        for i, (ent, _) in enumerate(keys):
            by_entity[ent].append(i)

        scores = thresholds = flagged = None
        model_info = {"population_windows": n, "window": "entity-day (UTC)", "features": names,
                      "feature_transform": "log1p for counts and bytes; ratio unchanged"}
        if n >= MIN_POPULATION_FOR_IF:
            model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
            model.fit(X)
            scores = -model.score_samples(X)
            threshold = float(if_threshold_override) if if_threshold_override else DEFAULT_IF_THRESHOLD
            thresholds = threshold
            flagged = scores > threshold
            result.if_used = True
            model_info.update({"model": "sklearn.ensemble.IsolationForest", "sklearn_version": sklearn.__version__,
                               "n_estimators": 200, "contamination": "auto", "random_state": 42,
                               "score": "anomaly score = -score_samples (higher is more anomalous; ~0.5 is typical)",
                               "model_offset": round(float(-model.offset_), 4),
                               "threshold": round(threshold, 4),
                               "decision_rule": f"anomalous when score > {threshold:.2f} AND at least one feature "
                                                f"deviates with robust z >= {CORROBORATION_Z}, or when "
                                                f"3+ features deviate with robust z >= {BASELINE_Z}"})
        else:
            model_info.update({"model": "none", "reason": f"Isolation Forest requires at least "
                               f"{MIN_POPULATION_FOR_IF} entity-day windows; only {n} available. "
                               "Statistical baseline only."})
            result.notes.append(f"{kind}: Isolation Forest skipped (population {n} < {MIN_POPULATION_FOR_IF}).")
        result.model_info[kind] = model_info

        for i, (ent, day) in enumerate(keys):
            deviations = []
            for j, name in enumerate(names):
                z = float(Z[i, j])
                if z >= 2.0 and raw[i][name] > pop_medians_raw[name]:
                    deviations.append({"feature": name, "label": FEATURE_LABELS[name], "value": raw[i][name],
                                       "population_median": pop_medians_raw[name], "robust_z": round(z, 2),
                                       "basis": "population"})
            hist_idx = [k for k in by_entity[ent] if k != i]
            if len(hist_idx) >= 3:
                H = X[hist_idx]
                for j, name in enumerate(names):
                    med = float(np.median(H[:, j]))
                    mad = float(np.median(np.abs(H[:, j] - med))) * 1.4826
                    scale = mad if mad > 0 else (float(np.std(H[:, j])) or 0.5)
                    z = (X[i, j] - med) / scale
                    if z >= BASELINE_Z and raw[i][name] > 0:
                        own_med = float(np.median([raw[k][name] for k in hist_idx]))
                        if raw[i][name] > own_med:
                            deviations.append({"feature": name, "label": FEATURE_LABELS[name], "value": raw[i][name],
                                               "own_median": own_med, "robust_z": round(float(z), 2),
                                               "basis": "own history"})
            best: dict[str, dict] = {}
            for d in deviations:
                if d["feature"] not in best or d["robust_z"] > best[d["feature"]]["robust_z"]:
                    best[d["feature"]] = d
            deviations = sorted(best.values(), key=lambda d: -d["robust_z"])
            baseline_flags = [d for d in deviations if d["robust_z"] >= BASELINE_Z]
            if_flag = bool(flagged[i]) if flagged is not None else False
            corroborated = any(d["robust_z"] >= CORROBORATION_Z for d in deviations)
            if scores is not None:
                is_anom = (if_flag and corroborated) or len(baseline_flags) >= 3
            else:
                is_anom = len(baseline_flags) >= 2
            method = "baseline+isolation_forest" if scores is not None else "baseline"
            day_start = datetime.strptime(day, "%Y-%m-%d")
            db.add(AnomalyResult(
                workspace_id=workspace_id, run_id=run_id, entity_type=kind, entity=ent, window_start=day_start,
                window_end=day_start + timedelta(days=1), features=raw[i], baseline_flags=baseline_flags,
                top_deviations=deviations[:5],
                if_score=round(float(scores[i]), 4) if scores is not None else None,
                if_threshold=round(thresholds, 4) if thresholds is not None else None,
                if_flagged=if_flag, is_anomalous=is_anom, method=method, model_info=model_info,
            ))
            if is_anom:
                result.flagged += 1
    db.flush()
    return result


def describe_result(r: AnomalyResult) -> str:
    parts = []
    if r.if_score is not None:
        parts.append(f"Isolation Forest score {r.if_score:.3f} vs threshold {r.if_threshold:.3f}"
                     + (" (flagged)" if r.if_flagged else " (not flagged)"))
    if r.top_deviations:
        devs = "; ".join(
            f"{d['label']} = {d['value']:g} (" + (f"population median {d['population_median']:g}"
                                                   if d["basis"] == "population" else f"own median {d['own_median']:g}")
            + f", robust z {d['robust_z']})" for d in r.top_deviations[:3])
        parts.append("largest deviations: " + devs)
    return f"{r.entity_type} {r.entity} on {r.window_start:%Y-%m-%d}: " + "; ".join(parts)
