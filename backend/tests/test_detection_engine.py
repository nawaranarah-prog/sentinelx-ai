"""Run every sample dataset through the real pipeline and verify the expected detections are produced."""

import uuid

import pytest

from app.demo.generator import dataset_records
from app.ingestion.normalizer import normalize_record
from app.models import AnomalyResult, Detection, Incident, IncidentTechnique, User
from app.models.identity import MODE_ANALYST
from app.services.pipeline import ingest_rows
from app.services.workspace import create_workspace, seed_synthetic_indicators


def _run(db, name: str, with_intel: bool = False):
    owner = User(email=f"owner-{name}-{uuid.uuid4().hex[:8]}@example.com", password_hash="x")
    db.add(owner)
    db.flush()
    ws = create_workspace(db, f"ds-{name}", owner, MODE_ANALYST)
    if with_intel:
        seed_synthetic_indicators(db, ws.id)
    db.commit()
    rows = [normalize_record(r) for r in dataset_records(name)]
    stats = ingest_rows(db, ws, rows, source_label="test")
    rules = {d.rule_key for d in db.query(Detection).filter_by(workspace_id=ws.id)}
    return ws, stats, rules


def test_normal_dataset_produces_no_detections(db):
    ws, stats, rules = _run(db, "normal")
    assert stats["accepted"] > 300
    assert rules == set(), f"false positives on normal data: {rules}"
    assert db.query(Incident).filter_by(workspace_id=ws.id).count() == 0


@pytest.mark.parametrize("name,expected", [
    ("brute_force", {"SX-001", "SX-002", "SX-005", "SX-006", "SX-004", "SX-008", "SX-009"}),
    ("privilege_escalation", {"SX-004", "SX-006", "SX-003", "SX-007", "SX-008"}),
    ("powershell", {"SX-005", "SX-007"}),
    ("exfiltration", {"SX-008", "SX-009"}),
    ("mixed", {"SX-001", "SX-002", "SX-003", "SX-004", "SX-005", "SX-006", "SX-007", "SX-008", "SX-009"}),
])
def test_attack_datasets_trigger_expected_rules(db, name, expected):
    _, stats, rules = _run(db, name)
    assert expected <= rules, f"missing {expected - rules}"
    assert stats["incidents_created"] >= 1


def test_detections_have_evidence_explanations_and_guidance(db):
    ws, _, _ = _run(db, "brute_force")
    for d in db.query(Detection).filter_by(workspace_id=ws.id):
        assert d.explanation.startswith("Triggered because")
        assert d.evidence_links, d.rule_key
        assert d.false_positives and d.recommendations
        assert 0 < d.confidence <= 1
    bf = db.query(Detection).filter_by(workspace_id=ws.id, rule_key="SX-001").filter(Detection.user == "t.nguyen").one()
    assert "38 failed authentication attempts" in bf.explanation and "203.0.113.45" in bf.explanation
    s2 = db.query(Detection).filter_by(workspace_id=ws.id, rule_key="SX-002").one()
    assert s2.severity == "critical" and s2.evidence_summary["same_source"] is True


def test_brute_force_chain_correlates_into_one_incident_with_mitre(db):
    ws, _, _ = _run(db, "brute_force", with_intel=True)
    inc = max((i for i in db.query(Incident).filter_by(workspace_id=ws.id) if "t.nguyen" in i.users),
              key=lambda i: db.query(Detection).filter_by(incident_id=i.id).count())
    rules = {d.rule_key for d in db.query(Detection).filter_by(incident_id=inc.id)}
    assert {"SX-001", "SX-002", "SX-004", "SX-009", "SX-010"} <= rules
    assert "user 't.nguyen'" in inc.correlation_reason and "→" in inc.correlation_reason
    techs = {t.technique_id for t in db.query(IncidentTechnique).filter_by(incident_id=inc.id)}
    assert {"T1110.001", "T1078", "T1059.001", "T1098.007", "T1048.002"} <= techs
    assert inc.severity == "critical" and inc.risk_band == "Critical"
    assert sum(f["points"] for f in inc.risk_factors) >= inc.risk_score  # capped at 100
    assert all({"factor", "points", "max", "detail"} <= set(f) for f in inc.risk_factors)
    ti = db.query(Detection).filter_by(incident_id=inc.id, rule_key="SX-010").first()
    assert ti.mitre == [] and "No ATT&CK technique" in ti.evidence_summary["mitre_note"]


def test_internal_backup_traffic_is_not_exfiltration(db):
    ws, _, _ = _run(db, "normal")
    assert db.query(Detection).filter_by(workspace_id=ws.id, rule_key="SX-009").count() == 0


def test_rerun_is_idempotent(db):
    from app.services.pipeline import run_pipeline
    ws, _, _ = _run(db, "powershell")
    before = db.query(Detection).filter_by(workspace_id=ws.id).count()
    stats = run_pipeline(db, ws)
    assert stats["detections_created"] == 0
    assert db.query(Detection).filter_by(workspace_id=ws.id).count() == before


def test_isolation_forest_and_baseline(db):
    ws, stats, _ = _run(db, "mixed")
    assert stats["isolation_forest_used"] is True
    rows = db.query(AnomalyResult).filter_by(workspace_id=ws.id).all()
    assert rows and all(r.if_score is not None for r in rows)
    flagged = [r for r in rows if r.is_anomalous]
    assert 0 < len(flagged) < len(rows) * 0.2, "anomaly layer should flag a small minority"
    assert any(r.entity == "t.nguyen" and r.is_anomalous for r in rows)
    r = flagged[0]
    assert r.model_info["model"] == "sklearn.ensemble.IsolationForest" and r.top_deviations


def test_small_population_skips_isolation_forest(db):
    from app.detection.engine import load_events
    from app.ml.anomaly import run_anomaly_detection
    owner = User(email="small@example.com", password_hash="x")
    db.add(owner)
    db.flush()
    ws = create_workspace(db, "small", owner, MODE_ANALYST)
    rows = [normalize_record({"timestamp": f"2026-09-01T10:0{i}:00Z", "user": "a", "host": "h", "action": "login",
                              "status": "success", "event_type": "authentication"}) for i in range(5)]
    ingest_rows(db, ws, rows, "test")
    res = run_anomaly_detection(db, ws.id, load_events(db, ws.id))
    assert res.if_used is False and any("skipped" in n for n in res.notes)

