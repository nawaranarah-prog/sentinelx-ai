import os
import subprocess
import sys
from pathlib import Path

from conftest import PASSWORD, register

from app.rag.embedding import embed
from app.rag.service import chunk_text


def test_chunking_and_embedding():
    text = "# Heading A\n\n" + ("alpha beta gamma. " * 80) + "\n\n# Heading B\n\nshort section"
    chunks = chunk_text(text)
    assert len(chunks) >= 2 and chunks[0][0] == "Heading A" and chunks[-1] == ("Heading B", "short section")
    assert all(len(c[1]) <= 900 for c in chunks)
    v1, v2 = embed("password spraying attack"), embed("password spraying attack")
    assert v1 == v2 and abs(sum(x * x for x in v1) - 1) < 1e-3


def test_retrieval_ranks_relevant_playbook(demo):
    res = demo.get("/api/knowledge/search?q=encoded powershell download cradle").json()["results"]
    assert res and "PowerShell" in res[0]["document_title"]
    res = demo.get("/api/knowledge/search?q=MEGA consumer cloud storage policy").json()["results"]
    assert any("Policy" in r["document_title"] or "Exfiltration" in r["document_title"] for r in res[:2])


def test_admin_document_upload_and_retrieval(client):
    admin = register(client, "kb")
    doc = b"# Nova Bank Wire Fraud Runbook\n\nIf a wire transfer anomaly is detected, call the treasury duty officer " \
          b"and freeze outgoing SWIFT batches pending verification."
    r = admin.post("/api/knowledge/documents", files={"file": ("wire.md", doc)})
    assert r.status_code == 201 and r.json()["chunk_count"] >= 1
    res = admin.get("/api/knowledge/search?q=freeze SWIFT batches treasury duty officer").json()["results"]
    assert res[0]["document_title"] == "Nova Bank Wire Fraud Runbook"
    assert admin.post("/api/knowledge/documents", files={"file": ("x.pdf", b"not a pdf")}).status_code == 422
    assert admin.post("/api/knowledge/documents", files={"file": ("x.docx", b"PK..")}).status_code == 422
    assert admin.delete(f"/api/knowledge/documents/{r.json()['id']}").status_code == 200
    actions = {a["action"] for a in admin.get("/api/audit").json()["items"]}
    assert {"UPLOAD_DOCUMENT", "DELETE_DOCUMENT"} <= actions


def test_reports_all_types_and_formats(demo):
    inc = demo.get("/api/incidents").json()["items"][0]
    for rtype in ("incident", "technical", "executive"):
        r = demo.post("/api/reports", json={"incident_id": inc["id"], "report_type": rtype})
        assert r.status_code == 201, r.text
        rep = r.json()
        c = rep["content"]
        assert c["incident"]["number"] == inc["number"] and c["risk"]["factors"] and c["techniques"]
        assert c["ai_summary"]["mode"] == "LOCAL" and c["synthetic_data"] is True
        if rtype == "executive":
            assert c["timeline"] == []
        else:
            assert c["timeline"]
        pdf = demo.get(f"/api/reports/{rep['id']}/download?format=pdf")
        assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
        html = demo.get(f"/api/reports/{rep['id']}/download?format=html").text
        assert inc["number"] in html and "<script" not in html and "SYNTHETIC" in html
        md = demo.get(f"/api/reports/{rep['id']}/download?format=md").text
        assert md.startswith("# ") and "SentinelX Risk Score" in md or "Risk score" in md
    assert demo.get(f"/api/reports/{rep['id']}/download?format=exe").status_code == 422
    exports = demo.get("/api/audit?action=EXPORT_REPORT").json()
    assert exports["total"] >= 9


def test_audit_log_records_and_never_stores_secrets(client, db):
    from app.models import AuditLog
    acct = register(client, "audit")
    client.post("/api/auth/login", json={"email": acct.email, "password": "WrongPassword123"})
    client.post("/api/auth/login", json={"email": acct.email, "password": PASSWORD})
    client.cookies.clear()
    acct.post("/api/auth/change-password", json={"current_password": PASSWORD, "new_password": "BrandNewPass123"})
    client.cookies.clear()
    rows = db.query(AuditLog).filter(AuditLog.user_email == acct.email).all()
    actions = {r.action for r in rows}
    assert {"REGISTER", "LOGIN", "LOGIN_FAILED", "CHANGE_PASSWORD"} <= actions
    blob = " ".join(str(r.details) for r in rows)
    assert PASSWORD not in blob and "WrongPassword123" not in blob and "BrandNewPass123" not in blob


def test_audit_scrubber():
    from app.audit.service import scrub
    out = scrub({"password": "x", "nested": {"api_key": "y", "ok": "z"}, "Authorization": "Bearer t"})
    assert out == {"password": "[REDACTED]", "nested": {"api_key": "[REDACTED]", "ok": "z"}, "Authorization": "[REDACTED]"}


def test_simulation_controls_are_audited(demo):
    assert demo.get("/api/simulation").json()["available"] is True
    assert demo.post("/api/simulation/start").json()["running"] is True
    assert demo.post("/api/simulation/pause").json()["running"] is False
    actions = {a["action"] for a in demo.get("/api/audit?page_size=200").json()["items"]}
    assert {"START_SIMULATION", "PAUSE_SIMULATION", "LOAD_DEMO", "VIEW_INCIDENT", "VIEW_EVENT"} <= actions


def test_simulation_tick_ingests_through_pipeline(demo):
    from app.services.simulation import get_sim
    sim = get_sim(demo.workspace_id)
    before = demo.get("/api/workspaces/current").json()["counts"]["events"]
    assert sim.tick() > 0
    assert demo.get("/api/workspaces/current").json()["counts"]["events"] > before


def test_migrations_apply_cleanly_without_drift(tmp_path):
    backend = Path(__file__).resolve().parents[1]
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{(tmp_path / 'mig.db').as_posix()}"}
    alembic = [sys.executable, "-m", "alembic"]
    up = subprocess.run(alembic + ["upgrade", "head"], cwd=backend, env=env, capture_output=True, text=True)
    assert up.returncode == 0, up.stderr
    check = subprocess.run(alembic + ["check"], cwd=backend, env=env, capture_output=True, text=True)
    assert check.returncode == 0 and "No new upgrade operations" in (check.stdout + check.stderr)
    down = subprocess.run(alembic + ["downgrade", "base"], cwd=backend, env=env, capture_output=True, text=True)
    assert down.returncode == 0, down.stderr
