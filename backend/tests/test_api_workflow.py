"""End-to-end analyst workflow through the HTTP API: upload → detect → investigate → report → audit."""

from conftest import register, upload

from app.demo.generator import dataset_records, to_csv, to_json


def test_upload_pipeline_and_counts(client):
    acct = register(client, "upload")
    content = to_csv(dataset_records("mixed"), aliases=True)
    job = upload(acct, "mixed.csv", content)
    assert job["status"] == "COMPLETED", job
    assert job["accepted_rows"] == job["total_rows"] > 1000
    assert job["field_mapping"]["src_ip"] == "source_ip" and job["field_mapping"]["username"] == "user"
    assert job["detections_created"] >= 15 and job["incidents_created"] >= 5
    ws = acct.get("/api/workspaces/current").json()
    assert ws["counts"]["events"] == job["accepted_rows"]
    assert ws["counts"]["detections"] == job["detections_created"]
    # Re-uploading the same file stores nothing new.
    again = upload(acct, "mixed.csv", content)
    assert again["accepted_rows"] == 0 and again["duplicate_rows"] == job["total_rows"]
    notifs = acct.get("/api/notifications").json()
    assert any(n["kind"] == "ingestion_complete" for n in notifs["items"])
    assert any(n["kind"] == "new_incident" for n in notifs["items"])


def test_preview_and_bad_files(client):
    acct = register(client, "preview")
    js = to_json(dataset_records("powershell")[:50])
    r = acct.post("/api/ingest/preview", files={"file": ("p.json", js.encode())})
    assert r.status_code == 200 and r.json()["valid_rows"] == 50 and len(r.json()["sample"]) == 10
    r = acct.post("/api/ingest/preview", files={"file": ("bad.json", b'[{"a": 1},')})
    assert r.status_code == 422 and "Malformed JSON" in r.json()["detail"]
    assert acct.post("/api/ingest/upload", files={"file": ("x.exe", b"MZ")}).status_code == 422
    job = upload(acct, "bad.csv", "timestamp,user\nnot-a-date,a\nalso-bad,b\n")
    assert job["status"] == "FAILED" and job["rejected_rows"] == 2 and job["errors"]
    job = upload(acct, "empty.json", "[]")
    assert job["status"] == "FAILED" and "no event rows" in job["error_message"]


def test_samples_and_schema_downloads(client):
    assert client.get("/api/ingest/samples").json()[0]["synthetic"] is True
    r = client.get("/api/ingest/samples/brute_force.csv")
    assert r.status_code == 200 and r.text.startswith("event_id,timestamp")
    assert client.get("/api/ingest/samples/mixed.json").json()[0]["src_ip"]
    assert client.get("/api/ingest/samples/nope.csv").status_code == 404
    assert "| source_ip |" in client.get("/api/ingest/schema.md").text


def test_event_explorer_filters_and_detail(demo):
    r = demo.get("/api/events?user=t.nguyen&event_type=authentication&page_size=10")
    body = r.json()
    assert body["total"] > 0 and all(e["user"] == "t.nguyen" for e in body["items"])
    assert demo.get("/api/events?ip=203.0.113.45").json()["total"] >= 39
    assert demo.get("/api/events?q=nltest").json()["total"] >= 1
    sev = demo.get("/api/events?severity=high&severity=medium").json()
    assert all(e["severity"] in ("high", "medium") for e in sev["items"])
    ev = demo.get(f"/api/events/{body['items'][0]['id']}").json()
    assert "raw" in ev and "metadata" in ev and "incidents" in ev
    assert demo.get("/api/events?start=garbage").status_code == 422


def test_incident_workspace_and_case_management(demo):
    incs = demo.get("/api/incidents").json()["items"]
    top = incs[0]
    assert top["risk_score"] == max(i["risk_score"] for i in incs)
    inc = demo.get(f"/api/incidents/{top['id']}").json()
    for key in ("detections", "techniques", "risk_factors", "correlation_reason", "anomaly_summary", "checklist",
                "status_history"):
        assert inc[key], key
    tl = demo.get(f"/api/incidents/{top['id']}/timeline").json()
    assert tl["total"] == inc["evidence_event_count"] and tl["items"][0]["timestamp"] <= tl["items"][-1]["timestamp"]
    graph = demo.get(f"/api/incidents/{top['id']}/graph").json()
    labels = {n["label"] for n in graph["nodes"]}
    assert set(inc["users"][:1]) <= labels and set(inc["hosts"][:1]) <= labels
    det_nodes = [n for n in graph["nodes"] if n["type"] == "detection"]
    assert len(det_nodes) == len(inc["detections"])
    node_ids = {n["id"] for n in graph["nodes"]}
    assert all(e["source"] in node_ids and e["target"] in node_ids for e in graph["edges"])

    members = demo.get("/api/members").json()
    assert demo.post(f"/api/incidents/{top['id']}/assign", json={"user_id": members[0]["id"]}).status_code == 200
    r = demo.patch(f"/api/incidents/{top['id']}", json={"status": "CONTAINED", "note": "Host isolated"})
    assert r.status_code == 200 and r.json()["status"] == "CONTAINED"
    assert demo.patch(f"/api/incidents/{top['id']}", json={"status": "CONTAINED"}).status_code == 409
    assert demo.patch(f"/api/incidents/{top['id']}", json={"status": "BOGUS"}).status_code == 422
    assert demo.post(f"/api/incidents/{top['id']}/notes", json={"body": "Reset password", "kind": "note"}).status_code == 201
    assert demo.patch(f"/api/incidents/{top['id']}/checklist", json={"index": 0, "done": True}).json()["checklist"][0]["done"]
    assert demo.put(f"/api/incidents/{top['id']}/tags", json={"tags": ["exfil", "vip"]}).json()["tags"] == ["exfil", "vip"]
    assert demo.post(f"/api/incidents/{top['id']}/bookmark").json()["bookmarked"] is True
    inc = demo.get(f"/api/incidents/{top['id']}").json()
    assert [h["to"] for h in inc["status_history"]][-2:] == ["IN_PROGRESS", "CONTAINED"]
    history = demo.get(f"/api/incidents/{top['id']}/history").json()
    assert {"CHANGE_INCIDENT_STATUS", "ASSIGN_INCIDENT", "ADD_NOTE", "VIEW_INCIDENT"} <= {h["action"] for h in history}
    demo.patch(f"/api/incidents/{top['id']}", json={"status": "IN_PROGRESS"})


def test_promote_standalone_detection(client):
    acct = register(client, "promote")
    csv = "timestamp,user,host,process,command\n2026-09-02T10:00:00Z,x,WS1,cmd.exe,schtasks /create /tn t /tr \"powershell -w hidden\" /sc onlogon\n"
    job = upload(acct, "one.csv", csv)
    assert job["detections_created"] == 1 and job["incidents_created"] == 0
    det = acct.get("/api/detections?correlated=false").json()["items"][0]
    r = acct.post(f"/api/detections/{det['id']}/promote")
    assert r.status_code == 201
    assert acct.post(f"/api/detections/{det['id']}/promote").status_code == 409


def test_analytics_search_mitre_entities_intel(demo, db):
    from app.models import Event
    s = demo.get("/api/analytics/summary").json()
    assert s["kpis"]["events"] == db.query(Event).filter_by(workspace_id=demo.workspace_id).count()
    assert sum(b["total"] for b in s["events_over_time"]) == s["kpis"]["events"]
    assert s["techniques"] and s["top_users"] and s["detections_by_rule"]
    res = demo.get("/api/search?q=t.nguyen").json()["results"]
    assert {"user", "incident"} <= {r["type"] for r in res}
    assert any(r["type"] == "technique" for r in demo.get("/api/search?q=T1110").json()["results"])
    mitre = demo.get("/api/mitre/techniques").json()
    assert any(t["incident_count"] > 0 for t in mitre["techniques"])
    users = demo.get("/api/entities/users").json()
    assert users[0]["risk_score"] >= users[-1]["risk_score"] and users[0]["factors"]
    prof = demo.get("/api/entities/user/t.nguyen").json()
    assert prof["detections"] and prof["anomalies"]
    ti = demo.get("/api/intel/search?q=203.0.113.45").json()
    assert ti["detected_type"] == "ip" and ti["matches"][0]["is_synthetic"] is True
    assert ti["sightings"]["event_count"] >= 39 and ti["sightings"]["incidents"]
    miss = demo.get("/api/intel/search?q=1.1.1.1").json()
    assert miss["matches"] == [] and "Not present" in miss["verdict"]
    provs = demo.get("/api/intel/providers").json()
    assert any(p["label"] == "SYNTHETIC / DEMO INTELLIGENCE" for p in provs)
    assert any(p["status"] == "NOT CONFIGURED" for p in provs)


def test_indicator_retro_hunt(client):
    acct = register(client, "ioc")
    upload(acct, "n.csv", "timestamp,user,host,dst_ip,bytes\n2026-09-02T10:00:00Z,a,WS1,45.9.9.9,500\n")
    r = acct.post("/api/intel/indicators", json={"value": "45.9.9.9", "severity": "high", "confidence": 0.9})
    assert r.status_code == 201 and r.json()["indicator"]["indicator_type"] == "ip"
    assert r.json()["retro_hunt"]["detections_created"] == 1


def test_health_is_honest(demo):
    comps = {c["name"]: c for c in demo.get("/api/system/health").json()["components"]}
    from app.database import session as dbs
    if dbs.engine.dialect.name == "sqlite":
        assert comps["Database"]["status"] == "DEGRADED" and "SQLite" in comps["Database"]["detail"]
    else:
        assert comps["Database"]["status"] == "CONNECTED" and "PostgreSQL" in comps["Database"]["detail"]
    assert comps["AI Provider"]["status"] == "NOT CONFIGURED"
    assert comps["ML Engine"]["status"] == "CONNECTED"
    assert comps["Threat Intelligence"]["label"] == "SYNTHETIC / DEMO INTELLIGENCE"
    cfg = demo.get("/api/system/config").json()
    assert cfg["secret_key"] == "configured (hidden)" and "test-secret" not in str(cfg)


def test_security_headers_and_error_hygiene(client):
    r = client.get("/api/health/live")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    r = client.post("/api/auth/login", json={"email": "not-an-email", "password": "x"})
    assert r.status_code == 422 and "Traceback" not in r.text
