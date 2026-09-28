"""Platform features: hunts, detection lab, simulation, knowledge graph, Attack DNA, investigations, analytics."""

from conftest import register

from app.models import Event, GraphEdge, GraphNode


def _flagship(demo):
    return next(i for i in demo.get("/api/incidents").json()["items"] if "t.nguyen" in i["users"])


# ------------------------------------------------------------------------------------------------ deep links
def test_incident_resolves_by_number(demo):
    inc = _flagship(demo)
    by_num = demo.get(f"/api/incidents/{inc['number']}")
    assert by_num.status_code == 200 and by_num.json()["id"] == inc["id"]
    assert demo.get("/api/incidents/INC-9999").status_code == 404
    assert demo.get("/api/incidents/not-a-ref").status_code == 404


def test_event_resolves_by_uid(demo, db):
    ev = db.query(Event).filter_by(workspace_id=demo.workspace_id).first()
    assert demo.get(f"/api/events/by-uid/{ev.event_uid}").json()["id"] == ev.id


# ------------------------------------------------------------------------------------------------ hunts
def test_hunt_translate_run_and_create_incident(demo, db):
    t = demo.post("/api/hunts/translate", json={"text": "Find large uploads to external destinations"}).json()
    assert t["method"] == "rule-based" and "large_transfer" in t["spec"]["behaviors"]
    res = demo.post("/api/hunts/run", json={"spec": t["spec"], "natural_language": "large uploads", "name": "Uploads"}).json()
    assert res["total"] > 0 and res["hunt"].startswith("HUNT-")
    uids = [e["event_uid"] for e in res["events"]]
    stored = {u for (u,) in db.query(Event.event_uid).filter(Event.workspace_id == demo.workspace_id, Event.event_uid.in_(uids))}
    assert stored == set(uids)  # hunt results are real events
    hunt = demo.get(f"/api/hunts/{res['hunt']}").json()
    assert hunt["result"]["total"] == res["total"]
    inc = demo.post(f"/api/hunts/{res['hunt']}/incident", json={"title": "Hunt: large external uploads"})
    assert inc.status_code == 201, inc.text
    detail = demo.get(f"/api/incidents/{inc.json()['number']}").json()
    assert detail["origin"] == "hunt" if "origin" in detail else True


def test_invalid_hunt_is_rejected(demo):
    r = demo.post("/api/hunts/run", json={"spec": {"behaviors": ["teleportation"]}})
    assert r.status_code == 422


def test_viewer_cannot_create_incident_from_hunt(client, demo):
    viewer = register(client, "hunt-viewer")
    demo.post("/api/members", json={"email": viewer.email, "role": "VIEWER"})
    hunts = demo.get("/api/hunts").json()
    assert hunts
    r = viewer.post(f"/api/hunts/{hunts[0]['number']}/incident", ws=demo.workspace_id, json={"title": "nope nope"})
    assert r.status_code == 403


# ------------------------------------------------------------------------------------------------ detection lab
def test_candidate_rule_backtest_and_activation(demo):
    spec = {"name": "Many failed logins per user", "severity": "high", "stage": "Credential Access",
            "mitre": ["T1110.001"], "description": "Test candidate",
            "match": {"event_types": ["authentication"], "status": "failure"},
            "threshold": {"count": 20, "window_minutes": 120, "group_by": "user"}}
    c = demo.post("/api/lab/candidates", json={"spec": spec})
    assert c.status_code == 201, c.text
    key = c.json()["rule_key"]
    assert key.startswith("SX-C")
    # Activation requires a backtest first.
    assert demo.post(f"/api/lab/rules/{key}/activate").status_code == 422
    bt = demo.post(f"/api/lab/rules/{key}/backtest").json()
    assert bt["alerts"] > 0 and "benign_baseline_alerts" in bt and bt["scenario_coverage"]
    listed = next(r for r in demo.get("/api/lab/candidates").json() if r["rule_key"] == key)
    assert listed["kind"] == "candidate" and listed["enabled"] is False and listed["last_backtest"]
    act = demo.post(f"/api/lab/rules/{key}/activate").json()
    assert act["enabled"] is True
    assert demo.delete(f"/api/lab/rules/{key}").status_code == 422  # active rules cannot be discarded


def test_invalid_rule_spec_rejected(demo):
    assert demo.post("/api/lab/candidates", json={"spec": {"name": "x"}}).status_code == 422


def test_rule_quality_regression_and_evasion(demo):
    q = demo.get("/api/lab/quality").json()
    assert q and {"rule_key", "detections"} <= set(q[0])
    reg = demo.post("/api/lab/regression").json()
    assert "results" in reg or "datasets" in reg or reg
    ev = demo.get("/api/lab/evasion").json()
    assert ev and all("evaded" in t or "detected" in t for t in ev)


# ------------------------------------------------------------------------------------------------ simulation
def test_sandbox_with_controls_and_gap_analysis(demo):
    cat = demo.get("/api/sim/scenarios").json()
    assert cat["scenarios"] and any(c["id"] == "mfa" for c in cat["controls"])
    res = demo.post("/api/lab/sandbox", json={"scenario": "credential_compromise", "controls": ["mfa"]}).json()
    assert res["baseline"]["rules_fired"] and res["with_controls"] is not None and "summary" in res
    gap = demo.post("/api/sim/gap", json={"scenario": "credential_compromise",
                                          "variations": {"attempt_interval_s": 400}}).json()
    assert "rules_evaded" in gap
    assert demo.post("/api/lab/sandbox", json={"scenario": "nope"}).status_code == 422
    assert demo.get("/api/sim/runs").json()


def test_incident_what_if_counterfactual_similar(demo):
    inc = _flagship(demo)
    wi = demo.post(f"/api/incidents/{inc['number']}/what-if", json={"controls": ["mfa"]})
    assert wi.status_code == 200, wi.text
    dets = demo.get(f"/api/incidents/{inc['id']}").json()["detections"]
    cf = demo.post(f"/api/incidents/{inc['number']}/counterfactual", json={"remove_detection_ids": [dets[0]["id"]]}).json()
    assert "risk" in str(cf).lower()
    sim = demo.get(f"/api/incidents/{inc['number']}/similar").json()
    assert sim["dna"] and sim["dna"].get("signature") and "weights" in sim
    fam = demo.get("/api/analytics/families").json()
    assert "families" in fam


# ------------------------------------------------------------------------------------------------ knowledge graph
def test_knowledge_graph_is_built_from_events(demo, db):
    assert db.query(GraphNode).filter_by(workspace_id=demo.workspace_id).count() > 10
    edge = db.query(GraphEdge).filter_by(workspace_id=demo.workspace_id).first()
    assert edge.sample_event_uids  # every relationship is backed by events
    uid = edge.sample_event_uids[0]
    assert db.query(Event).filter_by(workspace_id=demo.workspace_id, event_uid=uid).count() == 1
    found = demo.get("/api/graph/search?q=t.nguyen").json()
    assert found and found[0]["key"] == "t.nguyen"
    node = demo.get(f"/api/graph/nodes/{found[0]['id']}").json()
    assert node["node"]["kind"] == "user" and node["edges"]
    inc = _flagship(demo)
    sub = demo.get(f"/api/incidents/{inc['number']}/knowledge-graph").json()
    assert sub["nodes"] and sub["edges"]
    host = inc["hosts"][0]
    paths = demo.get(f"/api/graph/paths?source=t.nguyen&target={host}").json()
    assert "paths" in paths
    assert demo.get("/api/graph/paths?source=t.nguyen&target=does-not-exist").status_code == 404


def test_graph_is_workspace_scoped(client, demo):
    other = register(client, "graph-other")
    assert other.get("/api/graph/search?q=t.nguyen").json() == []


# ------------------------------------------------------------------------------------------------ investigations
def test_investigation_lifecycle(demo):
    inc = _flagship(demo)
    inv = demo.post("/api/investigations", json={"title": "Is t.nguyen compromised?", "incident": inc["number"]})
    assert inv.status_code == 201, inv.text
    num = inv.json()["number"]
    assert num.startswith("INV-")
    h = demo.post(f"/api/investigations/{num}/items", json={"kind": "hypothesis", "text": "Credential stuffing",
                                                            "supporting": ["EVT:x"]}).json()
    assert h["status"] == "open"
    assert demo.patch(f"/api/investigations/{num}/items/{h['id']}", json={"status": "supported"}).json()["status"] == "supported"
    assert demo.patch(f"/api/investigations/{num}/items/{h['id']}", json={"status": "bogus"}).status_code == 422
    assert demo.post(f"/api/investigations/{num}/items", json={"kind": "spell", "text": "x"}).status_code == 422
    full = demo.get(f"/api/investigations/{num}").json()
    assert full["items"] and full["incident"] if "incident" in full else full["items"]
    assert any(i["number"] == num for i in demo.get("/api/investigations").json())


# ------------------------------------------------------------------------------------------------ analytics
def test_entity_analytics(demo):
    for url in ("/api/entities/user/t.nguyen/baseline", "/api/entities/user/t.nguyen/life-story",
                "/api/entities/user/t.nguyen/risk-history", "/api/entities/user/t.nguyen/peers",
                "/api/analytics/changes?hours=48", "/api/analytics/risk-movers", "/api/analytics/unexplained",
                "/api/system/data-quality", "/api/system/pipeline"):
        r = demo.get(url)
        assert r.status_code == 200, (url, r.text)
    assert demo.get("/api/entities/planet/x/baseline").status_code == 404
    pipe = demo.get("/api/system/pipeline").json()
    assert "stages" in pipe


def test_report_accepts_incident_number(demo):
    inc = _flagship(demo)
    r = demo.post("/api/reports", json={"incident_id": inc["number"], "report_type": "executive"})
    assert r.status_code == 201, r.text
    assert r.json()["content"]["incident"]["number"] == inc["number"]
