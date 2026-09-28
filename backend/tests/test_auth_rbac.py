from conftest import PASSWORD, register


def test_register_login_me_logout(client):
    acct = register(client, "auth")
    me = acct.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["email"] == acct.email
    assert me.json()["workspaces"][0]["role"] == "ADMIN"
    r = client.post("/api/auth/login", json={"email": acct.email, "password": PASSWORD})
    assert r.status_code == 200
    token = r.json()["access_token"]
    client.cookies.clear()
    h = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/auth/logout", headers=h).status_code == 200
    assert client.get("/api/auth/me", headers=h).status_code == 401, "revoked token must be rejected"


def test_bad_credentials_and_weak_passwords(client):
    acct = register(client, "creds")
    assert client.post("/api/auth/login", json={"email": acct.email, "password": "wrong-password-1"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"}).status_code == 401
    r = client.post("/api/auth/register", json={"email": "weak@example.com", "password": "short"})
    assert r.status_code == 422 and "10 characters" in r.json()["detail"]
    r = client.post("/api/auth/register", json={"email": acct.email, "password": PASSWORD})
    assert r.status_code == 409
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


def test_password_hashes_are_not_plaintext(client, db):
    from app.models import User
    acct = register(client, "hash")
    u = db.query(User).filter_by(email=acct.email).one()
    assert PASSWORD not in u.password_hash and u.password_hash.startswith("$2")


def test_password_change_invalidates_old_sessions(client):
    acct = register(client, "pwchange")
    new = "An0therStrongPass"
    r = acct.post("/api/auth/change-password", json={"current_password": PASSWORD, "new_password": new})
    assert r.status_code == 200
    client.cookies.clear()
    assert acct.get("/api/auth/me").status_code == 401
    assert client.post("/api/auth/login", json={"email": acct.email, "password": new}).status_code == 200
    client.cookies.clear()


def test_cookie_session_requires_csrf_header_for_mutations(client):
    acct = register(client, "cookie")
    r = client.post("/api/auth/login", json={"email": acct.email, "password": PASSWORD})
    assert "sx_session" in r.cookies or client.cookies.get("sx_session")
    assert client.get("/api/auth/me").status_code == 200
    assert client.patch("/api/auth/me", json={"theme": "light"}).status_code == 403
    assert client.patch("/api/auth/me", json={"theme": "light"}, headers={"X-SentinelX-CSRF": "1"}).status_code == 200
    client.cookies.clear()


def test_tenant_isolation(client, demo):
    outsider = register(client, "outsider")
    # Cannot select someone else's workspace at all.
    assert outsider.get("/api/events", ws=demo.workspace_id).status_code == 404
    assert outsider.get("/api/incidents", ws=demo.workspace_id).status_code == 404
    # Object ids from another tenant are invisible inside the outsider's own workspace.
    first_inc = demo.get("/api/incidents").json()["items"][0]
    inc_id, inc_number = first_inc["id"], first_inc["number"]
    ev_id = demo.get("/api/events?page_size=1").json()["items"][0]["id"]
    det_id = demo.get("/api/detections?page_size=1").json()["items"][0]["id"]
    assert outsider.get(f"/api/incidents/{inc_id}").status_code == 404
    assert outsider.get(f"/api/events/{ev_id}").status_code == 404
    assert outsider.get(f"/api/detections/{det_id}").status_code == 404
    assert outsider.get(f"/api/incidents/{inc_id}/timeline").status_code == 404
    assert outsider.get(f"/api/events?incident_id={inc_id}").json()["total"] == 0
    assert outsider.post("/api/ai/chat", json={"message": "What happened?", "context": [f"INC:{inc_number}"]}).status_code == 404
    assert outsider.post("/api/reports", json={"incident_id": inc_id}).status_code == 404
    assert outsider.get("/api/events").json()["total"] == 0


def test_rbac_enforced_on_backend(client):
    admin = register(client, "rbacadmin")
    viewer_email, analyst_email = f"viewer-{admin.email}", f"analyst-{admin.email}"
    assert admin.post("/api/members", json={"email": viewer_email, "role": "VIEWER", "password": PASSWORD}).status_code == 201
    assert admin.post("/api/members", json={"email": analyst_email, "role": "SOC_ANALYST", "password": PASSWORD}).status_code == 201
    tokens = {}
    for email in (viewer_email, analyst_email):
        tokens[email] = client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).json()["access_token"]
        client.cookies.clear()

    def h(email):
        return {"Authorization": f"Bearer {tokens[email]}", "X-Workspace-ID": str(admin.workspace_id)}

    csv = b"timestamp,user,action\n2026-09-01T10:00:00Z,a,login\n"
    # Viewer: read-only
    assert client.get("/api/incidents", headers=h(viewer_email)).status_code == 200
    assert client.post("/api/ingest/upload", headers=h(viewer_email), files={"file": ("a.csv", csv)}).status_code == 403
    assert client.post("/api/ai/chat", headers=h(viewer_email), json={"message": "hi"}).status_code == 403
    assert client.post("/api/intel/indicators", headers=h(viewer_email), json={"value": "1.2.3.4"}).status_code == 403
    # Analyst: investigation but no administration
    assert client.post("/api/ingest/upload", headers=h(analyst_email), files={"file": ("a.csv", csv)}).status_code == 202
    rule_id = client.get("/api/rules", headers=h(analyst_email)).json()[0]["id"]
    assert client.patch(f"/api/rules/{rule_id}", headers=h(analyst_email), json={"enabled": False}).status_code == 403
    assert client.get("/api/audit", headers=h(analyst_email)).status_code == 403
    assert client.post("/api/members", headers=h(analyst_email), json={"email": "x@example.com", "role": "ADMIN",
                                                                         "password": PASSWORD}).status_code == 403
    assert client.post("/api/knowledge/documents", headers=h(analyst_email),
                       files={"file": ("a.md", b"# Title\n\nSome content here")}).status_code == 403
    # Admin
    assert admin.patch(f"/api/rules/{rule_id}", json={"parameters": {"failure_threshold": 12}}).status_code == 200
    assert admin.patch(f"/api/rules/{rule_id}", json={"parameters": {"unknown": 1}}).status_code == 422
    assert admin.get("/api/audit").status_code == 200
    members = admin.get("/api/members").json()
    viewer_id = next(m["id"] for m in members if m["email"] == viewer_email)
    assert admin.patch(f"/api/members/{viewer_id}", json={"role": "SOC_ANALYST"}).status_code == 200
    me_id = next(m["id"] for m in members if m["email"] == admin.email)
    assert admin.patch(f"/api/members/{me_id}", json={"role": "VIEWER"}).status_code == 400, "last admin protected"
    actions = {a["action"] for a in admin.get("/api/audit?page_size=200").json()["items"]}
    assert {"ADD_MEMBER", "CHANGE_RULE", "CHANGE_ROLE"} <= actions
