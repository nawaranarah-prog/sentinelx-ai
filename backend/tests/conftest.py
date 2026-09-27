import os
import sys
import tempfile
import uuid
from pathlib import Path

_tmp = Path(tempfile.mkdtemp(prefix="sentinelx-test-"))
os.environ.update({
    # TEST_DATABASE_URL lets the same suite run against PostgreSQL (the database is wiped first).
    "DATABASE_URL": os.environ.get("TEST_DATABASE_URL") or f"sqlite:///{(_tmp / 'test.db').as_posix()}",
    "SECRET_KEY": "test-secret-key-for-pytest-only-0123456789",
    "ENVIRONMENT": "test",
    "LLM_PROVIDER": "none",
    "LLM_API_KEY": "",
    "RATE_LIMIT_AUTH_PER_MINUTE": "10000",
    "RATE_LIMIT_AI_PER_MINUTE": "10000",
    "RATE_LIMIT_UPLOAD_PER_MINUTE": "10000",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import app.models  # noqa: E402,F401
from app.database import session as dbs  # noqa: E402
from app.database.session import Base  # noqa: E402

Base.metadata.drop_all(dbs.engine)
Base.metadata.create_all(dbs.engine)
_s = dbs.SessionLocal()
from app.services.workspace import bootstrap_reference_data  # noqa: E402

bootstrap_reference_data(_s)
_s.close()

from app.main import app  # noqa: E402

PASSWORD = "Str0ngPassw0rd!"


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def db():
    s = dbs.SessionLocal()
    try:
        yield s
    finally:
        s.close()


class Account:
    def __init__(self, client: TestClient, email: str, token: str, workspace_id: int):
        self.client, self.email, self.token, self.workspace_id = client, email, token, workspace_id

    def headers(self, workspace_id: int | None = None) -> dict:
        return {"Authorization": f"Bearer {self.token}", "X-Workspace-ID": str(workspace_id or self.workspace_id)}

    def get(self, url, ws=None, **kw):
        return self.client.get(url, headers=self.headers(ws), **kw)

    def post(self, url, ws=None, **kw):
        return self.client.post(url, headers=self.headers(ws), **kw)

    def patch(self, url, ws=None, **kw):
        return self.client.patch(url, headers=self.headers(ws), **kw)

    def put(self, url, ws=None, **kw):
        return self.client.put(url, headers=self.headers(ws), **kw)

    def delete(self, url, ws=None, **kw):
        return self.client.delete(url, headers=self.headers(ws), **kw)


def register(client: TestClient, prefix: str = "user") -> Account:
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"
    r = client.post("/api/auth/register", json={"email": email, "password": PASSWORD, "full_name": prefix.title()})
    assert r.status_code == 201, r.text
    client.cookies.clear()
    body = r.json()
    return Account(client, email, body["access_token"], body["user"]["workspaces"][0]["id"])


@pytest.fixture
def account(client) -> Account:
    return register(client)


@pytest.fixture(scope="session")
def demo(client):
    """One Nova Bank demo workspace shared by read-only tests."""
    acct = register(client, "demo")
    r = acct.post("/api/workspaces/demo")
    assert r.status_code == 201, r.text
    acct.workspace_id = r.json()["workspace"]["id"]
    return acct


def upload(acct: Account, filename: str, content: bytes | str, ws: int | None = None) -> dict:
    if isinstance(content, str):
        content = content.encode()
    r = acct.post("/api/ingest/upload", ws=ws, files={"file": (filename, content, "application/octet-stream")})
    assert r.status_code == 202, r.text
    job = acct.get(f"/api/ingest/jobs/{r.json()['id']}", ws=ws).json()
    return job
