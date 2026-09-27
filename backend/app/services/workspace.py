from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.database.session import utcnow
from app.demo.generator import SYNTHETIC_INDICATORS, generate
from app.detection.engine import ensure_default_rules
from app.ingestion.normalizer import RowError, normalize_record
from app.mitre.catalog import seed_mitre
from app.models import (
    AIConversation,
    AnomalyResult,
    Asset,
    Detection,
    Event,
    Host,
    Incident,
    IngestionJob,
    Membership,
    Notification,
    Report,
    Role,
    ThreatIndicator,
    User,
    Workspace,
)
from app.models.identity import ALL_ROLES, MODE_DEMO, ROLE_ADMIN
from app.rag.service import seed_knowledge_base
from app.services.pipeline import ingest_rows

ROLE_DESCRIPTIONS = {
    "ADMIN": ("Full control of the workspace: users and roles, detection rules, knowledge base, configuration, "
              "audit logs, plus all analyst capabilities.",
              ["users:manage", "rules:manage", "knowledge:manage", "config:manage", "audit:read", "investigate",
               "ingest", "ai:query", "reports:create", "intel:manage", "read"]),
    "SOC_ANALYST": ("Investigation, ingestion, AI assistant, reports and threat intelligence.",
                    ["investigate", "ingest", "ai:query", "reports:create", "intel:manage", "read"]),
    "VIEWER": ("Read-only access to workspace data.", ["read"]),
}


def ensure_roles(db: Session) -> dict[str, Role]:
    roles = {r.name: r for r in db.query(Role)}
    for name in ALL_ROLES:
        desc, perms = ROLE_DESCRIPTIONS[name]
        if name not in roles:
            roles[name] = Role(name=name, description=desc, permissions=perms)
            db.add(roles[name])
    db.flush()
    return roles


def bootstrap_reference_data(db: Session) -> None:
    ensure_roles(db)
    seed_mitre(db)
    db.commit()


def add_member(db: Session, workspace: Workspace, user: User, role_name: str) -> Membership:
    roles = ensure_roles(db)
    m = db.query(Membership).filter_by(workspace_id=workspace.id, user_id=user.id).first()
    if m:
        m.role_id = roles[role_name].id
    else:
        m = Membership(workspace_id=workspace.id, user_id=user.id, role_id=roles[role_name].id)
        db.add(m)
    db.flush()
    return m


def create_workspace(db: Session, name: str, owner: User | None, mode: str) -> Workspace:
    seed_mitre(db)
    ws = Workspace(name=name[:120], mode=mode, owner_id=owner.id if owner else None,
                   settings={"business_hours": [7, 20], "correlation_window_minutes": 120})
    db.add(ws)
    db.flush()
    if owner:
        add_member(db, ws, owner, ROLE_ADMIN)
    ensure_default_rules(db, ws.id)
    seed_knowledge_base(db, ws.id)
    db.flush()
    return ws


def seed_synthetic_indicators(db: Session, workspace_id: int) -> int:
    now = utcnow()
    n = 0
    for ind in SYNTHETIC_INDICATORS:
        exists = db.query(ThreatIndicator).filter_by(workspace_id=workspace_id, indicator_type=ind["indicator_type"],
                                                     value=ind["value"]).first()
        if exists:
            continue
        db.add(ThreatIndicator(workspace_id=workspace_id, source="SentinelX Synthetic Demo Feed", is_synthetic=True,
                               first_seen=now.replace(day=1), last_seen=now, **ind))
        n += 1
    db.flush()
    return n


def load_demo_data(db: Session, workspace: Workspace, days: int = 7, seed: int = 7) -> dict:
    seed_synthetic_indicators(db, workspace.id)
    db.commit()
    records = generate(end=None, days=days, seed=seed, prefix="NB")
    rows = []
    for rec in records:
        try:
            rows.append(normalize_record(rec))
        except RowError:
            continue
    stats = ingest_rows(db, workspace, rows, source_label="nova-bank-synthetic")
    stats["generated_records"] = len(records)
    return stats


def reset_workspace_data(db: Session, workspace_id: int) -> None:
    """Remove telemetry and derived analysis (keeps members, rules, knowledge base and settings)."""
    for model in (Report, AIConversation, Incident, Detection, AnomalyResult, Event, IngestionJob, Host, Asset,
                  Notification):
        db.execute(delete(model).where(model.workspace_id == workspace_id))
    ws = db.get(Workspace, workspace_id)
    ws.incident_seq = 0
    ws.last_pipeline_stats = {}
    ws.last_pipeline_run_at = None
    db.flush()


def create_demo_workspace(db: Session, owner: User) -> tuple[Workspace, dict]:
    ws = create_workspace(db, "Nova Bank (Demo)", owner, MODE_DEMO)
    db.commit()
    stats = load_demo_data(db, ws)
    db.commit()
    return ws, stats
