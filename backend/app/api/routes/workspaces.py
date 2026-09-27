from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import AdminCtx, AnalystCtx, ReadCtx, WorkspaceContext, get_current_user
from app.api.serializers import iso, user_brief
from app.audit.service import record
from app.core.security import hash_password, password_problems
from app.database.session import get_db
from app.models import Detection, Event, Incident, Membership, Role, User, Workspace
from app.models.identity import MODE_ANALYST, MODE_DEMO, ROLE_ADMIN
from app.schemas import MemberCreateIn, MemberUpdateIn, WorkspaceCreateIn, WorkspaceSettingsIn
from app.services.pipeline import run_pipeline, workspace_lock
from app.services.simulation import get_sim
from app.services.workspace import (
    add_member,
    create_demo_workspace,
    create_workspace,
    load_demo_data,
    reset_workspace_data,
)

router = APIRouter(prefix="/api/workspaces", tags=["workspaces"])
members_router = APIRouter(prefix="/api/members", tags=["users & roles"])
sim_router = APIRouter(prefix="/api/simulation", tags=["demo simulation"])


def workspace_payload(db: Session, ws: Workspace, role: str) -> dict:
    counts = {
        "events": db.query(func.count(Event.id)).filter(Event.workspace_id == ws.id).scalar(),
        "detections": db.query(func.count(Detection.id)).filter(Detection.workspace_id == ws.id).scalar(),
        "incidents": db.query(func.count(Incident.id)).filter(Incident.workspace_id == ws.id).scalar(),
    }
    return {"id": ws.id, "name": ws.name, "mode": ws.mode, "role": role, "settings": ws.settings or {},
            "created_at": iso(ws.created_at), "last_pipeline_run_at": iso(ws.last_pipeline_run_at),
            "last_pipeline_stats": ws.last_pipeline_stats or {}, "counts": counts,
            "synthetic_data": ws.mode == MODE_DEMO}


@router.get("")
def list_workspaces(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ms = db.query(Membership).filter_by(user_id=user.id).order_by(Membership.id).all()
    return [{"id": m.workspace.id, "name": m.workspace.name, "mode": m.workspace.mode, "role": m.role.name}
            for m in ms]


@router.post("", status_code=201)
def create(body: WorkspaceCreateIn, request: Request, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    owned = db.query(Workspace).filter_by(owner_id=user.id).count()
    if owned >= 10:
        raise HTTPException(status_code=400, detail="Workspace limit reached (10 per account).")
    ws = create_workspace(db, body.name, user, MODE_ANALYST)
    db.commit()
    record(db, "CHANGE_SETTINGS", user=user, workspace_id=ws.id, target_type="workspace", target_id=ws.id,
           details={"created": body.name}, request=request)
    return workspace_payload(db, ws, ROLE_ADMIN)


@router.post("/demo", status_code=201)
def open_demo(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(Workspace).filter_by(owner_id=user.id, mode=MODE_DEMO).first()
    if existing:
        return {"workspace": workspace_payload(db, existing, ROLE_ADMIN), "created": False, "stats": None}
    ws, stats = create_demo_workspace(db, user)
    record(db, "LOAD_DEMO", user=user, workspace_id=ws.id, target_type="workspace", target_id=ws.id,
           details={k: stats.get(k) for k in ("accepted", "detections_created", "incidents_created")}, request=request)
    return {"workspace": workspace_payload(db, ws, ROLE_ADMIN), "created": True, "stats": stats}


@router.get("/current")
def current(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return workspace_payload(db, ctx.workspace, ctx.role)


@router.patch("/current/settings")
def update_settings(body: WorkspaceSettingsIn, request: Request, ctx: WorkspaceContext = AdminCtx,
                    db: Session = Depends(get_db)):
    ws = ctx.workspace
    settings = dict(ws.settings or {})
    changes = body.model_dump(exclude_none=True)
    if "name" in changes:
        ws.name = changes.pop("name")
    if "business_hours" in changes:
        changes["business_hours"] = list(changes["business_hours"])
    settings.update(changes)
    ws.settings = settings
    db.commit()
    record(db, "CHANGE_SETTINGS", user=ctx.user, workspace_id=ws.id, target_type="workspace", target_id=ws.id,
           details=body.model_dump(exclude_none=True), request=request)
    return workspace_payload(db, ws, ctx.role)


@router.post("/current/reanalyze")
def reanalyze(request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    with workspace_lock(ctx.workspace_id):
        stats = run_pipeline(db, ctx.workspace)
        db.commit()
    record(db, "CHANGE_SETTINGS", user=ctx.user, workspace_id=ctx.workspace_id, target_type="pipeline",
           target_id=ctx.workspace_id, details={"reanalyze": True, "detections_created": stats["detections_created"]},
           request=request)
    return stats


# ------------------------------------------------------------------------------------------- members
@members_router.get("")
def list_members(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    ms = db.query(Membership).filter_by(workspace_id=ctx.workspace_id).order_by(Membership.id).all()
    return [{**user_brief(m.user), "role": m.role.name, "is_active": m.user.is_active,
             "last_login_at": iso(m.user.last_login_at), "member_since": iso(m.created_at)} for m in ms]


@members_router.get("/roles")
def list_roles(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return [{"name": r.name, "description": r.description, "permissions": r.permissions} for r in db.query(Role)]


def _admin_count(db: Session, ws_id: int) -> int:
    return db.query(Membership).join(Role).filter(Membership.workspace_id == ws_id, Role.name == ROLE_ADMIN).count()


@members_router.post("", status_code=201)
def add(body: MemberCreateIn, request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    email = body.email.lower()
    user = db.query(User).filter_by(email=email).first()
    created = False
    if user is None:
        if not body.password:
            raise HTTPException(status_code=422, detail="No account exists for this email; provide an initial password.")
        problems = password_problems(body.password)
        if problems:
            raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(problems) + ".")
        user = User(email=email, full_name=body.full_name or email.split("@")[0],
                    password_hash=hash_password(body.password), settings={"theme": "dark"})
        db.add(user)
        db.flush()
        created = True
    elif db.query(Membership).filter_by(workspace_id=ctx.workspace_id, user_id=user.id).first():
        raise HTTPException(status_code=409, detail="This user is already a member of the workspace.")
    add_member(db, ctx.workspace, user, body.role)
    db.commit()
    record(db, "ADD_MEMBER", user=ctx.user, workspace_id=ctx.workspace_id, target_type="user", target_id=user.id,
           details={"email": email, "role": body.role, "account_created": created}, request=request)
    return {**user_brief(user), "role": body.role, "account_created": created}


@members_router.patch("/{user_id}")
def change_role(user_id: int, body: MemberUpdateIn, request: Request, ctx: WorkspaceContext = AdminCtx,
                db: Session = Depends(get_db)):
    m = db.query(Membership).filter_by(workspace_id=ctx.workspace_id, user_id=user_id).first()
    if m is None:
        raise HTTPException(status_code=404, detail="Member not found")
    old = m.role.name
    if old == ROLE_ADMIN and body.role != ROLE_ADMIN and _admin_count(db, ctx.workspace_id) <= 1:
        raise HTTPException(status_code=400, detail="A workspace must keep at least one ADMIN.")
    add_member(db, ctx.workspace, m.user, body.role)
    db.commit()
    record(db, "CHANGE_ROLE", user=ctx.user, workspace_id=ctx.workspace_id, target_type="user", target_id=user_id,
           details={"from": old, "to": body.role}, request=request)
    return {"user_id": user_id, "role": body.role}


@members_router.delete("/{user_id}")
def remove(user_id: int, request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    m = db.query(Membership).filter_by(workspace_id=ctx.workspace_id, user_id=user_id).first()
    if m is None:
        raise HTTPException(status_code=404, detail="Member not found")
    if m.role.name == ROLE_ADMIN and _admin_count(db, ctx.workspace_id) <= 1:
        raise HTTPException(status_code=400, detail="A workspace must keep at least one ADMIN.")
    db.delete(m)
    db.commit()
    record(db, "REMOVE_MEMBER", user=ctx.user, workspace_id=ctx.workspace_id, target_type="user", target_id=user_id,
           request=request)
    return {"ok": True}


# ---------------------------------------------------------------------------------------- simulation
def _demo_only(ctx: WorkspaceContext) -> None:
    if ctx.workspace.mode != MODE_DEMO:
        raise HTTPException(status_code=400, detail="Simulation is only available in DEMO workspaces.")


@sim_router.get("")
def sim_status(ctx: WorkspaceContext = ReadCtx):
    return {"available": ctx.workspace.mode == MODE_DEMO, **get_sim(ctx.workspace_id).status()}


@sim_router.post("/start")
def sim_start(request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    _demo_only(ctx)
    sim = get_sim(ctx.workspace_id)
    sim.start()
    record(db, "START_SIMULATION", user=ctx.user, workspace_id=ctx.workspace_id, target_type="simulation",
           target_id=ctx.workspace_id, request=request)
    return sim.status()


@sim_router.post("/pause")
def sim_pause(request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    _demo_only(ctx)
    sim = get_sim(ctx.workspace_id)
    sim.pause()
    record(db, "PAUSE_SIMULATION", user=ctx.user, workspace_id=ctx.workspace_id, target_type="simulation",
           target_id=ctx.workspace_id, request=request)
    return sim.status()


@sim_router.post("/reset")
def sim_reset(request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    _demo_only(ctx)
    sim = get_sim(ctx.workspace_id)
    sim.pause()
    with workspace_lock(ctx.workspace_id):
        reset_workspace_data(db, ctx.workspace_id)
        db.commit()
    stats = load_demo_data(db, ctx.workspace)
    db.commit()
    sim.ticks = sim.events_generated = 0
    record(db, "RESET_SIMULATION", user=ctx.user, workspace_id=ctx.workspace_id, target_type="simulation",
           target_id=ctx.workspace_id, details={"reloaded_events": stats.get("accepted")}, request=request)
    return {**sim.status(), "reload": stats}
