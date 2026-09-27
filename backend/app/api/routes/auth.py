from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.deps import SESSION_COOKIE, AuthInfo, get_auth, get_current_user
from app.api.serializers import iso
from app.audit.service import record
from app.core import ratelimit
from app.core.config import get_settings
from app.core.security import create_access_token, dummy_verify, hash_password, password_problems, verify_password
from app.database.session import get_db, utcnow
from app.models import Membership, RevokedToken, User
from app.models.identity import MODE_ANALYST
from app.schemas import ChangePasswordIn, LoginIn, ProfileUpdateIn, RegisterIn
from app.services.workspace import create_workspace

router = APIRouter(prefix="/api/auth", tags=["authentication"])


def _session_response(response: Response, user: User) -> dict:
    token, _, expires_in = create_access_token(user.id)
    settings = get_settings()
    response.set_cookie(SESSION_COOKIE, token, max_age=expires_in, httponly=True, secure=settings.cookie_secure,
                        samesite="lax", path="/")
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in}


def me_payload(db: Session, user: User) -> dict:
    memberships = db.query(Membership).filter_by(user_id=user.id).order_by(Membership.id).all()
    return {
        "id": user.id, "email": user.email, "full_name": user.full_name, "settings": user.settings or {},
        "created_at": iso(user.created_at), "last_login_at": iso(user.last_login_at),
        "workspaces": [{"id": m.workspace.id, "name": m.workspace.name, "mode": m.workspace.mode,
                        "role": m.role.name} for m in memberships],
    }


@router.post("/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ratelimit.enforce(request, "auth", get_settings().rate_limit_auth_per_minute)
    if not get_settings().allow_registration:
        raise HTTPException(status_code=403, detail="Registration is disabled on this instance.")
    problems = password_problems(body.password)
    if problems:
        raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(problems) + ".")
    email = body.email.lower()
    if db.query(User).filter_by(email=email).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    user = User(email=email, full_name=body.full_name or email.split("@")[0], password_hash=hash_password(body.password),
                settings={"theme": "dark"}, last_login_at=utcnow())
    db.add(user)
    db.flush()
    ws = create_workspace(db, f"{user.full_name}'s Workspace", user, MODE_ANALYST)
    db.commit()
    record(db, "REGISTER", user=user, workspace_id=ws.id, target_type="user", target_id=user.id, request=request)
    record(db, "LOGIN", user=user, workspace_id=ws.id, target_type="user", target_id=user.id, request=request)
    return {**_session_response(response, user), "user": me_payload(db, user)}


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    ratelimit.enforce(request, "auth", get_settings().rate_limit_auth_per_minute)
    email = body.email.lower()
    user = db.query(User).filter_by(email=email).first()
    if user is None:
        dummy_verify()
    if user is None or not verify_password(body.password, user.password_hash) or not user.is_active:
        record(db, "LOGIN_FAILED", user=user, target_type="user", target_id=getattr(user, "id", ""),
               details={"email": email}, request=request)
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    user.last_login_at = utcnow()
    db.commit()
    first = db.query(Membership).filter_by(user_id=user.id).order_by(Membership.id).first()
    record(db, "LOGIN", user=user, workspace_id=first.workspace_id if first else None, target_type="user",
           target_id=user.id, request=request)
    return {**_session_response(response, user), "user": me_payload(db, user)}


@router.post("/logout")
def logout(request: Request, response: Response, auth: AuthInfo = Depends(get_auth), db: Session = Depends(get_db)):
    db.add(RevokedToken(jti=auth.jti, expires_at=datetime.fromtimestamp(auth.exp)))
    db.query(RevokedToken).filter(RevokedToken.expires_at < utcnow()).delete()
    db.commit()
    ws = request.headers.get("x-workspace-id")
    record(db, "LOGOUT", user=auth.user, workspace_id=int(ws) if ws and ws.isdigit() and
           db.query(Membership).filter_by(user_id=auth.user.id, workspace_id=int(ws)).first() else None,
           target_type="user", target_id=auth.user.id, request=request)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return me_payload(db, user)


@router.patch("/me")
def update_profile(body: ProfileUpdateIn, request: Request, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    changes = {}
    if body.full_name is not None and body.full_name.strip():
        user.full_name = body.full_name.strip()
        changes["full_name"] = user.full_name
    if body.theme is not None:
        user.settings = {**(user.settings or {}), "theme": body.theme}
        changes["theme"] = body.theme
    db.commit()
    record(db, "CHANGE_SETTINGS", user=user, target_type="user", target_id=user.id, details={"profile": changes},
           request=request)
    return me_payload(db, user)


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, response: Response,
                    auth: AuthInfo = Depends(get_auth), db: Session = Depends(get_db)):
    ratelimit.enforce(request, "auth", get_settings().rate_limit_auth_per_minute)
    user = auth.user
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    problems = password_problems(body.new_password)
    if problems:
        raise HTTPException(status_code=422, detail="New password must contain " + ", ".join(problems) + ".")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=422, detail="New password must differ from the current password.")
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = utcnow()
    db.add(RevokedToken(jti=auth.jti, expires_at=datetime.fromtimestamp(auth.exp)))
    db.commit()
    record(db, "CHANGE_PASSWORD", user=user, target_type="user", target_id=user.id, request=request)
    return {"ok": True, **_session_response(response, user)}
