from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database.session import get_db
from app.models import Membership, RevokedToken, User, Workspace
from app.models.identity import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER

SESSION_COOKIE = "sx_session"
CSRF_HEADER = "x-sentinelx-csrf"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

READ_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)
ANALYST_ROLES = (ROLE_ADMIN, ROLE_ANALYST)
ADMIN_ROLES = (ROLE_ADMIN,)


@dataclass
class AuthInfo:
    user: User
    jti: str
    exp: int


@dataclass
class WorkspaceContext:
    user: User
    workspace: Workspace
    role: str

    @property
    def workspace_id(self) -> int:
        return self.workspace.id


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"})


def get_auth(request: Request, db: Session = Depends(get_db)) -> AuthInfo:
    token = None
    auth_header = request.headers.get("authorization", "")
    from_cookie = False
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    elif request.cookies.get(SESSION_COOKIE):
        token = request.cookies[SESSION_COOKIE]
        from_cookie = True
    if not token:
        raise _unauthorized()
    if from_cookie and request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
        # Cookie-authenticated state changes must carry a custom header, which cross-site forms cannot send.
        raise HTTPException(status_code=403, detail="Missing CSRF header")
    payload = decode_access_token(token)
    if not payload:
        raise _unauthorized("Session expired or invalid. Please sign in again.")
    if db.get(RevokedToken, payload["jti"]):
        raise _unauthorized("Session has been signed out.")
    try:
        user_id = int(payload["sub"])
    except (TypeError, ValueError):
        raise _unauthorized() from None
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise _unauthorized()
    if user.password_changed_at and payload.get("iat", 0) < int(user.password_changed_at.timestamp()) - 1:
        raise _unauthorized("Password was changed. Please sign in again.")
    return AuthInfo(user=user, jti=payload["jti"], exp=payload["exp"])


def get_current_user(auth: AuthInfo = Depends(get_auth)) -> User:
    return auth.user


def get_workspace_context(request: Request, user: User = Depends(get_current_user),
                          db: Session = Depends(get_db)) -> WorkspaceContext:
    raw = request.headers.get("x-workspace-id") or request.query_params.get("workspace_id")
    membership = None
    if raw:
        try:
            ws_id = int(raw)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid workspace id") from None
        membership = db.query(Membership).filter_by(user_id=user.id, workspace_id=ws_id).first()
        if membership is None:
            # Same response whether the workspace does not exist or belongs to someone else.
            raise HTTPException(status_code=404, detail="Workspace not found")
    else:
        membership = db.query(Membership).filter_by(user_id=user.id).order_by(Membership.id).first()
        if membership is None:
            raise HTTPException(status_code=404, detail="No workspace available")
    return WorkspaceContext(user=user, workspace=membership.workspace, role=membership.role.name)


def require_roles(*roles: str):
    def dependency(ctx: WorkspaceContext = Depends(get_workspace_context)) -> WorkspaceContext:
        if ctx.role not in roles:
            raise HTTPException(status_code=403, detail=f"This action requires one of the roles: {', '.join(roles)}")
        return ctx

    return dependency


ReadCtx = Depends(require_roles(*READ_ROLES))
AnalystCtx = Depends(require_roles(*ANALYST_ROLES))
AdminCtx = Depends(require_roles(*ADMIN_ROLES))
