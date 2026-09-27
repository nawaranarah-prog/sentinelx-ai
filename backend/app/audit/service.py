import re

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog

AUDIT_ACTIONS = (
    "LOGIN", "LOGIN_FAILED", "LOGOUT", "REGISTER", "CHANGE_PASSWORD", "VIEW_INCIDENT", "VIEW_EVENT",
    "QUERY_AI", "UPLOAD_DATA", "UPLOAD_DOCUMENT", "DELETE_DOCUMENT", "EXPORT_REPORT", "GENERATE_REPORT",
    "CHANGE_RULE", "CHANGE_ROLE", "ADD_MEMBER", "REMOVE_MEMBER", "CHANGE_SETTINGS", "CHANGE_INCIDENT_STATUS",
    "ASSIGN_INCIDENT", "ADD_NOTE", "PROMOTE_DETECTION", "UPDATE_INCIDENT", "ADD_INDICATOR", "IMPORT_INDICATORS",
    "LOAD_DEMO", "START_SIMULATION", "PAUSE_SIMULATION", "RESET_SIMULATION", "TEST_AI_PROVIDER",
    "CHANGE_ASSET",
)

_SENSITIVE_KEY = re.compile(r"pass(word)?|secret|token|api[_-]?key|authorization|cookie|credential", re.I)


def scrub(value):
    """Remove secrets from audit details before they are persisted."""
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SENSITIVE_KEY.search(str(k)) else scrub(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…"
    return value


def record(
    db: Session,
    action: str,
    *,
    user=None,
    workspace_id: int | None = None,
    target_type: str = "",
    target_id: str | int = "",
    details: dict | None = None,
    request: Request | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        workspace_id=workspace_id,
        user_id=getattr(user, "id", None),
        user_email=getattr(user, "email", "") or "",
        action=action,
        target_type=target_type,
        target_id=str(target_id),
        details=scrub(details or {}),
        ip_address=(request.client.host if request and request.client else "")[:64],
        user_agent=(request.headers.get("user-agent", "") if request else "")[:255],
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry
