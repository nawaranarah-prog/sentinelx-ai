from sqlalchemy.orm import Session

from app.models import Membership, Notification


def notify_workspace(db: Session, workspace_id: int, kind: str, title: str, body: str = "", link: str = "",
                     severity: str = "info", only_user_id: int | None = None) -> int:
    if only_user_id is not None:
        user_ids = [only_user_id]
    else:
        user_ids = [m.user_id for m in db.query(Membership.user_id).filter_by(workspace_id=workspace_id)]
    for uid in user_ids:
        db.add(Notification(workspace_id=workspace_id, user_id=uid, kind=kind, title=title[:255], body=body,
                            link=link[:255], severity=severity))
    return len(user_ids)
