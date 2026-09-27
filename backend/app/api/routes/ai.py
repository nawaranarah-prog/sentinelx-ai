from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.ai import assistant
from app.ai.providers import provider_status
from app.api.deps import AdminCtx, AnalystCtx, ReadCtx, WorkspaceContext
from app.api.serializers import iso
from app.audit.service import record
from app.core import ratelimit
from app.core.config import get_settings
from app.database.session import get_db
from app.models import AIConversation, AIMessage
from app.schemas import ChatIn

router = APIRouter(prefix="/api/ai", tags=["AI assistant"])


@router.get("/status")
def status(ctx: WorkspaceContext = ReadCtx):
    return provider_status()


@router.post("/test")
def test_provider(request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    st = provider_status(probe=True)
    record(db, "TEST_AI_PROVIDER", user=ctx.user, workspace_id=ctx.workspace_id, target_type="ai_provider",
           target_id=st.get("provider") or "none", details={"status": st["status"]}, request=request)
    return st


@router.get("/suggestions")
def suggestions(incident_id: int | None = None, ctx: WorkspaceContext = ReadCtx):
    return {"suggestions": assistant.SUGGESTIONS_INCIDENT if incident_id else assistant.SUGGESTIONS_GENERAL}


@router.post("/chat")
def chat(body: ChatIn, request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    ratelimit.enforce(request, "ai", get_settings().rate_limit_ai_per_minute, str(ctx.user.id))
    result = assistant.chat(db, ctx, body.message, body.conversation_id, body.incident_id)
    msg = result["message"]
    record(db, "QUERY_AI", user=ctx.user, workspace_id=ctx.workspace_id, target_type="ai_conversation",
           target_id=result["conversation_id"],
           details={"question": body.message[:200], "incident_id": result["incident_id"], "mode": msg["mode"],
                    "provider": msg["provider"], "tools": [c["tool"] for c in msg["tool_calls"]],
                    "validation_passed": msg["validation"].get("passed")}, request=request)
    return result


@router.get("/conversations")
def conversations(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    rows = db.query(AIConversation).filter_by(workspace_id=ctx.workspace_id, user_id=ctx.user.id)\
        .order_by(AIConversation.updated_at.desc()).limit(50)
    return [{"id": c.id, "title": c.title, "incident_id": c.incident_id, "updated_at": iso(c.updated_at)} for c in rows]


@router.get("/conversations/{conv_id}")
def conversation(conv_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    c = db.query(AIConversation).filter_by(id=conv_id, workspace_id=ctx.workspace_id, user_id=ctx.user.id).first()
    if c is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    msgs = db.query(AIMessage).filter_by(conversation_id=c.id).order_by(AIMessage.id).all()
    return {"id": c.id, "title": c.title, "incident_id": c.incident_id,
            "messages": [assistant.message_payload(m) for m in msgs]}


@router.delete("/conversations/{conv_id}")
def delete_conversation(conv_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    c = db.query(AIConversation).filter_by(id=conv_id, workspace_id=ctx.workspace_id, user_id=ctx.user.id).first()
    if c is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    db.delete(c)
    db.commit()
    return {"ok": True}
