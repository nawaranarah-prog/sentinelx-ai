from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai import agent, tools
from app.ai.providers import provider_status
from app.api.deps import AdminCtx, AnalystCtx, ReadCtx, WorkspaceContext
from app.api.serializers import iso
from app.audit.service import record
from app.core import ratelimit
from app.core.config import get_settings
from app.database.session import get_db
from app.models import AIConversation, AIError, AIMessage

router = APIRouter(prefix="/api/ai", tags=["AI copilot"])

SUGGESTIONS = {
    "ask": ["What happened today?", "What are the most serious incidents?", "Which user is behaving strangely?",
            "Which entities have the biggest risk increase?", "Which incidents are still unresolved?",
            "What changed in the environment today?"],
    "investigate": ["Investigate the highest-risk incident", "Is this account compromised?", "What evidence supports this incident?",
                    "What evidence contradicts it?", "What don't we know?", "What should I investigate next?"],
    "hunt": ["Find unusual authentication from new locations involving privileged accounts",
             "Find privileged accounts logging in outside normal hours", "Find rare outbound connections from servers",
             "Find PowerShell activity followed by internal connections", "Find large uploads to external destinations"],
    "explain": ["Why did this fire?", "What does this event mean?", "Why is this unusual?", "Summarize this entity",
                "Explain this attack path", "What does T1059.001 mean in this incident?"],
    "compare": ["Have we seen this attack before?", "Compare it with the previous incident", "Which attack families exist?"],
    "report": ["Generate an incident report", "Write an executive summary", "Generate a technical investigation report"],
    "simulate": ["Simulate a low-and-slow brute force", "What happens if I add MFA?", "Which rules miss attack variations?",
                 "Remove the brute-force detection and recompute the risk"],
}


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: int | None = None
    mode: str = "ask"
    context: list[str] = Field(default_factory=list, max_length=10)
    investigation: str | None = None


@router.get("/status")
def status(ctx: WorkspaceContext = ReadCtx):
    return provider_status()


@router.post("/test")
def test_provider(request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    st = provider_status(probe=True)
    record(db, "TEST_AI_PROVIDER", user=ctx.user, workspace_id=ctx.workspace_id, target_type="ai_provider",
           target_id=st.get("provider") or "none", details={"status": st["status"]}, request=request)
    return st


@router.get("/errors")
def errors(ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    rows = db.query(AIError).filter_by(workspace_id=ctx.workspace_id).order_by(AIError.id.desc()).limit(25)
    return [{"reference": e.reference, "provider": e.provider, "model": e.model, "category": e.category,
             "detail": e.detail[:600], "at": iso(e.created_at)} for e in rows]


@router.get("/suggestions")
def suggestions(mode: str = "ask", ctx: WorkspaceContext = ReadCtx):
    return {"suggestions": SUGGESTIONS.get(mode, SUGGESTIONS["ask"]), "modes": list(agent.MODES)}


@router.get("/tools")
def list_tools(ctx: WorkspaceContext = ReadCtx):
    tctx = tools.ToolContext(db=None, workspace=ctx.workspace, user_id=ctx.user.id, role=ctx.role)  # type: ignore[arg-type]
    return [{"name": t["name"], "description": t["description"]} for t in tools.specs_for(tctx)]


@router.post("/chat")
def chat(body: ChatIn, request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    ratelimit.enforce(request, "ai", get_settings().rate_limit_ai_per_minute, str(ctx.user.id))
    if body.mode not in agent.MODES:
        raise HTTPException(status_code=422, detail=f"mode must be one of {', '.join(agent.MODES)}")
    result = agent.run_turn(db, ctx, body.message, body.conversation_id, body.mode, body.context, body.investigation)
    msg = result["message"]
    record(db, "QUERY_AI", user=ctx.user, workspace_id=ctx.workspace_id, target_type="ai_conversation",
           target_id=result["conversation"]["id"],
           details={"question": body.message[:200], "mode": body.mode, "answer_mode": msg["mode"], "model": msg["model"],
                    "tools": [a["tool"] for a in msg["activity"]], "citations_verified": msg["validation"].get("verified_citations"),
                    "citations_removed": len(msg["validation"].get("invalid_citations", [])), "error_ref": msg["error_ref"]},
           request=request)
    return result


@router.get("/conversations")
def conversations(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    rows = db.query(AIConversation).filter_by(workspace_id=ctx.workspace_id, user_id=ctx.user.id)\
        .order_by(AIConversation.updated_at.desc()).limit(50)
    return [agent.conversation_payload(c) for c in rows]


@router.get("/conversations/{conv_id}")
def conversation(conv_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    c = db.query(AIConversation).filter_by(id=conv_id, workspace_id=ctx.workspace_id, user_id=ctx.user.id).first()
    if c is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    msgs = db.query(AIMessage).filter_by(conversation_id=c.id).order_by(AIMessage.id).all()
    return {**agent.conversation_payload(c), "messages": [agent.message_payload(m) for m in msgs]}


@router.delete("/conversations/{conv_id}")
def delete_conversation(conv_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    c = db.query(AIConversation).filter_by(id=conv_id, workspace_id=ctx.workspace_id, user_id=ctx.user.id).first()
    if c is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    db.delete(c)
    db.commit()
    return {"ok": True}
