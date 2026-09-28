import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.ai.agent import narrative_for_report
from app.api.deps import AnalystCtx, ReadCtx, WorkspaceContext
from app.api.routes.incidents import get_incident_or_404
from app.api.serializers import iso
from app.audit.service import record
from app.database.session import get_db
from app.models import Report, User
from app.reporting.builder import build_report
from app.reporting.render import to_html, to_markdown, to_pdf
from app.schemas import ReportIn
from app.services.notifications import notify_workspace

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["reports"])


def report_payload(r: Report, author: str | None = None, full: bool = False) -> dict:
    out = {"id": r.id, "incident_id": r.incident_id, "report_type": r.report_type, "title": r.title,
           "ai_mode": r.ai_mode, "created_by": author, "created_at": iso(r.created_at)}
    if full:
        out["content"] = r.content
    return out


@router.post("", status_code=201)
def create_report(body: ReportIn, request: Request, ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    inc = get_incident_or_404(db, ctx, body.incident_id)
    try:
        narrative = (narrative_for_report(db, ctx.workspace, ctx.user.id, inc, body.report_type)
                     if body.include_ai_summary else None)
        content = build_report(db, ctx.workspace, ctx.user.id, inc, body.report_type, narrative)
    except Exception:
        log.exception("Report generation failed for incident %s", inc.id)
        raise HTTPException(status_code=500, detail="Report generation failed. The error was logged.") from None
    ai_mode = "LIVE" if narrative else "NONE"
    rep = Report(workspace_id=ctx.workspace_id, incident_id=inc.id, report_type=body.report_type,
                 title=content["title"], content=content, ai_mode=ai_mode, created_by_id=ctx.user.id)
    db.add(rep)
    db.flush()
    notify_workspace(db, ctx.workspace_id, "report_ready", f"Report ready: {rep.title}",
                     "Includes a model-written narrative." if narrative else "Generated from incident data.",
                     f"/reports/{rep.id}", only_user_id=ctx.user.id)
    db.commit()
    record(db, "GENERATE_REPORT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="report",
           target_id=rep.id, details={"incident": inc.number, "type": body.report_type, "ai_mode": ai_mode},
           request=request)
    return report_payload(rep, ctx.user.email, full=True)


@router.get("")
def list_reports(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db), incident_id: int | None = None):
    q = db.query(Report).filter_by(workspace_id=ctx.workspace_id)
    if incident_id:
        q = q.filter_by(incident_id=incident_id)
    rows = q.order_by(Report.id.desc()).limit(100).all()
    authors = {u.id: u.email for u in db.query(User).filter(User.id.in_({r.created_by_id for r in rows}))}
    return [report_payload(r, authors.get(r.created_by_id)) for r in rows]


def _get(db: Session, ctx: WorkspaceContext, report_id: int) -> Report:
    r = db.query(Report).filter_by(id=report_id, workspace_id=ctx.workspace_id).first()
    if r is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return r


@router.get("/{report_id}")
def get_report(report_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    r = _get(db, ctx, report_id)
    author = db.get(User, r.created_by_id) if r.created_by_id else None
    return report_payload(r, author.email if author else None, full=True)


@router.get("/{report_id}/download")
def download(report_id: int, request: Request, format: str = "pdf", ctx: WorkspaceContext = ReadCtx,
             db: Session = Depends(get_db)):
    r = _get(db, ctx, report_id)
    generated = r.created_at.strftime("%Y-%m-%d %H:%M UTC")
    stem = f"sentinelx_{r.content['incident']['number']}_{r.report_type}_report"
    try:
        if format == "pdf":
            body, media = to_pdf(r.content, generated), "application/pdf"
        elif format == "html":
            body, media = to_html(r.content, generated), "text/html; charset=utf-8"
        elif format == "md":
            body, media = to_markdown(r.content, generated), "text/markdown; charset=utf-8"
        elif format == "json":
            import json
            body, media = json.dumps(r.content, indent=2), "application/json"
        else:
            raise HTTPException(status_code=422, detail="format must be pdf, html, md or json")
    except HTTPException:
        raise
    except Exception:
        log.exception("Report rendering failed")
        raise HTTPException(status_code=500, detail="Report rendering failed. The error was logged.") from None
    record(db, "EXPORT_REPORT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="report", target_id=r.id,
           details={"format": format, "incident": r.content["incident"]["number"]}, request=request)
    disposition = "inline" if format == "html" and request.query_params.get("inline") else "attachment"
    return Response(body, media_type=media, headers={"Content-Disposition": f'{disposition}; filename="{stem}.{format}"'})
