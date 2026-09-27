from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import AdminCtx, AnalystCtx, ReadCtx, WorkspaceContext
from app.api.serializers import detection_brief, incident_brief, technique_info
from app.audit.service import record
from app.database.session import get_db, utcnow
from app.mitre.catalog import TACTIC_ORDER, TECHNIQUE_INDEX
from app.models import Detection, Incident, IncidentTechnique, KnowledgeChunk, KnowledgeDocument, ThreatIndicator
from app.rag import service as rag
from app.rag.embedding import EMBEDDING_NAME
from app.schemas import IndicatorIn
from app.services.pipeline import run_pipeline, workspace_lock
from app.threat_intel import service as ti

mitre_router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK"])
intel_router = APIRouter(prefix="/api/intel", tags=["threat intelligence"])
kb_router = APIRouter(prefix="/api/knowledge", tags=["knowledge base (RAG)"])


# ------------------------------------------------------------------------------------------- MITRE
@mitre_router.get("/techniques")
def techniques(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    inc_counts = dict(db.execute(
        select(IncidentTechnique.technique_id, func.count(IncidentTechnique.id))
        .join(Incident, Incident.id == IncidentTechnique.incident_id)
        .where(Incident.workspace_id == ctx.workspace_id).group_by(IncidentTechnique.technique_id)).all())
    det_counts: dict[str, int] = {}
    for (mitre,) in db.execute(select(Detection.mitre).where(Detection.workspace_id == ctx.workspace_id)):
        for m in mitre or []:
            det_counts[m["id"]] = det_counts.get(m["id"], 0) + 1
    items = [{**info, "incident_count": inc_counts.get(tid, 0), "detection_count": det_counts.get(tid, 0)}
             for tid, info in TECHNIQUE_INDEX.items()]
    return {"tactics": TACTIC_ORDER, "techniques": items,
            "note": "Catalogue limited to techniques SentinelX rules can map. Source: MITRE ATT&CK Enterprise."}


@mitre_router.get("/techniques/{tid}")
def technique(tid: str, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    if tid not in TECHNIQUE_INDEX:
        raise HTTPException(status_code=404, detail="Technique not in the SentinelX catalogue")
    rows = db.query(IncidentTechnique, Incident).join(Incident, Incident.id == IncidentTechnique.incident_id).filter(
        Incident.workspace_id == ctx.workspace_id, IncidentTechnique.technique_id == tid).all()
    dets = [d for d in db.query(Detection).filter(Detection.workspace_id == ctx.workspace_id)
            if any(m["id"] == tid for m in d.mitre or [])]
    return {**technique_info(tid),
            "incidents": [{**incident_brief(i), "reason": t.reason, "event_uids": t.event_uids} for t, i in rows],
            "detections": [detection_brief(d) for d in dets[:100]]}


# ----------------------------------------------------------------------------------- threat intel
@intel_router.get("/providers")
def providers(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    synth = db.query(ThreatIndicator).filter_by(workspace_id=ctx.workspace_id, is_synthetic=True).count()
    local = db.query(ThreatIndicator).filter_by(workspace_id=ctx.workspace_id, is_synthetic=False).count()
    return [
        {"name": "SentinelX Synthetic Demo Feed", "status": "CONNECTED" if synth else "NOT CONFIGURED",
         "indicators": synth, "label": "SYNTHETIC / DEMO INTELLIGENCE",
         "detail": "Fictional indicators seeded for the Nova Bank demo. Not from any real provider."},
        {"name": "Workspace indicators (analyst-managed)", "status": "CONNECTED", "indicators": local,
         "label": "LOCAL", "detail": "Indicators added manually or imported by analysts."},
        {"name": "External threat-intelligence providers", "status": "NOT CONFIGURED", "indicators": 0,
         "label": "NOT CONFIGURED", "detail": "No external provider integration is configured in this deployment."},
    ]


@intel_router.get("/search")
def search(q: str = Query(min_length=1, max_length=255), ctx: WorkspaceContext = ReadCtx,
           db: Session = Depends(get_db)):
    return ti.search(db, ctx.workspace_id, q)


@intel_router.get("/indicators")
def list_indicators(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db), indicator_type: str | None = None,
                    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)):
    query = db.query(ThreatIndicator).filter_by(workspace_id=ctx.workspace_id)
    if indicator_type:
        query = query.filter_by(indicator_type=indicator_type)
    total = query.count()
    rows = query.order_by(ThreatIndicator.id.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [ti.indicator_payload(i) for i in rows], "total": total, "page": page, "page_size": page_size}


def _upsert_indicator(db: Session, ws_id: int, user_id: int, data: dict) -> ThreatIndicator | None:
    value = str(data.get("value", "")).strip()[:255]
    if not value:
        return None
    itype = data.get("indicator_type") or data.get("type") or ti.detect_type(value)
    if itype not in ("ip", "domain", "hash", "hostname", "username"):
        return None
    value = ti.normalize_value(value, itype)
    existing = db.query(ThreatIndicator).filter_by(workspace_id=ws_id, indicator_type=itype, value=value).first()
    now = utcnow()
    try:
        conf = min(1.0, max(0.0, float(data.get("confidence", 0.7))))
    except (TypeError, ValueError):
        conf = 0.7
    sev = data.get("severity") if data.get("severity") in ("low", "medium", "high", "critical") else "medium"
    if existing:
        existing.confidence, existing.severity, existing.last_seen, existing.active = conf, sev, now, True
        return existing
    ind = ThreatIndicator(workspace_id=ws_id, value=value, indicator_type=itype,
                          source=str(data.get("source") or "Analyst import")[:120], is_synthetic=False,
                          confidence=conf, severity=sev, description=str(data.get("description") or "")[:2000],
                          tags=[str(t)[:40] for t in (data.get("tags") or [])][:20] if isinstance(data.get("tags"), list) else [],
                          first_seen=now, last_seen=now, created_by_id=user_id)
    db.add(ind)
    return ind


def _rehunt(db: Session, ctx: WorkspaceContext) -> dict:
    with workspace_lock(ctx.workspace_id):
        stats = run_pipeline(db, ctx.workspace)
        db.commit()
    return {"detections_created": stats["detections_created"], "incidents_created": stats["incidents_created"]}


@intel_router.post("/indicators", status_code=201)
def add_indicator(body: IndicatorIn, request: Request, ctx: WorkspaceContext = AnalystCtx,
                  db: Session = Depends(get_db)):
    ind = _upsert_indicator(db, ctx.workspace_id, ctx.user.id, body.model_dump())
    if ind is None:
        raise HTTPException(status_code=422, detail="Invalid indicator")
    db.commit()
    record(db, "ADD_INDICATOR", user=ctx.user, workspace_id=ctx.workspace_id, target_type="indicator",
           target_id=ind.id, details={"value": ind.value, "type": ind.indicator_type}, request=request)
    return {"indicator": ti.indicator_payload(ind), "retro_hunt": _rehunt(db, ctx)}


@intel_router.post("/indicators/import", status_code=201)
def import_indicators(request: Request, file: UploadFile = File(...), ctx: WorkspaceContext = AnalystCtx,
                      db: Session = Depends(get_db)):
    content = file.file.read(2 * 1024 * 1024 + 1)
    if len(content) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Indicator files are limited to 2 MB")
    try:
        items = ti.parse_indicator_file(file.filename or "", content)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail=f"Could not parse indicator file: {exc}") from None
    added = sum(1 for item in items[:10_000] if _upsert_indicator(db, ctx.workspace_id, ctx.user.id, item))
    db.commit()
    record(db, "IMPORT_INDICATORS", user=ctx.user, workspace_id=ctx.workspace_id, target_type="indicator",
           target_id="bulk", details={"filename": file.filename, "imported": added, "rows": len(items)}, request=request)
    return {"imported": added, "rows": len(items), "retro_hunt": _rehunt(db, ctx)}


@intel_router.delete("/indicators/{indicator_id}")
def deactivate_indicator(indicator_id: int, request: Request, ctx: WorkspaceContext = AnalystCtx,
                         db: Session = Depends(get_db)):
    ind = db.query(ThreatIndicator).filter_by(id=indicator_id, workspace_id=ctx.workspace_id).first()
    if ind is None:
        raise HTTPException(status_code=404, detail="Indicator not found")
    ind.active = False
    db.commit()
    record(db, "ADD_INDICATOR", user=ctx.user, workspace_id=ctx.workspace_id, target_type="indicator",
           target_id=ind.id, details={"deactivated": ind.value}, request=request)
    return ti.indicator_payload(ind)


# ------------------------------------------------------------------------------------ knowledge base
def doc_payload(d: KnowledgeDocument) -> dict:
    return {"id": d.id, "title": d.title, "filename": d.filename, "content_type": d.content_type,
            "category": d.category, "origin": d.origin, "char_count": d.char_count, "chunk_count": d.chunk_count,
            "created_at": d.created_at.isoformat() + "Z"}


@kb_router.get("/documents")
def list_documents(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    docs = db.query(KnowledgeDocument).filter_by(workspace_id=ctx.workspace_id).order_by(KnowledgeDocument.id).all()
    return {"documents": [doc_payload(d) for d in docs], "embedding": EMBEDDING_NAME,
            "vector_store": "Embeddings stored per chunk in the relational database; cosine similarity computed "
                            "in the application (see docs/ai.md)."}


@kb_router.get("/documents/{doc_id}")
def get_document(doc_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    d = db.query(KnowledgeDocument).filter_by(id=doc_id, workspace_id=ctx.workspace_id).first()
    if d is None:
        raise HTTPException(status_code=404, detail="Document not found")
    chunks = db.query(KnowledgeChunk).filter_by(document_id=d.id).order_by(KnowledgeChunk.ordinal).all()
    return {**doc_payload(d), "chunks": [{"id": c.id, "ordinal": c.ordinal, "heading": c.heading,
                                          "content": c.content} for c in chunks]}


@kb_router.post("/documents", status_code=201)
def upload_document(request: Request, file: UploadFile = File(...), ctx: WorkspaceContext = AdminCtx,
                    db: Session = Depends(get_db)):
    content = file.file.read(10 * 1024 * 1024 + 1)
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Documents are limited to 10 MB")
    name = (file.filename or "document.txt").replace("\\", "/").split("/")[-1][:255]
    try:
        text, ctype = rag.extract_text(name, content)
    except rag.DocumentRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    title = text.splitlines()[0].lstrip("# ").strip()[:200] if text.splitlines()[0].startswith("#") else name.rsplit(".", 1)[0]
    doc = rag.index_document(db, ctx.workspace_id, title, name, text, ctype, category="uploaded", user_id=ctx.user.id)
    db.commit()
    record(db, "UPLOAD_DOCUMENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="document",
           target_id=doc.id, details={"filename": name, "chunks": doc.chunk_count}, request=request)
    return doc_payload(doc)


@kb_router.delete("/documents/{doc_id}")
def delete_document(doc_id: int, request: Request, ctx: WorkspaceContext = AdminCtx, db: Session = Depends(get_db)):
    d = db.query(KnowledgeDocument).filter_by(id=doc_id, workspace_id=ctx.workspace_id).first()
    if d is None:
        raise HTTPException(status_code=404, detail="Document not found")
    db.query(KnowledgeChunk).filter_by(document_id=d.id).delete()
    db.delete(d)
    db.commit()
    record(db, "DELETE_DOCUMENT", user=ctx.user, workspace_id=ctx.workspace_id, target_type="document",
           target_id=doc_id, details={"title": d.title}, request=request)
    return {"ok": True}


@kb_router.get("/search")
def kb_search(q: str = Query(min_length=1, max_length=500), k: int = Query(5, ge=1, le=20),
              ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    return {"query": q, "results": rag.search(db, ctx.workspace_id, q, k), "embedding": EMBEDDING_NAME}
