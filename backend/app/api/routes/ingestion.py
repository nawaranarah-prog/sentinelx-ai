from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy.orm import Session

from app.api.deps import AnalystCtx, ReadCtx, WorkspaceContext
from app.api.serializers import iso
from app.audit.service import record
from app.core import ratelimit
from app.core.config import get_settings
from app.database.session import get_db
from app.demo.generator import DATASETS, dataset_records, to_csv, to_json
from app.ingestion.normalizer import FIELD_ALIASES, WINDOWS_EVENT_CODES
from app.ingestion.parser import FileRejected, detect_format, parse_upload
from app.models import IngestionJob
from app.services.pipeline import process_ingestion_job

router = APIRouter(prefix="/api/ingest", tags=["ingestion"])

FIELD_DOCS = {
    "event_id": ("string", "Unique ID from the source system. Used for de-duplication; generated if absent."),
    "timestamp": ("datetime", "REQUIRED. ISO 8601, 'YYYY-MM-DD HH:MM:SS', or epoch seconds/milliseconds. Stored as UTC."),
    "event_type": ("enum", "authentication | process | file | network | privilege | other. Inferred when missing."),
    "user": ("string", "Account name. DOMAIN\\user is split; stored lower-case."),
    "source_ip": ("ip", "Originating IP address (IPv4/IPv6). Invalid values are dropped with a warning."),
    "destination_ip": ("ip", "Destination IP address."),
    "host": ("string", "Hostname where the event occurred. Stored upper-case."),
    "process": ("string", "Process image name, e.g. powershell.exe."),
    "command": ("string", "Full command line or script block text."),
    "action": ("string", "What happened: login, logout, process_start, file_read, group_add, upload..."),
    "status": ("enum", "success | failure (synonyms such as failed, denied, ok, allowed are normalized)."),
    "severity": ("enum", "info | low | medium | high | critical (numeric 0-10 and syslog words accepted)."),
    "bytes": ("integer", "Bytes transferred outbound. Accepts suffixes like 1.5MB."),
    "resource": ("string", "File path, share, URL, domain or group name the action targeted."),
    "source": ("string", "Log source / product name."),
    "metadata": ("object", "Every unmapped field is preserved in metadata; the raw original row is also stored."),
}


def _read_limited(upload: UploadFile) -> bytes:
    limit = get_settings().max_upload_mb * 1024 * 1024
    data = upload.file.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds the {get_settings().max_upload_mb} MB upload limit.")
    return data


def job_payload(j: IngestionJob) -> dict:
    return {
        "id": j.id, "filename": j.filename, "file_format": j.file_format, "status": j.status, "stage": j.stage,
        "total_rows": j.total_rows, "processed_rows": j.processed_rows, "accepted_rows": j.accepted_rows,
        "rejected_rows": j.rejected_rows, "duplicate_rows": j.duplicate_rows, "errors": j.errors or [],
        "warnings": j.warnings or [], "field_mapping": j.field_mapping or {},
        "detections_created": j.detections_created, "incidents_created": j.incidents_created,
        "incidents_updated": j.incidents_updated, "anomalies_flagged": j.anomalies_flagged,
        "error_message": j.error_message, "created_at": iso(j.created_at), "started_at": iso(j.started_at),
        "finished_at": iso(j.finished_at), "created_by_id": j.created_by_id,
    }


@router.get("/schema")
def schema():
    return {
        "fields": [{"name": k, "type": v[0], "description": v[1], "aliases": FIELD_ALIASES.get(k, [])}
                   for k, v in FIELD_DOCS.items()],
        "windows_event_codes": {str(k): v for k, v in WINDOWS_EVENT_CODES.items()},
        "formats": ["CSV (header row required; , ; tab or | delimited)", "JSON array or {\"events\": [...]}",
                    "NDJSON / JSON Lines (.ndjson, .jsonl)", "Nested JSON objects are flattened (e.g. ECS source.ip)"],
        "limits": {"max_upload_mb": get_settings().max_upload_mb, "max_rows": get_settings().max_upload_rows},
    }


@router.get("/schema.md", response_class=PlainTextResponse)
def schema_markdown():
    lines = ["# SentinelX Event Schema", "", "| Field | Type | Description | Accepted aliases |", "|---|---|---|---|"]
    for k, (t, d) in FIELD_DOCS.items():
        lines.append(f"| {k} | {t} | {d} | {', '.join(FIELD_ALIASES.get(k, []))} |")
    lines += ["", "## Windows Security event codes understood", ""]
    for code, info in WINDOWS_EVENT_CODES.items():
        lines.append(f"- {code}: {info}")
    return PlainTextResponse("\n".join(lines), headers={"Content-Disposition": 'attachment; filename="sentinelx_event_schema.md"'})


@router.get("/samples")
def samples():
    return [{"name": k, "description": v["description"], "scenarios": v["scenarios"],
             "synthetic": True} for k, v in DATASETS.items()]


@router.get("/samples/{name}.{fmt}")
def sample_file(name: str, fmt: str):
    if name not in DATASETS or fmt not in ("csv", "json"):
        raise HTTPException(status_code=404, detail="Unknown sample dataset")
    recs = dataset_records(name)
    aliases = name == "mixed"
    body = to_csv(recs, aliases) if fmt == "csv" else to_json(recs, aliases)
    media = "text/csv" if fmt == "csv" else "application/json"
    return Response(body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="sentinelx_sample_{name}.{fmt}"'})


@router.post("/preview")
def preview(request: Request, file: UploadFile = File(...), ctx: WorkspaceContext = AnalystCtx):
    ratelimit.enforce(request, "upload", get_settings().rate_limit_upload_per_minute * 3, str(ctx.user.id))
    content = _read_limited(file)
    try:
        parsed = parse_upload(file.filename or "", content, get_settings().max_upload_rows)
    except FileRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    sample = []
    for r in parsed.rows[:10]:
        f = dict(r.fields)
        f["timestamp"] = f["timestamp"].isoformat() + "Z"
        sample.append(f)
    return {"filename": file.filename, "file_format": parsed.file_format, "columns": parsed.columns,
            "field_mapping": parsed.field_mapping,
            "unmapped_columns": [c for c in parsed.columns if c not in parsed.field_mapping],
            "total_rows": parsed.total_rows, "valid_rows": len(parsed.rows), "rejected_rows": parsed.rejected,
            "duplicates_in_file": parsed.duplicates_in_file, "warning_count": parsed.warning_count,
            "errors": parsed.errors[:50], "warnings": parsed.warnings[:50], "sample": sample}


@router.post("/upload", status_code=202)
def upload(request: Request, background: BackgroundTasks, file: UploadFile = File(...),
           ctx: WorkspaceContext = AnalystCtx, db: Session = Depends(get_db)):
    ratelimit.enforce(request, "upload", get_settings().rate_limit_upload_per_minute, str(ctx.user.id))
    content = _read_limited(file)
    filename = (file.filename or "upload").replace("\\", "/").split("/")[-1][:255]
    try:
        fmt = detect_format(filename, content)
    except FileRejected as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    job = IngestionJob(workspace_id=ctx.workspace_id, created_by_id=ctx.user.id, filename=filename, file_format=fmt,
                       status="QUEUED", stage="QUEUED")
    db.add(job)
    db.commit()
    record(db, "UPLOAD_DATA", user=ctx.user, workspace_id=ctx.workspace_id, target_type="ingestion_job",
           target_id=job.id, details={"filename": filename, "bytes": len(content)}, request=request)
    background.add_task(process_ingestion_job, job.id, filename, content)
    return job_payload(job)


@router.get("/jobs")
def list_jobs(ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    jobs = db.query(IngestionJob).filter_by(workspace_id=ctx.workspace_id).order_by(IngestionJob.id.desc()).limit(50)
    return [job_payload(j) for j in jobs]


@router.get("/jobs/{job_id}")
def get_job(job_id: int, ctx: WorkspaceContext = ReadCtx, db: Session = Depends(get_db)):
    job = db.query(IngestionJob).filter_by(id=job_id, workspace_id=ctx.workspace_id).first()
    if job is None:
        raise HTTPException(status_code=404, detail="Ingestion job not found")
    return job_payload(job)
