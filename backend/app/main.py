import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import OperationalError

from app import __version__
from app.api.routes import (
    ai,
    auth,
    detections,
    events,
    incidents,
    ingestion,
    insights,
    intel,
    reports,
    system,
    workspaces,
)
from app.core.config import get_settings
from app.database import session as dbs
from app.services.simulation import stop_all

log = logging.getLogger("sentinelx")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI):
    from app.services.workspace import bootstrap_reference_data

    if get_settings().auto_migrate:
        from app.database.migrate import upgrade_to_head

        upgrade_to_head()
    db = dbs.SessionLocal()
    try:
        bootstrap_reference_data(db)
    except OperationalError:
        log.error("Database not ready or not migrated. Run `alembic upgrade head`.")
    finally:
        db.close()
    yield
    stop_all()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="SentinelX AI API",
        version=__version__,
        description="SentinelX AI — Detect. Investigate. Understand. SOC platform API: ingestion, detection, "
                    "correlation, incidents, MITRE ATT&CK, threat intelligence, AI assistant, RAG, reports, audit.",
        lifespan=lifespan,
        docs_url="/api/docs", redoc_url="/api/redoc", openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware, allow_origins=settings.cors_origin_list, allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Workspace-ID", "X-SentinelX-CSRF"],
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex[:12]
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/docs") or request.url.path.startswith("/api/redoc"):
            pass  # Swagger UI needs its own CDN scripts
        elif response.headers.get("content-type", "").startswith("text/html"):
            response.headers.setdefault("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'")
        else:
            response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        if settings.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError):
        errors = [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]), "message": e.get("msg", "invalid")}
                  for e in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": "Validation failed", "errors": errors})

    @app.exception_handler(OperationalError)
    async def db_handler(request: Request, exc: OperationalError):
        log.error("Database error on %s: %s", request.url.path, type(exc).__name__)
        return JSONResponse(status_code=503, content={"detail": "The database is unavailable. Please try again shortly.",
                                                      "request_id": getattr(request.state, "request_id", None)})

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        if isinstance(exc, HTTPException):
            raise exc
        log.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(status_code=500, content={"detail": "Internal server error",
                                                      "request_id": getattr(request.state, "request_id", None)})

    for module in (auth, workspaces, events, ingestion, detections, incidents, intel, ai, reports, insights, system):
        for name in dir(module):
            obj = getattr(module, name)
            if name.endswith("router") and hasattr(obj, "routes"):
                app.include_router(obj)
    return app


app = create_app()
