# Architecture

## Components

| Component | Responsibility | Key modules |
|---|---|---|
| SPA (React + TS) | Analyst UI, routing, caching (TanStack Query), charts, command palette | `frontend/src` |
| API (FastAPI) | Auth, tenant resolution, RBAC, validation, OpenAPI at `/api/docs` | `app/api`, `app/schemas` |
| Ingestion | Parse CSV/JSON/NDJSON safely; normalize to the common schema | `app/ingestion/parser.py`, `normalizer.py` |
| Pipeline | Store → detect → anomaly → correlate; per-workspace lock; background jobs | `app/services/pipeline.py` |
| Detection engine | Rule catalogue, rule implementations, persistence with dedupe keys | `app/detection` |
| ML | Statistical baseline + IsolationForest over entity-day windows | `app/ml/anomaly.py` |
| Correlation | Cluster detections → incidents, MITRE aggregation, risk, checklist | `app/correlation/engine.py`, `app/services/risk.py` |
| AI | Providers, read-only toolbox, injection guard, validator, local analyst | `app/ai` |
| RAG | Extraction, chunking, embeddings, retrieval | `app/rag` |
| Reporting | Report content builder + Markdown/HTML/PDF rendering | `app/reporting` |
| Audit | Append-only audit records with secret scrubbing | `app/audit` |

## Multi-tenancy

A **workspace** is the tenant boundary. Users belong to workspaces through **memberships** that carry a **role** (ADMIN, SOC_ANALYST, VIEWER).

- Every tenant-owned table has `workspace_id` (events, detections, incidents, indicators, knowledge chunks, reports, audit logs, notifications, ...).
- The active workspace is sent in the `X-Workspace-ID` header. `get_workspace_context` verifies the membership and returns **404** for workspaces the user does not belong to (same response whether it exists or not).
- Every query filters on `ctx.workspace_id`; object lookups use `filter_by(id=..., workspace_id=...)`, so object IDs from another tenant resolve to 404.
- The AI toolbox is constructed with a workspace id and cannot address other tenants.
- Tests (`tests/test_auth_rbac.py::test_tenant_isolation`, `tests/test_ai.py::test_toolbox_is_workspace_scoped`) exercise these boundaries.

## Data model (main tables)

```
users ─< memberships >─ workspaces ─< roles
workspaces ─< ingestion_jobs ─< events (normalized columns + metadata JSON + raw JSON, unique fingerprint per workspace)
workspaces ─< detection_rules ─< detections ─< detection_events >─ events
workspaces ─< incidents ─< incident_events >─ events          (role: evidence | context)
                        ─< incident_techniques >─ mitre_techniques
                        ─< incident_status_history, investigation_notes, case_assignments
workspaces ─< anomaly_results, hosts, assets, threat_indicators
workspaces ─< knowledge_documents ─< knowledge_chunks (embedding JSON)
workspaces ─< ai_conversations ─< ai_messages
workspaces ─< reports, audit_logs, notifications, saved_searches, bookmarks
revoked_tokens (JWT denylist for logout / password change)
```

Indexes on events: `(workspace_id, timestamp)`, `(workspace_id, user)`, `(workspace_id, host)`, `(workspace_id, source_ip)`, `(workspace_id, destination_ip)`, `(workspace_id, event_type)`, `(workspace_id, severity)`, `(workspace_id, event_uid)`; link tables are indexed on `event_id`; detections on `(workspace_id, timestamp)`, `(workspace_id, incident_id)`, `rule_key`, `severity`, `user`, `host`, `source_ip`.

JSON columns are `JSON` on SQLite and `JSONB` on PostgreSQL (`JSON().with_variant(JSONB(), "postgresql")`).

Migrations live in `backend/alembic/versions`. `alembic check` in CI (on PostgreSQL) and in the test suite (on SQLite) fails if models and migrations drift.

## Request flow for an upload

1. `POST /api/ingest/upload` (SOC_ANALYST+) reads at most `MAX_UPLOAD_MB`, checks the extension, creates an `IngestionJob`, writes an `UPLOAD_DATA` audit record and returns **202**.
2. A background task parses the file as data only (no execution, no formula evaluation), rejects malformed rows with row numbers, and normalizes the rest.
3. Rows are inserted in batches; fingerprints (supplied event id, or SHA-256 of the canonical raw record) make re-uploads idempotent.
4. `run_pipeline` executes detection, anomaly analysis and correlation under a per-workspace lock, updates host/asset inventory, and creates notifications.
5. The job record stores accepted/rejected/duplicate counts, detections created, incidents created/updated, and errors; the UI polls it every second.

## Frontend structure

- `lib/session.tsx` – current user, active workspace, role, login/logout, theme.
- `lib/api.ts` – fetch wrapper (same-origin cookies, `X-SentinelX-CSRF`, `X-Workspace-ID`, typed errors).
- `lib/hooks.ts` – `useWsQuery` includes the workspace id in every cache key so switching tenants never shows stale data.
- `components/` – layout, command palette, charts, attack graph, AI chat, event panel, primitives.
- `pages/` – one module per screen, lazy-loaded.

## Scaling notes

The design targets a single-node deployment with up to hundreds of thousands of events per workspace. For larger volumes: move the pipeline into a job queue (RQ/Celery/Arq), run rules incrementally over time windows rather than over all stored events, keep the rate limiter and simulation state in Redis, and use pgvector for embeddings.
