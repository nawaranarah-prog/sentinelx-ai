# Deployment

## Docker Compose (single host)

```bash
cp .env.example .env
# Required: SECRET_KEY, POSTGRES_PASSWORD. Recommended behind TLS: COOKIE_SECURE=true
docker compose up -d --build
docker compose ps            # all three services should become healthy
```

Services:

| Service | Image | Health check | Notes |
|---|---|---|---|
| `postgres` | postgres:16-alpine | `pg_isready` | data in the `pgdata` volume |
| `backend` | built from `backend/Dockerfile` (python:3.12-slim, non-root) | `GET /api/health/ready` (runs `SELECT 1`) | entrypoint runs `alembic upgrade head`, optionally `python -m app.seed` when `SEED_DEMO=true` |
| `frontend` | built from `frontend/Dockerfile` (nginx:1.27-alpine) | `GET /healthz` | serves the SPA, proxies `/api/` to the backend, sets CSP and security headers |

Only the frontend port (`FRONTEND_PORT`, default 8080) is published; the database and API are reachable only on the Compose network.

### TLS

Put a TLS-terminating proxy (Caddy, Traefik, a cloud load balancer) in front of the frontend container and set `COOKIE_SECURE=true`. The backend runs uvicorn with `--proxy-headers` so client IPs for rate limiting and audit logs come from `X-Forwarded-For`.

### Backups

`docker compose exec postgres pg_dump -U sentinelx sentinelx > backup.sql`

### Upgrades

Pull the new version and `docker compose up -d --build`. Migrations run automatically at backend start. `alembic downgrade -1` is available inside the backend container.

## Vercel (frontend + API in one project)

The repository is Vercel-ready: `vercel.json` builds the SPA into `frontend/dist` and serves the FastAPI app as a Python function (`api/index.py`) under `/api/*` on the same origin.

- Serverless mode is detected from `VERCEL=1`: uploads are processed inside the request (no background tasks), the continuous simulation is replaced by an on-demand "Generate batch" action, and migrations run at cold start (`AUTO_MIGRATE`, guarded by a PostgreSQL advisory lock).
- **A PostgreSQL database is required** for correct behavior. Vercel runs several function instances in parallel; without `DATABASE_URL` each instance falls back to its own temporary SQLite file in `/tmp`, so users and data are not shared between requests. The UI shows a "Temporary storage" warning and System Health reports `EPHEMERAL` in that state.
- Connect Neon (Vercel Marketplace → Neon → connect to the project) or set `DATABASE_URL`/`POSTGRES_URL` manually, then redeploy.
- Set `SECRET_KEY`, `ENVIRONMENT=production`, `COOKIE_SECURE=true`, and optional `LLM_*` in Project → Settings → Environment Variables.

```bash
npm i -g vercel
vercel link
vercel install neon          # accept the Neon marketplace terms when prompted
vercel deploy --prod
```

## Managed platforms

The same two images work on any container platform (Render, Railway, Fly.io, Azure Container Apps, AWS ECS/App Runner, Google Cloud Run) with a managed PostgreSQL:

1. Provision PostgreSQL 14+; set `DATABASE_URL=postgresql+psycopg://user:pass@host:5432/db` (a `postgres://` URL is also accepted and converted).
2. Deploy `backend/` with `SECRET_KEY`, `DATABASE_URL`, `ENVIRONMENT=production`, `COOKIE_SECURE=true`, `CORS_ORIGINS=<frontend origin>` and optional `LLM_*`.
3. Deploy `frontend/` and point its `/api/` proxy at the backend (edit `proxy_pass` in `nginx.conf`), or serve the static build from a CDN and set `VITE_API_BASE` at build time. When the API is on a different origin, cookies become third-party; prefer a same-origin setup (path-based routing) so the SameSite cookie keeps working.

Run a single backend instance (or add Redis-backed rate limiting and a job queue before scaling out; see [architecture.md](architecture.md#scaling-notes)).

## Verification after deploy

```bash
curl -fsS https://<host>/api/health/live
curl -fsS https://<host>/api/health/ready
```

Then in the browser: register → Open Nova Bank demo → open an incident → ask the assistant "What happened?" → generate a report → check the audit log. System Health must show Database `CONNECTED` (PostgreSQL) and the AI provider status that matches your configuration.

## Status of this repository

The project was built and tested locally (backend on SQLite and on a real PostgreSQL 16 server, frontend production build, Playwright E2E). The Docker images and Compose file were written for this layout but could not be built in the development environment because Docker was not installed there; CI builds and tests everything except the images. A Vercel deployment exists (see README for the URL).
