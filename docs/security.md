# Security design

## Authentication

- Passwords: bcrypt (cost 12) over a SHA-256 pre-hash (so passphrases longer than bcrypt's 72-byte limit stay fully significant). Policy: ≥10 characters with a letter and a digit, ≤256.
- Login does a dummy hash when the account does not exist to reduce timing-based user enumeration; the error message is identical for unknown email and wrong password.
- Sessions: HS256 JWT (`sub`, `jti`, `iat`, `exp`, `iss`) valid for `ACCESS_TOKEN_EXPIRE_MINUTES`.
  - Browser: httpOnly, `SameSite=Lax` cookie (`Secure` when `COOKIE_SECURE=true`). Any cookie-authenticated state-changing request must carry `X-SentinelX-CSRF: 1`, which cross-site forms cannot set.
  - API clients: `Authorization: Bearer <token>`.
- Logout stores the token's `jti` in `revoked_tokens` (expired entries are purged). Changing the password revokes the current token and invalidates every token issued before the change.
- The app refuses to start in `ENVIRONMENT=production` with the default `SECRET_KEY`.

## Authorization

- RBAC per workspace membership: ADMIN, SOC_ANALYST, VIEWER. Route dependencies (`ReadCtx`, `AnalystCtx`, `AdminCtx`) enforce it on the server for every endpoint; the UI only hides what the server would refuse.
- Tenant isolation: see [architecture.md](architecture.md#multi-tenancy). Cross-tenant access returns 404.
- A workspace cannot lose its last ADMIN; viewers cannot own incidents.

## Input handling

- Uploads: size limit (`MAX_UPLOAD_MB`) enforced while reading, row limit (`MAX_UPLOAD_ROWS`), extension allow-list, binary-content rejection, strict JSON/CSV parsing. Files are parsed as data only and never executed; spreadsheet formulas are not evaluated. Original filenames are reduced to their basename.
- Knowledge documents: `.md/.txt/.pdf` only, 10 MB, encrypted PDFs rejected. Indicator imports: 2 MB, 10,000 rows.
- Every request body is a Pydantic model with length and range limits; rule-parameter updates are validated against the default parameter types.
- Validation errors return field-level messages; unhandled exceptions return `{"detail": "Internal server error", "request_id": ...}` without stack traces (they are logged server-side). Database outages return 503.

## Transport and browser hardening

- API responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, restrictive CSP (`default-src 'none'`), HSTS when `COOKIE_SECURE=true`, `X-Request-ID`.
- nginx (Docker): CSP `default-src 'self'; script-src 'self'` (no inline scripts — the theme bootstrap is a static file), `frame-ancestors 'none'`, same headers as above.
- Reports are shown in a sandboxed `iframe` (`srcdoc`, no `allow-scripts`); report HTML escapes all incident data and contains no script.
- AI answers are rendered with `react-markdown` with raw HTML disabled.
- CORS is limited to `CORS_ORIGINS`; the default deployment is same-origin so CORS is not needed at all.

## Abuse controls

- Sliding-window rate limits: auth endpoints per IP, AI chat per user, uploads per user (`RATE_LIMIT_*`). State is in-process (single instance); use Redis for multiple instances.
- AI: bounded tool rounds, per-request timeout, context size cap, message length cap (4,000 characters).

## Audit logging

`audit_logs` records LOGIN, LOGIN_FAILED, LOGOUT, REGISTER, CHANGE_PASSWORD, VIEW_INCIDENT, VIEW_EVENT, QUERY_AI, UPLOAD_DATA, UPLOAD_DOCUMENT, DELETE_DOCUMENT, GENERATE_REPORT, EXPORT_REPORT, CHANGE_RULE, CHANGE_ROLE, ADD_MEMBER, REMOVE_MEMBER, CHANGE_SETTINGS, CHANGE_INCIDENT_STATUS, ASSIGN_INCIDENT, ADD_NOTE, UPDATE_INCIDENT, PROMOTE_DETECTION, ADD_INDICATOR, IMPORT_INDICATORS, LOAD_DEMO, START/PAUSE/RESET_SIMULATION, TEST_AI_PROVIDER, CHANGE_ASSET — with user, target, IP, user agent and details. Details pass through `scrub()`, which redacts keys containing password, secret, token, api key, authorization, cookie or credential; a test asserts that no password appears in stored audit data. Admins can filter and export the log as CSV.

## AI-specific controls

See [ai.md](ai.md): trust-separated prompts, escaping, injection detection, read-only workspace-scoped tools, output validation, honest mode labelling.

## Secrets

- No secrets in the repository; `.env` is git-ignored and `.env.example` contains placeholders only.
- `/api/system/config` reports secrets only as "configured (hidden)" / "not set"; a test checks the secret value never appears.
- The LLM key is read from the environment and never sent to the browser or stored in the database.

## Automated checks

CI runs `ruff`, `bandit -ll` (no medium/high findings at the time of writing), `pip-audit` and `npm audit --audit-level=high` (no known vulnerabilities at the time of writing), plus the RBAC/isolation/injection tests.

## Known limitations

- Single-instance rate limiting and simulation state.
- No MFA or SSO (would be the next step for a real deployment).
- JWT secret rotation requires a restart and invalidates all sessions.
