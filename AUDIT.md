# NetAudit – Full Audit

Scope: backend (FastAPI/Celery), agent, Docker/nginx, frontend (read for auth handling only).
Method: manual code review. **Tests were not run** (no Python on this machine) and no dependency scanner was run (no lockfile for the frontend; no network scan of pins). Line refs are approximate to the files named.

## Critical

| # | Issue | Where | Fix |
|---|-------|-------|-----|
| C1 | **Postgres and Redis published on `0.0.0.0`** with fallback passwords `changeme`. Anyone on the LAN can read/modify the DB or queue Celery tasks. Published only because the host-network worker connects via 127.0.0.1. | `docker-compose.yml` db/redis `ports` | Bind `127.0.0.1:5432:5432` / `127.0.0.1:6379:6379`; remove `:-changeme` defaults and make compose fail if unset (`${VAR:?}`). |
| C2 | **Insecure secret defaults.** `SECRET_KEY` falls back to `change-this-secret-key-in-production` and `ENCRYPTION_KEY` to a fixed 32-char string. If `.env` is missing/copied unedited, JWTs can be forged (instant admin) and stored API keys/LDAP password decrypted. No startup check rejects placeholder values. | `docker-compose.yml`, `core/config.py` | `${SECRET_KEY:?}` in compose; validator in `Settings` rejecting placeholders/short keys in production. |
| C3 | **Any logged-in user can tamper with any device's findings.** `/api/agent/*` only checks the token's org, not that the scan/device belongs to the token. An end user (open registration → `/api/user/agent-token`) can POST results for any scan in the org; `process_agent_results` then **deletes all findings** for `scan.target`'s device and writes attacker-supplied ones (hide malware, fabricate findings). Replays accepted: scan status is never checked. | `routes/agent.py` `upload_results`, `tasks/scan_tasks.py` `_process_agent_results_async` | Bind agent token → device; require scan `RUNNING`, owned by that device, one-shot; don't wipe findings from unauthenticated-to-device data. |
| C4 | **Open self-registration.** After the first user, anyone reaching the API becomes an `END_USER` in the org, which (with C3, C5) is more than harmless. The first request on a fresh install becomes IT admin (and concurrent first requests can create two orgs). | `routes/auth.py` `register` | Disable after bootstrap or require invite/admin approval; use `create_admin` script for bootstrap. |

## High

| # | Issue | Where | Fix |
|---|-------|-------|-----|
| H1 | **Scan target validation is weak.** (a) `10.0.0.0/0` passes (only the base IP is checked) → scans the whole internet; (b) any non-IP string is accepted as "hostname", including public hosts and values starting with `-` (nmap option injection, e.g. `-oN/path`); (c) `is_private` also allows loopback/link-local. | `schemas.StartScanRequest.validate_target` | Parse with `ipaddress.ip_network(strict=False)`, enforce prefix ≥ /16 and RFC1918 membership; reject leading `-`; allowlist hostnames or resolve+check. |
| H2 | **Scheduled scans have no target validation at all.** `CreateScheduledScanRequest.target` is a bare `str`, so a writer can schedule recurring scans of any external host or inject nmap options. | `schemas.CreateScheduledScanRequest`, `routes/schedules.py` | Reuse the same validator. |
| H3 | **Packet-capture authorization gaps.** WS `/ws/capture/{id}` checks only that the JWT is a valid access token – **no role or org check** (an `END_USER` can stream packets if they know a session id). `stop`/`status`/`export` don't check that the session belongs to the caller's org (info already stored as `org_id`, never compared). `interface` and `bpf_filter` are unvalidated; capture needs host-net + root + `promisc`. Captures can contain credentials in clear text; capture is `get_current_it_user` (viewer role) rather than writer/admin. | `routes/capture.py`, `tasks/capture_tasks.py` | Require writer/admin; compare `info.org_id`; validate interface against registered list; validate BPF; load user from DB in WS. |
| H4 | **No TLS.** nginx listens on 80 only (443 is mapped but nothing listens; certs mount unused). JWTs, passwords and agent tokens go in clear text; `request.base_url` in agent download yields `http://` URLs; agent doesn't refuse `http://`. No HSTS. | `docker/nginx/nginx.conf` | Add `listen 443 ssl` + redirect; HSTS; agent should reject non-https URLs. |
| H5 | **JWT leaks into logs.** WS auth uses `?token=<JWT>` and nginx's `log_format` logs `$request` (includes query string). | `nginx.conf`, `routes/ws.py`, `capture.py` | Log `$uri` only, or authenticate WS via first message / short-lived ticket. |
| H6 | **Rate limiting is ineffective.** `get_remote_address` behind nginx sees only nginx's IP (uvicorn isn't run with `--proxy-headers`), so all users share one bucket (a login brute-force or one noisy user locks out everyone) and limits are per-process in memory (2 workers). No lockout/backoff on password guessing. | `core/limiter.py`, `Dockerfile` CMD | Redis storage URI, trusted-proxy real-IP key, per-account throttling. |
| H7 | **Containers run as root with extra caps.** Backend image has no `USER`; `api` and `worker` get `NET_ADMIN`+`NET_RAW`, worker also on host network. API doesn't need these caps. | `backend/Dockerfile`, compose | Non-root user; drop caps from `api`; keep minimal on `worker`. |
| H8 | **Agent job types don't match server (functional bug).** Server dispatches `scan_type.value` (`virus`, `port_scan`, `full_device`); agent only handles `virus_scan` / `system_audit` and otherwise logs "unknown_job_type" and returns. The scan was already set `RUNNING`, so end-user scans hang forever. | `routes/agent.py` vs `agent/agent.py execute_job` | Align type names; set RUNNING only on ack; add timeout/reaper. |
| H9 | **PDF markup injection.** Titles/descriptions/hostnames (derived from nmap banners or agent data) go into reportlab `Paragraph()` unescaped; reportlab markup supports `<img src=…>`/`<a>`, enabling local-file/URL fetching or broken reports. | `services/pdf_report.py` | `xml.sax.saxutils.escape` on all dynamic text. |

## Medium

- **LDAP filter injection**: `user_filter_template.format(username=username)` with no `escape_filter_chars` (`ldap_service.py`, both `authenticate` and likely `search_users`). Also `tls_verify=false` option and non-TLS default path with `use_tls` False.
- **Gemini API key in URL** (`?key=`): httpx exceptions include the URL; `/settings/test-ai` returns `str(e)` to the client and logs may too → key leak.
- **SSRF by admins**: Ollama URL and UniFi host are arbitrary; UniFi client uses `verify=False` always (MITM of the API key). Make verification configurable / pinned.
- **Logo upload** trusts client `Content-Type`; SVG accepted and later embedded in PDF/`<img>`. Restrict to png/jpeg after magic-byte sniffing.
- **Tokens**: refresh tokens aren't rotated/revocable; no logout; 30-day lifetime; role not re-checked from token (good) but no `jti`. Tokens held in `localStorage` (XSS → full takeover) – no CSP set by nginx.
- **Agent identity = IP address.** Device upserted by `local_ip` from the request body; fallback `127.0.0.1` collides across machines; DHCP changes create duplicates; a token holder can claim another device's pending jobs by spoofing its IP.
- **`init_db()` uses `create_all` + ad-hoc `ALTER TABLE`** while `alembic` is a dependency with no migrations → schema drift risk.
- **Concurrent-scan limit** is hard-coded `3` in the route (ignores `MAX_CONCURRENT_SCANS`) and is check-then-insert (race).
- **Error disclosure**: `scan.error_message = str(e)`, PDF route returns exception text.
- **Dependencies are old** (June-2024 era): fastapi 0.111/starlette, python-jose 3.3.0 (known CVEs), python-multipart 0.0.9 (ReDoS CVE), cryptography 42.0.7, jinja2 3.1.4, scapy 2.5.0, anthropic 0.26, openai 1.30. Frontend has **no lockfile** (`npm install` in Dockerfile → non-reproducible builds). Run `pip-audit` / `npm audit` and bump.
- **Encryption key derivation**: key = raw env string padded/truncated to 32 bytes (no KDF); `decrypt()` swallows all errors and returns `""` (silent failure after key rotation). No key-rotation path.

## Low / hygiene

- `docs/redoc` hidden in prod (good) but `/api/health` is unauthenticated and leaks version.
- Login/registration reveal existence of email ("Email already registered").
- Passwords: min 8 chars only; bcrypt silently truncates at 72 bytes.
- `PATCH /api/users` allows an admin to demote/deactivate themselves or the last admin; documented `DELETE /api/users/{id}` doesn't exist.
- `user.py`: "last scan" query isn't org-scoped; `get_or_create_agent_token` returns an existing token with no way to ever see/rotate/revoke it.
- Agent file duplicated in `agent/` and `backend/agent_files/` (currently identical – will drift); linux service file runs as `netaudit-agent` user that nothing creates, config lives in `$HOME`.
- Nginx: missing CSP, no `X-Forwarded-*` on `/ws/`, `server_name _`, `X-XSS-Protection` is obsolete. Frontend container runs as root.
- Nmap vuln detection (`OUTDATED_VERSIONS`) uses naive substring checks (`"nginx" … "1.1"` matches 1.18, 1.19, 1.1x → false positives; "openssh 6." fine).
- Unused: WeasyPrint system libs in Dockerfile; `BackgroundTasks` param in `trigger_remediation`; `LoginRequest` schema.

## Tests

54 tests exist (auth, scan service, AI providers) using a mocked session. Not executed here. **No coverage** for: agent endpoints, capture, org isolation, role enforcement on writers/admin routes, target validation edge cases (`/0`, leading `-`), schedules, reports, WebSocket auth. The authorization gaps above (C3, H3) would not be caught by the current suite.

## Suggested order of work

1. C1, C2, H4 (config/deploy – quick, high impact).
2. C3, C4, H3 (authorization).
3. H1, H2 (target validation, shared validator).
4. H5–H9, then Medium items; upgrade dependencies and add tests for each fix.

## Fix status (criticals)

Applied, **untested** (no Python available to run the suite):
- C1: db/redis bound to `127.0.0.1`; compose no longer has password/secret fallbacks (`${VAR:?}` – `.env` must now define them).
- C2: `Settings` refuses placeholder secrets / `SECRET_KEY` < 32 chars when `ENVIRONMENT=production`.
- C3: agent tokens bind to a device (`registered_user_id`); results/error uploads require a RUNNING scan targeting the caller's own device. Remaining gap: a token may still claim any *unclaimed* device IP, and findings are still wiped on upload.
- C4: `/api/auth/register` works only for the first (bootstrap) user; later accounts via admin `POST /api/users` or LDAP. Frontend `/register` page/link still exists and will show the 403. The first-user race remains.

- H1/H2 (applied, untested): shared `validate_scan_target` in `schemas.py` used by scans and schedules — private IPs/CIDRs only (RFC1918, loopback, ULA), CIDR no larger than /16 (v6 /112), no leading `-`, hostnames must match a strict regex and resolve only to private addresses. Note: schedules re-run the target later without re-resolving (DNS-rebinding residual risk).
- H3 (applied, untested): capture start/stop/export and the capture WebSocket require IT writer/admin; sessions are checked against the caller's org (404 otherwise); session ids must be UUIDs; interface checked against the worker-registered list + charset; BPF filter charset/length-limited; WS loads the user from the DB (active + role) before accepting.

- H4/H5/H6 (applied, untested): nginx now serves HTTPS only (80 redirects; HSTS; TLS 1.2+; needs `certs/cert.pem` + `key.pem`, see README), logs `$uri` instead of the full request line (no WS tokens in logs), overwrites `X-Forwarded-For`; uvicorn runs with `--proxy-headers`; slowapi uses Redis storage (in-memory in tests). Still open: no account lockout, no CSP, WS tokens still travel in the query string.

---

# Hardening pass (11-phase checklist) — what applied to this project

Verification status: backend compiles, `app.main` imports, **100 pytest tests pass** (Python 3.12 container); frontend `tsc` clean and `vite build` succeeds (Node 20 container). **Not yet verified:** a full `docker compose up` (needs `.env` + TLS certs), nginx config syntax, and live Turnstile/Redis rate-limit behaviour. Found and fixed by this run: a syntax error in the logo-upload code and one old test that asserted the leaky AI error text.

| Phase | Applies? | Outcome |
|-------|----------|---------|
| 1 Legal/data | Yes | `docs/DATA_MAP.md` (PII, tables, third parties, GDPR/CCPA flags); draft `/privacy` page linked from login/register. **Draft must be completed by the operator** (controller, retention). Retention, erasure and export added (see below); the operator must still complete the privacy notice. |
| 2 RLS | **No** – no Supabase; plain Postgres via SQLAlchemy. Tenant isolation is by `organization_id` in queries (audited; capture and a `user.py` lookup were missing it → fixed). | — |
| 3 Auth failure paths | Partly – there is **no password-reset or email-verification flow** to test. | Wrong-password lockout (5 failures → 15 min, 429 + Retry-After, persisted counter, `users.failed_login_attempts/locked_until` added via `init_db`); constant-time-ish unknown-email path (dummy bcrypt); closed-registration check runs before the email lookup so existing emails aren't revealed. |
| 4 Headers | Yes | nginx: CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP; API middleware: nosniff, DENY, no-store, CSP `default-src 'none'`. CSP allows only `challenges.cloudflare.com` for Turnstile. `style-src 'unsafe-inline'` kept (Tailwind/React Flow). |
| 5 OWASP | Yes | SQLi: none found (ORM only; `text()` only static DDL). XSS: no `dangerouslySetInnerHTML`; logo upload now magic-byte checked (no SVG). Fixed: LDAP filter injection (`escape_filter_chars`), PDF markup injection, Gemini key moved from URL to header, org scoping gap. Still open: JWTs in localStorage (refresh tokens are now revocable, see below); UniFi `verify=False`; dependency audit done (see below). |
| 6 Server validation | Yes | Length/format limits on all request schemas (usernames, passwords ≤72 bytes, IPs, URLs, LDAP server/filter/role map, UniFi site path-safe, JSON payload size caps incl. agent results 5 MB). |
| 7 Leaks | Yes | Frontend bundle only receives `VITE_API_URL/VITE_WS_URL/VITE_TURNSTILE_SITE_KEY` (no secrets). End-user findings endpoint slimmed (`UserFindingResponse`: no colleague emails, MACs, raw data). Log redaction processor (`core/logging.py`) + PII removed from LDAP log lines. **Rule: never prefix a secret with `VITE_`; never log request bodies/headers.** |
| 8 API keys | Yes | All AI/LDAP/UniFi keys server-side, AES-GCM at rest, never returned (`has_api_key`). Gemini key no longer in URLs/logs. Turnstile secret server-only. |
| 9 Rate limits | Yes | See table below. |
| 10 CAPTCHA & CORS | Yes | Turnstile on login + register (backend `core/turnstile.py`, fail-closed when enabled; disabled if `TURNSTILE_SECRET_KEY` unset — **set both keys in `.env` for it to take effect**). CORS: explicit origins only (wildcard rejected), explicit methods/headers. App is same-origin through nginx. |
| 11 Errors | Yes | Global 500 handler (generic), validation 422 no longer echoes input, AI/LDAP/UniFi/scan/capture/PDF errors generic in responses (details in logs only). |

### Rate limits (per client IP unless noted; Redis-backed)
Billing/abuse first: AI remediation `10/min, 100/hour`; AI connection test `5/min`; scan start `10/min, 60/hour`; capture start `10/min`; end-user scan `5/min`; PDF report `10/min`; JSON report `30/min`; user create `20/min`; update user `60/min`; LDAP/UniFi tests `10/min`; LDAP search `20/min`; logo upload `10/min`; agent installer download `10/min`; agent-token `10/min`; login `10/min` (+ account lockout); register `5/min`; refresh `20/min`. Agents are limited **per agent token** (checkin `6/min` vs 30 s polling; results/error `30/min`) so NAT'd offices don't share a bucket.

---

# Rebuild pass (architecture fixes)

Verified: **166 pytest tests pass** (unit + real-DB integration), and a real `docker compose up` of db/redis/api/frontend/nginx was exercised end to end over HTTPS on Postgres+Redis. **Not exercised:** the Celery worker/beat and ClamAV containers (the worker uses host networking to reach Postgres/Redis on 127.0.0.1, which Docker Desktop on Windows doesn't support — test on a Linux host), real Turnstile, live AI/LDAP/UniFi integrations.

What changed and why
- **Authorization is now tested as a rule, not assumed.** `tests/integration/` runs the real app on a real database: a role matrix over 27 endpoints (401/403 per role), cross-organization access (404 on every resource type), lockout, closed registration, error hygiene. A structural test walks every router (auto-discovered) and fails if any route lacks an auth dependency, and pins the set of WebSocket endpoints. It found three real bugs: viewers could queue topology scans; JWT subject ids reached the DB as strings; Celery task ids likewise.
- **Tenant scoping in one place:** `core/tenancy.get_for_org` replaces nine hand-written org-filtered lookups.
- **Agent protocol redesigned.** A token now belongs to one *device* (not an IP). Jobs are addressed by `Scan.device_id`; agents only receive/report on their own device's RUNNING jobs; results no longer wipe unrelated findings (only the types a report covers); a scan where ClamAV is missing fails instead of reporting "clean"; jobs the agent never finishes are failed by a reaper; job types now match what the agent runs (fixes the hanging end-user scans); users get one outstanding scan at a time; tokens can be rotated (`POST /api/user/agent-token/rotate`). The agent refuses plain-HTTP dashboard URLs.
- **One copy of the agent** (`./agent`, mounted into the API container); the duplicate `backend/agent_files` is gone.
- **Dependencies:** unused packages removed (psycopg2, lxml, google-generativeai, jinja2, tenacity, dotenv, alembic, websockets), `python-jose` (unmaintained, CVEs) replaced by `PyJWT`, web/auth stack moved to current versions and pinned. Left deliberately: `anthropic==0.26.0`, `openai==1.30.1` (not exercised without real keys; they force `httpx<0.28`), reportlab 4.2.5, scapy 2.5.0.
- **Containers:** API/beat run as UID 10001 with all capabilities dropped and `no-new-privileges`; frontend uses unprivileged nginx; API has a healthcheck that nginx waits on. The worker stays root with NET_RAW/NET_ADMIN (nmap SYN scans, packet capture) — the one privileged service.
- **Found by the live boot:** uvicorn's own access log recorded WebSocket `?token=<JWT>`; now disabled (nginx logs path only).

Still open (not done in this pass)
- JWTs in localStorage (XSS would still expose the current session; the CSP limits that). Moving them to httpOnly cookies needs CSRF protection and is a larger change.
- ~~Schema management via `create_all` + ad-hoc `ALTER TABLE`~~ — **done: Alembic migrations** (see below).
- UniFi client still has `verify=False`.
- Worker/beat/ClamAV and the AI SDK upgrades need testing on a Linux host with real credentials.

## Alembic migrations (added)
- `backend/migrations/` + `alembic.ini`; async `env.py` reads `DATABASE_URL` from the app settings and takes a Postgres advisory lock so concurrent runs are safe. Initial migration `0001` was generated from the models against Postgres 16.
- Tables are created **only** by Alembic. A `migrate` compose service runs `alembic upgrade head`; api, worker and beat wait for it (`service_completed_successfully`). The API refuses to start if the database is not at the code's head (`check_schema`). `init_db`/`create_all` are gone, and a test enforces that.
- Verified on real Postgres: upgrade, then `alembic check` clean (models match the migration), downgrade (also drops the enum types), upgrade again, clean. A fresh `docker compose up` migrated the database, started the API and served requests.
- A database created by the old code (no `alembic_version` table): if it already matches the models, run `docker compose run --rm migrate alembic stamp head`; otherwise recreate it (it was demo data).

## Revocable sessions (added)
- Refresh tokens are tracked server-side (`refresh_tokens` table, migration `0002`): each has a `jti` and a family id shared by all tokens descended from one login.
- **Single use + rotation**: `POST /api/auth/refresh` revokes the presented token and issues a successor in the same family. Presenting an already-used token more than 10 s later is treated as theft and revokes the whole family; within 10 s (two tabs racing) it just gets a 401. Validly signed tokens with no database row (forged, or issued before this change) are rejected.
- **Logout**: `POST /api/auth/logout` revokes the session; the frontend calls it. Always 204, so it can't be used to probe tokens.
- **Deactivating a user or changing their role** revokes all their sessions. (Access tokens, 60 min, are still re-checked against the user's active flag on every request.)
- A daily Celery beat task purges expired rows.
- Existing logged-in users must sign in once after deploying. Tests: `tests/integration/test_sessions.py`.

## Retention, erasure and export (added)
- Daily beat task `purge_old_data` (runs in the worker, which owns the results volume): finished scans older than `RETENTION_SCAN_DAYS` (180) are deleted with their findings and raw nmap output; devices unseen for `RETENTION_DEVICE_DAYS` (365) are deleted unless findings still reference them; `.pcap` files older than `RETENTION_CAPTURE_DAYS` (7) are deleted. `0` disables a rule. Running/pending scans are never purged, and file deletion is restricted to the results directory (paths come from the database).
- `DELETE /api/users/{id}` (admin): anonymizes the user, revokes sessions, deletes agent tokens and (default) the user's registered devices with their findings. Admins cannot erase themselves; other organizations' users return 404.
- `GET /api/users/{id}/export` (admin): user record, devices, findings, token metadata (never hashes) and scans they started.
- Tests: `tests/integration/test_retention.py`. Not covered: database backups and the quarantine volume; the purge task itself has not run in a live worker (the logic is tested directly).

## Dependency audit (done)
- **Backend** (`pip-audit` on `requirements.txt` with transitive dependencies): one finding, scapy 2.5.0 (GHSA-cq46-m9x9-j8w2, unsafe pickle session loading; we never load scapy sessions, so not reachable). Upgraded to scapy 2.7.0, where the feature is removed; re-audit reports no known vulnerabilities, and the scapy calls the app uses (`sniff`, `PcapWriter`, ARP/IP/TCP/UDP/ICMP/DNS layers) import and the 189 tests pass. Live capture and LLDP sniffing were not run (needs the Linux worker).
- **Frontend** (`npm audit`): was 4 findings (esbuild and vite dev-server issues; react-router open redirect via backslash in `<Link>`/`navigate`). Upgraded vite 5→7, @vitejs/plugin-react 4→5 and react-router-dom 6→7; now 0 vulnerabilities, `tsc` and `vite build` pass. Clicked through in a browser against a real stack (vite dev server proxied to the API): unauthenticated redirect to /login, register, login, all seven sidebar pages and /privacy render with no app errors; an expired access token triggers refresh with token rotation and the page recovers; Sign out revokes the session server-side (the old refresh token then returns 401). Not exercised: pages with data (no scans/devices existed), the topology "capture" button, and the TLS front end (self-signed cert not trusted by the browser).
- `frontend/package-lock.json` is now committed and the Dockerfile uses `npm ci`, so builds are reproducible.
- Re-run both audits regularly (`pip-audit -r backend/requirements.txt`, `npm audit`); consider Dependabot/Renovate. Pinned-but-old SDKs (anthropic 0.26, openai 1.30, reportlab, httpx 0.27) have no known advisories today but are behind current releases.
