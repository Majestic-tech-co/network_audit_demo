# NetAudit

AI-powered network security audit platform for enterprise IT teams.
Self-hosted, on-premises — no data leaves your network.

---

## Quick Start

### 1. Configure
```bash
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, REDIS_PASSWORD, SECRET_KEY, ENCRYPTION_KEY
```

### 2. Start
```bash
docker compose up -d
```
First boot takes 2–3 minutes (ClamAV downloads signatures).

### 3. Create admin account
```bash
docker compose exec api python -m app.scripts.create_admin
```

### 4. Open dashboard
Navigate to `http://your-server-ip` — the dashboard guides you through the rest.

---

## Agent Installation (end-user devices)

**Windows:** Run `agent/install_windows.bat`

**Linux:**
```bash
pip install httpx psutil structlog
python agent/agent.py configure --url http://your-server --token TOKEN
sudo systemctl enable --now netaudit-agent  # uses agent/netaudit-agent.service
```

**macOS:**
```bash
pip3 install httpx psutil structlog
python3 agent/agent.py configure --url http://your-server --token TOKEN
launchctl load ~/Library/LaunchAgents/com.netaudit.agent.plist
```

ClamAV must be installed separately for virus scanning:
- Ubuntu: `apt install clamav`
- macOS: `brew install clamav`
- Windows: https://www.clamav.net/downloads

---

## AI Providers

Configure in Settings. Options:
- **Ollama** (default) — fully local, no API key, no data leaves network
- **Claude** — best quality, API key from console.anthropic.com
- **OpenAI** — GPT-4o, API key from platform.openai.com
- **Gemini** — Google AI, API key from aistudio.google.com

---

## Security

- RFC 1918 private ranges only (public IPs blocked server-side)
- Agent tokens SHA-256 hashed before storage
- AI API keys AES-256-GCM encrypted at rest
- Virus results transmit file hashes only, never file contents
- All Docker services on isolated internal network

**Only scan networks you own or are authorized to scan.**

---

## Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Tailwind, React Flow, Zustand |
| Backend | FastAPI, SQLAlchemy async, Alembic |
| Queue | Celery + Redis |
| Database | PostgreSQL 16 |
| Virus scan | ClamAV |
| PDF export | WeasyPrint |
| Real-time | WebSockets + Redis pub/sub |
| AI | Claude / OpenAI / Gemini / Ollama (pluggable) |

## TLS

nginx serves the app over HTTPS only (port 80 redirects to 443) and will not start without
`docker/nginx/certs/cert.pem` and `docker/nginx/certs/key.pem`. For a self-signed cert (testing / internal use):

```bash
openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
  -keyout docker/nginx/certs/key.pem -out docker/nginx/certs/cert.pem -subj "/CN=netaudit.local"
```

Agents verify certificates, so use a cert from a CA your machines trust for production.
The HTTP→HTTPS redirect assumes `HTTPS_PORT=443`.

## Development & tests

```bash
# backend tests (unit + real-DB integration)
docker run --rm -v "$PWD/backend:/src:ro" python:3.12-slim bash -c \
  "cp -r /src /app && cd /app && pip install -q -r requirements.txt -r requirements-test.txt && pytest -q"
```

Required `.env` values (compose refuses to start without them): `POSTGRES_PASSWORD`, `REDIS_PASSWORD`,
`SECRET_KEY` (`openssl rand -hex 32`), `ENCRYPTION_KEY` (exactly 32 chars). Agent installers are served from
`./agent` (mounted into the API container). The worker needs a Linux host (host networking + raw sockets).

## Database migrations (Alembic)

Schema changes are made only through Alembic (`backend/migrations/`); `docker compose up` runs them through the
`migrate` service before the app starts.

```bash
# after changing models in backend/app/models/models.py (needs a reachable Postgres via DATABASE_URL):
cd backend
alembic revision --autogenerate -m "describe the change"   # review the generated file!
alembic upgrade head
alembic check                                               # must print: No new upgrade operations detected
```

Existing database from before migrations that already matches the models:
`docker compose run --rm migrate alembic stamp head`.

## Continuous integration

`.github/workflows/ci.yml` runs on every push and pull request, and weekly (new advisories appear without commits):
backend tests; migrations applied to an empty Postgres, `alembic check` (fails if a model change has no migration) and
downgrade/re-upgrade; `pip-audit`; frontend `tsc`, build and `npm audit`; and `docker compose config`. Dependabot
(`.github/dependabot.yml`) opens weekly update PRs. In GitHub, mark the CI jobs as required checks on `main` (branch
protection) so a failing audit or missing migration blocks merging.
