# Aegis

> Aegis: A Runtime Security Framework for Autonomous AI Agents

Aegis is a **fail-closed** runtime security gateway that sits between autonomous AI agents and the external tools they call (GitHub, terminals, and beyond). Every tool call is **intercepted before execution**, authenticated, evaluated against a deterministic policy engine, scored for risk, analyzed for behavioral context, subjected to a human-approval workflow when warranted, and — only if all checks pass — executed via sandboxed tool adapters. Every step produces a tamper-evident, hash-chained audit record and streams events in real time to the admin dashboard over WebSockets.

## Architecture overview

```
AI Agent  --[API Key]-->  Aegis Gateway
                               |
             +-----------------+------------------+
             | Authentication | Request Intercept |
             +-----------------+------------------+
                               |
             +---------+----------+----------+-----------+
             | Policy | Risk Engine | Context | Decision  |
             +---------+----------+----------+-----------+
                               |
              +----------------+---------------+
              | ALLOW          | BLOCK         | APPROVAL  |
              v                v               v
        Tool Adapter      Audit Log       Human Approval
              |
              +--> GitHub (encrypted tokens, HTTP timeouts)
              +--> Secure Terminal (Docker-sandboxed non-root)
              |
              v
          Audit Log (SHA-256 chained hashes, append-only)
              |
              v
          WebSocket Events
              |
              v
          Admin Dashboard (Next.js / Tailwind / shadcn/ui)
```

## Security invariants (always true)

| # | Invariant |
|---|-----------|
| 1 | No unauthenticated agent request reaches a tool. |
| 2 | No request reaches a tool before policy/risk/context/decision. |
| 3 | `BLOCK` → tool MUST NOT execute. |
| 4 | `REQUIRE_APPROVAL` → tool MUST NOT execute until approved. |
| 5 | Expired approval → MUST NOT execute. |
| 6 | Revoked API key → MUST NOT execute. |
| 7 | Unexpected security error → BLOCK. |
| 8 | Sensitive credentials → NEVER in logs. |
| 9 | Experimental crypto → NEVER replaces AES-256-GCM. |
| 10 | Frontend state → NEVER source of truth for authorization. |

## Tech stack

| Layer | Stack |
|-------|-------|
| Backend | Python 3.12 · FastAPI · Pydantic 2 · SQLAlchemy 2 async · Alembic |
| Database | PostgreSQL 16 |
| Auth | JWT HS256 · Argon2id · API keys (HMAC-SHA256 + pepper) |
| Crypto | AES-256-GCM · HMAC-SHA256 · SHA-256 chain hashes |
| Tools | GitHub API · Docker-sandboxed terminal |
| Frontend | Next.js 14 App Router · React · TypeScript · Tailwind · shadcn/ui |
| Real-time | FastAPI WebSockets · PubSub hub with reconnect resync |
| Tests | pytest · httpx · respx · Playwright |
| Deploy | Docker · Docker Compose (postgres + backend + frontend + healthchecks) |
| Research | Isolated experimental AEAD cipher (`app/crypto_research/`) · benchmarks vs AES-256-GCM |

## Quick start (development)

### Requirements

- Python 3.12+
- Node 20+
- Docker Engine + Docker Compose (for PostgreSQL and the terminal sandbox)

### 1. Clone & configure

```bash
cd aegis
cp .env.example .env
# Edit .env and fill the __REPLACE__ placeholders
```

### 2. Backend setup

```bash
cd backend
python -m venv .venv
.venv\Scripts\activate     # Windows
# source .venv/bin/activate  # macOS/Linux
pip install -e .
alembic upgrade head
python -m app.scripts.create_admin   # interactive, or use AEGIS_ADMIN_EMAIL + AEGIS_ADMIN_PASSWORD env vars
uvicorn app.main:app --reload --port 8000
```

Open `http://localhost:8000/health` and `http://localhost:8000/docs`.

### 3. Frontend setup

```bash
cd frontend
npm install
npm run dev
# open http://localhost:3000/login
```

### 4. Agent quick-start

Use the admin UI to create an agent. Copy the one-time `plaintext_key`.

```bash
curl -X POST http://localhost:8000/v1/execute \
  -H 'X-Api-Key: ag-XXXX_YYYY' \
  -H 'Content-Type: application/json' \
  -d '{ "tool": "github", "action": "read_repository", "parameters": { "repository": "owner/repo" } }'
```

### 5. Docker

```bash
docker compose up --build -d
docker compose ps   # wait until all 3 services show healthy
```

## Testing

```bash
# Backend (from backend/ venv)
pytest -v --cov=app --cov-report=term

# Security suite only
pytest tests/test_security_*.py -v

# Integration suite
pytest tests/integration -v

# 7 E2E scenarios
pytest tests/test_e2e_scenarios.py -v

# Frontend E2E (Playwright)
cd frontend
npx playwright install --with-deps chromium
npx playwright test
```

## Documentation

| Doc | Location |
|-----|----------|
| Architecture & request lifecycle | [docs/architecture.md](docs/architecture.md) |
| Security & threat model | [docs/security.md](docs/security.md) |
| STRIDE threat model per component | [docs/threat-model.md](docs/threat-model.md) |
| API reference | [docs/api.md](docs/api.md) + `http://localhost:8000/docs` |
| Experimental crypto research | [docs/crypto-research.md](docs/crypto-research.md) |

## Demo credentials / setup

Run:

```bash
python -m app.scripts.create_admin
# Email: admin@aegis.local
# Password: (you typed it)
```

Then log in at `http://localhost:3000/login`.

## Suggested demo flow

1. Log in as admin.
2. Create an agent → copy the one-time plaintext key.
3. Create 3 policies:
   - `Safe GitHub Read` (ALLOW, priority 10, tool=github, action=read_*)
   - `Destructive Terminal` (BLOCK, priority 5, tool=terminal, action pattern=delete)
   - `Default` (REQUIRE_APPROVAL, priority 9999, tool=any)
4. Agent requests `github/read_repository` → ALLOW → dashboard + audit update live via WebSocket.
5. Agent requests `terminal/delete` → BLOCK → dashboard shows blocked request; terminal container is never spawned.
6. Agent requests `terminal/execute command=cat something_private` → REQUIRE_APPROVAL → approve queue appears; approve → request runs → execution completes.
7. Open Audit → Verify Chain → shows `Chain Valid`.
8. Revoke agent API key → agent retries → 401 Unauthorized.

## Known limitations

- Terminal sandbox spawns as a sibling Docker container (requires backend to have access to the Docker socket; documented as acceptable for prototype — in production deploy with docker-in-docker + dedicated socket proxy).
- GitHub write operations intentionally not implemented; only read-safe actions are available.
- JWT token blocklist is in-process; restarting the backend expires outstanding blocks. For multi-instance deployments, replace with Redis backing.
- WebSocket catchup window limited to last N events in memory; for production, persist events or use a dedicated message broker.
- Experimental crypto is a research prototype and explicitly NOT recommended for production use.
