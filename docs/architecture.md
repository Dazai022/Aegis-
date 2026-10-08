# Architecture

## Overview

Aegis is a 10-stage runtime security gateway. Every agent tool-call transits the stages in strict pipeline order; no stage after Decision can execute unless the preceding authorization gates permit.

```
Stage 1   Authentication      Admin JWT (HS256) / Agent API key (HMAC-SHA256 + pepper)
Stage 2   Request Intercept   UUID request id, Pydantic validation, sensitive param sanitization
Stage 3   Policy Engine       Deterministic, first-match-wins by priority, default REQUIRE_APPROVAL
Stage 4   Risk Engine         0-100 score, LOW/MEDIUM/HIGH/CRITICAL, 10 explainable signals
Stage 5   Context Engine      First-use, frequency, unusual patterns, prior decisions
Stage 6   Decision Engine     5-rule precedence; any exception → BLOCK (fail-closed)
Stage 7   Approval System     Parameter-bound, single-use, expiry, anti-replay
Stage 8   Tool Execution      Registry of adapters; execute only if ALLOW or APPROVED
Stage 9   Audit Logger        Append-only, SHA-256 chained-hash integrity
Stage 10  WebSocket Events    PubSub topics, reconnect resync with sequence IDs
```

## Component graph

```
AI Agent
   │  HTTP + X-Api-Key
   ▼
┌──────────────────────────────────────────────── FastAPI app ─────────────────────────────────────────────────┐
│                                                                                                              │
│  auth middleware ───▶ interceptor ──▶ policies ──▶ risk ──▶ context ──▶ decisions ──▶ approval ──▶ tools    │
│                                              │          │         │              │              │            │
│                                              ▼          ▼         ▼              ▼              ▼            │
│                                        SQLAlchemy + PostgreSQL (admins, agents, keys, policies, versions,    │
│                                        requests, risk, context, decisions, approvals, executions, audit,     │
│                                        github connections, terminal sessions)                                │
│                                              │                                                               │
│                                              ▼                                                               │
│                                       audit logger (SHA-256 chain)                                           │
│                                              │                                                               │
│                                              ▼                                                               │
│                                       websocket hub ───▶ admin dashboard                                      │
│                                                                                                              │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                 │                                   │
                                 ▼                                   ▼
                       External GitHub API                  Docker-sandboxed terminal
```

## Request lifecycle (in order)

1. **Agent authenticates** `X-Api-Key`. The raw key is never stored; the HMAC of `key || pepper` is looked up in `agent_api_keys`. State must be `active`.
2. **Request interceptor**: assign `request_id` (UUID), validate tool/action/params with Pydantic. Reject malformed, oversized, or unsupported-tool requests. Sanitize known-sensitive parameter keys into `[REDACTED]` for storage. Insert `execution_requests` row with `status = intercepted`.
3. **Policy engine**: sort enabled policies by `priority ASC`, evaluate tool/action pattern match / parameter constraints. First match wins. No match → `REQUIRE_APPROVAL`. Insert `policy_result` reference.
4. **Risk engine**: score 0-100 across 10 signals; each signal has name, weight, reason, evidence. Persist JSONB. Map to LOW/MEDIUM/HIGH/CRITICAL with configurable thresholds.
5. **Context engine**: look back at the agent's recent history; flag first-time tool, high-frequency burst, unusual action pattern, prior failures, recent blocks. Persist findings.
6. **Decision engine**: strict 5-rule precedence. (1) BLOCK policy → BLOCK. (2) HIGH/CRITICAL risk → REQUIRE_APPROVAL. (3) REQUIRE_APPROVAL policy → REQUIRE_APPROVAL. (4) ALLOW policy + LOW/MEDIUM risk → ALLOW. (5) any unhandled exception → BLOCK. Always write a `decisions` row.
7. **Approval (if required)**: create pending approval with `parameters_hash = SHA256(canonical_json(params))`, `expires_at = now + APPROVAL_EXPIRE_SECONDS`. Admin approves/rejects; approval is atomic (row-level status change). Double-approve → 409. Expired → 410. Tampered params → hash mismatch → rejected.
8. **Tool execution (ALLOW or APPROVED)**: `ToolExecutor.execute_if_permitted` code-gates the adapter call. Adapter registry dispatches to `GitHubAdapter` or `SecureTerminalAdapter`.
9. **Audit**: append-only insert to `audit_logs`. `previous_hash` is the last known chain hash; `current_hash = SHA256(previous_hash || "|" || canonical_json(record))`.
10. **WebSocket hub**: publish on topics `requests.new`, `requests.decision`, `requests.exec.started`, `requests.exec.completed`, `requests.blocked`, `approvals.requested`, `approvals.completed`, `security.alert`. Each event carries a monotonic sequence id for reconnect resync.

## Modules

- `app/core/config.py` — Pydantic Settings, env-var-only secrets.
- `app/core/database.py` — async SQLAlchemy engine + Base with UUID/mixins.
- `app/core/logging.py` — structured JSON logger with secret redaction.
- `app/core/deps.py` — `get_current_admin` (JWT), `get_current_agent` (API key), authorization helpers.
- `app/security/` — JWT, AES-256-GCM, HMAC-SHA256, Argon2id + dummy verify.
- `app/models/` — SQLAlchemy models for all entities.
- `app/schemas/` — Pydantic request/response schemas.
- `app/services/` — request interceptor, cross-engines orchestrator.
- `app/policies/`, `app/risk/`, `app/context/`, `app/decisions/`, `app/approvals/` — per-stage engines.
- `app/tools/` — `base.ToolAdapter` ABC, `executor`, `github/`, `terminal/sandbox.Dockerfile`.
- `app/audit/` — append-only writer + chain verifier.
- `app/websocket/` — async pub/sub hub + sequence-id ring buffer for catch-up.
- `app/crypto_research/` — isolated experimental AEAD cipher.
- `app/scripts/create_admin.py` — click-based admin bootstrap.
- `alembic/` — migrations.
- `tests/` — unit, security, integration, and E2E pytest suites.

## Boundaries & trust

| Boundary | Authentication | Authorization |
|----------|---------------|---------------|
| Admin → Backend REST | JWT (HS256, 15 min) | require_admin |
| Agent → Backend REST | HMAC-SHA256 API key lookup | require_agent |
| Admin → Backend WS | JWT in query/header | require_admin |
| Backend → GitHub API | AES-256-GCM-decrypted PAT per connection | scope-limited to read actions |
| Backend → Docker sandbox | Spawned containers as non-root sandbox user, cap-drop ALL, network none | command scoped, 30s timeout |
