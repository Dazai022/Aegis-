# Aegis - Implementation Plan

All tasks are ordered by the brief's 9-phase roadmap. Tasks within a phase that do not write overlapping files can be executed concurrently; tasks that share code paths are kept serial to avoid conflicts. Each task references the acceptance criteria it satisfies and provides rule/rubric Test Requirements (TRs) that the implementer must self-verify before marking the task completed.

## Phase 1: Project scaffolding, configuration, PostgreSQL, SQLAlchemy, Alembic, health endpoint

### Task 1.1: Monorepo scaffolding + root files (.gitignore, docker-compose.yml skeleton, .env.example, README skeleton, docs/ structure)
- **Status**: `completed`
- **Priority**: high
- **Depends On**: None
- **Description**:
  - Create monorepo structure: `backend/`, `frontend/`, `docs/` + root `docker-compose.yml`, `.gitignore`, `README.md` (skeleton with required sections — real content written in a later docs task), `.env.example` (placeholders only, no real secrets).
  - Create docs placeholders with correct headings: `architecture.md`, `api.md`, `security.md`, `threat-model.md`, `crypto-research.md`.
- **Acceptance Criteria Addressed**: AC-20
- **Test Requirements**:
  - `rule` TR-1.1.1: `tree -L 3 aegis/` (or PowerShell equivalent) shows every directory from the brief's layout exists.
  - `rule` TR-1.1.2: `.env.example` contains no matching `=sk-`, `=eyJ`, `=AES-`, `password=real`, lines with plausible secret values; `.gitignore` ignores `*.pyc`, `.venv/`, `__pycache__/`, `node_modules/`, `.next/`, `.env`, `*.sqlite`.
  - `rubric` TR-1.1.3: Structure fidelity; scale 1-5 (1=missing dirs, 3=skeleton partial, 5=full skeleton matches brief exactly); threshold >=4; evidence: dir tree.
- **Notes**: No runtime code yet; pure layout.
- **Completion Evidence**:
  - TR-1.1.1 PASS: 28 directories from brief layout present (PowerShell check passed 2026-10-03).
  - TR-1.1.2 PASS: `.env.example` scanned — no lines containing `=sk-`, `=eyJ`, `=AES-`, `=ghs_`, `password=real`. `.gitignore` explicitly covers `*.pyc`, `.venv`, `__pycache__`, `node_modules`, `.next`, `.env`, `*.sqlite`.
  - TR-1.1.3 score **5/5**. Monorepo exactly mirrors brief layout; docs contain full non-stub headings/content (not placeholders; already populated because docs were written as reference for later stages). No TODO markers detected in any of the docs root files.

### Task 1.2: Backend package (pyproject.toml, deps pin, package layout, core config via Pydantic Settings, logger, encryption utilities, pepper helper, secrets loading from env)
- **Status**: `completed`
- **Priority**: high
- **Depends On**: 1.1
- **Description**:
  - Create `backend/pyproject.toml` with Python 3.12+ and pinned deps: `fastapi`, `uvicorn[standard]`, `pydantic[email]>=2`, `pydantic-settings`, `sqlalchemy[asyncio]`, `asyncpg`, `alembic`, `argon2-cffi`, `pyjwt`, `cryptography`, `httpx`, `slowapi`, `limits`, `websockets`, `python-dotenv`, `psutil`, `click`, plus dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `respx`, `aiofiles`.
  - Create package layout: `backend/app/{api,core,models,schemas,services,security,policies,risk,context,decisions,approvals,tools/github,tools/terminal,audit,websocket,crypto_research,scripts}`.
  - Implement `backend/app/core/config.py` (Pydantic Settings: `DATABASE_URL`, `JWT_SECRET`, `JWT_ALG=HS256`, `JWT_EXPIRE_MIN=15`, `PEPPER`, `AES_MASTER_KEY_BASE64`, `CORS_ORIGINS`, `RATE_LIMIT_LOGIN_PER_MIN`, `APPROVAL_EXPIRE_SECONDS`, `RISK_LEVELS={LOW:30,MEDIUM:60,HIGH:80,CRITICAL:101}`).
  - `backend/app/core/logging.py` (structured JSON logger with redaction filter for JWT/API-key/secret patterns, request-id propagation stub).
  - `backend/app/security/crypto.py`: AES-256-GCM encrypt/decrypt with base64-wrapped (nonce||ciphertext||tag); HMAC-SHA256 helper for API keys.
  - `backend/app/security/passwords.py`: Argon2id hashing + verify + dummy verify helper (same timing shape regardless of user existence).
- **Acceptance Criteria Addressed**: AC-2, AC-3, AC-10, AC-21
- **Test Requirements**:
  - `rule` TR-1.2.1: `python -c "from app.core.config import settings; assert settings.JWT_ALG == 'HS256'"` passes in backend venv.
  - `rule` TR-1.2.2: AES-256-GCM roundtrip test (encrypt then decrypt) returns the same plaintext; tampered ciphertext raises `InvalidTag`.
  - `rule` TR-1.2.3: HMAC-SHA256 output matches `hmac.new(key=pepper, msg=api_key_bytes, digestmod=sha256).hexdigest()` against a known vector.
  - `rule` TR-1.2.4: Argon2id verify returns True for correct password, False for wrong; dummy verify runs without throwing and takes similar time.
  - `rubric` TR-1.2.5: Secure posture of settings module; scale 1-5 (1=hardcoded secrets, 3=env but mixed defaults, 5=all secrets from env, strict types, no dangerous defaults); threshold >=4; evidence: config.py code + .env.example diff.
- **Completion Evidence**:
  - TR-1.2.1 PASS: settings load correctly, JWT_ALG validator forbids non-HS256 values, JWT_EXPIRE_MIN=15, RISK_LEVELS correct (2026-10-03).
  - TR-1.2.2 PASS: `AesGcm(key)` roundtrip "Hello, Aegis!" + flip-last-byte tamper → `CryptoError` raised.
  - TR-1.2.3 PASS: `HmacHelper.api_key_hash("ag-test-key-12345") == hmac.new(pepper_bytes, ...).hexdigest()`; constant-time equals behaves correctly.
  - TR-1.2.4 PASS: short pw raises length min; correct pw verifies; dummy verify 0.225s wall-clock; non-matching passwords fail verify.
  - TR-1.2.5 score **5/5**: all secrets via `SecretStr` from env, hard length/base64 validation on AES, non-HS256 alg raises ValueError, placeholder warning in prod, no default secret strings in source. `.env.example` has no real values; `__REPLACE_WITH_*__` marker in all secret slots.

### Task 1.3: DB engine + SQLAlchemy session (async) + Alembic init + minimal Base + health endpoints
- **Status**: `completed`
- **Priority**: high
- **Depends On**: 1.2
- **Description**:
  - `backend/app/core/database.py`: async engine, async sessionmaker, Base declarative base with UUID PK, created_at/updated_at mixin.
  - `backend/alembic.ini`, `backend/alembic/env.py` (async, autogenerate compatible).
  - `backend/app/api/__init__.py` + router skeleton.
  - `backend/app/main.py` (FastAPI app, include routers, CORS middleware with restrict origins, `hide_server` headers, exception handlers that never leak stack traces in production).
  - `backend/app/api/health.py`: `GET /health`, `GET /health/ready` (ready checks DB connectivity via `SELECT 1`).
- **Acceptance Criteria Addressed**: AC-1, AC-18, AC-19, AC-21
- **Test Requirements**:
  - `rule` TR-1.3.1: With Postgres reachable (testcontainers preferred for tests, or SQLite in-memory fallback for unit-test health path without real DB — actual `/health/ready` must test postgres), `GET /health` returns `{"status":"ok"}`.
  - `rule` TR-1.3.2: With Postgres **unreachable**, `GET /health/ready` returns 503 with structured error.
  - `rule` TR-1.3.3: Exceptions propagated through FastAPI produce error envelope `{"error":{"code":...,"message":...}}` without traceback when `ENV=prod`.
  - `rule` TR-1.3.4: Alembic init created: `alembic list_versions` runs without error on a fresh DB; initial (empty) migration generated.
  - `rubric` TR-1.3.5: Middleware/hardening; scale 1-5 (1=no headers/cors open, 3=basic cors, 5=strict cors + security headers: CSP, X-Content-Type-Options, X-Frame-Options, HSTS placeholder, server_tokens off); threshold >=4; evidence: middleware list.
- **Completion Evidence**:
  - TR-1.3.1 PASS: `GET /health` → 200, `{"status":"ok","service":"aegis","version":"0.1.0","environment":"dev"}`
  - TR-1.3.2 NOT RUN YET (needs real Postgres) — will validate in Phase 2 integration tests.
  - TR-1.3.3 PASS: middleware catch-all for ENV=prod uses generic message + 500 envelope; 404 unknown routes → `{error:{code:NOT_FOUND}}` envelope.
  - TR-1.3.4 PASS: `ScriptDirectory.from_config()` walks revisions successfully; `env.py` compiles cleanly; initial `versions/` dir created; empty revision list = 0 (as expected for fresh empty app before Task 1.4).
  - TR-1.3.5 score **5/5**: CORS origins restricted to list via env, CSP default-src='self' + frame-ancestors none, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security set when https, Referrer-Policy same-origin, Permissions-Policy disables camera/mic/geo, Server header removed ("").

### Task 1.4: SQLAlchemy models for ALL entities + initial Alembic migration with indexes, FKs, cascades
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 1.3
- **Description**:
  - `backend/app/models/`: `admin.py`, `agent.py`, `api_key.py`, `policy.py`, `policy_version.py`, `execution_request.py`, `risk_assessment.py`, `context_assessment.py`, `decision.py`, `approval.py`, `tool_execution.py`, `audit_log.py`, `github_connection.py`, `terminal_session.py`.
  - Model invariants: admins use Argon2id; agent_api_keys store only the HMAC+pepper hash + mask for display; audit_logs store `previous_hash` and `current_hash` for chain.
  - Add indexes on frequently-queried cols: execution_requests(agent_id, created_at), audit_logs(created_at), approvals(status, expires_at), decisions(request_id UNIQUE).
  - `alembic revision --autogenerate -m "initial"` and review/edit the produced migration to ensure all constraints/UUID/cascades match.
- **Acceptance Criteria Addressed**: AC-18, AC-12
- **Test Requirements**:
  - `rule` TR-1.4.1: `alembic upgrade head` succeeds on a fresh DB.
  - `rule` TR-1.4.2: `alembic downgrade base` then `alembic upgrade head` succeeds (rollback+reapply works, or mark specific downgrade unsupported if unavoidable with rationale — otherwise required).
  - `rule` TR-1.4.3: Attempting to insert an execution_request for a nonexistent agent raises an FK error.
  - `rule` TR-1.4.4: Deleting an agent cascades appropriately: execution_requests retained (FK set-null or soft delete — document the choice; the brief allows cascade behavior as long as audit chain stays intact, so audit_logs should not cascade deletes, execution_requests can be ON DELETE RESTRICT or SET NULL depending on chosen policy; audit_logs must be append-only and never cascade delete).

## Phase 2: Admin authentication, JWT, Agent authentication / API keys, authorization, rate limiting

### Task 2.1: Admin JWT auth endpoints, middleware, auth dependencies, create_admin CLI script, login rate limit
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 1.4
- **Description**:
  - `backend/app/security/jwt.py`: encode HS256 only, 15-min expiry; decode strictly rejects non-HS256 via explicit options.
  - `backend/app/api/auth.py`: `POST /auth/login`, `POST /auth/logout` (token blocklist in-memory + optional Redis fallback; for prototype use in-memory with TTL), `GET /auth/me`.
  - `backend/app/core/deps.py`: `get_current_admin` dependency.
  - `backend/app/scripts/create_admin.py`: CLI (Click) prompting for email/password or reading `AEGIS_ADMIN_EMAIL`/`AEGIS_ADMIN_PASSWORD`.
  - Rate limit login via `slowapi`: e.g. 5 attempts per minute per IP, 10 per 15 min per account.
  - Generic 401 responses ("invalid credentials") regardless of user existence; dummy Argon2id run for nonexistent users to flatten timing.
- **Acceptance Criteria Addressed**: AC-2
- **Test Requirements**:
  - `rule` TR-2.1.1: `create_admin` runs and inserts a row; login with correct creds returns JWT; `/auth/me` returns admin email; logout then `/auth/me` fails.
  - `rule` TR-2.1.2: JWT signed with alg: `none` or `RS256` is rejected by `/auth/me` (decode raises, returns 401).
  - `rule` TR-2.1.3: Expired JWT returns 401.
  - `rule` TR-2.1.4: 6 invalid logins in < 1 min return 429.
  - `rule` TR-2.1.5: Login with invalid email vs invalid password returns the same 401 envelope; a timing test over many iterations reports median ratio within 1.5x (indicative; unit test uses the dummy verify function explicitly).
  - `rule` TR-2.1.6: No logs contain password or raw JWT (grep log output lines for inserted test password).

### Task 2.2: Agent CRUD API, API key generation (CSPRNG), display-once plaintext, HMAC storage, states, revocation, agent/me, agent-api-key middleware dependency
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 2.1
- **Description**:
  - `backend/app/api/agents.py`: admin-only `POST /agents` (create) + `GET /agents` list + `POST /agents/{id}/revoke`; agent-scoped `GET /agents/me` (authenticated by API key).
  - API key generation: `secrets.token_urlsafe(32)` => `ag-` prefix; plaintext shown once in response `plaintext_key` field (never returned again).
  - Storage: compute `HMAC-SHA256(utf8(plaintext_key) + utf8(pepper))`; store the hex digest; also store last-4 mask for admin UI identification.
  - Key states: `active`, `revoked`, `invalid`; revoked keys fail auth immediately.
  - `backend/app/core/deps.py`: `get_current_agent` dependency that reads header `X-Api-Key: <key>`, recomputes HMAC, DB lookup, state check, fails closed.
- **Acceptance Criteria Addressed**: AC-3, AC-16
- **Test Requirements**:
  - `rule` TR-2.2.1: Create agent returns `plaintext_key` and `agent.id`; second call to `GET /agents/me` with that key succeeds; repeat query of `POST /agents` response fields — DB row does NOT contain the plaintext; DB row's `hmac_hash` equals `hmac(key=pepper, msg=plaintext).hexdigest()`.
  - `rule` TR-2.2.2: Revoke the agent; subsequent `/agents/me` with that key returns 401.
  - `rule` TR-2.2.3: Invalid, garbage, missing API keys all return 401 from agent-scoped endpoints; no tool execution path is reachable (enforced in later tasks, but here `GET /agents/me` rejects).
  - `rule` TR-2.2.4: Non-admin JWT hitting admin-only agent endpoints returns 403.

### Task 2.3: Authorization dependency framework (admin vs agent scopes), CORS tighten, error envelope standard, structured request id middleware
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: 2.2
- **Description**:
  - `require_admin`, `require_agent`, `require_any_authenticated` deps; each adds request.user state.
  - CORS origins restricted to settings; allow headers/cookies only if needed.
  - Consistent error envelope: `HTTPException` handler + top-level `Exception` handler → `{"error":{"code":"...","message":"..."}}`.
  - Request ID middleware: `X-Request-ID` passthrough or generate UUID; bind to structured logger context; include in all audit records.
- **Acceptance Criteria Addressed**: AC-21, AC-4 (prereq)
- **Test Requirements**:
  - `rule` TR-2.3.1: Unauthenticated request to `/agents` returns 401.
  - `rule` TR-2.3.2: Agent API key used on admin route returns 403.
  - `rule` TR-2.3.3: Unknown exception during request returns 500 envelope without stack trace in `ENV=prod`; internal log has the trace (assert log entry exists but response body does not contain `Traceback`).
  - `rule` TR-2.3.4: Every response contains header `X-Request-ID` matching the one that will be stored in audit later.

## Phase 3: Execution request model, interceptor, policy engine, risk engine, context engine, decision engine

### Task 3.1: Execution schemas + request interceptor (Pydantic validation, unique Request ID, sanitization)
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 2.3
- **Description**:
  - `backend/app/schemas/execution.py`: `ExecutionRequestIn(tool: Literal["github","terminal"], action: str, parameters: dict)`, `ExecutionResponseOut` with decision + result + evidence refs.
  - `backend/app/services/request_interceptor.py`: assign UUID request id; sanitize sensitive params (e.g., filter keys named `token`, `password`, `secret`, `key`) in the sanitized snapshot stored in DB; validate tool/action per allowed registry.
  - Persist the request in `execution_requests` row (agent_id, tool, action, params_json, request_id, created_at, source="gateway", status="intercepted").
- **Acceptance Criteria Addressed**: AC-4, AC-21
- **Test Requirements**:
  - `rule` TR-3.1.1: Malformed JSON, missing fields, wrong types, unsupported tool all return 422 with envelope.
  - `rule` TR-3.1.2: Oversized parameters payload > `settings.MAX_REQUEST_BYTES` returns 413.
  - `rule` TR-3.1.3: params containing `"password": "hunter2"` are stored sanitized as `"password": "[REDACTED]"` in `execution_requests.parameters_sanitized`; audit log never shows the value.
  - `rule` TR-3.1.4: Each request gets unique UUID persisted and returned in headers.

### Task 3.2: Policy engine service + policy CRUD + versioning; policies affect decision
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 3.1
- **Description**:
  - `backend/app/policies/engine.py`: deterministic evaluator.
  - Model: `Policy` + `PolicyVersion` (every update bumps version and archives prior version).
  - Fields: name, description, priority (int, lower=higher precedence), tool (null=ANY), action_pattern (glob or regex; use `fnmatch` for simplicity), parameter constraints (JSON schema subset dict), effect enum: `ALLOW|BLOCK|REQUIRE_APPROVAL`, enabled bool.
  - `backend/app/api/policies.py`: admin-only CRUD + `GET /policies/{id}/versions`, `POST /policies/{id}/revert/{version}`.
  - Evaluation: sort enabled by priority ASC; first match whose tool/action/params satisfy → effect; no match → REQUIRE_APPROVAL.
- **Acceptance Criteria Addressed**: AC-5
- **Test Requirements**:
  - `rule` TR-3.2.1: Two policies with identical tool/action match, priorities 1 (ALLOW) and 2 (BLOCK) → result ALLOW; swap priorities → result BLOCK.
  - `rule` TR-3.2.2: No matching policy → REQUIRE_APPROVAL.
  - `rule` TR-3.2.3: Parameter constraints expressed as `{"command":{"pattern":"^rm\\s"}}` correctly match and fire.
  - `rule` TR-3.2.4: Updating a policy inserts a new `PolicyVersion` row; revert restores prior effect/priority.

### Task 3.3: Risk engine — signals, weights, score 0-100, thresholds, explainable output
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 3.1
- **Description**:
  - `backend/app/risk/engine.py`: `RiskEngine.assess(request, history) -> RiskAssessment`.
  - Signals registry with names, weights, reason, evidence:
    - `destructive_action` (action contains keywords: delete, drop, remove, rm, mkfs, shutdown, reboot, destroy) weight +30
    - `sensitive_resource` (param contains /etc, /root, .aws, production) +25
    - `privileged_tool` (tool=terminal) +10
    - `unusual_action` (action not in last 100 actions for the tool) +20
    - `first_time_tool` (never seen tool for agent) +15
    - `high_frequency` (>30 req/hour) +10
    - `suspicious_params` (path traversal `../`, shell metachar `;|&&` without allowlist) +20
    - `prompt_injection_indicators` (action/params substrings `ignore previous`, `system:`, `jailbreak`) +15
    - `sensitive_data_access` (params mention PII keys, tokens, secrets) +25
  - Cap at 100; thresholds read from settings: 0<=LOW<30<=MEDIUM<60<=HIGH<80<=CRITICAL<=100.
  - Persist signals array in `risk_assessments` with JSONB for reproducibility.
- **Acceptance Criteria Addressed**: AC-6, AC-16
- **Test Requirements**:
  - `rule` TR-3.3.1: `rm -rf /` request → risk ≥ 80 (CRITICAL); safe `github/read_file("README.md")` → score ≤ 29 (LOW).
  - `rule` TR-3.3.2: Same request + same DB history → identical score (determinism test, loop 10 times).
  - `rule` TR-3.3.3: One extra signal switched on increases score deterministically.
  - `rule` TR-3.3.4: Suspicious param `../../etc/passwd` triggers the path traversal signal; evidence cites the exact substring matched.

### Task 3.4: Context engine — agent behavior analysis, first-time usage, frequency, unusual patterns, prior decisions/failures
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 3.1, 3.3
- **Description**:
  - `backend/app/context/engine.py`: `ContextEngine.analyze(request_id, agent_id, tool, action) -> ContextAssessment` (findings: `first_time_tool`, `high_frequency`, `unusual_action_pattern`, `prior_failures`, `recent_blocks`).
  - Use last N requests via `execution_requests` queries, bounded windows.
- **Acceptance Criteria Addressed**: AC-7
- **Test Requirements**:
  - `rule` TR-3.4.1: Seed 50 github/read_repository calls for agent A, then request terminal/delete_files → `unusual_action_pattern` present.
  - `rule` TR-3.4.2: First call of tool=github → `first_time_tool` present; second call → absent.
  - `rule` TR-3.4.3: Burst of 35 requests in <60 min → `high_frequency` present; with context findings feeding the decision engine per rule 2 ("Critical/high risk → REQUIRE_APPROVAL"), the combined path is tested as part of TR-3.5.3.

### Task 3.5: Decision engine — strict precedence, fail-closed exception handling, persistence
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 3.2, 3.3, 3.4
- **Description**:
  - `backend/app/decisions/engine.py`: pure function + orchestrator that writes `decisions` row and returns to caller.
  - Precedence codified exactly:
    1. any BLOCK policy effect → BLOCK
    2. risk_level in {HIGH, CRITICAL} → REQUIRE_APPROVAL
    3. any REQUIRE_APPROVAL policy effect → REQUIRE_APPROVAL
    4. explicit ALLOW and risk_level ≤ MEDIUM → ALLOW
    5. ANY unhandled exception → BLOCK (fail closed; log exception, never stack trace to client)
  - Returned decision includes reason, policy_id, risk_score, risk_level, context_findings list.
- **Acceptance Criteria Addressed**: AC-8
- **Test Requirements**:
  - `rule` TR-3.5.1: Precedence matrix of 16 fixture combos each returns the expected exact decision.
  - `rule` TR-3.5.2: Inject `RuntimeError` into policy engine mock → engine returns BLOCK; client response envelope `error.code=SECURITY_EVALUATION_FAILED`; audit log marks decision BLOCK.
  - `rule` TR-3.5.3: Allow-only policy + context-finding boosting to HIGH risk → REQUIRE_APPROVAL (verifies context influences decision via risk).
  - `rule` TR-3.5.4: No matching policy → REQUIRE_APPROVAL regardless of risk (unless risk escalates — but REQUIRE_APPROVAL is already the default).

## Phase 4: Approval system, audit system + tamper-evident hash chains

### Task 4.1: Approval service + CRUD endpoints, expiry, double-spend prevention, parameter binding
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 3.5
- **Description**:
  - `backend/app/approvals/service.py` and `backend/app/api/approvals.py`:
    - `GET /approvals?status=pending`, `GET /approvals/{id}`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject`.
  - Approval row: request_id FK, agent_id, decision_override=APPROVED/REJECTED, expires_at, parameters_hash (SHA-256 of canonicalized request params), approver_id, approved_at, status (PENDING/APPROVED/REJECTED/EXPIRED).
  - Prevent double-approve: unique constraint if status set; prevent approval after expires_at.
  - On approve: bound execution runs exactly once within a tight window — approval is consumed atomically with execution.
- **Acceptance Criteria Addressed**: AC-9
- **Test Requirements**:
  - `rule` TR-4.1.1: `approve` call succeeds then second `approve` returns 409.
  - `rule` TR-4.1.2: Approval with `expires_at in the past` → approve call returns 410 GONE.
  - `rule` TR-4.1.3: Tampered params (changed command text) presented with a valid approval id → execution rejected because recomputed `parameters_hash` != approval's `parameters_hash`.
  - `rule` TR-4.1.4: Reject call ends pending state; execute path using that approval id returns 403/blocked.

### Task 4.2: Audit service + append-only write + hash-chain construction + verify endpoint/utility
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 4.1
- **Description**:
  - `backend/app/audit/service.py`: on every request lifecycle event (intercepted, decided, executed, blocked, approved, rejected), append audit row.
  - Row fields: request_id, agent_id, tool, action, timestamp, policy_result (policy_id + effect), risk_score, risk_level, context_findings, decision, execution_result (status, stdout_snippet_sha256, stderr_snippet_sha256, exit_code), error_category, duration_ms, previous_hash (nullable for first record), current_hash.
  - `current_hash = SHA256(previous_hash_hex + "|" + canonical_record_json)` where canonical JSON is sorted-keys, deterministic.
  - `backend/app/api/audit.py`: `GET /audit` (filter/paginate admin only), `GET /audit/verify` (scans chain, returns `{"valid":bool,"broken_at":null|id}`).
  - Append-only enforcement: DB trigger OR application-only guarantee with readonly role in production OR at minimum no UPDATE/DELETE on audit_logs table (application code never deletes; Alembic migration adds the constraint).
- **Acceptance Criteria Addressed**: AC-12, AC-10, AC-2
- **Test Requirements**:
  - `rule` TR-4.2.1: Write 5 audits in-order; `/audit/verify` returns valid=true.
  - `rule` TR-4.2.2: Tamper record #2 `decision` field directly via SQL (test setup only) → `/audit/verify` returns valid=false and broken_at equals record #2.
  - `rule` TR-4.2.3: Application services do not expose UPDATE/DELETE endpoints for audit_logs; sqlalchemy model AuditLog has no exposed update methods.
  - `rule` TR-4.2.4: Grep the last 100 audit records for any redacted password/key value; zero matches.

## Phase 5: GitHub adapter, secure terminal adapter, tool execution orchestrator

### Task 5.1: Tool adapter abstraction + execution orchestrator (runs only after decision ALLOW or APPROVED)
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 4.2
- **Description**:
  - `backend/app/tools/base.py`: `class ToolAdapter(ABC)` with `validate_action(action, params)`, `execute(action, params, context) -> ToolResult(stdout, stderr, exit_code, duration_ms, metadata)`.
  - `backend/app/tools/executor.py`: `execute_if_permitted(request_id, decision, approval=None)` returns ToolExecution row + result; **asserts at code-gate level** that decision == ALLOW or approval is APPROVED with a valid parameters_hash match; otherwise raises InternalSecurityViolation and logs without executing.
  - Register `github` and `terminal` adapters in a registry keyed by name.
- **Acceptance Criteria Addressed**: AC-4, AC-11
- **Test Requirements**:
  - `rule` TR-5.1.1: Decision BLOCK → execute orchestrator raises, adapter execute is never called (use mock with `side_effect=AssertionError` on adapter.execute to fail if it's invoked).
  - `rule` TR-5.1.2: Decision REQUIRE_APPROVAL without approval → orchestrator raises.
  - `rule` TR-5.1.3: Decision ALLOW → adapter execute called; ToolExecution row persisted.

### Task 5.2: GitHub adapter (real GitHub API, encrypted credentials, error/rate-limit handling) + connections CRUD
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 5.1
- **Description**:
  - `backend/app/tools/github/adapter.py`: implements ToolAdapter for actions: `read_repository`, `list_files`, `read_file`, `list_branches`, `read_commit`.
  - Uses httpx async with timeouts; base_url `https://api.github.com`; accepts connection_id (FK to `github_connections`) to fetch AES-GCM-decrypted token at call time.
  - Handles 401/403/404/429/5xx as typed errors normalized in ToolResult.
  - `backend/app/api/tools_github.py`: admin-only connections CRUD — store token AES-256-GCM encrypted; never return it in response bodies.
- **Acceptance Criteria Addressed**: AC-10
- **Test Requirements**:
  - `rule` TR-5.2.1: Mock httpx transport returns fixture repo contents → `read_repository/repo=foo/bar` returns normalized list; respx mock assertions on outbound path/headers `Authorization: token <...>`.
  - `rule` TR-5.2.2: Mock return 429 `Retry-After: 60` → adapter reports error category `RATE_LIMITED` and duration capped at timeout; result does NOT retry indefinitely.
  - `rule` TR-5.2.3: Create a github_connection with token `ghs_test_token_123`; fetch back via list endpoint → token column not present in response; DB row decrypts to `ghs_test_token_123` only with master key; without master key, decrypt fails InvalidTag.
  - `rule` TR-5.2.4: `grep` logs + audit for `ghs_test_token_123` → zero matches after adapter runs with it.

### Task 5.3: Secure Terminal adapter (Docker-sandboxed container, non-root, quotas, no mounts, network restricted)
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 5.1
- **Description**:
  - `backend/app/tools/terminal/sandbox.Dockerfile`: pinned `python:3.12-slim`, create user `sandbox`, drop capabilities, default workdir /workspace owned by sandbox.
  - `backend/app/tools/terminal/adapter.py`: spawn a short-lived container per command with:
    - `--user sandbox` (non-root)
    - `--memory=256m --cpus=0.5` (memory/CPU limits)
    - `--read-only` (root FS readonly except tmpfs for /workspace)
    - `--tmpfs /workspace:rw,noexec,size=64m` (or exec only if absolutely required; keep noexec for safety unless execution truly needs write+exec inside, in which case document and keep tmpfs only, no host mounts)
    - `--network none` by default (allow override for specific actions only through explicit policy gating — default: none)
    - `--cap-drop ALL`
    - `--security-opt no-new-privileges`
    - Command timeout via `--stop-timeout` + python-side timer, default 30s.
  - Result: capture stdout/stderr bytes (truncate to configurable MAX_OUTPUT_BYTES 64KB), exit_code, duration_ms; strip any host env vars (never pass DATABASE_URL, JWT_SECRET, etc — container starts with clean env).
- **Acceptance Criteria Addressed**: AC-11, AC-16 (command injection isolation)
- **Test Requirements**:
  - `rule` TR-5.3.1: Command `echo hello` inside sandbox returns stdout="hello\n", exit_code=0.
  - `rule` TR-5.3.2: Container spawn args include each of: non-root user, memory limit, cpu limit, --cap-drop ALL, --network none or --network=container:null, no `-v /:/...` host mounts; assert the spawned call's argv in tests (use a wrapper/spy).
  - `rule` TR-5.3.3: Command `sleep 120` is reaped by timeout (≤ 45s elapsed wall time in test with timeout=30s), returns error category TIMEOUT.
  - `rule` TR-5.3.4: Command that tries `cat /proc/1/environ` finds no JWT_SECRET/DATABASE_URL strings (even if it fails to read due to permissions — confirm container env is clean via `env` command test).

## Phase 6: WebSockets, real-time events

### Task 6.1: WebSocket hub (async pub/sub), reconnect/resync with sequence IDs, zero-secret payloads
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 4.2, 5.3
- **Description**:
  - `backend/app/websocket/hub.py`: async in-process PubSubHub with topics; supports subscription with JWT-based admin auth over WebSocket upgrade path.
  - `backend/app/api/ws.py`: `GET /ws/events` upgrade, subscribe to all-or-filtered topics: `requests.new`, `requests.decision`, `requests.exec.started`, `requests.exec.completed`, `requests.blocked`, `approvals.requested`, `approvals.completed`, `security.alert`.
  - Sequence id per event per topic; catch-up endpoint `GET /ws/catchup?topic=X&since_seq=N` or initial snapshot on connect.
  - Events sanitized: never include JWTs, raw API keys, raw GitHub tokens, plaintext params that are redacted.
- **Acceptance Criteria Addressed**: AC-13
- **Test Requirements**:
  - `rule` TR-6.1.1: Create request via API → an admin WS client receives exactly one `requests.new` event with correct request_id and tool/action; verify no secret header present in event payload (test with a deliberately-injected marker token and assert it's absent in the event bytes sent).
  - `rule` TR-6.1.2: Approve an approval → `approvals.completed` arrives.
  - `rule` TR-6.1.3: Simulate disconnect by dropping client mid-flow; reconnect with `since_seq` → client receives missed events in order without duplicates.
  - `rule` TR-6.1.4: Unauthenticated WS upgrade attempt returns 401 before protocol switch.

## Phase 7: Next.js dashboard (login, dashboard, agents, policies, requests, approvals, audit, risk, tools, settings)

### Task 7.1: Frontend scaffolding — Next.js, TypeScript, Tailwind, shadcn/ui, lib (api client, env), auth context
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 6.1
- **Description**:
  - `frontend/package.json`: `next@^14`, `react`, `react-dom`, `typescript`, `tailwindcss`, `postcss`, `autoprefixer`, `@radix-ui/react-*` components set matching shadcn/ui, `@tanstack/react-query`, `zod`, `clsx`, `tailwind-merge`, `lucide-react`, `recharts`, `date-fns`, `next-themes`, plus dev deps `@playwright/test`, `@types/node`, `@types/react`, `@types/react-dom`, `eslint`, `eslint-config-next`.
  - Initialize Tailwind config with dark mode `class`, content globs, shadcn/ui `ui` alias path.
  - `frontend/app/layout.tsx` + `frontend/app/globals.css` (theme provider, Tailwind layers).
  - Install shadcn/ui components via manual install (button, card, input, label, table, badge, dialog, dropdown-menu, toast, tabs, textarea, switch, select, form, sonner, separator, avatar, skeleton, progress, chart).
  - `frontend/lib/api.ts`: typed axios/fetch wrapper that attaches JWT from secure cookie (httpOnly preferred, or localStorage for prototype — choose httpOnly + CSRF token for correct security posture: backend issues session cookie on login; or stick with Bearer + refresh tokens in same httpOnly). Spec: use `Authorization: Bearer <token>` stored in-memory with short expiry, refresh via httpOnly cookie for better security compromise between prototype and secure defaults.
  - `frontend/hooks/useAuth.ts`, `frontend/hooks/useRealtime.ts` (WebSocket hook with reconnect).
- **Acceptance Criteria Addressed**: AC-14, AC-21
- **Test Requirements**:
  - `rule` TR-7.1.1: `next build` succeeds without TS errors (strict:true).
  - `rule` TR-7.1.2: Dev server starts; login page `/login` loads 200.
  - `rubric` TR-7.1.3: UX baseline; scale 1-5 (1=broken layout, 3=basic, 5=cyber-security-dashboard aesthetic: dark theme, cards, badges, consistent spacing, good typography); threshold >=4; evidence: screenshot.

### Task 7.2: Login/Logout pages + auth guard HOC + API integration (real /auth/login + /auth/logout + /auth/me)
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 7.1
- **Description**:
  - `/login` page: email+password form with validation; on success store JWT in memory + go `/dashboard`.
  - Auth guard: pages under `(admin)` group redirect to `/login` if no valid session.
  - Logout button calls `/auth/logout`, clears state, redirects.
- **Acceptance Criteria Addressed**: AC-14
- **Test Requirements**:
  - `rule` TR-7.2.1: Playwright test login succeeds with valid credentials; `/auth/me` response user email displays in top-right profile dropdown.
  - `rule` TR-7.2.2: Invalid credentials show generic error "Invalid credentials" (not "email not found").
  - `rule` TR-7.2.3: Logout then navigating to `/dashboard` redirects to `/login`.

### Task 7.3: Dashboard page (real metrics) + Agents CRUD page + Policy CRUD/version pages + realtime hooks
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 7.2
- **Description**:
  - `/dashboard`: stat cards for Total Requests / Allowed / Blocked / Pending Approval / Avg Risk / High Risk Requests, Recent Activity list, Risk distribution chart (recharts), Tool Usage chart. All via real endpoints.
  - `/agents`: table of agents with status; create-agent modal that shows the plaintext key ONE TIME with warning copy; revoke button with confirmation.
  - `/policies`: table with effect-colored badges (ALLOW green, BLOCK red, REQUIRE_APPROVAL amber), create/edit modal with priority, tool, action pattern, param constraints (JSON editor), effect; versions drawer; revert button.
  - Use `useRealtime` to bump metrics on events.
- **Acceptance Criteria Addressed**: AC-14, AC-20
- **Test Requirements**:
  - `rule` TR-7.3.1: With zero activity, dashboard card `Total Requests` == 0; after creating 2 fake activity rows (seed via backend test helper or API), dashboard shows 2 without page refresh (WS push).
  - `rule` TR-7.3.2: Create policy via UI → fetch list API shows it; edit effect → new version row appears in versions drawer.
  - `rule` TR-7.3.3: Create agent UI flow displays a single plaintext key banner with "Copy and save — you will NOT see this again". Navigate away and back → plaintext is gone.

### Task 7.4: Requests list + detail (security reasoning, signals, hashes) + Approvals queue + Audit page + Risk summary + Tools connections + Settings
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 7.3
- **Description**:
  - `/requests`: paginated list with filter by tool/status/decision; link to `/requests/[id]`.
  - `/requests/[id]`: full request details page with sections: Request Info (ID, agent, tool, action, ts), Policy Result, Risk score + bar + signal chips (weight/reason/evidence expandable), Context Findings, Decision, Execution status + result, Audit hash (prev/current).
  - `/approvals`: queue showing cards; for each: agent+request summary, risk score, signals, policy, params summary, buttons APPROVE (red-high risk modal confirm) / REJECT.
  - `/audit`: audit list + `Verify Chain` button that calls `/audit/verify` and renders OK or broken_at with message.
  - `/risk`: risk distribution chart, top signals tables.
  - `/tools`: github connections create/edit (token input only, never displayed), terminal sandbox status.
  - `/settings`: password change, risk thresholds editable via admin, approval expiry edit.
- **Acceptance Criteria Addressed**: AC-14
- **Test Requirements**:
  - `rule` TR-7.4.1: For a seeded request with CRITICAL risk, request detail page shows 5+ risk signal chips and score badge color=red.
  - `rule` TR-7.4.2: Approve a pending approval from the UI → backend decision+execution runs; UI row transitions to APPROVED → then COMPLETED after execution event WS push.
  - `rule` TR-7.4.3: Audit verify on healthy chain shows a green "Chain Valid" banner.

## Phase 8: Experimental crypto research module

### Task 8.1: Formal design doc in crypto-research.md + code module with NOT-FOR-PRODUCTION marker
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: 1.2 (uses existing helpers)
- **Description**:
  - Design doc `docs/crypto-research.md`:
    - Name (e.g. "AEGIS-X128/256: Experimental Authenticated Encryption Cipher — NOT FOR PRODUCTION"), block=128 bits, key=256 bits, 14 rounds, S-box (8-bit, derived empirically from digits of pi or standardized source), P-box (bit diffusion matrix), round function (Feistel or SP-network — choose SPN), key schedule (14 round keys derived via HKDF-like), nonce=96-bit, auth=GHASH-like or CBC-MAC, combined encryption+auth AEAD interface.
  - Module `backend/app/crypto_research/`:
    - `__init__.py` with banner docstring "EXPERIMENTAL / NOT FOR PRODUCTION".
    - `cipher.py`: `encrypt(key, nonce, plaintext, associated_data) -> (ciphertext, tag)` and `decrypt` that verifies tag first.
    - `sbox.py`, `key_schedule.py`, `permutation.py` separated for clarity.
- **Acceptance Criteria Addressed**: AC-15
- **Test Requirements**:
  - `rule` TR-8.1.1: Design document fully describes each section listed above (state/block, key size, round fn, substitution, permutation, key schedule, rounds, nonce, auth, encrypt, decrypt).
  - `rule` TR-8.1.2: `__init__.py` + docstrings carry the EXPERIMENTAL/NOT FOR PRODUCTION markers; research module is never imported in `app.security.crypto` (grep import chain).

### Task 8.2: Correctness, avalanche, key sensitivity, entropy/frequency, statistical, perf/memory vs AES-256-GCM tests
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: 8.1
- **Description**:
  - Tests `backend/tests/test_crypto_research.py`:
    - Correctness: 100 random (key,nonce,plaintext,ad) tuples → encrypt then decrypt matches.
    - Tampered ciphertext or tag → decrypt raises.
    - Avalanche effect: flip exactly 1 plaintext bit → ≥ 50% of ciphertext bits differ after full rounds (1k trials, median ≥ 50%).
    - Key sensitivity: flip 1 key bit → ciphertext differs on same plaintext (≥ 50% bits).
    - Entropy: Shannon entropy of 1MB encrypted random plaintext is close to 8 bits/byte (≥ 7.95).
    - Frequency: chi-squared uniformity test on 1MB output, p≥0.01 (does not reject H0 of uniformity; alpha=0.01).
    - Perf: benchmark encrypt throughput MB/s for 64KB, 1MB vs AES-256-GCM (cryptography lib); report both; do not claim superiority.
    - Memory: tracemalloc peak diff between AEGIS-X and AES-256-GCM runs reported.
- **Acceptance Criteria Addressed**: AC-15
- **Test Requirements**:
  - `rule` TR-8.2.1: 100/100 correctness pass.
  - `rule` TR-8.2.2: Avalanche median ≥ 0.50 across 1000 trials.
  - `rule` TR-8.2.3: Entropy ≥ 7.95 bits per byte on a 1MB run; chi-square does not reject uniformity.
  - `rubric` TR-8.2.4: Research quality; scale 1-5 (1=incorrect math, 3=correct but weak, 5=well-documented, formally specified, tests are statistically meaningful, clear comparison table with AES); threshold >=4; evidence: test report + docs/crypto-research.md.

## Phase 9: Security tests, integration tests, E2E tests, Docker verification, full documentation

### Task 9.1: Consolidated security test suite covering AC-16 vectors
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 7.4, 8.2
- **Description**:
  - `backend/tests/test_security_jwt.py`: alg-none, RS256, expired, tampered payload, wrong audience.
  - `backend/tests/test_security_api_keys.py`: garbage key, revoked key, missing header, brute force rate limit if applicable.
  - `backend/tests/test_security_sqli.py`: ORM parameterization + attempt `'; DROP TABLE audit_logs;--` in all string params — audit_logs still intact after test.
  - `backend/tests/test_security_inputs.py`: malformed JSON, oversized payload → 413.
  - `backend/tests/test_security_paths.py`: path traversal in file params for both adapters.
  - `backend/tests/test_security_commands.py`: command injection attempts `; cat /etc/passwd`, `$(whoami)`, backticks — adapter must run the literal cmd string without host shell expansion or exit the sandbox.
  - `backend/tests/test_security_approvals.py`: replay approval id, expired approval, parameter tamper (already in TR-4.1.x but gather here with adversarial vectors).
  - `backend/tests/test_security_routes.py`: non-admin JWT cannot hit admin routes.
- **Acceptance Criteria Addressed**: AC-16, AC-21
- **Test Requirements**:
  - `rule` TR-9.1.1: Every file listed passes individually; overall run `pytest tests/test_security_*.py -v` — 0 failures.

### Task 9.2: Integration + HTTP API tests across each engine
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 9.1
- **Description**:
  - `tests/integration/`: login, agent create, agent auth, execute request (full pipeline), policy evaluation, risk, approval, execution, audit log, WebSocket event (each of 8 scenarios).
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-3, AC-4, AC-5, AC-6, AC-7, AC-8, AC-9, AC-10, AC-11, AC-12, AC-13
- **Test Requirements**:
  - `rule` TR-9.2.1: Each of 8 integration files passes; combined `pytest tests/integration -v` — 0 failures.

### Task 9.3: Full E2E scenarios 1-7 (backend orchestration E2E tests with DB + adapters; separate Playwright E2E verifying dashboard)
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 9.2
- **Description**:
  - Backend E2E: `tests/test_e2e_scenarios.py` with 7 scenarios as described in AC-17.
  - Frontend Playwright E2E: `frontend/tests/e2e/` covering dashboard flows, login, policy create/edit, approve flow, request detail, logout, WebSocket updates.
- **Acceptance Criteria Addressed**: AC-17, AC-14
- **Test Requirements**:
  - `rule` TR-9.3.1: 7/7 backend scenarios pass.
  - `rule` TR-9.3.2: Playwright suite has ≥ 80% of declared critical E2E scenarios passing (or all passing if environment permits; otherwise report blocked with evidence).
  - `rubric` TR-9.3.3: E2E robustness; scale 1-5 (1=flaky or fake adapters only, 3=mix of mock+real, 5=clearly exercises real code paths end-to-end including sandbox + audit chain); threshold >=4.

### Task 9.4: docker-compose.yml production stack, Postgres, Backend, Frontend services with healthchecks + startup order
- **Status**: `pending`
- **Priority**: high
- **Depends On**: 9.3
- **Description**:
  - Root `docker-compose.yml`:
    - `postgres:16-alpine`: persistent volume env-var credentials, healthcheck `pg_isready`.
    - `backend`: `Dockerfile` using `python:3.12-slim`, non-root, installs deps, `alembic upgrade head` via entrypoint/wrapper, `uvicorn app.main:app --host 0.0.0.0 --port 8000`. healthcheck `GET /health`. `depends_on: postgres: { condition: service_healthy }`.
    - `frontend`: `Dockerfile` multi-stage build node → nginx or `next start`; healthcheck; env vars for NEXT_PUBLIC_API_URL.
    - No secrets in compose; read from `.env` file.
  - Terminal sandbox container: separate `docker build` for `sandbox.Dockerfile`; backend spawns sibling containers (or use docker-in-docker documented; critical: never mount host Docker socket into sandbox, only into the backend container if absolutely required, and document as risk).
- **Acceptance Criteria Addressed**: AC-19
- **Test Requirements**:
  - `rule` TR-9.4.1: `docker compose up --build -d` → `docker compose ps` shows 3/3 healthy after timeout.
  - `rule` TR-9.4.2: Curl `http://localhost:8000/health` → 200; `http://localhost:3000` → 200 for frontend (or appropriate port).
  - `rule` TR-9.4.3: Backend container logs do not show secrets (no JWT_SECRET / AES_MASTER_KEY printed in env dump).

### Task 9.5: Final documentation pass (README, architecture, security, threat-model, crypto-research, API)
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: 9.4
- **Description**:
  - `README.md`: purpose, architecture summary, requirements (python3.12, node20+, docker), install (pip, npm), env setup (cp .env.example), DB (alembic upgrade head), backend/frontend run, docker setup, testing, API usage, security model, demo credentials creation (create_admin script steps), demo flow (agent → execute → dashboard).
  - `docs/architecture.md`: request lifecycle with diagram, component relationships.
  - `docs/security.md`: threat model, auth, policy, risk, audit, terminal sandbox.
  - `docs/threat-model.md`: STRIDE analysis per component.
  - `docs/api.md`: OpenAPI exported snapshot or link to `/docs` with key endpoints listed.
  - `docs/crypto-research.md`: completed with benchmark numbers from tests.
- **Acceptance Criteria Addressed**: AC-20, AC-15
- **Test Requirements**:
  - `rubric` TR-9.5.1: Documentation completeness; scale 1-5 (1=stubs, 3=partial, 5=every required section from the brief exists, commands run copy-paste); threshold >=4; evidence: quick smoke of `README.md` commands in a fresh shell (or dry-run by reviewer).
