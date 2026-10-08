# Aegis - Product Requirements Document

## Overview
- **Summary**: Aegis is a real, working Runtime Security Gateway that intercepts tool-requests from autonomous AI agents before any external action is taken, then authenticates, evaluates policy, scores risk, analyzes context, renders a deterministic security decision, requires human approval when warranted, executes approved tools via adapters, writes tamper-evident audit records, and streams all events to a real-time admin dashboard over WebSockets.
- **Purpose**: Prevent unvetted, high-risk, or unapproved AI-agent actions from reaching external systems (GitHub, terminals) while producing an auditable, human-reviewable record of every decision.
- **Target Users**: (1) Security administrators who configure policies, review approvals, and audit agent actions via the web dashboard. (2) AI agent developers who route tool calls through the gateway using per-agent API keys. (3) Security researchers evaluating the deterministic engines and the experimental crypto module.

## Goals
1. Build a **fail-closed** gateway: any unexpected internal security error blocks the request; the default policy is `REQUIRE_APPROVAL`, never unrestricted `ALLOW`.
2. Guarantee that **no external tool executes before** authentication, policy, risk, context, and decision engines have run.
3. Provide three unambiguous outcomes for every request: `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`.
4. Produce **tamper-evident audit records** with chained SHA-256 hashes and a verifier.
5. Implement **real, working, testable** integrations with GitHub (read-only adapter) and a **Docker-sandboxed** terminal adapter.
6. Ship a **real-time admin dashboard** (Next.js + Tailwind + shadcn/ui) that updates live via WebSockets and only surfaces real backend data (no mock numbers).
7. Implement an **isolated experimental cryptographic construction** in a dedicated research module with a clear "NOT FOR PRODUCTION" marker and side-by-side benchmarks vs AES-256-GCM.
8. Pass a comprehensive **unit / integration / security / E2E** test suite covering every engine, every security invariant, and the full agent → policy → risk → decision → tool → audit → dashboard pipeline.
9. Package the system with a working **Docker Compose** stack (postgres, backend, frontend).

## Non-Goals
1. Aegis is **not a SIEM** — its primary purpose is `INTERCEPT → EVALUATE → DECIDE → EXECUTE_OR_BLOCK`, not log aggregation at enterprise scale.
2. The **experimental crypto module must never replace** AES-256-GCM for production encryption of secrets.
3. No public self-registration for admins; accounts are created via a bootstrap CLI only.
4. The terminal adapter does **not** execute arbitrary commands on the host; it runs inside a Docker-sandboxed isolated container with CPU, memory, network, and filesystem restrictions.
5. No unrestricted GitHub credentials are ever exposed to agents.

## Background & Context
The full architectural spec and implementation order (Phases 1-9) are defined in the referenced long-text project brief. Key invariants that must always hold:
- INV-1: No unauthenticated agent request reaches a tool.
- INV-2: No request reaches a tool before policy/risk/context/decision evaluation.
- INV-3: `BLOCK` means the tool MUST NOT execute.
- INV-4: `REQUIRE_APPROVAL` means the tool MUST NOT execute until approved.
- INV-5: Expired approval MUST NOT execute.
- INV-6: Revoked API key MUST NOT execute.
- INV-7: Unexpected security evaluation failure MUST BLOCK.
- INV-8: Sensitive credentials MUST NEVER appear in logs.
- INV-9: The experimental algorithm MUST NEVER replace AES-256-GCM.
- INV-10: Frontend state is never the source of truth for authorization; backend authorization is authoritative.

## Functional Requirements
- **FR-1 Admin Authentication**: `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` using Argon2id + JWT (HS256, 15-min access tokens, explicit alg rejection). Admin-only bootstrap CLI: `python -m app.scripts.create_admin`. Login rate limiting. Generic login errors + dummy password verification to prevent username enumeration.
- **FR-2 Agent Authentication & API Keys**: `POST /agents`, `GET /agents`, `POST /agents/{id}/revoke`, `GET /agents/me`. API keys generated with CSPRNG; database stores `HMAC-SHA256(key + server_pepper)` only; plaintext shown once at creation. Key states: active / revoked / invalid.
- **FR-3 Execution Gateway**: `POST /v1/execute` runs the full pipeline: (1) auth, (2) request validation + unique request ID, (3) policy, (4) risk, (5) context, (6) decision, (7) approval if required, (8) tool execution if allowed, (9) audit, (10) WebSocket emission.
- **FR-4 Policy Engine**: Deterministic, first-match-wins after priority ordering. Policies support id, name, description, priority, tool, action pattern, parameter constraints, effect (ALLOW/BLOCK/REQUIRE_APPROVAL), enabled, version. CRUD APIs + versioning. Default: no-match = REQUIRE_APPROVAL.
- **FR-5 Risk Engine**: Deterministic, explainable risk score 0-100 with LOW (0-29) / MEDIUM (30-59) / HIGH (60-79) / CRITICAL (80-100) configurable thresholds. Signals: destructive action, sensitive resource, privileged tool, unusual action, first-time tool, request frequency, suspicious params, prompt injection indicators, unusual behavior, sensitive data access. Each signal exposes name, weight, reason, evidence.
- **FR-6 Context Engine**: Analyzes first-time tool usage, recent request history/frequency, previous decisions/failures, unusual action patterns, and agent behavior. Findings influence the decision engine (e.g., an agent that only reads GitHub and suddenly runs terminal deletes is flagged unusual).
- **FR-7 Decision Engine**: Strict deterministic precedence: (1) BLOCK policy → BLOCK, (2) CRITICAL/HIGH risk → REQUIRE_APPROVAL, (3) policy requires approval → REQUIRE_APPROVAL, (4) explicit ALLOW + acceptable risk → ALLOW, (5) unexpected evaluation error → BLOCK.
- **FR-8 Approval System**: `GET /approvals`, `GET /approvals/{id}`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject`. Approval expiry. Prevent double approve/reject, expired approvals, and parameter tampering between approval and execution (approval is bound to a specific, signed/hash-of-parameters request).
- **FR-9 Tool Adapters**: (a) `GitHubAdapter`: read repo, list files, read file, list branches, read commit via GitHub API with timeout/rate-limit/403/404/5xx handling; credentials encrypted at rest. (b) `Secure Terminal Adapter`: Docker-based isolated container with timeout, memory/CPU limits, non-root user, restricted filesystem, no host mount, no Docker socket. Dangerous commands blocked by policy. Returns stdout/stderr/exit_code/duration.
- **FR-10 Audit Logging & Tamper Evidence**: Every request creates an audit record with chained hashes: `current_hash = SHA256(previous_hash + canonicalized_current_record)`. Verification API/utility. Never logs passwords/JWTs/API keys/secrets.
- **FR-11 Real-Time WebSockets**: Events for: new execution request, decision made, execution started, execution completed, blocked request, approval requested, approval completed, security alert. Reconnect handling. No secrets in messages.
- **FR-12 Admin Dashboard (Next.js)**: Pages `/login`, `/dashboard`, `/agents`, `/policies`, `/requests`, `/approvals`, `/audit`, `/risk`, `/tools`, `/settings`. Dashboard renders real backend data for total requests, allowed, blocked, pending approval, average risk, high-risk requests, recent activity, risk distribution, tool usage. Real-time updates via WebSocket. Request detail page surfaces full security reasoning and audit hash. Policy CRUD UI with effect badges. Approval queue with approve/reject.
- **FR-13 Experimental Crypto Module**: Isolated module under `backend/app/crypto_research/` — formally designed (state/block size, key size, round fn, S-boxes/substitution, P-box/permutation/diffusion, key schedule, rounds, nonce, auth mechanism, encrypt/decrypt), implemented, and tested (correctness, avalanche, key sensitivity, entropy, frequency, statistical, perf/memory vs AES-256-GCM). Marked EXPERIMENTAL / NOT FOR PRODUCTION.
- **FR-14 Observability & Health**: Structured logging with request id/agent id/tool/action/latency/decision (no secrets). `GET /health`, `GET /health/ready` verifies DB readiness.
- **FR-15 Database & Migrations**: PostgreSQL via SQLAlchemy + Alembic initial migration and working migration rollback test. Entities: admins, agents, agent_api_keys, policies, policy_versions, execution_requests, risk_assessments, context_assessments, decisions, approvals, tool_executions, audit_logs, github_connections, terminal_sessions. UUID PKs, created_at/updated_at, FKs, indexes, constraints, cascades.
- **FR-16 Docker**: `docker-compose.yml` with postgres, backend, frontend services, health checks, backend waits for Postgres readiness, env-var driven (no hardcoded creds).
- **FR-17 Security Surfaces**: Input validation, output sanitization, parameterized SQL (ORM), CSRF/CORS, security headers, rate limiting, request size limits, timeouts, structured error handling that never leaks stack traces in production.

## Non-Functional Requirements
- **NFR-1 Fail-Closed**: Any exception from policy/risk/context/decision/adapters during evaluation of a request → decision is `BLOCK`.
- **NFR-2 Determinism**: Given the same request and DB state, the same decision is produced; the decision engine is unit-tested to that property.
- **NFR-3 Secret Zero-Logging**: A grep for passwords, raw API keys, JWTs, encryption keys, OAuth tokens in application logs, audit records, and WS payloads returns no matches.
- **NFR-4 Security First UX**: Dashboard does not surface secrets; approval UI requires explicit confirmation for high-risk actions; policy UI disables/enables with effect badges.
- **NFR-5 Build & Migrate**: Backend starts after Alembic migration on a fresh DB; frontend starts and connects to the backend API. Docker Compose brings the stack up healthy.
- **NFR-6 Test Coverage (evidence-backed)**: Backend unit/integration/security/E2E tests actually execute and pass. Playwright tests for key dashboard flows actually execute and pass.

## Constraints
- **Technical**: Backend = Python 3.12 + FastAPI + Pydantic + SQLAlchemy + Alembic + PostgreSQL. Frontend = Next.js + React + TypeScript + Tailwind + shadcn/ui. Auth = Argon2id + JWT (HS256 only) + API keys (HMAC-SHA256 + server-side pepper). Runtime crypto = AES-256-GCM. Websockets. Pytest + HTTP integration tests + Playwright. Docker + Docker Compose.
- **Business**: No TODOs, mocks, placeholders, or fake API responses for core functionality. Every major component must communicate and be tested.
- **Dependencies**: Python packages (fastapi, uvicorn, sqlalchemy, alembic, asyncpg, pydantic-settings, argon2-cffi, PyJWT, python-multipart, httpx, slowapi, cryptography, psutil, pytest, pytest-asyncio, httpx, etc.). Npm packages: next, react, react-dom, typescript, tailwindcss, shadcn-ui components, @tanstack/react-query, zod, etc. Docker and Docker Compose for local execution and the sandboxed terminal.

## Assumptions
1. The target runtime has Docker Engine and Docker Compose available for the PostgreSQL service and the terminal sandbox.
2. GitHub integration tests requiring a real token will provide a test-mode path using httpx mock transports with recorded realistic responses and a separate integration path gated by a `GITHUB_TEST_TOKEN` env var; tests must pass in CI without external tokens (mock path) and be verified manually with a real token when available.
3. Playwright/browser tests are run with the Playwright test runner; the CI environment has the required browser binaries installed (or `npx playwright install` is run first).
4. Experimental crypto module benchmarks are best-effort within the environment but must demonstrate correctness and avalanche properties statistically.
5. For this prototype, the secure terminal container image is either built from a Dockerfile in the repo or uses a standard minimal sandbox image; the critical invariant is that commands never run on the host.

## Acceptance Criteria

### AC-1: Backend starts and health endpoints work after migration
- **Type**: `rule`
- **Given**: A fresh PostgreSQL database, `.env` configured, and Alembic migrations applied.
- **When**: The backend is started and `GET /health` and `GET /health/ready` are called.
- **Then**: Both return 200 with JSON indicating `ok`, and `ready` confirms DB connectivity.
- **Pass Condition**: `curl /health` → 200; `curl /health/ready` → 200; backend logs contain no startup errors.
- **Evidence**: Backend test `tests/test_health.py` passes; manual `curl` output recorded in task completion.

### AC-2: Admin authentication flow (login/logout/me + rate limit + no enumeration)
- **Type**: `rule`
- **Given**: An admin account created via `python -m app.scripts.create_admin`.
- **When**: Login with correct credentials, invalid credentials, repeated invalid attempts, then `GET /auth/me` and `POST /auth/logout`.
- **Then**: Valid login returns JWT (HS256 only, 15-min expiry); `/auth/me` returns admin info; `/auth/logout` succeeds; invalid credentials return generic 401; after N attempts rate limit returns 429; timing of invalid-user vs invalid-password is indistinguishable within tolerance.
- **Pass Condition**: Backend integration tests `tests/test_auth_admin.py` and `tests/test_security_auth.py` pass.
- **Evidence**: `pytest tests/test_auth_admin.py tests/test_security_auth.py -v` output.

### AC-3: Agent creation, key display-once, key revocation, and agent/me
- **Type**: `rule`
- **Given**: Admin JWT.
- **When**: `POST /agents` → then agent calls `GET /agents/me` with the returned API key → then `POST /agents/{id}/revoke` → then agent retries with the revoked key.
- **Then**: Agent creation returns a plaintext key exactly once; DB stores only HMAC-SHA256(key+pepper); valid key authenticates; revoked key returns 401; `GET /agents` lists agents; `/agents/me` identifies the calling agent.
- **Pass Condition**: Backend tests `tests/test_agents.py` and `tests/test_security_api_keys.py` pass.
- **Evidence**: `pytest tests/test_agents.py tests/test_security_api_keys.py -v` output.

### AC-4: POST /v1/execute runs the full pipeline (intercept → evaluate → decision) and tool never executes before decision
- **Type**: `rule`
- **Given**: A valid agent API key and a policy that BLOCKs destructive terminal commands.
- **When**: POST `/v1/execute` with `{tool: terminal, action: delete, parameters: ...}`.
- **Then**: Decision returned is BLOCK; no container/process is spawned (verifiable via adapter counter or mock adapter that throws if called for blocked actions); audit record exists; WebSocket event for blocked request is emitted.
- **Pass Condition**: `tests/test_execute_pipeline.py` scenario BLOCK, and the strict execution-order unit test (mock that fails if adapter called before decision) passes.
- **Evidence**: `pytest tests/test_execute_pipeline.py -v` output + strict order test output.

### AC-5: Policy engine is deterministic — first-match-wins by priority; no match = REQUIRE_APPROVAL
- **Type**: `rule`
- **Given**: Enabled policies with explicit priorities and one matching ALLOW, one matching BLOCK.
- **When**: Evaluate a request that matches both.
- **Then**: The policy with the higher priority (lowest numeric, per schema) wins; request that matches no policy returns REQUIRE_APPROVAL.
- **Pass Condition**: `tests/test_policy_engine.py` passes (determinism matrix, priority tests, default-behavior tests).
- **Evidence**: `pytest tests/test_policy_engine.py -v` output.

### AC-6: Risk engine produces deterministic, explainable score + signals within thresholds
- **Type**: `rule`
- **Given**: A destructive terminal command (rm -rf) and a safe GitHub read call.
- **When**: Risk engine evaluates both.
- **Then**: Destructive command returns HIGH or CRITICAL risk with named, weighted signals; safe read returns LOW. Score is reproducible (same inputs → same score). Signal names, weights, reason, evidence are all present.
- **Pass Condition**: `tests/test_risk_engine.py` passes (determinism, signal list, threshold mapping, avalanche of action differences).
- **Evidence**: `pytest tests/test_risk_engine.py -v` output.

### AC-7: Context engine detects unusual behavior and affects decision
- **Type**: `rule`
- **Given**: An agent history of 50 github/read_repository calls.
- **When**: Same agent requests `terminal/delete_files`.
- **Then**: Context engine records an "unusual action pattern" finding; decision engine (via precedence rule 2) promotes to REQUIRE_APPROVAL even if a policy would otherwise ALLOW.
- **Pass Condition**: `tests/test_context_engine.py` and `tests/test_decision_engine.py` cross-test pass.
- **Evidence**: `pytest tests/test_context_engine.py tests/test_decision_engine.py -v` output.

### AC-8: Decision engine strictly follows precedence and fails closed on exceptions
- **Type**: `rule`
- **Given**: Explicit BLOCK policy, explicit ALLOW policy with CRITICAL risk, ALLOW with medium risk, and a policy-engine exception injected via mock.
- **When**: Decision engine is invoked for each case.
- **Then**: (1) BLOCK policy → BLOCK, (2) ALLOW + CRITICAL → REQUIRE_APPROVAL, (3) ALLOW + MEDIUM → ALLOW, (4) exception → BLOCK.
- **Pass Condition**: `tests/test_decision_engine.py` precedence matrix passes; exception-injection test returns BLOCK.
- **Evidence**: `pytest tests/test_decision_engine.py -v` output.

### AC-9: Approval workflow (expiry, double-spend prevention, parameter tamper protection)
- **Type**: `rule`
- **Given**: An execution that returns REQUIRE_APPROVAL.
- **When**: Admin calls approve → same approval_id approve again → another request attempts to reuse approval → wait for expiry then try to execute.
- **Then**: First approve succeeds and the bound request executes; second approve returns 409/already processed; unbound request with reused approval signature is rejected; expired approval returns 410 and never executes.
- **Pass Condition**: `tests/test_approvals.py` passes (all 4 sub-scenarios: approve, double, tamper, expire).
- **Evidence**: `pytest tests/test_approvals.py -v` output.

### AC-10: GitHub adapter — read operations succeed, errors handled, tokens never logged
- **Type**: `rule`
- **Given**: A configured GitHub connection (AES-256-GCM encrypted token at rest) and a mock httpx transport returning sample repo/file responses plus injected 403/404/rate-limit/timeout.
- **When**: Read repository, list files, read file, list branches, read commit are called; also each error case.
- **Then**: Success cases return normalized tool results; error cases return typed errors; logs + audit never contain the token; token cannot be recovered from DB column without master key.
- **Pass Condition**: `tests/test_github_adapter.py` passes; log-scan test (grep logs for token value) passes; decrypt-tamper test (invalid master key fails) passes.
- **Evidence**: `pytest tests/test_github_adapter.py tests/test_crypto_secrets.py -v` output.

### AC-11: Secure Terminal adapter — commands run inside sandbox, host isolation respected, blocked commands never spawn
- **Type**: `rule`
- **Given**: Docker Engine available for the sandbox container (or mock spawner that records container parameters).
- **When**: Execute `echo hello` in sandbox and verify returned stdout/stderr/exit_code/duration; also attempt `rm -rf /` after a BLOCK policy.
- **Then**: `echo hello` returns stdout="hello\n" exit=0 from inside the sandbox container with non-root, memory/CPU limits, no host mounts; blocked `rm -rf /` never spawns a container.
- **Pass Condition**: `tests/test_terminal_adapter.py` passes (spawn config asserts) + `tests/test_security_terminal_isolation.py` passes.
- **Evidence**: `pytest tests/test_terminal_adapter.py tests/test_security_terminal_isolation.py -v` output.

### AC-12: Audit hash chain — append-only integrity verified end-to-end
- **Type**: `rule`
- **Given**: A sequence of 5 execution requests creating 5 audit records.
- **When**: Tamper with the `decision` column of the 2nd record then run the verifier.
- **Then**: Verifier detects the break exactly at record #2; before tampering, verifier returns OK for the whole chain; each record stores both previous_hash and current_hash.
- **Pass Condition**: `tests/test_audit_chain.py` chain-of-5 + tamper-detection test passes.
- **Evidence**: `pytest tests/test_audit_chain.py -v` output.

### AC-13: WebSocket events — dashboard receives events with reconnect and zero-secret payloads
- **Type**: `rule`
- **Given**: An admin WebSocket authenticated to `/ws/events`.
- **When**: An agent issues a request that triggers: new request, decision, execution start, complete.
- **Then**: All 4 events arrive in order; payloads include request id, tool, action, decision; no JWT/API keys/tokens appear in any event. Simulated disconnect + reconnect: client resumes and receives missed events (via catch-up query or sequence id).
- **Pass Condition**: `tests/test_websocket_events.py` order + no-secret scan + reconnect-resync passes.
- **Evidence**: `pytest tests/test_websocket_events.py -v` output.

### AC-14: Dashboard (Next.js) — login, policy CRUD, approval flow, request details all backed by real APIs + real-time WebSocket updates
- **Type**: `rule`
- **Given**: Running backend + seeded DB.
- **When**: Playwright runs the dashboard E2E suite: login → navigate /dashboard (verify metrics != static zeros) → /agents → create agent → /policies create policy → run agent request → /approvals approve → /audit see record → /requests/{id} see details → WebSocket live tile updates without refresh.
- **Then**: Every step passes; no screen renders static placeholder numbers; create/read/update policy actually persists to DB; approve actually executes the tool; audit record hashes visible.
- **Pass Condition**: `frontend/tests/e2e/...` Playwright suite passes.
- **Evidence**: `cd frontend && npx playwright test` output (or `npm test`) with passing counts.

### AC-15: Experimental crypto module — correctness, avalanche, key sensitivity, entropy, statistical, and AES comparison benchmarks
- **Type**: `rule`
- **Given**: The research module under `crypto_research/` marked EXPERIMENTAL/NOT-FOR-PRODUCTION, with documented state/block/key sizes, round function, S-boxes, P-box, key schedule, nonce, auth mechanism, encrypt/decrypt.
- **When**: Run `pytest tests/test_crypto_research.py` which exercises encrypt→decrypt round-trip, single-bit flip (avalanche ≥ half-bits changed after full rounds), single-bit key flip (different ciphertext), frequency test near-uniform, Shannon entropy, perf/memory vs AES-256-GCM recorded.
- **Then**: All tests pass with numeric thresholds; docs/crypto-research.md summarizes results without claiming superiority over AES.
- **Pass Condition**: `pytest tests/test_crypto_research.py -v` passes.
- **Evidence**: Pytest output + summarized benchmark table.

### AC-16: Security suite — invalid JWT algorithms, SQLi, path traversal, command injection, approval replay, oversized requests, rate-limit abuse, unauthorized admin routes
- **Type**: `rule`
- **Given**: Running backend under test.
- **When**: Each security vector from the brief is applied.
- **Then**: JWT alg=none/RS256 rejected; SQLi payloads never execute raw SQL (ORM-only parameterized); path traversal never escapes sandbox root; command injection never leaks out of adapter abstraction; approval replay rejected; >max payload returns 413; rate-limited endpoint returns 429; non-admin JWT on /agents/create returns 403.
- **Pass Condition**: `pytest tests/test_security_*.py -v` passes all.
- **Evidence**: Consolidated security test output.

### AC-17: Full E2E scenarios 1-7 across agent → aegis → policy → risk → decision → tool → audit → dashboard
- **Type**: `rule`
- **Given**: Stack is up.
- **When**: Run 7 scenarios: (1) GitHub read ALLOW + audit; (2) Dangerous terminal BLOCK + no exec + audit; (3) High-risk request → REQUIRE_APPROVAL + approval appears; (4) Approval → execute + audit updated; (5) Expired approval → execution denied; (6) Invalid API key → 401 + no tool; (7) Policy error → BLOCK + no tool.
- **Then**: Each scenario matches expected outcome exactly, and dashboard reflects state.
- **Pass Condition**: `tests/test_e2e_scenarios.py` passes 7/7.
- **Evidence**: E2E pytest output per scenario.

### AC-18: Alembic migrations — fresh DB migrate-up + rollback works; app starts cleanly
- **Type**: `rule`
- **Given**: Empty Postgres DB.
- **When**: `alembic upgrade head` → start backend → create admin + agent + request + audit → `alembic downgrade -1` → `alembic upgrade head`.
- **Then**: No migration errors; backend passes `/health/ready` at each step; downgrade-then-upgrade preserves schema invariants (primary keys, indexes, FKs).
- **Pass Condition**: Manual migration sequence succeeds and `tests/test_migrations.py` (if added) passes.
- **Evidence**: `alembic ...` command output + health checks captured.

### AC-19: Docker Compose — stack starts healthy; backend waits for Postgres; no hardcoded creds
- **Type**: `rule`
- **Given**: `.env` populated with values matching `.env.example`.
- **When**: `docker compose up --build -d` then `docker compose ps` and `curl /health`.
- **Then**: postgres, backend, frontend services all show healthy; backend start delays until DB ready (depends_on condition + wait script or psycopg retries); compose uses env vars; no secrets committed to repo.
- **Pass Condition**: `docker compose ps` shows 3/3 healthy after a bounded timeout.
- **Evidence**: `docker compose ps` output + `/health` response captured.

### AC-20: Overall code and package structure matches monorepo layout; no TODOs in core files
- **Type**: `rubric`
- **Dimension**: Structural fidelity to the brief's monorepo layout and quality of file organization
- **Scale**: 1-5
- **Anchors**: 1 = files are scattered or key directories missing; 3 = directories exist per brief but some modules are stubbed or unimportable; 5 = every directory in the brief exists, modules import cleanly, and `grep -r "TODO" backend/app frontend/app docs --include="*.py" --include="*.ts" --include="*.tsx" --include="*.md"` returns no matches for core functionality.
- **Pass Threshold**: >= 4
- **Evidence**: Directory tree dump + TODO grep output.

### AC-21: Code quality — secure defaults, least-privilege, fail-closed, no secrets in repo
- **Type**: `rubric`
- **Dimension**: Secure coding posture across backend + frontend + config
- **Scale**: 1-5
- **Anchors**: 1 = several clear anti-patterns (raw SQL, plaintext secrets, JWT alg-none accepted, etc.); 3 = most areas correct but 1-2 minor findings; 5 = independent scan finds zero actionable security issues: parameterized queries via ORM, Argon2id, HS256-only, env-vars only for secrets, .env.example with no real keys, CORS restrictive, error handling sanitized.
- **Pass Threshold**: >= 4
- **Evidence**: Output of targeted code scans + security test results.

## Open Questions
- [ ] Which minimal, hardened image do we base the terminal sandbox on (alpine-based custom Dockerfile in-repo, or a pinned slim image)? Decision default: custom `backend/app/tools/terminal/sandbox.Dockerfile` using python:3.12-slim with non-root user, drop capabilities, no networking by default unless overridden.
- [ ] Should the initial admin bootstrap command prompt for password or accept via env var for CI? Decision default: support both: prompt interactive, but accept `AEGIS_ADMIN_PASSWORD` env var for scripting.
