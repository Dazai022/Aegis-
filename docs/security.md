# Security

## Threat model (summary)

See [docs/threat-model.md](threat-model.md) for full STRIDE analysis per component.

## Authentication

### Admin accounts
- Passwords hashed with **Argon2id** (t=3, m=64MB, p=1, 16 byte salt, 32 byte hash) via `argon2-cffi`.
- JWT access tokens: **HS256 only**. Decode strictly rejects any other algorithm (no `alg: none`, no RS256 with pubkey-forge). 15-minute expiry.
- Token blocklist is in-process; tokens blacklisted on logout or revocation.
- Login endpoint returns a **generic "Invalid credentials"** 401 regardless of whether the email exists or the password is wrong.
- A dummy Argon2id verify runs against a synthetic hash for nonexistent accounts to flatten user-enumeration timing.
- Login rate limit: `slowapi` 5 per minute per IP, 10 per 15 minutes per account → `429 Too Many Requests`.

### Agent API keys
- 256-bit key material generated via `secrets.token_urlsafe(32)`; format: `ag-{base64url_32B}`.
- Plaintext shown **exactly once** at creation time.
- DB stores only `HMAC-SHA256(key_bytes || server_pepper_bytes).hexdigest()` plus `last_4` mask for UI display.
- States: `active`, `revoked`, `invalid`. A revoked key is treated identically to a wrong key (no information leak).
- Dependency `get_current_agent` fails closed: any DB failure, key mismatch, revoked state, missing header → `401`.

## Authorization

- Backend dependencies enforce role checks before any business logic runs. Frontend UI guards are convenience only; backend rules are authoritative (INV-10).
- Three dependency flavors: `require_admin`, `require_agent`, `require_any_authenticated`.
- All write operations (policy create/edit, approve/reject, revoke agent, manage GitHub connections) require admin.
- `/v1/execute`, `/agents/me` require agent.

## Policy engine

- Deterministic, first-match-wins after priority ordering.
- Default (no matching policy): **REQUIRE_APPROVAL**, never unrestricted ALLOW.
- Policy versions are immutable snapshots; every update inserts a new `PolicyVersion` row.
- Parameter constraints are JSON-schema-subset matched against the request params dict.

## Risk engine

- Score 0-100 from 10 explicit, weighted signals.
- HIGH (≥60) and CRITICAL (≥80) promote any non-BLOCK decision to REQUIRE_APPROVAL.
- Signals include destructive action, sensitive resource, privileged tool, unusual action, first-time tool, frequency, suspicious params (path traversal, shell metacharacters), prompt-injection substrings, unusual behavior, and sensitive data access.

## Context engine

- Looks back at bounded agent history: last N requests (default N=100), last 60 min frequency, prior blocks, first-time tool, action-pattern shift.
- Findings are merged with risk scoring to escalate unexpected behavior even when an explicit ALLOW policy exists.

## Decision engine

Strict precedence. Rule 5 is the fail-closed safety net:

1. BLOCK policy → **BLOCK**
2. CRITICAL / HIGH risk → **REQUIRE_APPROVAL**
3. REQUIRE_APPROVAL policy → **REQUIRE_APPROVAL**
4. explicit ALLOW AND risk ≤ MEDIUM → **ALLOW**
5. Any exception thrown by stages 1-4 → **BLOCK**

## Approval system

- Parameter binding: approval stores `SHA256(canonical_sorted_keys(tool || action || params))`. On execute, recompute and compare; mismatch → rejected.
- Single-use: status transitions `PENDING → APPROVED | REJECTED | EXPIRED` atomically. Double approve → 409.
- Expiry: `expires_at = now + APPROVAL_EXPIRE_SECONDS` (default 600s). Expired approvals → 410.
- Expired-approvals → 410.

## Audit log

- Append-only. Application code has no UPDATE/DELETE paths.
- SHA-256 chained hash:
  ```
  canonical = json.dumps(record_sorted_keys, separators=(",", ":"))
  current_hash = SHA256((previous_hash_hex or "0") + "|" + canonical).hexdigest()
  ```
- `GET /audit/verify` recomputes the entire chain and reports the exact `broken_at` record id on failure.

## GitHub adapter

- Tokens stored AES-256-GCM encrypted at rest. Decrypted only in-memory during a single adapter call, then zeroed (best-effort via Python del + gc).
- HTTPx transport with timeouts, retries disabled (fail fast), normalized typed errors for 401/403/404/429/5xx.
- Read-only actions: `read_repository`, `list_files`, `read_file`, `list_branches`, `read_commit`.
- Credentials never appear in logs; structured logger redaction filter matches token regexes.

## Secure terminal adapter

- **Never executes on the host.** Every command spawns an isolated Docker container:
  - Image: in-repo `sandbox.Dockerfile` (slim, `useradd sandbox`, no extra packages).
  - `--user sandbox`, `--cap-drop ALL`, `--security-opt no-new-privileges`.
  - Memory: 256 MB, CPUs: 0.5.
  - Root FS: `--read-only`; `/workspace` tmpfs only, no host mounts.
  - Network: `--network none` by default (policy override allowed only for a small allowlist).
  - Timeout: 30 s hard deadline; container killed on expiry.
- Container environment is clean: never forwards `DATABASE_URL`, `JWT_SECRET`, `PEPPER`, `AES_MASTER_KEY_BASE64`.
- Blocking destructive commands by policy **before** `docker run` is called → no container starts.

## WebSockets

- Upgrade path requires a valid admin JWT.
- Event payloads are sanitized; no redacted fields, no raw tokens.
- Monotonic sequence id per topic; clients can resubscribe with `?since_seq=N` to catch up on a bounded ring buffer.
- Disconnects → reconnect → resubscribe → catch-up applies → real-time resumes.

## Secret handling

- All secrets arrive via env vars only. `.env.example` carries no real values.
- Structured logger applies regex-based redaction to messages + exception strings before emit.
- Exception handlers return envelope `{"error":{"code":STRING,"message":STRING}}`; stack traces are logged internally but never sent to clients in `ENV=prod`.

## Secure coding checklist applied

- Parameterized SQLAlchemy ORM only (no `text()` with string interpolation unless inputs are literal, audited).
- Input validation: Pydantic for every request body/path/query.
- Request size limit: `MAX_REQUEST_BYTES` enforced at app layer.
- CORS origins: env-var list only.
- HTTP security headers in middleware: CSP (restrictive), X-Content-Type-Options, X-Frame-Options (DENY), Strict-Transport-Security placeholder.
- Server tokens stripped (FastAPI `server_header=False`).
- Fail-closed everywhere: null/None result from engine = BLOCK.
