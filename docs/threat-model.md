# Threat model

## Asset inventory

| # | Asset | Location | Sensitivity |
|---|-------|----------|-------------|
| A1 | Admin password hashes | `admins.password_hash` | High (Argon2id) |
| A2 | JWT signing secret | env `JWT_SECRET` | Critical |
| A3 | API-key HMAC pepper | env `PEPPER` | Critical |
| A4 | AES-256 master key | env `AES_MASTER_KEY_BASE64` | Critical |
| A5 | GitHub PAT values (encrypted) | `github_connections.encrypted_token` | High |
| A6 | API-key HMAC hashes | `agent_api_keys.hmac_hash` | Medium |
| A7 | Audit log chain hashes | `audit_logs.*_hash` | High (integrity) |
| A8 | Execution parameters (may contain secrets) | `execution_requests.parameters_json` | Medium-High |
| A9 | Admin session tokens (JWT) | In-flight + in-memory blocklist | High |

## STRIDE by component

### 1. Admin Login Endpoint (`POST /auth/login`)

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | Attacker logs in as admin via credential stuffing, brute force, or leaked hash | Argon2id; rate limit 5/min/IP + 10/15min/account; generic 401; dummy verify to block enumeration |
| Tampering | Attacker crafts JWT with alg `none` or forged RS256 with pubkey-as-HMAC-key | Decode strictly HS256 only; reject all other algorithms; secret length ≥ 32B |
| Repudiation | Admin denies logging in | Audit log every login success/failure with IP + UA + chained hash |
| InfoDisclosure | Error messages reveal which accounts exist | Generic 401; no timing leak via dummy verify |
| DenialOfService | Exhaust Argon2id CPU budget | Rate limit; per-IP tarpit; max request size |
| Elevation | Brute force → escalate to admin → system compromise | Rate limit + Argon2id cost params + lockout; 15-min tokens; rotate on suspicion |

### 2. Agent API Key Auth (`X-Api-Key` header)

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | Key reuse, stolen key, key-guessing | 256-bit CSPRNG key; HMAC-SHA256 lookup; display-once; revoke immediately on suspicion |
| Tampering | Tamper with DB to mark revoked key as active | Active state column NOT NULL; DB check constraints; fail closed if DB lookup fails |
| InfoDisclosure | UI reveals full key, logs leak key | `last_4` mask only; logger regex redaction; audit sanitizes params |
| Elevation | Agent key used on admin-only routes | `require_admin` dependency rejects agent JWT/keys |

### 3. Policy Engine

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Tampering | Policy effect modified after evaluation to downgrade BLOCK→ALLOW | Policy versions are immutable snapshots; every mutation inserts new `PolicyVersion`; decisions persist policy_id+effect+version for audit |
| Repudiation | Admin disavows creating a permissive policy | Every policy mutation writes audit event with admin_id + policy diff |
| DoS | Large regex `action_pattern` causes catastrophic backtracking | Use `fnmatch` glob-style (no regex by default); length caps on patterns; timeout on match |
| Elevation | Agent somehow injects its own policy | Policy CRUD requires `require_admin` |

### 4. Decision Engine

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Tampering | Exception raised to short-circuit ALLOW path | Rule 5: any exception → BLOCK; fail closed; exception logged internally but not to client |
| Repudiation | Decision order ambiguous | Every decision persists a DB row with timestamp + policy/risk/context refs; deterministic precedence |
| InfoDisclosure | Internal decision reasons leak agent secrets | Response envelope includes `reason` (safe) but not raw internal state |

### 5. Approval System

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | Replay a captured approval | Approval single-use, status transitions atomically; `parameters_hash` binds approval to specific params |
| Tampering | Change parameters between approval and execution | `parameters_hash` recompute on execute; mismatch → 403 |
| Repudiation | Approver denies approving a dangerous action | Audit chain records admin_id, before/after state, exact parameters hash |
| DoS | Flood of pending approvals blocks queue | Pagination; filters; expiry cleanup cron |
| Elevation | Low-priv approver acts on CRITICAL requests | (Optional) approval tiering prototype: single admin tier in MVP; extend to tiers in future |

### 6. GitHub Adapter

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | Adapter leaks raw token via logs/audit | AES-256-GCM encrypt at rest; logger redaction; HTTP header assert that Authorization is never serialized to audit/event |
| Tampering | Write action executed despite read-only claim | Action allowlist; action registry rejects unknown actions at adapter validate_action |
| InfoDisclosure | Read_file reads arbitrary paths, traverses to private repos | Parameter validation: repository must match `^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+$`; path parameter disallow `../` |
| DoS | GitHub API rate limit exhaustion → service-wide failure | Per-connection rate-limit-aware backoff; max 1 concurrent per connection; 429 normalized as typed error |

### 7. Secure Terminal Adapter

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | Command runs on host instead of sandbox | Dockerfile + spawn args hardcoded; test asserts argv contains each hardening flag |
| Tampering | Sandbox escape via kernel CVE | Slim base image, minimal packages; non-root; cap-drop ALL; read-only root; tmpfs only; network none |
| InfoDisclosure | Container inherits `DATABASE_URL` from host env | Clean env spawn; deny-list env keys; `env` empty array in docker run |
| DoS | `fork bomb` consumes host resources | Memory + CPU limits; PID limit per container; 30 s hard timeout → SIGKILL |
| Elevation | `docker run` args injected | No shell interpolation; subprocess args list, not string; validate command string length |

### 8. Audit Log

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Tampering | Attacker edits/deletes an incriminating audit record | Append-only application guarantee; SHA-256 chained hash; `/audit/verify`; in production: DB-level `REVOKE UPDATE/DELETE` |
| Repudiation | Operator denies a BLOCK/APPROVE action | Chain hash + admin_id + timestamp + WS event emission with same hash |
| InfoDisclosure | Audit records contain passwords/tokens | Parameter sanitization at interceptor; logger redaction; zero-secret tests |

### 9. WebSockets

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Spoofing | Unauthenticated client subscribes to WS events | JWT at upgrade path; 401 before `101 Switching Protocols` |
| Tampering | Client injects fake WS events | Server-push only; zero client-to-server messages in MVP except subscribe control |
| InfoDisclosure | Event payload leaks redacted fields, tokens | Dedicated sanitization pass; TR asserts event bytes do not contain secret marker |
| DoS | Open thousands of WS connections to exhaust server memory | Max concurrent connections per admin; heartbeat timeouts; bounded catch-up ring buffer |

### 10. Docker Compose / Deployment

| STRIDE | Threat | Mitigation |
|--------|--------|------------|
| Tampering | Backend image replaced in registry; env vars printed in `docker inspect` | No hardcoded secrets in compose or images; all via env-file; separate secrets volume in production |
| Spoofing | Postgres password defaulted / weak | `.env.example` `__REPLACE__` placeholders + startup assertion in backend (fail if unchanged) |
| DoS | DB out of disk → audit chain stops writing | Backend fails closed if audit insert fails → BLOCK; healthcheck alerts; disk space monitoring recommended |
