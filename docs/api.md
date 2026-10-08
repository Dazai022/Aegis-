# API

Aegis exposes an OpenAPI 3.1 spec at runtime via FastAPI's auto-generated docs:

- Swagger UI: `http://localhost:8000/docs`
- OpenAPI JSON: `http://localhost:8000/openapi.json`
- ReDoc: `http://localhost:8000/redoc`

This document lists the canonical routes. Every response (success and error) uses a consistent envelope:

**Success envelope (typical)**:
```json
{ "data": { ...payload... } }
```

**Error envelope**:
```json
{ "error": { "code": "INVALID_REQUEST", "message": "Human readable, no stack trace." } }
```

Error codes used:
`INVALID_REQUEST`, `VALIDATION_ERROR`, `UNAUTHENTICATED`, `FORBIDDEN`, `NOT_FOUND`, `CONFLICT`, `GONE`, `TOO_MANY_REQUESTS`, `RATE_LIMITED`, `REQUEST_TOO_LARGE`, `SECURITY_EVALUATION_FAILED`, `INTERNAL_ERROR`.

## 0. Health & readiness

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | none | Liveness: returns 200 `{"status":"ok","service":"aegis"}` |
| GET | `/health/ready` | none | Readiness: 200 if DB connected; 503 with error envelope otherwise |

## 1. Admin authentication

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| POST | `/auth/login` | none | `{email:string, password:string}` | `{access_token:string, token_type:"bearer", expires_in:900, admin:{id,email,created_at}}` |
| POST | `/auth/logout` | admin JWT | none | `{status:"ok"}` |
| GET | `/auth/me` | admin JWT | none | `{id,email,created_at,last_login_at}` |

## 2. Agents & API keys (admin CRUD + agent self)

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| POST | `/agents` | admin | `{name:string, description?:string, owner?:string}` | `{agent:{id,name,...}, plaintext_key:"ag-XXX", mask:"...abcd"}` (plaintext_key once only) |
| GET | `/agents` | admin | query `?page&per_page&status` | `{items:[{id,name,status,last_used_at,mask}], total, page, per_page}` |
| POST | `/agents/{id}/revoke` | admin | optional `{reason?:string}` | `{id, status:"revoked"}` |
| GET | `/agents/me` | agent API key | none | `{id,name,owner,created_at,last_used_at}` |

## 3. Policy management (CRUD + versions + revert)

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| POST | `/policies` | admin | `{name,description?,priority:int,tool:"github"|"terminal"|null,action_pattern:string,parameter_constraints?:object,effect:"ALLOW"|"BLOCK"|"REQUIRE_APPROVAL",enabled:bool}` | policy + version 1 |
| GET | `/policies` | admin | query filters | paginated list |
| GET | `/policies/{id}` | admin | | full policy incl current version |
| PATCH | `/policies/{id}` | admin | subset of fields | creates version N+1 |
| POST | `/policies/{id}/disable` | admin | | `{enabled:false, version}` |
| POST | `/policies/{id}/enable` | admin | | `{enabled:true, version}` |
| GET | `/policies/{id}/versions` | admin | | `{versions:[{id,version,effect,priority,snapshot,created_at}]}` |
| POST | `/policies/{id}/revert/{version}` | admin | | creates new version = prior snapshot; new version number |

## 4. Core execution pipeline (agent)

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| POST | `/v1/execute` | agent API key | `{tool:"github"|"terminal", action:string, parameters:object}` | `{request_id, decision:"ALLOW"|"BLOCK"|"REQUIRE_APPROVAL", reason, policy_id, risk_score, risk_level, context_findings, approval_id?, execution?:{stdout, stderr, exit_code, duration_ms, metadata}, audit_hash}` |

Full pipeline: (1) auth, (2) validate + sanitize + unique id, (3) policy, (4) risk, (5) context, (6) decision, (7) approval if required, (8) tool execute if permitted, (9) audit append, (10) WS publish.

## 5. Approval workflow (admin)

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| GET | `/approvals` | admin | query `?status=pending\|approved\|rejected\|expired` | paginated list |
| GET | `/approvals/{id}` | admin | | full approval incl request_id, params summary, risk info, context findings |
| POST | `/approvals/{id}/approve` | admin | optional `{comment?:string}` → atomically consumes, executes bound request | `{status:"approved", execution:{...}}` |
| POST | `/approvals/{id}/reject` | admin | optional `{reason?:string, comment?:string}` | `{status:"rejected"}` |

Guarantees: double approve → 409 CONFLICT; expired → 410 GONE; tampered params on execute → `SECURITY_EVALUATION_FAILED` with decision BLOCK.

## 6. Execution requests (admin read)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/requests` | admin | Paginated list with filters: `?agent_id&tool&decision&from&to` |
| GET | `/requests/{id}` | admin | Full detail: request info + policy result + risk signals + context findings + decision + execution + audit hashes |

## 7. Audit log & chain verification (admin)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit` | admin | Paginated audit list with filters |
| GET | `/audit/{id}` | admin | Single audit row with canonical_hash, prev_hash, current_hash |
| GET | `/audit/verify` | admin | `{valid:true/false, broken_at:null\|row_id, checked_count:int}` |

## 8. Risk stats (admin dashboard)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/risk/summary` | admin | Aggregate: avg, distribution by level, top signals, trend |
| GET | `/risk/top?window=24h` | admin | Top-N agents / tools / risk signals |

## 9. Tool connections (admin)

| Method | Path | Auth | Body | Response |
|--------|------|------|------|----------|
| POST | `/tools/github/connections` | admin | `{name:string, personal_access_token:string}` → token encrypted AES-256-GCM → never returned | connection `{id,name,created_at,last_ok_at}` |
| GET | `/tools/github/connections` | admin | | list (masked status, no token) |
| DELETE | `/tools/github/connections/{id}` | admin | | soft delete / revokes |
| POST | `/tools/github/connections/{id}/test` | admin | | Pings `/user` endpoint; reports connectivity |
| GET | `/tools/terminal/status` | admin | Docker availability, sandbox image, last healthy run |

## 10. Settings (admin)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/settings` | admin | Returns non-secret config: risk thresholds, approval expiry, CORS origins, rate limits |
| PATCH | `/settings` | admin | Edits: `approval_expire_seconds`, `risk_levels`, `max_request_bytes` |
| POST | `/settings/password` | admin | Body `{current_password, new_password}` → Argon2id re-hash of admin's own pw |

## 11. Real-time WebSocket (admin)

| Upgrade | Path | Auth | Topics |
|---------|------|------|--------|
| GET → 101 Switching | `/ws/events?token=<admin-jwt>` | admin JWT (query param or `Authorization: Bearer` header) | `requests.new`, `requests.decision`, `requests.exec.started`, `requests.exec.completed`, `requests.blocked`, `approvals.requested`, `approvals.completed`, `security.alert` |

- Every event carries: `{topic, seq, ts, request_id, payload}`.
- Reconnect with `?since_seq=<last-seen>`; hub replays the bounded ring buffer then resumes live.

## 12. Scripts & CLI

- `python -m app.scripts.create_admin` — interactive or env-var based admin bootstrap. Required before first login.
- `python -m app.scripts.verify_audit_chain` — CLI equivalent of `GET /audit/verify` without server running.

## Common HTTP codes

| Code | When |
|------|------|
| 200 | Success |
| 201 | Created |
| 400 | `INVALID_REQUEST` |
| 401 | `UNAUTHENTICATED` (bad/missing JWT/API key) |
| 403 | `FORBIDDEN` (role violation, approval hash mismatch, expired approval) |
| 404 | `NOT_FOUND` |
| 409 | `CONFLICT` (double approve, unique constraint) |
| 410 | `GONE` (expired approval) |
| 413 | `REQUEST_TOO_LARGE` |
| 422 | `VALIDATION_ERROR` (Pydantic) |
| 429 | `TOO_MANY_REQUESTS` (rate limit) |
| 500 | `INTERNAL_ERROR` (never includes stack trace in prod) |
| 503 | `HEALTH_UNAVAILABLE` (DB in readiness) |
