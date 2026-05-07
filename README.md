# CIPHRA — Secure RBAC Chatbot

> **C**lassified **I**nformation **P**rotected via **H**ash-chained **R**ole **A**ccess

A production-grade reference implementation of the proposal *"Secure AI Chatbot with Role-Based Access Control and Encrypted Logging System"* (Pak-Austria Fachhochschule, Secure Software Design, Semester 6).

CIPHRA is an enterprise AI chatbot that **classifies every query by data sensitivity, enforces role-based access control on responses, blocks prompt-injection attempts, and records every interaction in a tamper-evident SHA-256 hash chain.** Sensitive audit fields are encrypted at rest with AES-256-GCM, the audit table is append-only at both the application and PostgreSQL layers, and the entire authentication stack from password policy to refresh-token rotation follows OWASP Cheat Sheet patterns.

---

## Table of Contents

1. [Why this project exists](#why-this-project-exists)
2. [Feature overview](#feature-overview)
3. [Architecture](#architecture)
4. [Quick Start (Docker)](#quick-start-docker)
5. [Manual Development Setup](#manual-development-setup)
6. [Default Users](#default-users)
7. [Roles & Sensitivity Tiers](#roles--sensitivity-tiers)
8. [Security Implementation Details](#security-implementation-details)
9. [How the Hash-Chained Audit Log Works](#how-the-hash-chained-audit-log-works)
10. [API Reference](#api-reference)
11. [AI Providers](#ai-providers)
12. [STRIDE Threat Model](#stride-threat-model)
13. [OWASP Top 10 Coverage](#owasp-top-10-coverage)
14. [Project Structure](#project-structure)
15. [Application Security Testing](#application-security-testing)
16. [Production Hardening Checklist](#production-hardening-checklist)
17. [Known Limitations](#known-limitations)
18. [Tech Stack](#tech-stack)
19. [License & Acknowledgements](#license--acknowledgements)

---

## Why this project exists

Modern enterprises adopt AI chatbots faster than they adopt the controls those chatbots need. Most chatbot frameworks treat access control as an afterthought, with the result that a customer-service representative — who would never receive a payroll spreadsheet by email — can extract the same data through a chat interface in seconds.

CIPHRA is built around the inverse premise: every chatbot reply is a deliberate authorization decision. A user's role determines what the model is allowed to discuss with them; the model's output is filtered before it leaves the server; every query, decision, and denial is recorded in a log that cannot be silently rewritten.

The project also serves as a working showcase of secure-software-design principles — JWT with refresh-token rotation, bcrypt with policy enforcement, append-only auditing, parameterised SQL, OWASP security headers — applied together rather than in isolation.

---

## Feature overview

**Authentication & Sessions**
- Bcrypt password hashing (cost factor 12) with SHA-256 pre-hash for inputs above 72 bytes
- NIST SP 800-63B-aligned password policy (length, character classes, common-password blocklist, sequential and repeating-character detection, username substring rejection)
- JWT access tokens (15-minute lifetime, HS256) with `sub`, `username`, `role`, `jti`, `iat`, `exp` claims
- Opaque refresh tokens (7-day lifetime) stored only as SHA-256 hashes in the database
- **Refresh-token rotation with reuse detection** — replay of a revoked token kills the entire token family
- Account lockout after **5 failed logins**, **15-minute** cooldown, **60-minute** counter window
- Constant-time login response (dummy bcrypt verification when username does not exist) to defeat timing-based user enumeration
- Optional TOTP-based two-factor authentication module (`auth/two_factor.py`) — implemented but not yet wired to a route

**Authorization (RBAC)**
- Four roles: `guest < employee < manager < admin`
- Four data sensitivity tiers: `public < internal < confidential < restricted`
- Pure-function permission evaluator (`rbac/policy.py`) — no external state, trivial to unit-test
- Server-side `require_role` dependency on every protected endpoint

**Query Pipeline (defence in depth)**
- Input sanitisation — control-character stripping, length cap, NFKC Unicode normalisation
- **Homoglyph folding** — Cyrillic, Greek, and full-width letters that mimic ASCII (а → a, ο → o, Ｐ → P) are folded before regex evaluation
- Whitespace-collapse — `p a s s w o r d`-style evasion is detected and joined
- Query sensitivity classification (4 tiers, regex-based)
- Prompt-injection detection — 7 canonical patterns (e.g. "ignore previous instructions", "act as admin", "reveal the system prompt")
- Hardened system prompt embedded with the user's role and access tier

**Response Filter**
- Universal redactions on every reply: emails, OpenAI-shaped API keys (`sk-...`), Bearer tokens, credit-card-shaped digit sequences, US Social Security numbers, PEM-formatted private keys
- Sentence-level RBAC re-classification — each sentence in the model's reply is re-checked against the user's tier; any over-tier sentence is replaced with `[REDACTED — above your role's access level]`

**Audit Logging**
- SHA-256 hash chain — every row's `current_hash = SHA256(prev_hash || canonical_payload)`
- Genesis row anchored to `AUDIT_GENESIS_SEED`
- AES-256-GCM at-rest encryption of `query_text` and `response_text` (random 12-byte nonce per row, 16-byte authentication tag, base64 wire format prefixed `enc:v1:` for algorithm versioning)
- **PostgreSQL trigger-level append-only enforcement** — `UPDATE` and `DELETE` on `audit_logs` raise `insufficient_privilege` at the database engine, before SQLAlchemy ever sees them
- Chain verification endpoint (`GET /api/audit/verify`) replays the chain from genesis and reports the first invalid row id

**Transport & HTTP Hardening**
- OWASP Secure Headers Project alignment: HSTS, Content-Security-Policy, X-Frame-Options DENY, X-Content-Type-Options nosniff, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies
- Server-banner stripping (defensive — Uvicorn re-attaches at the ASGI layer; documented in *Known Limitations*)
- 1 MiB request body cap (DoS defence)
- Per-user / per-IP rate limiting via `slowapi` (60 requests/minute default in Docker compose, 30/min default in code)
- CORS restricted to explicit origins — no wildcards
- Generic 500 handler that never leaks stack traces

**IP Blocklist (available, not currently mounted)**
- Static + dynamic IP blocklist with CIDR support, TTL-based expiry, and whitelist (`middleware/ip_blocklist.py`). Ready to attach when you want it.

---

## Architecture

```
   Browser (untrusted)
       │  HTTPS + Bearer JWT
       ▼
   ┌────────────────────┐
   │ Nginx (frontend)   │   Serves React SPA, proxies /api → backend
   │   port 3000        │
   └─────────┬──────────┘
             ▼
   ┌─────────────────────────────────────────────────────────────────┐
   │              FastAPI backend (Uvicorn)  port 8000                │
   │                                                                  │
   │   Middleware chain (every request)                               │
   │     • body_size_guard (1 MiB cap)                                │
   │     • security_headers (OWASP-aligned)                           │
   │     • CORS (allowlisted origins only)                            │
   │     • slowapi rate limiter (per-user / per-IP)                   │
   │                                                                  │
   │   Routers                                                        │
   │     /api/auth/*    register, login, refresh, logout, me          │
   │     /api/chat       authenticated chat                           │
   │     /api/admin/*   user management (admin only)                  │
   │     /api/audit/*   logs + chain verification (manager+)          │
   │     /api/stats/*   dashboard counters (admin only)               │
   │                                                                  │
   │   Chat pipeline:  sanitize → classify → detect-injection →       │
   │                   RBAC → AI provider → response filter → audit   │
   └────────────┬─────────────────────────────────┬───────────────────┘
                ▼                                 ▼
   ┌──────────────────────────┐     ┌─────────────────────────────────┐
   │  PostgreSQL 16            │     │   AI Provider                   │
   │   • users                 │     │    • mock (default)             │
   │   • refresh_tokens        │     │    • openai (Chat Completions)  │
   │   • audit_logs            │     │    • ollama (local LLM)         │
   │     (append-only triggers)│     │                                 │
   └──────────────────────────┘     └─────────────────────────────────┘
```

### Trust Boundaries

CIPHRA enforces three trust boundaries — places where data crosses from one zone of trust into another, and where a security check is required:

1. **Browser → Backend.** Every API request must carry a valid Bearer JWT issued by the backend. The frontend is treated as untrusted; no security decision is ever made on the client side.
2. **Backend → Database.** All queries flow through SQLAlchemy ORM, which uses parameterised SQL exclusively. No string interpolation reaches the SQL engine.
3. **Backend → AI Provider.** Only sanitised, classified, and authorised queries reach the model. Every reply is filtered for sensitive patterns and re-checked against the user's role tier before transmission.

---

## Quick Start (Docker)

The fastest path — runs PostgreSQL, the FastAPI backend, and the React frontend together.

```bash
# 1. Extract the project and enter the directory
cd ciphra

# 2. Configure environment (optional — defaults work for local dev)
cp .env.example .env
# Generate strong random secrets and edit .env:
#   openssl rand -hex 32   →  paste as JWT_SECRET_KEY
#   openssl rand -hex 32   →  paste as AUDIT_GENESIS_SEED

# 3. Build and start everything
docker compose up --build

# 4. Open the app
#    Frontend:   http://localhost:3000
#    Backend:    http://localhost:8000
#    API docs:   http://localhost:8000/docs
#    Health:     http://localhost:8000/api/health
```

On first boot the backend logs a warning with the seeded credentials. Sign in with one of the four [Default Users](#default-users) and start chatting.

To stop everything: `docker compose down`. Add `-v` if you also want to wipe the database volume.

---

## Manual Development Setup

For working on the code without rebuilding containers on every change.

### Backend

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Option A — SQLite (zero infrastructure):
echo "DATABASE_URL=sqlite:///./app.db" >> .env

# Option B — local PostgreSQL:
#   DATABASE_URL=postgresql://user:pass@localhost:5432/chatbot_db

uvicorn app.main:app --reload
# OpenAPI docs at http://localhost:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Vite dev server at http://localhost:5173
```

The Vite dev server proxies `/api/*` to `http://localhost:8000` (see `frontend/vite.config.js`).

---

## Default Users

On first boot, when the `users` table is empty, four accounts are seeded — one per role. **Rotate or delete these before any real deployment.** The startup logs print a warning containing all four credentials.

| Username   | Password         | Role     | Maximum data tier |
|------------|------------------|----------|-------------------|
| `admin`    | `Adm!nP@ss2026`  | admin    | restricted        |
| `manager`  | `Mgr!n@ger2026`  | manager  | confidential      |
| `employee` | `Emp!oyee@2026`  | employee | internal          |
| `guest`    | `Gue$t!Pass2026` | guest    | public            |

All four passwords satisfy the password policy (≥10 chars, three character classes, not in the common-password blocklist).

---

## Roles & Sensitivity Tiers

### Roles (least → most privileged)
1. **guest** — exploration-level account. Public information only.
2. **employee** — internal employees. Public + internal.
3. **manager** — managerial staff. Public + internal + confidential. Can view audit logs.
4. **admin** — full access including restricted data, user management, and the dashboard.

### Sensitivity classes (assigned by the classifier)

| Class          | Example triggers                                                       |
|----------------|------------------------------------------------------------------------|
| `public`       | (default) any query that does not match a higher rule                  |
| `internal`     | HR policy, sprint, org chart, internal memo, employee handbook         |
| `confidential` | salary, payroll, strategic plan, M&A, SSN, credit card, lawsuit        |
| `restricted`   | password, API key, private key, AWS secret, database credentials       |

When a query matches multiple tiers, the **highest** wins (safer to deny than permit).

### Decision rule

A user with role `R` may receive data classified at `C` if and only if `level(C) ≤ level(max_for_role(R))`. The mapping is implemented in `app/rbac/policy.py` as a pure function, making it impossible to bypass through state manipulation and trivial to unit-test.

---

## Security Implementation Details

### Password hashing — `auth/password.py`
- Bcrypt at cost 12 (~250 ms per verification on modern hardware)
- Inputs above 72 bytes are SHA-256 pre-hashed to preserve full entropy beyond bcrypt's hard limit
- Verification uses `bcrypt.checkpw` (constant-time comparison)

### Password policy — `auth/password_policy.py`
NIST SP 800-63B-aligned. A submitted password must:
- Be 10–128 characters
- Contain at least three of: lowercase, uppercase, digits, symbols
- Not appear in the common-password blocklist
- Not contain the username as a substring
- Not contain a sequential run of ≥5 characters (defeats `abcde`, `12345`)
- Not contain a repeating run of ≥4 identical characters (defeats `aaaa`, `1111`)

All failures are returned together so the user can correct in one round-trip.

### JWT issuance — `auth/jwt_handler.py`
- HS256 signed with `JWT_SECRET_KEY`
- 15-minute access token lifetime; claims: `sub`, `username`, `role`, `jti`, `iat`, `exp`, `type=access`
- The decode function explicitly checks `type == "access"` so a refresh token cannot be presented as an access token
- Only `algorithms=["HS256"]` accepted — `alg=none` and any other algorithm are rejected

### Refresh-token rotation
Implements the OWASP Cheat Sheet pattern. When a refresh is presented:
1. Locate the row by SHA-256 hash of the presented token
2. If expired or already revoked, reject
3. **If the token was already revoked but reused, revoke the entire family** for that user (clear theft-and-replay signal)
4. Issue a new opaque token, mark the old row as revoked, store the new hash in `replaced_by`

### Account lockout — `auth/lockout.py`
- 5 failed logins within the last 15 minutes → 15-minute lockout
- Counter resets on successful login or 60 minutes of inactivity
- Lockout state lives on the user row and is updated in the same transaction as the login attempt — audit and lockout cannot drift apart

### Query pipeline — `routers/chat.py`
The chat endpoint applies these stages in order:
1. **Authentication** — `get_current_user` dependency validates the JWT and loads the user
2. **Sanitisation** — strip control characters, cap length
3. **Sensitivity classification** — `classify_query` returns the highest-matched tier
4. **Prompt-injection detection** — if matched, write `PROMPT_INJECTION_BLOCKED`, return refusal, model is **never** invoked
5. **RBAC check** — `RBACEngine.is_permitted(role, classification)`
6. If denied → audit `QUERY_DENIED` and return the deny reason (model not called)
7. If permitted → call AI provider → run response filter → audit `QUERY` with the filtered reply

### Response filter — `chatbot/filter.py`
Applied unconditionally to every model reply:
- Universal redactions: emails, `sk-...` API keys, Bearer tokens, credit-card patterns, SSNs, PEM private keys → replaced with `[REDACTED_*]` markers
- Sentence-level RBAC: each sentence is re-classified, and any over-tier sentence is replaced with `[REDACTED — above your role's access level]`

### Middleware (`main.py`)
- `body_size_guard` — rejects requests above 1 MiB with HTTP 413
- `security_headers` — attaches the full OWASP header set on every response
- `CORSMiddleware` — explicit allowlist; no wildcards
- `slowapi.Limiter` — keyed on `Authorization` header when present, else client IP

### Database hardening (`init.sql`)
- `pgcrypto` and `citext` extensions enabled
- A PL/pgSQL trigger function `ciphra_audit_append_only()` raises `insufficient_privilege` on any UPDATE or DELETE against `audit_logs`
- Triggers `audit_append_only_update` and `audit_append_only_delete` are attached after the application creates the table

---

## How the Hash-Chained Audit Log Works

Every audit row stores two hash fields:

- `prev_hash` — the `current_hash` of the previous row (genesis row uses `AUDIT_GENESIS_SEED`)
- `current_hash` = `SHA256(prev_hash || pipe || canonical_serialisation_of_this_row)`

Tampering with any row's data changes its `current_hash`, but the next row still references the *old* `current_hash` as its `prev_hash`. Verification replays the chain from genesis: any mismatch identifies the first invalid row id.

### Why hash plaintext, not ciphertext?

`query_text` and `response_text` are encrypted with AES-256-GCM, which uses a **fresh random nonce per encryption**. That makes ciphertext non-deterministic — re-encrypting the same plaintext produces different bytes. If we hashed ciphertext, we would either need to fix the nonce (catastrophic for AES-GCM security) or accept that the chain breaks on every read.

Instead, `current_hash` is computed over the canonical plaintext form. Verification decrypts each row, recomputes the hash, and compares. Tamper-evidence is preserved without sacrificing GCM's nonce-uniqueness requirement.

### Defence in depth

The hash chain provides tamper **evidence** (you can detect modification). The PostgreSQL append-only triggers provide tamper **resistance** (you cannot easily perform modification in the first place). Together they cover both attack paths:

- An attacker without DB access cannot break the chain because they cannot reach the rows
- A DBA running raw SQL is blocked by the trigger before they can modify anything
- An attacker with sufficient privilege to drop the trigger can modify rows — but the next chain verification will detect it and report which row was tampered with

### Verification

```bash
# As an admin, retrieve the chain status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/audit/verify
# Response: { "valid": true, "first_invalid_id": null, "total": 42 }
```

---

## API Reference

All endpoints are prefixed `/api`. Detailed schemas are at `/docs` (FastAPI auto-generated). Endpoints requiring authentication take an `Authorization: Bearer <access_token>` header.

### Authentication
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/register` | none | Register a new user (always assigned `employee` role; admin-creation is admin-only via `/admin/users`) |
| POST | `/auth/login` | none | Returns access + refresh token pair |
| POST | `/auth/refresh` | none | Returns a new access token (refresh token in body) |
| POST | `/auth/refresh-pair` | none | Returns a new access + refresh pair, rotating the refresh token |
| POST | `/auth/logout` | yes | Revokes the current refresh token |
| GET | `/auth/me` | yes | Returns the current user profile |
| POST | `/auth/change-password` | yes | Change own password (requires current password) |

### Chat
| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/chat` | yes | Submit a query. Returns the filtered reply, classification, and status (`allowed` / `denied`). |

### Admin (admin role only)
| Method | Path | Description |
|---|---|---|
| GET | `/admin/users` | List all users |
| POST | `/admin/users` | Create a user with any role |
| PATCH | `/admin/users/{id}/role` | Change a user's role |
| PATCH | `/admin/users/{id}/active` | Activate or deactivate a user |

### Audit (manager + admin)
| Method | Path | Description |
|---|---|---|
| GET | `/audit/logs` | List audit log entries (decrypted on read) |
| GET | `/audit/verify` | Replay the hash chain and report integrity |

### Stats (admin only)
| Method | Path | Description |
|---|---|---|
| GET | `/stats/dashboard` | Aggregate counters: users, queries, denials, audit count |

---

## AI Providers

The AI backend is pluggable via a single environment variable. All providers receive a hardened system prompt that includes the user's role and instructs the model to refuse role-overriding instructions.

### `mock` (default — no external dependencies)

Canned, deterministic responses. Perfect for development and for verifying RBAC behaviour without burning API credits or running an LLM.

```env
AI_PROVIDER=mock
```

### `openai`

```env
AI_PROVIDER=openai
OPENAI_API_KEY=sk-proj-...
OPENAI_MODEL=gpt-4o-mini
```

The backend calls the OpenAI Chat Completions API (`https://api.openai.com/v1/chat/completions`) directly via httpx.

### `ollama` (self-hosted, no data leaves your network)

```env
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://host.docker.internal:11434
OLLAMA_MODEL=neural-chat
```

**Setup checklist:**

```bash
# 1. Make sure Ollama is running on the host
ollama serve

# 2. Pull the model you want (one-time)
ollama pull neural-chat

# 3. Verify it's reachable
curl http://localhost:11434/api/tags
```

**Linux note.** `host.docker.internal` does not resolve by default on Linux. If your backend container cannot reach Ollama, add this to the `backend:` service in `docker-compose.yml`:

```yaml
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Any Ollama-compatible model works (`llama3.2`, `mistral`, `phi3`, `neural-chat`, `qwen2.5`, etc.) — pull it with `ollama pull <name>` and set `OLLAMA_MODEL` accordingly.

---

## STRIDE Threat Model

| Threat                     | Mitigation in this project                                                                                                       |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| **S**poofing              | JWT with role claim signed HS256; verified on every protected request via `get_current_user`; bcrypt-12 password verification    |
| **T**ampering             | SHA-256 hash chain on audit log; PostgreSQL trigger blocks UPDATE/DELETE; AES-GCM authentication tags                            |
| **R**epudiation           | Every auth/query/admin event audit-logged with user, role, IP, user-agent, timestamp                                              |
| **I**nformation Disclosure | RBAC denial in the chat pipeline; sentence-level filter on model output; universal redactions for emails/keys/SSNs/credit cards   |
| **D**enial of Service     | 1 MiB body cap; slowapi rate limit (60/min default); per-account login lockout                                                    |
| **E**levation of Privilege | Server-side role checks on every protected endpoint; registration schema rejects role injection; admin role only via admin route  |
| **Prompt Injection**      | Input normalisation + 7 canonical pattern detector + hardened system prompt + post-generation output filter                       |

---

## OWASP Top 10 Coverage

| OWASP ID                              | Risk                          | Defence in CIPHRA                                                                                                                |
|---------------------------------------|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------|
| A01: Broken Access Control            | Bypassing authorization        | RBACEngine on every query; sentence-level filter on output; `require_role` dependency on every protected route                  |
| A02: Cryptographic Failures           | Weak crypto, exposed secrets   | bcrypt-12; AES-256-GCM with random nonces; HS256 JWT; secrets only via env vars                                                  |
| A03: Injection                        | SQL injection, prompt injection | All SQL via SQLAlchemy ORM (parameterised); 7-pattern injection detector; control-char sanitiser                                |
| A04: Insecure Design                  | Missing controls by design     | Threat-modelled at proposal stage; security control paired with each functional requirement                                     |
| A05: Security Misconfiguration        | Default creds, weak headers    | Full OWASP header middleware; default seeds print rotation warning; debug off by default                                         |
| A06: Vulnerable Components            | Outdated dependencies          | Pinned versions in `requirements.txt`; bcrypt 4.2.0, cryptography 43.0.3, FastAPI 0.115.0                                       |
| A07: Identification & Auth Failures   | Weak passwords, brute force    | NIST 800-63B password policy; per-account lockout; constant-time login; refresh-token reuse detection                            |
| A08: Software & Data Integrity        | Tampered logs                  | Hash-chained audit log; AES-GCM auth tags; database triggers                                                                      |
| A09: Logging & Monitoring             | Missing audit trail            | Every auth/query event logged with full metadata; chain verification endpoint                                                    |
| A10: SSRF                             | Server-side request forgery    | No user input ever forms an outbound URL; AI provider URLs come exclusively from configuration                                  |

---

## Project Structure

```
ciphra/
├── README.md                              ← this file
├── docker-compose.yml                     ← postgres + backend + frontend
├── init.sql                               ← Postgres extensions + append-only audit triggers
├── .env.example                           ← root-level template (used by docker-compose)
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env / .env.example                ← backend-specific config
│   ├── app/
│   │   ├── main.py                        ← FastAPI app, middleware chain, lifespan, seed users
│   │   ├── config.py                      ← Pydantic settings (env-loaded)
│   │   ├── database.py                    ← SQLAlchemy engine + session factory
│   │   ├── models.py                      ← User, RefreshToken, AuditLog, RoleEnum, SensitivityEnum
│   │   ├── schemas.py                     ← Pydantic request/response schemas
│   │   │
│   │   ├── auth/
│   │   │   ├── password.py                ← bcrypt + SHA-256 pre-hash
│   │   │   ├── password_policy.py         ← NIST 800-63B policy enforcement
│   │   │   ├── jwt_handler.py             ← issue/decode/rotate JWTs
│   │   │   ├── lockout.py                 ← failed-login counter + lockout window
│   │   │   ├── two_factor.py              ← TOTP 2FA (available, not yet wired to a route)
│   │   │   └── dependencies.py            ← get_current_user, require_role
│   │   │
│   │   ├── audit/
│   │   │   ├── logger.py                  ← record_event(), verify_chain()
│   │   │   ├── crypto.py                  ← AES-256-GCM encrypt/decrypt for log fields
│   │   │   └── alerting.py                ← (placeholder for security event alerts)
│   │   │
│   │   ├── chatbot/
│   │   │   ├── ai_engine.py               ← mock / openai / ollama dispatcher
│   │   │   ├── classifier.py              ← sensitivity classifier + prompt-injection detector
│   │   │   └── filter.py                  ← response-filter (redactions + sentence-level RBAC)
│   │   │
│   │   ├── rbac/
│   │   │   └── policy.py                  ← RBACEngine (pure-function evaluator)
│   │   │
│   │   ├── middleware/
│   │   │   └── ip_blocklist.py            ← IP blocklist middleware (available, not yet attached)
│   │   │
│   │   ├── routers/
│   │   │   ├── auth.py                    ← /auth/* endpoints
│   │   │   ├── chat.py                    ← /chat
│   │   │   ├── admin.py                   ← /admin/* (admin only)
│   │   │   ├── audit.py                   ← /audit/* (manager + admin)
│   │   │   ├── stats.py                   ← /stats/dashboard (admin only)
│   │   │   └── _utils.py                  ← shared helpers (client_ip, user_agent, etc.)
│   │   │
│   │   └── utils/
│   │       └── password_strength.py       ← entropy-based strength meter
│   │
│   └── tests/
│       ├── test_security.py               ← core security control tests
│       ├── test_security_controls.py      ← extended attack-pattern tests
│       └── test_openai_connection.py      ← optional live AI provider check
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf                         ← serves SPA, proxies /api to backend
    ├── package.json
    ├── vite.config.js
    ├── index.html
    └── src/
        ├── main.jsx                       ← React + Router entrypoint
        ├── App.jsx                        ← route definitions
        ├── api/client.js                  ← fetch wrapper, auto-refresh on 401
        ├── context/AuthContext.jsx        ← auth state + token storage
        └── components/
            ├── Login.jsx                  ← login form
            ├── Register.jsx               ← registration with policy errors
            ├── Chat.jsx                   ← chat UI with role badge
            ├── AdminPanel.jsx             ← user management (admin)
            ├── AuditLog.jsx               ← audit viewer + chain verification button
            ├── Dashboard.jsx              ← stats dashboard (admin)
            ├── Layout.jsx                 ← header / nav / role-aware menu
            └── Logo.jsx                   ← brand mark
```

---

## Application Security Testing

The codebase ships ready for the standard SAST + DAST workflow.

### Static Application Security Testing (SAST)

**Bandit** (Python security linter):

```bash
pip install bandit
bandit -r backend/app -f txt
```

Expected output: 1 low-severity finding (B110 try/except/pass in `audit/crypto.py` line 47) which is the documented intentional fall-through in the AES-GCM key-derivation function. Zero high or medium issues.

**Semgrep** with an OWASP-aligned ruleset:

```bash
pip install semgrep
semgrep --config sast-reports/semgrep-rules.yaml backend/app
```

Expected output: 0 findings across rules covering A01–A10 (SQL injection via string formatting, weak hashes, hard-coded credentials, JWT signature bypass, unsafe deserialisation, debug mode, CORS wildcards, SSRF).

### Dynamic Application Security Testing (DAST)

A custom 12-test probe is provided. Each test is mapped to an OWASP Top 10 category and a CWE identifier:

| ID  | Test                                            | OWASP / CWE          |
|-----|-------------------------------------------------|----------------------|
| T01 | Security headers present                        | A05 / CWE-693        |
| T02 | Authentication required on protected endpoints  | A01 / CWE-862        |
| T03 | JWT alg=none forgery rejected                   | A02/A07 / CWE-347    |
| T04 | SQL injection in /auth/login                    | A03 / CWE-89         |
| T05 | User enumeration via login response             | A01 / CWE-204        |
| T06 | Mass-assignment privilege escalation            | A01 / CWE-269        |
| T07 | Account lockout on brute force                  | A07 / CWE-307        |
| T08 | Weak password policy                            | A07 / CWE-521        |
| T09 | Request body size limit                         | A05 / CWE-400        |
| T10 | Stack trace / internal path disclosure          | A05 / CWE-209        |
| T11 | Server banner fingerprinting                    | A05 / CWE-200        |
| T12 | RBAC cross-tier query denial                    | A01 / CWE-285        |

```bash
# With the system running on port 8000:
pip install httpx
python dast-reports/ciphra_dast.py http://localhost:8000
```

Expected: 11 of 12 tests pass; T11 fails informationally because Uvicorn re-attaches the `Server: uvicorn` header at the ASGI layer (see *Known Limitations*).

---

## Production Hardening Checklist

Before deploying CIPHRA to anything that holds real data:

- [ ] **Rotate all default passwords** for the seeded admin/manager/employee/guest accounts
- [ ] **Set strong random secrets** for `JWT_SECRET_KEY` and `AUDIT_GENESIS_SEED` (`openssl rand -hex 32`)
- [ ] **Set `AUDIT_ENCRYPTION_KEY` explicitly** rather than letting it derive from the JWT secret
- [ ] **Run behind HTTPS** — terminate TLS at a reverse proxy (Nginx, Traefik, or a managed load balancer)
- [ ] **Strip the Uvicorn server banner** by adding `--header server:` to the launch command, or configure your reverse proxy to overwrite it
- [ ] **Restrict CORS_ORIGINS** to only your production frontend origin
- [ ] **Enable 2FA** by wiring `auth/two_factor.py` into the login flow
- [ ] **Attach the IP blocklist middleware** in `main.py` and configure your initial blocklist
- [ ] **Migrate refresh tokens to HttpOnly cookies** instead of localStorage (frontend change)
- [ ] **Configure database backups** with restricted access — backups contain encrypted audit data, but the encryption key needs to be backed up separately
- [ ] **Set `LOG_LEVEL=WARNING`** and forward logs to a SIEM
- [ ] **Run Bandit + Semgrep + the DAST probe** as part of CI; fail builds on new findings

---

## Known Limitations

These are honest gaps you should know about:

- **Uvicorn `Server` header.** The middleware tries to delete the header, but Uvicorn re-attaches it at the ASGI protocol layer. The DAST probe correctly flags this. Fix in production by passing `--header server:` to Uvicorn or stripping at the reverse proxy.
- **Refresh tokens in localStorage.** The frontend stores refresh tokens in localStorage, which is XSS-exposable. The defence (CSP, no inline scripts) is in place, but HttpOnly cookies would be stronger.
- **2FA is implemented but not wired in.** `auth/two_factor.py` provides TOTP secret generation, QR provisioning, code verification with drift tolerance, and backup codes — but no router currently calls it. Hooking it into the login flow is a small change.
- **IP blocklist available but not mounted.** `middleware/ip_blocklist.py` is complete; `main.py` does not currently `add_middleware(IPBlocklistMiddleware)`.
- **No password reset / forgot-password flow.** Users with forgotten passwords need an admin to issue a new password via `/admin/users`.
- **No email verification on registration.** New accounts are immediately active.
- **`alerting.py` is a placeholder.** No automated alerts are emitted when, for example, the chain verification fails.

---

## Tech Stack

**Backend** — FastAPI 0.115, Uvicorn, SQLAlchemy 2.0, Pydantic 2, python-jose (JWT), bcrypt 4.2, cryptography 43, slowapi, httpx, Alembic.

**Frontend** — React 18.3, React Router 6.27, Vite 5, served in production by Nginx.

**Database** — PostgreSQL 16 (alpine in Docker). SQLite supported for local development.

**AI providers** — OpenAI Chat Completions, Ollama HTTP API, deterministic mock.

**Containerization** — Docker + Docker Compose (3 services: db, backend, frontend).

---

## License & Acknowledgements

Academic project for **Pak-Austria Fachhochschule, Institute of Applied Sciences and Technology** — Department of Electrical and Computer Engineering, Semester 6, Secure Software Design.

**Submitted by:** Aimen Basharat Khawaja, Ammar Ahmed, Momina Naeem, Hamad Ali Khan
**Submitted to:** Prof. Nabeel

References:
- OWASP Top Ten (2021), OWASP Application Security Verification Standard (ASVS), OWASP Authentication Cheat Sheet, OWASP Secure Headers Project
- OWASP Top 10 for LLM Applications (2023)
- NIST SP 800-63B — Digital Identity Guidelines: Authentication & Lifecycle Management
- Sandhu, Coyne, Feinstein, Youman (1996), *Role-based access control models*, IEEE Computer 29(2)
- Shostack, A. (2014), *Threat Modeling: Designing for Security*, Wiley
