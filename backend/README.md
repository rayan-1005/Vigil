# 🛡️ UPI Fraud Guard

> Real-time multilingual SMS & UPI fraud detection platform built for India's digital payments ecosystem.

[![Node.js](https://img.shields.io/badge/Node.js-20_LTS-339933?logo=node.js)](https://nodejs.org)
[![Express](https://img.shields.io/badge/Express-5-000000?logo=express)](https://expressjs.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql)](https://postgresql.org)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis)](https://redis.io)
[![HuggingFace](https://img.shields.io/badge/HuggingFace-Inference_API-FFD21E?logo=huggingface)](https://huggingface.co)

---

## Overview

UPI Fraud Guard accepts raw SMS or UPI message text in **any Indian language or Hinglish**, runs it through a multi-stage AI pipeline powered by the Hugging Face Inference API, and returns a **risk score, extracted entities, and a plain-language explanation** — all in under 2 seconds.

Designed for banks, payment aggregators, and fintech institutions to monitor and flag fraudulent communication at scale.

---

## System Architecture

```mermaid
flowchart TD
    Client(["🖥️ React Web App / PWA\nVite + TailwindCSS"])

    subgraph API ["⚙️ Express API Server · Node.js 20"]
        GW["API Gateway\n/api/v1/*"]
        Auth["Auth Middleware\nJWT Verify + Redis Revocation"]
        RL["Rate Limiter\nRedis Sliding Window"]
        Val["Zod Validator\nBody + Query Schemas"]
        Routes["Route Handlers\nauth · scan · alerts · analytics"]
    end

    subgraph ML ["🤖 ML Pipeline · Hugging Face Inference API"]
        S1["Stage 1 · Language Detection\nfacebook/fasttext-language-identification"]
        S2["Stage 2 · Translation conditional\nHelsinki-NLP/opus-mt-lang-en"]
        S3["Stage 3 · Fraud Classification\nmrm8488/bert-mini-finetuned-sms-spam-detection"]
        S4["Stage 4 · NER Extraction\ndslim/bert-base-NER"]
        S5["Stage 5 · Risk Aggregation\nInternal Node.js · regex + weights"]
    end

    subgraph Store ["🗄️ Data Layer"]
        PG[("PostgreSQL 16\ninstitutions · scan_requests\nscan_results · alerts · scam_patterns")]
        RD[("Redis 7\nJWT revocation · result cache\nrate-limit counters · SSE tokens")]
    end

    subgraph Async ["⚡ Async Layer"]
        BQ["BullMQ\nAlert Queue"]
        Worker["Alert Worker\nDB persist + SSE push"]
        SSE["SSE Manager\nPer-institution connections"]
    end

    Client -->|"HTTPS REST + SSE"| GW
    GW --> Auth --> RL --> Val --> Routes

    Routes -->|"POST /scan"| S1
    S1 -->|"non-English"| S2
    S1 -->|"English / mixed"| S3
    S2 --> S3
    S3 --> S4
    S4 --> S5

    Routes <-->|"reads / writes"| PG
    Routes <-->|"cache + tokens"| RD
    Auth -->|"jti revocation check"| RD
    RL -->|"sliding window counters"| RD

    S5 -->|"riskScore >= 70"| BQ
    BQ --> Worker
    Worker -->|"INSERT alert"| PG
    Worker --> SSE
    SSE -->|"event: fraud_alert"| Client
```

---

## Request Data Flow

```mermaid
sequenceDiagram
    actor User
    participant FE as React Frontend
    participant API as Express API
    participant Cache as Redis Cache
    participant ML as HF Pipeline
    participant DB as PostgreSQL
    participant Queue as BullMQ
    participant SSE as SSE Stream

    User->>FE: Paste suspicious message
    FE->>API: POST /api/v1/scan · Bearer JWT
    API->>API: Verify JWT + check revocation list
    API->>API: Zod validate body
    API->>Cache: GET scan:cache:<sha256>
    alt Cache hit
        Cache-->>API: Cached result
        API-->>FE: 200 cached: true
    else Cache miss
        API->>DB: INSERT scan_requests status=processing
        API->>ML: detectLanguage(message)
        ML-->>API: lang: hi · confidence: 0.94
        opt Non-English
            API->>ML: translateToEnglish(text, hi)
            ML-->>API: Translated English text
        end
        par Parallel HF calls
            API->>ML: classifyFraud(englishText)
            API->>ML: extractEntities(englishText)
        end
        ML-->>API: isFraud · mlScore
        ML-->>API: upiIds · urls · amounts · phones · bankNames
        API->>API: aggregateRisk → riskScore 0 to 100
        API->>DB: INSERT scan_results
        API->>Cache: SETEX scan:cache TTL 24h
        API-->>FE: 200 scanId + result
        opt riskScore >= 70
            API->>Queue: enqueueAlert
            Queue->>DB: INSERT alerts
            Queue->>SSE: pushAlert(institutionId)
            SSE-->>FE: event: fraud_alert
        end
    end
```

---

## ML Pipeline Detail

```mermaid
flowchart LR
    IN["📩 Raw Message\nany Indian language"]

    subgraph Pipeline
        direction TB
        P1["1 · Language Detection\nfasttext · ~150ms"]
        P2["2 · Translation\nopus-mt · ~400ms\nskip if English"]
        P3["3 · Fraud Classification\nbert-mini · ~300ms"]
        P4["4 · NER Extraction\nbert-base-NER · ~350ms"]
        P5["5 · Risk Aggregation\nInternal · less than 5ms"]
        P1 --> P2 --> P3
        P1 -->|English or mixed| P3
        P3 --> P4 --> P5
    end

    OUT["📊 Result\nriskScore 0 to 100\nriskLevel LOW to CRITICAL\nclassification · flags\nentities · explanation"]

    IN --> Pipeline --> OUT
```

**Risk Score Formula:**
```
riskScore = (mlScore × 100 × 0.6) + (patternScore × 0.3) + (entityRisk × 0.1)
```

| Score | Level | Classification |
|---|---|---|
| 0 – 34 | LOW | LEGITIMATE |
| 35 – 59 | MEDIUM | SUSPICIOUS |
| 60 – 79 | HIGH | FRAUDULENT |
| 80 – 100 | CRITICAL | FRAUDULENT |

---

## Auth & Token Flow

```mermaid
flowchart TD
    Login["POST /auth/login"]
    Bcrypt["bcrypt.compare\ncost factor 12\ndummy hash if email missing"]
    Issue["Issue Tokens\nAccess JWT · 15 min · HS256\nRefresh JWT · 7d · httpOnly cookie"]
    Req["Authenticated Request\nBearer accessToken"]
    Check["Verify JWT signature\nCheck Redis revoked:{jti}"]
    Allow["✅ Allow"]
    Deny["❌ 401 Unauthorized"]
    Logout["POST /auth/logout"]
    Revoke["Redis SETEX\nrevoked:{jti} · TTL = remaining lifetime"]
    Refresh["POST /auth/refresh\nhttpOnly cookie"]
    NewAccess["New 15-min Access Token"]

    Login --> Bcrypt
    Bcrypt -->|valid| Issue
    Bcrypt -->|invalid| Deny
    Issue --> Req
    Req --> Check
    Check -->|clean| Allow
    Check -->|revoked or expired| Deny
    Logout --> Revoke
    Refresh --> NewAccess
```

---

## SSE Secure Stream Flow

```mermaid
sequenceDiagram
    participant FE as Frontend
    participant API as Express API
    participant Redis as Redis
    participant SSE as SSE Manager

    note over FE,SSE: Original spec used JWT in ?token= query param (INSECURE — logged everywhere)
    note over FE,SSE: Our fix: short-lived single-use opaque stream token

    FE->>API: POST /alerts/stream-token · Bearer JWT
    API->>Redis: SETEX sse:token:<random48> 30s → institutionId
    API-->>FE: { streamToken: "abc123..." }

    FE->>API: GET /alerts/stream?streamToken=abc123
    API->>Redis: GETDEL sse:token:abc123
    Redis-->>API: institutionId (token consumed, single-use)
    API-->>FE: 200 text/event-stream headers

    loop Every 30s
        API->>FE: event: heartbeat
    end

    loop On high-risk scan
        API->>FE: event: fraud_alert · { scanId, riskScore, flags }
    end
```

---

## Database Schema

```mermaid
erDiagram
    institutions {
        uuid id PK
        varchar name
        varchar email UK
        varchar password_hash
        varchar role
        varchar api_key_hash UK
        boolean is_active
        timestamptz created_at
        timestamptz updated_at
    }

    scan_requests {
        uuid id PK
        uuid institution_id FK
        text raw_message
        varchar source
        inet ip_address
        text user_agent
        varchar status
        timestamptz created_at
    }

    scan_results {
        uuid id PK
        uuid scan_request_id FK
        varchar detected_language
        text translated_message
        smallint risk_score
        varchar risk_level
        varchar classification
        numeric confidence
        text explanation
        text_array flags
        jsonb entities
        jsonb pattern_matches
        integer hf_latency_ms
        timestamptz created_at
    }

    alerts {
        uuid id PK
        uuid scan_result_id FK
        uuid institution_id FK
        smallint risk_score
        varchar risk_level
        text_array flags
        timestamptz delivered_at
        timestamptz acknowledged_at
        timestamptz created_at
    }

    scam_patterns {
        uuid id PK
        varchar name UK
        varchar pattern_type
        text pattern_value
        varchar severity
        boolean is_active
        integer hit_count
        timestamptz created_at
    }

    institutions ||--o{ scan_requests : "submits"
    scan_requests ||--|| scan_results : "produces"
    scan_results ||--o{ alerts : "triggers"
    institutions ||--o{ alerts : "receives"
```

---

## Redis Key Schema

| Key Pattern | Type | TTL | Purpose |
|---|---|---|---|
| `scan:cache:<sha256>` | String JSON | 24h | Identical message result cache |
| `revoked:<jti>` | String | Token remaining TTL | JWT logout revocation list |
| `rl:pub:<ip>` | Sorted Set | 1 min | Public endpoint rate limit |
| `rl:auth:<id>` | Sorted Set | 1 min | Authenticated endpoint rate limit |
| `rl:login:<ip>` | Sorted Set | 15 min | Login brute-force guard |
| `sse:token:<token>` | String | 30s | Single-use SSE stream token |
| `hf:status` | String JSON | 30s | HF API last health result |

---

## Security Architecture

| Threat | Mitigation |
|---|---|
| Weak JWT secret | Zod env validation enforces ≥ 64 chars — process exits if missing |
| Long-lived tokens | 15-min access JWTs + httpOnly 7-day refresh cookie |
| No logout revocation | Redis jti blocklist, TTL = token remaining lifetime |
| JWT in SSE URL log exposure | Short-lived 30s single-use opaque stream token |
| Brute-force login | 10 attempts / 15 min per IP on `/auth/*` endpoints |
| API key plaintext storage | HMAC-SHA256 hashed in DB, shown once on creation |
| Timing attack on login | Dummy bcrypt compare when email not found |
| SQL injection | Parameterised `pg` queries only — zero string interpolation |
| Payload DoS | 50KB JSON body cap, 512-char HF input cap |
| Verbose error leakage | Stack traces stripped in all production responses |
| Server fingerprinting | `X-Powered-By` removed, Helmet security headers applied |
| CORS misconfig | Explicit origin whitelist from `CORS_ORIGIN` env var |
| Container privilege escalation | Non-root `appuser` in Dockerfile |

---

## Technology Stack

| Category | Choice | Rationale |
|---|---|---|
| Runtime | Node.js 20 LTS | Non-blocking I/O ideal for concurrent HF API calls |
| Framework | Express 5 | Minimal, stable, hackathon-friendly |
| Database | PostgreSQL 16 | Relational integrity + JSONB for entity storage |
| Cache / Queue | Redis 7 + BullMQ | Fast cache, reliable job queue, rate limiting store |
| ML Inference | Hugging Face Inference API | Zero infra, 3 public models, free-tier viable |
| Auth | JWT HS256 + bcrypt | Stateless access tokens, secure password hashing |
| Validation | Zod | Runtime type safety on all inputs and env vars |
| Real-time | Server-Sent Events | One-directional push, simpler than WebSockets |
| Logging | Winston | Structured JSON logs, redacts sensitive fields |
| Container | Docker + Compose | One-command local dev stack |

---

## Project Structure

```
upiguard-backend/
├── src/
│   ├── app.js                     # Express app, security middleware stack
│   ├── server.js                  # HTTP server + graceful shutdown
│   ├── config/
│   │   ├── env.js                 # Zod env validation — exits on error
│   │   └── database.js            # pg Pool singleton
│   ├── middleware/
│   │   ├── auth.js                # JWT verify, issue, revoke
│   │   ├── rateLimiter.js         # Redis sliding-window limiters
│   │   ├── validate.js            # Zod validation factory
│   │   └── errorHandler.js        # Global error handler, no stack in prod
│   ├── routes/
│   │   ├── auth.routes.js
│   │   ├── scan.routes.js
│   │   ├── alerts.routes.js
│   │   ├── analytics.routes.js
│   │   └── health.routes.js
│   ├── controllers/
│   │   ├── auth.controller.js     # register · login · refresh · logout
│   │   ├── scan.controller.js     # submit · history · detail
│   │   ├── alerts.controller.js   # stream-token · SSE · list · acknowledge
│   │   ├── analytics.controller.js
│   │   └── health.controller.js
│   ├── services/
│   │   ├── mlPipeline.js          # 5-stage HF pipeline + exponential backoff
│   │   ├── redisClient.js         # ioredis singleton
│   │   ├── sseManager.js          # SSE connection registry + stream tokens
│   │   └── alertWorker.js         # BullMQ worker
│   ├── schemas/
│   │   ├── auth.schema.js
│   │   └── scan.schema.js
│   └── utils/
│       ├── logger.js              # Winston structured logger
│       ├── apiError.js            # Typed API error class
│       └── crypto.js              # API key gen/hash, message hash, safeEqual
├── migrations/
│   ├── 001_init.sql               # Full schema with constraints + indexes
│   └── run.js                     # Migration runner script
├── .env.example
├── .gitignore
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Quick Start

```bash
# 1. Install
npm install

# 2. Configure
cp .env.example .env

# 3. Generate secrets
openssl rand -hex 64   # → JWT_SECRET
openssl rand -hex 32   # → API_KEY_SALT

# 4. Get a HuggingFace token
# huggingface.co/settings/tokens → New token (Read) → copy hf_xxx → HF_API_TOKEN

# 5. Run everything
docker compose up --build
```

Manual (no Docker API server):
```bash
docker compose up postgres redis -d
npm run migrate
npm run dev
```

---

## API Reference

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Public | Register institution account |
| POST | `/api/v1/auth/login` | Public | Login → access token + refresh cookie |
| POST | `/api/v1/auth/refresh` | Cookie | Issue new access token |
| POST | `/api/v1/auth/logout` | Bearer | Revoke current access token |
| POST | `/api/v1/scan` | Bearer | Submit message for fraud analysis |
| GET | `/api/v1/scans` | Bearer | Paginated scan history |
| GET | `/api/v1/scans/:id` | Bearer | Single scan full detail |
| GET | `/api/v1/analytics/summary` | Bearer | 30-day dashboard stats |
| POST | `/api/v1/alerts/stream-token` | Bearer | Issue SSE stream token |
| GET | `/api/v1/alerts/stream?streamToken=` | Token | Real-time SSE alert stream |
| GET | `/api/v1/alerts` | Bearer | Alert history |
| PATCH | `/api/v1/alerts/:id/acknowledge` | Bearer | Acknowledge an alert |
| GET | `/api/v1/health` | Public | Liveness check |
| GET | `/api/v1/health/deep` | Admin | Full dependency health check |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `REDIS_URL` | ✅ | Redis connection string |
| `JWT_SECRET` | ✅ | Min 64 chars — `openssl rand -hex 64` |
| `API_KEY_SALT` | ✅ | Min 32 chars — `openssl rand -hex 32` |
| `HF_API_TOKEN` | ✅ | Hugging Face token starting with `hf_` |
| `CORS_ORIGIN` | ✅ | Frontend origin e.g. `http://localhost:5173` |
| `NODE_ENV` | — | `development` / `production` (default: development) |
| `PORT` | — | API port (default: 3001) |
| `BCRYPT_ROUNDS` | — | bcrypt cost factor 10–14 (default: 12) |
| `JWT_ACCESS_EXPIRES_IN` | — | Access token TTL (default: `15m`) |
| `JWT_REFRESH_EXPIRES_IN` | — | Refresh token TTL (default: `7d`) |
| `HF_TIMEOUT_MS` | — | Per-request HF timeout ms (default: 5000) |
| `HF_RETRY_ATTEMPTS` | — | Max HF retries with backoff (default: 1) |
| `SSE_STREAM_TOKEN_TTL_S` | — | Stream token lifetime seconds (default: 30) |
