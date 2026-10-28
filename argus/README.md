# ARGUS — Attack Surface Intelligence

A local-first attack surface tracker: deterministic lab discovery, TLS/header
exposure checks, finding deduplication across scans, transparent risk scoring,
analyst lifecycle and a deterministic assistant.

> **Authorised use only.** Only assess domains and systems you own or have
> explicit written permission to test. This build **does not run real network
> discovery from the API** — `/api/scan` only produces the synthetic
> `acme-lab.local` inventory. The real DoH/TLS/HTTP helpers in
> `discovery_engine.py` are not exposed by any endpoint.

## What it does

* Inventories assets (apex + subdomains) with IP, open ports, HTTP status,
  TLS expiry and security headers.
* Derives findings from observed state: expired/expiring certificates, missing
  CSP/HSTS, exposed admin portals, RDP/MySQL exposure, legacy/dev assets.
* **Deduplicates findings across scans** with a stable fingerprint, so scanning
  ten times does not create ten copies of the same issue.
* Tracks the lifecycle: Open → Acknowledged → Resolved, with reopen detection
  when a resolved issue reappears and a `stale` flag when a finding was not
  observed in the latest scan.
* Scores findings and the domain with a documented formula (see below), and
  excludes resolved findings from current risk.
* Detects change: the base inventory is stable, and three subdomains appear on
  later scans to exercise the "new asset" path.
* Exposes JSON/TXT exports and a deterministic, evidence-grounded assistant.

## Stack

| Layer | Technology |
| --- | --- |
| Frontend | React 19 + Vite, nginx in the container |
| API | Python 3.11+, FastAPI |
| Data | SQLAlchemy 2, SQLite by default, PostgreSQL 16 supported |
| Schema | Alembic migrations |
| Auth | JWT (HS256) + PBKDF2 password hashing, 3 roles |

## Layout

```
argus/
  backend/
    main.py              FastAPI routes and scan orchestration
    discovery_engine.py  deterministic lab inventory + finding rules
    lifecycle.py         fingerprints, upsert, reopen and legacy merge
    risk_engine.py       finding and aggregate risk
    ai_assistant.py      deterministic Q&A and report
    auth.py              JWT, password hashing, RBAC middleware
    migrations.py        Alembic upgrade at startup
    alembic/             versioned schema
    models.py            Asset / Finding / Scan / User
    tests/               pytest suite (73 tests)
  frontend/              React dashboard
```

## Scan model

`POST /api/scan` runs `discovery_engine.scan_lab` for `acme-lab.local` only and
returns `400` for any other domain. Each scan:

1. Builds the lab inventory. The base 40 subdomains are seeded from the domain
   name, so they do not change between scans. Asset attributes (ports, headers,
   certificate dates) evolve per scan.
2. Upserts every asset and refreshes all observed fields.
3. Generates candidate findings from the *current* state and upserts them by
   fingerprint.
4. Recomputes per-asset and domain risk, then stores a `Scan` row with counts
   (`assets_discovered`, `new_assets`, `findings_discovered`, `new_findings`,
   `reopened_findings`).

The first scan sees 41 assets (apex + 40 subdomains). The second adds
`new-portal.acme-lab.local`; the third adds `unsecured-admin.acme-lab.local`.

### Finding identity and lifecycle

```
fingerprint = SHA-256(hostname | category | title)   # lower-cased, trimmed
```

* Same fingerprint on a later scan → update detail/severity/score, increment
  `dedup_count`, set `last_scan_id` and `last_seen`. No duplicate row.
* `Resolved` + observed again → **reopened**, `reopened_count += 1`. A fix that
  silently regresses is worth an analyst's attention.
* `Acknowledged` → evidence is refreshed but the analyst decision is kept.
* A finding **absent** from a scan is not auto-resolved. Failed or partial scans
  must never close real issues; the UI marks findings not seen in the latest
  scan as `stale`, and resolution stays an explicit analyst action.
* Legacy rows without fingerprints are backfilled at startup. Exact duplicates
  created before deduplication existed are merged into the oldest row (counts
  and last-seen are preserved).

## Risk scoring

**Finding risk** (0–100):

```
severity weight × exposure weight × (0.5 + 0.5 × confidence)
```

| Severity | Weight | Exposure | Weight |
| --- | ---: | --- | ---: |
| Critical | 100 | Internet | 1.00 |
| High | 75 | Internal | 0.55 |
| Medium | 50 | Local | 0.25 |
| Low | 25 | None | 0.10 |
| Info | 5 | | |

**Aggregate risk** (domain and per asset), over **open** findings only:

```
depth   = weighted mean of the top 5 finding scores (weights 5,4,3,2,1)
breadth = min(20, 4 × log2(1 + open_finding_count))
score   = min(100, 0.8 × depth + breadth)
```

The 0.8 damping leaves headroom: one critical finding scores ~84 rather than
clipping at 100, so the number still distinguishes one severe issue from twenty.
Breadth is capped at 20 so volume alone cannot manufacture a critical rating.

| Score | Level |
| --- | --- |
| ≥ 75 | Critical |
| ≥ 50 | High |
| ≥ 25 | Medium |
| ≥ 5 | Low |
| < 5 | Minimal |

The previous version summed every finding and clipped at 100, which reported
100 for almost any dataset. The weights are illustrative product decisions, not
a CVSS replacement; re-rank severity for the business context.

## Authentication and roles

| Role | Capabilities |
| --- | --- |
| `viewer` | read-only |
| `analyst` | run scans, acknowledge/resolve findings |
| `admin` | + manage users |

* PBKDF2-HMAC-SHA256, 260,000 iterations, per-user salt.
* HS256 JWTs, 8 hours by default. Role is re-read from the database on each
  request, so a demotion applies immediately.
* Without `ARGUS_JWT_SECRET`, a development process writes a random secret to
  `backend/.jwt_secret` (git-ignored). A production process refuses to start
  without it.
* First startup creates an administrator when `users` is empty. Development
  fallback is `admin` / `admin`; set `ARGUS_ADMIN_PASSWORD`, and set
  `ARGUS_ENV=production` to make missing secrets fatal.

## API

All routes except `GET /api/health` and `POST /api/auth/login` require
`Authorization: Bearer <token>`.

```
POST   /api/auth/login                 username/password -> JWT
GET    /api/auth/me                    current user
GET    /api/auth/users                 list users                  (admin)
POST   /api/auth/users                 create user                 (admin)
PATCH  /api/auth/users/{id}            role / active / password    (admin)

POST   /api/scan                       run lab scan (acme-lab.local only)
GET    /api/scan/history               recent scans
GET    /api/scan/latest                latest scan + observed findings
GET    /api/scan/{id}                  scan detail

GET    /api/assets                     assets, sorted by cached risk
GET    /api/assets/{id}                asset + findings + risk summary

GET    /api/findings                   filter by severity/category/status
GET    /api/findings/stats             counts, stale, dedup savings
GET    /api/findings/metrics           MTTR, reopen rate, dedup ratio
PATCH  /api/findings/{id}/status       lifecycle, assignee, note

GET    /api/dashboard/stats            risk, counts, trend
GET    /api/export/findings.json
GET    /api/export/assets.json
GET    /api/export/report.txt
POST   /api/ai/ask
POST   /api/ai/report
GET    /api/health
```

Interactive docs at `http://localhost:8001/docs`.

## Running locally

```powershell
cd argus/backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn main:app --reload --port 8001
```

```powershell
cd argus/frontend
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://localhost:8001`, so there is no
hard-coded backend port in the client. Set `VITE_DEV_API` to override the proxy
target when the backend runs elsewhere.

Tests:

```powershell
cd argus/backend
python -m pytest -q        # 73 tests
```

### Docker Compose

From the repository root:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

* SIEM UI `http://localhost:8080`, API `http://localhost:8000`
* ARGUS UI `http://localhost:8081`, API `http://localhost:8001`

Each project gets its own PostgreSQL 16 instance and volume. The backend applies
Alembic migrations at startup. Compose defaults are localhost-only; set real
passwords and secrets, and put TLS in front, before exposing anything.

## Database

SQLite by default (`backend/argus.db`). PostgreSQL:

```
ARGUS_DATABASE_URL=postgresql+psycopg://argus:argus@localhost:5432/argus
```

Migrations live in `backend/alembic/versions/`. Existing pre-Alembic databases
are stamped with the baseline revision and upgraded, so demo data survives.
The CLI reads the same environment variable as the app:

```powershell
python -m alembic current
python -m alembic upgrade head
python -m alembic revision --autogenerate -m "describe change"
```

## Limitations

Stated plainly:

* **Scans are simulated.** No endpoint performs DNS, HTTP or TLS requests
  against a target. The lab inventory is synthetic and must not be presented as
  a real assessment.
* Finding rules are heuristics over lab state. There is no vulnerability
  scanning, CVE matching, version fingerprinting or exploitation.
* Risk weights are illustrative; there is no CVSS/EPSS integration and no
  business-criticality input.
* Findings absent from a scan are not auto-resolved; this avoids false closures
  but requires analysts to close issues manually.
* `stale` means "not observed in the latest scan", not "no longer vulnerable".
* No scheduling/continuous monitoring, ticketing integration or webhooks.
* Authentication has no MFA, refresh tokens, password reset, revocation list or
  admin audit trail. Tokens live in `localStorage`, which an XSS bug could read.
* RBAC is three coarse roles with no per-asset scoping.
* Docker Compose defaults are development credentials.

## Roadmap

- [x] Deterministic asset inventory and finding rules
- [x] Finding deduplication and lifecycle
- [x] Transparent aggregate risk scoring
- [x] Change detection for new assets and regressions
- [x] Automated tests, CI and containers
- [x] Alembic migrations and PostgreSQL
- [x] JWT authentication and RBAC
- [ ] Authorised real discovery with per-target confirmation and rate limits
- [ ] Continuous scheduling and notification integrations
- [ ] Asset ownership and business-criticality weighting
