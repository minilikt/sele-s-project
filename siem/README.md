# SENTINEL SIEM

Local security monitoring platform for Windows event logs: ingestion, a
Sigma-compatible detection engine, alert triage, entity-graph correlation,
ATT&CK kill-chain analysis and an evidence-grounded investigation assistant.

Runs entirely on one machine — no cloud account or paid API required.

## What it does

| Capability | Implementation |
|---|---|
| Log ingestion | JSON API, plus drag-and-drop import of binary `.evtx`, XML exports and JSON event arrays |
| Detection | Declarative **Sigma YAML** rules, plus a legacy imperative engine |
| Correlation | Entity graph (users, hosts, IPs) with a bounded time window |
| Kill chain | ATT&CK tactics ordered into a progression, with a 0–100 confidence score |
| ATT&CK mapping | Rules declare `attack.*` tags; the API resolves tactics/techniques |
| Triage | Alert lifecycle with MTTA/MTTR and false-positive rate |
| Repeatability | Deterministic alert and incident fingerprints — re-running analysis never duplicates records |
| AI assistant | Deterministic, evidence-bound answers over stored events, alerts and incidents |

## Architecture

```
siem/
  backend/
    main.py              FastAPI application and routes
    sigma/               Sigma parser, matcher and execution engine
      parser.py          YAML -> rule + condition AST
      matcher.py         selection/modifier semantics
      event.py           ORM event -> Sigma field dictionary
      engine.py          rule execution, aggregation, sequences
    rules/windows/       The shipped Sigma rule set
    detection_engine.py  Legacy imperative rules (kept for comparison)
    entities.py          Typed entity extraction and graph projection
    correlation_engine.py  Alerts -> entity-linked incidents
    killchain.py         ATT&CK ordering and chain scoring
    evtx_import.py       .evtx / XML / JSON normalisation
    dedup.py             Fingerprinting and idempotent upserts
    auth.py              JWT authentication, PBKDF2 hashing, RBAC
    migrations.py        Programmatic Alembic upgrade at startup
    alembic/             Versioned schema migrations
    tests/               pytest suite (198 tests)
  frontend/              React + Vite dashboard
```

Data model: `SecurityEvent` → `Alert` → `Incident`.

## Detection rules

Rules live in `backend/rules/` as YAML and are loaded at startup and on
`POST /api/detection/reload`. A rule that fails to parse is reported with its
file path instead of being silently skipped.

### Supported Sigma subset

* `detection` selections: mappings, lists of mappings, keyword lists
* conditions: `and`, `or`, `not`, parentheses, `1 of selection_*`,
  `all of them`
* field modifiers: `contains`, `startswith`, `endswith`, `all`, `re`, `cidr`,
  `gt`/`gte`/`lt`/`lte`, `exists`, `base64`, `base64offset`, `windash`,
  `fieldref`
* case-insensitive matching with `*` and `?` wildcards, list values ORed unless
  `|all` is used
* `logsource`, `level`, `tags`, `references`, `falsepositives` metadata

Unsupported modifiers fail at load time rather than silently never matching.

### Platform extensions

Two extensions cover detections that a single-event Sigma rule cannot express.
They are documented here because they are **not** part of the upstream spec.

**Threshold aggregation**

```yaml
detection:
  selection:
    EventID: 4625
  condition: selection
group_by: [TargetUserName]
threshold: 5
timeframe: 10m
```

**Ordered sequence**

```yaml
detection:
  selection:
    EventID: 4625
  condition: selection
correlation:
  type: temporal_ordered
  group_by: [TargetUserName]
  timeframe: 15m
  steps:
    - name: failures
      selection: {EventID: 4625}
      min_count: 3
    - name: success
      selection: {EventID: 4624}
```

Steps must occur in order, for the same entity, inside the timeframe.

### Shipped detections

| Rule | Event(s) | ATT&CK | Severity |
|---|---|---|---|
| Multiple failed logons | 4625 ×5 / 10m | T1110 | High |
| Logon after repeated failures | 4625 → 4624 | T1110, T1078 | Critical |
| User account created | 4720 | T1136.001 | Medium |
| New account receives privileges | 4720 → 4672 | T1078, T1136 | Critical |
| Suspicious PowerShell | 4688 | T1059.001, T1027 | High |
| Scheduled task created | 4698 | T1053.005 | Medium |
| Security log cleared | 1102, 104 | T1070.001 | Critical |
| New service installed | 7045 | T1543.003 | High |

## Importing Windows logs

`POST /api/events/import` accepts three formats, detected from content first and
extension second:

| Format | Parser |
|---|---|
| Binary `.evtx` | [`python-evtx`](https://github.com/williballenthin/python-evtx) |
| XML export (`Get-WinEvent \| ConvertTo-Xml`, `wevtutil`) | `xml.etree`, namespace-agnostic |
| JSON array in the ingest format | plain `json` |

Each Windows record is normalised into the same payload the JSON ingest API
takes, so imported logs flow through the identical detection and correlation
pipeline:

* `EventID`, `TimeCreated`, `Computer`, `Channel`
* account from `TargetUserName`, `SubjectUserName`, `AccountName` or `UserName`
* source IP from `IpAddress`, `SourceIp` or `ClientAddress`
* event type and severity from a table of known IDs (4624/4625/4720/4672/4688/
  4698/1102/7045/…). Unknown IDs are **retained** as `Other` / `Low` rather than
  dropped.
* the full `EventData` dictionary is preserved in `raw_data`, so Sigma rules can
  match fields the normaliser does not know about.

Duplicate suppression keys on `(timestamp, event id, computer, account)`; pass
`skip_duplicates=false` to force a re-import. `dry_run=true` parses and returns a
preview without writing anything.

Limits: 100 MB per upload, 200,000 records per file. Truncation and per-record
parse errors are reported in the response instead of failing the whole import.

## Correlation

Alerts are grouped by the entities they actually reference, not by matching
account strings. Three entity types are extracted:

| Entity | Source |
|---|---|
| `user` | event account **and** the acting account (`SubjectUserName`) |
| `host` | computer name |
| `ip` | source address, validated as an IP |

Linking rules:

* two alerts join when they share a **user** or an **IP** — this catches lateral
  movement (same user, different hosts) and credential reuse (same IP, different
  accounts);
* shared **hosts** also link, but a host referenced by more than 6 alerts is
  ignored as a correlation key (`max_host_fanout`), because a domain controller
  legitimately sees everyone and would merge unrelated incidents;
* every alert in an incident must fall inside the requested window measured from
  the first alert. Transitive chains (A–B, B–C, C–D) are cut so an incident can
  never span hours because of a chain of short gaps;
* a group needs at least two alerts to become an incident.

`POST /api/incidents/correlate?window_minutes=120` tunes the window.
`&rebuild=true` deletes existing incidents first — useful after changing the
window or the entity rules, and destructive to incident status and notes, which
is why it is opt-in.

Each incident stores the entities involved, the projected graph
(`nodes`/`edges`, where an edge means "seen in the same alert") and the
kill-chain analysis. The dashboard renders the graph and the stage progression.

## Kill chain

`killchain.py` orders the ATT&CK tactics observed in an incident:

```
Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → Command and Control →
Exfiltration → Impact
```

The chain score is a transparent heuristic, not a probability:

```
score = 18 × (distinct tactics covered)
      + severity weight (Low 0, Medium 4, High 8, Critical 15)
      + 10 if tactics advance monotonically in time and at least 3 are covered
capped at 100
```

Interpretation:

| Score | Reading |
|---|---|
| 0–24 | single-stage activity; could be one noisy rule |
| 25–49 | two stages, or one severe stage |
| 50–74 | multi-stage activity that warrants triage |
| 75–100 | broad, ordered progression across the lifecycle |

Incidents are titled `Attack Chain:` from three stages upward. When the score
reaches 70 the incident severity is raised one level (High → Critical), so a
wide chain is never buried under a Medium rating. The score reflects **evidence
coverage**, not proof of compromise — a chain is still a hypothesis an analyst
must validate.

## Deduplication

Every alert carries a SHA-256 fingerprint of `(rule_id, sorted event ids)`.
Running detection again over unchanged events increments `dedup_count` instead
of inserting a duplicate, and never reopens a resolved or false-positive alert.
Incidents are fingerprinted by their contributing alert set.

This is what makes scheduled detection safe: `POST /api/detection/run` is
idempotent.

## API

All routes except `GET /api/health` and `POST /api/auth/login` require
`Authorization: Bearer <token>`.

```
POST   /api/auth/login                 username/password -> JWT
GET    /api/auth/me                    current user and role
GET    /api/auth/users                 list users                  (admin)
POST   /api/auth/users                 create user                 (admin)
PATCH  /api/auth/users/{id}            role / active / password    (admin)
GET    /api/health
POST   /api/events/ingest              bulk ingest (JSON array)
POST   /api/events/import              upload .evtx / XML / JSON (?dry_run)
POST   /api/events/generate-sample     synthetic attack scenarios
GET    /api/events/stats               totals by type/severity
POST   /api/detection/run              run Sigma + legacy engines (idempotent)
POST   /api/detection/reload           hot-reload YAML from disk  (admin)
GET    /api/detection/rules            catalogue with engine + tags
GET    /api/detection/rules/{id}/yaml  raw Sigma source
PATCH  /api/detection/rules/{id}       enable/disable, tune rules  (admin)
POST   /api/incidents/correlate        entity-graph grouping (?window_minutes, ?rebuild)
GET    /api/incidents                  incidents with entities + chain
GET    /api/incidents/{id}             full detail, timeline and graph
GET    /api/entities                   most-alerted entities and their edges
GET    /api/alerts                     filter by severity/status
GET    /api/alerts/metrics             volume, MTTA, MTTR, FP rate
PATCH  /api/alerts/{id}/status         lifecycle + assignee + note
GET    /api/mitre/coverage             ATT&CK coverage
POST   /api/ai/ask                     evidence-grounded Q&A
```

`?rebuild=true` on the correlation endpoint deletes every incident first and is
therefore restricted to admins.

Interactive docs at `http://localhost:8000/docs`.

## Running

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
uvicorn main:app --reload
```

```powershell
cd frontend
npm install
npm run dev
```

Tests:

```powershell
cd backend
python -m pytest -q
```

The suite covers condition parsing, every field modifier, each shipped rule
(positive and negative cases), deduplication, the alert lifecycle, entity
extraction and graph projection, kill-chain scoring, log import (XML, JSON and
EVTX dispatch), JWT/login/RBAC behaviour and the API regressions that were found
during development. CI runs it against SQLite and PostgreSQL 16.

The first startup creates one administrator when the `users` table is empty. In
development the fallback is `admin` / `admin`; set `SIEM_ADMIN_PASSWORD` to
change it. Setting `SIEM_ENV=production` makes a missing password or a missing
`SIEM_JWT_SECRET` fatal instead of falling back.

### Docker Compose (PostgreSQL)

```powershell
Copy-Item .env.example .env   # then replace the secrets
docker compose up --build
```

Frontend: `http://localhost:8080`, API: `http://localhost:8000`. The stack runs
PostgreSQL 16, applies Alembic migrations at backend startup, and serves the
built frontend through nginx, which proxies `/api` to the backend so the browser
only talks to one origin.

## Authentication and roles

| Role | Capabilities |
| --- | --- |
| `viewer` | read-only |
| `analyst` | ingest/import, run detection and correlation, triage alerts and incidents |
| `admin` | edit/reload detection rules, rebuild incidents, manage users |

* Passwords use PBKDF2-HMAC-SHA256 with 260,000 iterations and a per-user salt.
* Tokens are HS256 JWTs (8 hours by default) signed with `SIEM_JWT_SECRET`. The
  role is re-read from the database on every request, so a demotion takes effect
  immediately instead of at token expiry.
* Without `SIEM_JWT_SECRET`, a development process writes a random secret to
  `backend/.jwt_secret` (git-ignored) so reloads do not invalidate sessions. A
  production process refuses to start without the variable.
* The frontend keeps the token in `localStorage`; a 401 clears it and returns to
  the login screen. Viewer accounts get a read-only UI.

## Database

SQLite by default (`backend/siem.db`). To use PostgreSQL:

```
SIEM_DATABASE_URL=postgresql+psycopg://siem:siem@localhost:5432/siem
```

Schema changes are versioned with Alembic in `backend/alembic/versions/`. The
API upgrades to `head` at startup; a pre-Alembic SQLite database is detected and
stamped with the baseline revision, so existing data is kept.

```powershell
cd backend
python -m alembic current
python -m alembic upgrade head
python -m alembic revision --autogenerate -m "describe change"
```

`alembic/env.py` reads the same `SIEM_DATABASE_URL`, so the CLI and the app
cannot disagree about which database they are changing.

## Limitations

Stated plainly, because a detection tool that overstates itself is a liability:

* Rules are a **subset** of Sigma. The `|count()` aggregation syntax and
  `condition`-level timeframes are not implemented; use the documented
  extensions instead.
* Correlation is heuristic. Entity linking is deliberately conservative (users,
  IPs, bounded hosts) and will miss intrusions that reuse none of those
  identities. It does not yet track process lineage or file hashes.
* Incident fingerprints are based on the alert set, so a late-arriving alert
  produces a new incident next to the old one rather than updating it; use
  `rebuild=true` to regenerate the full set.
* The kill-chain score measures how much of the ATT&CK lifecycle the evidence
  covers. It is not a probability of compromise and must not be read as one.
* `.evtx` import parses records but does not recover deleted/corrupted records;
  EVTX writing is not supported.
* Ingest assumes Windows event semantics. The Sigma engine can be pointed at
  other sources, but the normaliser and entity extractor expect Windows fields.
* The AI assistant is deterministic retrieval and templating. It does not call
  an LLM yet, and it never takes action on the environment.
* Authentication is deliberately small: no refresh tokens, MFA, password reset,
  token revocation list, or audit log of admin actions. Tokens are bearer-only,
  so serve the app over TLS.
* RBAC has three coarse roles and no per-rule, per-source or per-tenant scoping.
* The frontend stores the JWT in `localStorage`, which an XSS bug could read. A
  hardened deployment would move it to an httpOnly cookie with CSRF protection.
* The Compose defaults (`admin`/`admin`, development mode) are for localhost
  only. Set real secrets and `SIEM_ENV=production` before exposing the stack.

## Roadmap

- [x] Windows security log analysis
- [x] Detection rules engine (failed logins, privilege changes, PowerShell)
- [x] Event correlation + incident timeline
- [x] MITRE ATT&CK mapping
- [x] Alert deduplication and triage metrics
- [x] Sigma YAML rule format
- [x] Automated tests
- [x] Entity-graph correlation and kill-chain state machine
- [x] `.evtx` import with field mapping
- [ ] Process-lineage graph (parent/child processes, hashes)
- [ ] LLM-backed assistant with citation enforcement
- [x] PostgreSQL migrations (Alembic) and containerised deployment
- [x] JWT authentication and RBAC
