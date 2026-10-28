# Security Engineering Portfolio

Two self-contained security platforms, built to be run locally and inspected
end to end — real parsers, real tests, no mock data pipelines.

| Project | Focus | Stack |
|---|---|---|
| [`siem/`](siem/README.md) | Detection engineering and incident investigation | Python, FastAPI, Sigma YAML, React, PostgreSQL/SQLite |
| [`argus/`](argus/README.md) | Attack surface tracking and risk scoring | Python, FastAPI, React, PostgreSQL/SQLite |

Both support PostgreSQL 16, Alembic migrations, JWT authentication with
role-based access, and a `docker compose` deployment.

## SIEM — detection platform

Ingests Windows security events, evaluates Sigma-compatible YAML detections,
correlates alerts into incidents and maps everything to MITRE ATT&CK.

Highlights:

* **Declarative Sigma engine** — condition parser (`1 of selection_*`,
  `all of them`, `and`/`or`/`not`), 13 field modifiers, load-time validation.
  A rule that cannot fire fails loudly instead of silently.
* **Ordered sequence correlation** for "failures *then* success" style
  detections that single-event rules cannot express.
* **Entity-graph correlation** — alerts are linked by user, host and IP rather
  than by matching account strings, with a bounded time window and a
  domain-controller fan-out guard.
* **ATT&CK kill-chain scoring** — observed tactics are ordered into a stage
  progression and scored 0–100, with the formula documented in the README.
* **Real log import** — binary `.evtx`, XML exports and JSON arrays are
  normalised, deduplicated and pushed through the same detection pipeline.
* **Idempotent detection** — deterministic alert fingerprints mean re-running
  a scan never duplicates alerts.
* **Analyst workflow** — lifecycle states, assignment, MTTA/MTTR and
  false-positive rate.
* **Authentication and RBAC** — PBKDF2 passwords, HS256 JWTs, admin/analyst/
  viewer roles enforced at the API, with a login screen and role-aware UI.
* **198 automated tests** covering parser, matcher, every shipped rule
  (positive and negative), deduplication, entity extraction, kill-chain
  scoring, log import, authentication and API regressions.

```powershell
cd siem/backend
python -m venv .venv; .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
uvicorn main:app --reload
```

## ARGUS — attack surface intelligence

Tracks an authorised inventory of assets, derives configuration/exposure
findings, deduplicates them across scans and scores risk transparently.

Highlights:

* **Stable lab inventory** for `acme-lab.local` with assets appearing on later
  scans to exercise change detection. The API deliberately does **not** run
  real network discovery.
* **Finding fingerprints** — re-running a scan refreshes an issue instead of
  duplicating it, while a resolved issue that reappears is reopened.
* **Lifecycle and staleness** — Open/Acknowledged/Resolved, reopen counts,
  observed-count history, and a `stale` flag for findings not seen in the
  latest scan.
* **Documented risk model** — severity × exposure × confidence per finding;
  a top-5 weighted aggregate plus a breadth term per asset/domain, excluding
  resolved findings. The old sum-and-clip formula is gone.
* **Same security baseline as the SIEM** — JWT/RBAC, Alembic, PostgreSQL
  support, containers and CI.
* **73 automated tests** across risk maths, discovery determinism, finding
  lifecycle, scans, dedup metrics, exports, the assistant and RBAC.

```powershell
cd argus/backend
python -m venv .venv; .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest -q
uvicorn main:app --reload
```

> **Authorised use only.** Only assess domains and systems you own or have
> explicit written permission to test. Both projects ship with synthetic lab
> data.

## Repository layout

```
siem/       SIEM platform (backend + frontend)
argus/      Attack surface platform (backend + frontend)
.github/    CI: SQLite + PostgreSQL tests, Sigma validation, frontend builds
docker-compose.yml
```

## Docker Compose

```powershell
Copy-Item .env.example .env    # replace the secrets
docker compose up --build
```

| Service | URL |
| --- | --- |
| SIEM UI | http://localhost:8080 |
| SIEM API | http://localhost:8000 |
| ARGUS UI | http://localhost:8081 |
| ARGUS API | http://localhost:8001 |

Each project has its own PostgreSQL 16 instance and volume. Both backends apply
Alembic migrations at startup. The Compose defaults are for localhost only; set
real credentials and terminate TLS before exposing the stack.
