"""
SENTINEL SIEM Platform — FastAPI application.

Wires together the detection engine, correlation engine, MITRE ATT&CK mapping,
sample data generator and the AI investigation assistant into a single API.
"""

from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import ai_assistant
import auth
import dedup
import evtx_import
import ioc
import sample_data
from correlation_engine import CorrelationEngine
from database import SessionLocal, get_db, init_db
from detection_engine import RulesEngine
from mitre_attack import (
    get_all_techniques,
    get_technique,
    get_techniques_by_tactic,
)
from models import Alert, DetectionRule, Incident, SecurityEvent, User
from sigma import SigmaEngine
from sigma.engine import DEFAULT_RULES_DIR, severity_for_level, technique_name

SIGMA_RULES_DIR = os.getenv("SIEM_SIGMA_RULES_DIR", DEFAULT_RULES_DIR)

app = FastAPI(title="SENTINEL SIEM Platform API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

auth.install(app)
app.include_router(auth.router)


# ── Startup ───────────────────────────────────────────────────────────────────

def _seed_rules(db: Session) -> None:
    """Seed the legacy imperative rules, disabled in favour of Sigma rules.

    The Python rule classes remain available (and testable) but new deployments
    run the declarative Sigma engine. Existing databases keep whatever enabled
    state an analyst set.
    """
    for rec in RulesEngine.get_default_rule_records():
        existing = db.get(DetectionRule, rec["id"])
        if existing is None:
            rec = dict(rec)
            rec["enabled"] = False
            rec["engine"] = "python"
            db.add(DetectionRule(**rec))
        elif not existing.engine:
            existing.engine = "python"
    db.commit()


def _retire_legacy_rules(db: Session) -> int:
    """Disable still-default legacy rules once Sigma equivalents exist.

    A rule whose stored config was customised is left untouched: an analyst may
    deliberately be running a tuned Python rule alongside the Sigma engine.
    """
    from detection_engine import ALL_RULE_CLASSES

    if db.query(DetectionRule).filter(DetectionRule.engine == "sigma").first() is None:
        return 0

    defaults = {cls.RULE_ID: json.dumps(cls.DEFAULT_CONFIG) for cls in ALL_RULE_CLASSES}
    retired = 0
    for rule in db.query(DetectionRule).all():
        if (rule.engine or "python") != "python":
            continue
        if rule.id not in defaults:
            continue
        if (rule.config or "") == defaults[rule.id] and rule.enabled:
            rule.enabled = False
            retired += 1
    db.commit()
    return retired


def _sync_sigma_rules(db: Session) -> "LoadResult":
    """Load Sigma YAML from disk and upsert it into ``detection_rules``."""
    loaded = SigmaEngine.load_rules([SIGMA_RULES_DIR])

    for rule in loaded.rules:
        tactic = rule.mitre_tactics[0] if rule.mitre_tactics else ""
        technique = rule.mitre_techniques[0] if rule.mitre_techniques else ""
        values = {
            "name": rule.title,
            "description": rule.description,
            "severity": severity_for_level(rule.level),
            "config": json.dumps(
                {
                    "group_by": rule.group_by,
                    "threshold": rule.threshold,
                    "timeframe_seconds": int(rule.timeframe.total_seconds()),
                    "correlation": rule.is_correlation,
                }
            ),
            "mitre_tactic": tactic,
            "mitre_technique_id": technique,
            "mitre_technique_name": technique_name(technique) or "",
            "engine": "sigma",
            "tags": json.dumps(rule.tags),
            "yaml_source": rule.raw_yaml,
            "rule_path": rule.source_path,
        }

        existing = db.get(DetectionRule, rule.id)
        if existing is None:
            db.add(DetectionRule(id=rule.id, enabled=True, **values))
        else:
            for key, value in values.items():
                setattr(existing, key, value)

    db.commit()
    return loaded


@app.on_event("startup")
def startup() -> None:
    init_db()
    db = SessionLocal()
    try:
        auth.ensure_bootstrap_admin(db)
        _seed_rules(db)
        _sync_sigma_rules(db)
        _retire_legacy_rules(db)
        dedup.backfill_fingerprints(db)
    finally:
        db.close()


# ── Serialization helpers ─────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_or(value: Any, fallback: Any) -> Any:
    """Decode a JSON text column, returning *fallback* on NULL/invalid data."""
    if value is None:
        return fallback
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return fallback


def _parse_ts(value) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def _event_out(e: SecurityEvent) -> Dict[str, Any]:
    raw = e.raw_data
    try:
        raw = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        pass
    return {
        "id": e.id,
        "timestamp": e.timestamp,
        "event_id": e.event_id,
        "event_type": e.event_type,
        "account": e.account,
        "source_ip": e.source_ip,
        "computer": e.computer_name,
        "computer_name": e.computer_name,
        "severity": e.severity,
        "source": e.source,
        "raw_data": raw,
        "ingestion_time": e.ingestion_time,
    }


def _alert_out(a: Alert) -> Dict[str, Any]:
    evidence = a.evidence
    try:
        evidence = json.loads(evidence) if isinstance(evidence, str) else evidence
    except Exception:
        pass
    event_ids = a.event_ids
    try:
        event_ids = json.loads(event_ids) if isinstance(event_ids, str) else event_ids
    except Exception:
        event_ids = []
    account = ""
    if isinstance(evidence, dict):
        account = evidence.get("account", "")
    return {
        "id": a.id,
        "rule_id": a.rule_id,
        "rule_name": a.rule_name,
        "severity": a.severity,
        "confidence": round((a.confidence or 0) * 100),
        "description": a.description,
        "evidence": evidence,
        "account": account,
        "mitre_tactic": a.mitre_tactic,
        "mitre_technique_id": a.mitre_technique_id,
        "mitre_technique_name": a.mitre_technique_name,
        "status": a.status,
        "created_at": a.created_at,
        "event_ids": event_ids,
        "dedup_count": a.dedup_count or 1,
        "last_seen_at": a.last_seen_at,
        "assigned_to": a.assigned_to,
        "resolution_note": a.resolution_note,
        "acknowledged_at": a.acknowledged_at,
        "resolved_at": a.resolved_at,
        "fingerprint": a.fingerprint,
    }


def _incident_out(inc: Incident, with_alerts: bool = False) -> Dict[str, Any]:
    alert_ids = json.loads(inc.alert_ids) if inc.alert_ids else []
    timeline = json.loads(inc.timeline) if inc.timeline else []
    techniques = json.loads(inc.mitre_techniques) if inc.mitre_techniques else []
    data: Dict[str, Any] = {
        "id": inc.id,
        "title": inc.title,
        "description": inc.description,
        "severity": inc.severity,
        "status": inc.status,
        "alert_ids": alert_ids,
        "timeline": timeline,
        "mitre_techniques": techniques,
        "notes": inc.investigation_notes,
        "investigation_notes": inc.investigation_notes,
        "created_at": inc.created_at,
        "updated_at": inc.updated_at,
        "last_seen_at": inc.last_seen_at,
        "assigned_to": inc.assigned_to,
        "fingerprint": inc.fingerprint,
        "chain_score": inc.chain_score or 0,
        "entities": _json_or(inc.entities, []),
        "entity_graph": _json_or(inc.entity_graph, {"nodes": [], "edges": []}),
        "attack_chain": _json_or(inc.attack_chain, {}),
    }
    return data


def _rule_out(r: DetectionRule) -> Dict[str, Any]:
    config = r.config
    try:
        config = json.loads(config) if isinstance(config, str) else config
    except Exception:
        config = {}
    return {
        "id": r.id,
        "name": r.name,
        "description": r.description,
        "severity": r.severity,
        "enabled": r.enabled,
        "config": config,
        "mitre_tactic": r.mitre_tactic,
        "mitre_technique_id": r.mitre_technique_id,
        "mitre_technique_name": r.mitre_technique_name,
        "created_at": r.created_at,
        "engine": r.engine or "python",
        "tags": json.loads(r.tags) if isinstance(r.tags, str) and r.tags.startswith("[") else [],
        "rule_path": r.rule_path,
        "has_source": bool(r.yaml_source),
    }


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SENTINEL SIEM backend"}


# ── Events ────────────────────────────────────────────────────────────────────

class EventIngest(BaseModel):
    timestamp: str
    event_id: int
    source: str = "Windows Security"
    account: str
    source_ip: Optional[str] = None
    computer_name: str = "WORKSTATION-01"
    event_type: str = "Authentication"
    severity: str = "Low"
    raw_data: Optional[dict] = None


def _canonical_ts(value: Any) -> str:
    """Normalise timestamps so DB rows and uploads compare equal.

    SQLite drops the timezone when storing a ``DateTime``, so keys must be
    UTC-normalised and rendered identically on both sides of the comparison.
    """
    if isinstance(value, datetime):
        moment = value
    else:
        try:
            moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return str(value)
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc).replace(tzinfo=None)
    return moment.isoformat(timespec="microseconds")


def _event_key(payload: Dict[str, Any]) -> tuple:
    """Identity used to avoid importing the same log record twice."""
    return (
        _canonical_ts(payload.get("timestamp")),
        int(payload.get("event_id") or 0),
        str(payload.get("computer_name") or "").upper(),
        str(payload.get("account") or "").lower(),
    )


def _insert_events(db: Session, payloads: List[Dict[str, Any]],
                   *, skip_duplicates: bool = False) -> Dict[str, int]:
    """Persist normalised event payloads, optionally skipping duplicates."""
    existing: set = set()
    if skip_duplicates and payloads:
        event_ids = {int(p.get("event_id") or 0) for p in payloads}
        rows = (
            db.query(
                SecurityEvent.timestamp,
                SecurityEvent.event_id,
                SecurityEvent.computer_name,
                SecurityEvent.account,
            )
            .filter(SecurityEvent.event_id.in_(event_ids))
            .all()
        )
        existing = {_event_key({"timestamp": r[0], "event_id": r[1],
                                "computer_name": r[2], "account": r[3]}) for r in rows}

    inserted = 0
    duplicates = 0
    for payload in payloads:
        if skip_duplicates:
            key = _event_key(payload)
            if key in existing:
                duplicates += 1
                continue
            existing.add(key)

        db.add(
            SecurityEvent(
                timestamp=_parse_ts(payload["timestamp"]),
                event_id=int(payload["event_id"]),
                source=payload.get("source") or "Windows Security",
                account=payload.get("account") or "unknown",
                source_ip=payload.get("source_ip"),
                computer_name=payload.get("computer_name") or "UNKNOWN",
                event_type=payload.get("event_type") or "Other",
                severity=payload.get("severity") or "Low",
                raw_data=json.dumps(payload.get("raw_data") or {}),
            )
        )
        inserted += 1

    db.commit()
    return {"inserted": inserted, "duplicates": duplicates}


@app.post("/api/events/ingest")
def ingest_events(events: List[EventIngest], db: Session = Depends(get_db)):
    payloads = [
        {
            "timestamp": ev.timestamp,
            "event_id": ev.event_id,
            "source": ev.source,
            "account": ev.account,
            "source_ip": ev.source_ip,
            "computer_name": ev.computer_name,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "raw_data": ev.raw_data or {},
        }
        for ev in events
    ]
    result = _insert_events(db, payloads)
    return {
        "ingested": result["inserted"],
        "message": f"{result['inserted']} event(s) ingested.",
    }


@app.post("/api/events/import")
async def import_event_log(
    file: UploadFile = File(...),
    skip_duplicates: bool = Query(True),
    dry_run: bool = Query(False),
    db: Session = Depends(get_db),
):
    """Import a `.evtx`, XML export or JSON event log."""
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(data) > 100 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds the 100 MB import limit")

    parsed = evtx_import.parse_upload(file.filename or "", data)

    if not parsed.events:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "No events could be parsed from this file",
                "format": parsed.source_format,
                "errors": parsed.errors[:10],
            },
        )

    if dry_run:
        return {
            "format": parsed.source_format,
            "parsed": len(parsed.events),
            "skipped": parsed.skipped,
            "errors": parsed.errors[:20],
            "preview": parsed.events[:5],
            "imported": 0,
            "duplicates": 0,
        }

    result = _insert_events(db, parsed.events, skip_duplicates=skip_duplicates)
    return {
        "format": parsed.source_format,
        "parsed": len(parsed.events),
        "imported": result["inserted"],
        "duplicates": result["duplicates"],
        "skipped": parsed.skipped,
        "errors": parsed.errors[:20],
        "message": (
            f"{result['inserted']} event(s) imported from {parsed.source_format}"
            + (f", {result['duplicates']} duplicate(s) skipped" if result["duplicates"] else "")
        ),
    }


@app.post("/api/events/generate-sample")
def generate_sample(db: Session = Depends(get_db)):
    events = sample_data.generate_sample_events(count=400)
    count = 0
    for ev in events:
        db.add(SecurityEvent(
            timestamp=_parse_ts(ev["timestamp"]),
            event_id=ev["event_id"],
            source=ev["source"],
            account=ev["account"],
            source_ip=ev["source_ip"],
            computer_name=ev["computer_name"],
            event_type=ev["event_type"],
            severity=ev["severity"],
            raw_data=json.dumps(ev.get("raw_data") or {}),
        ))
        count += 1
    db.commit()
    total = db.query(func.count(SecurityEvent.id)).scalar() or 0
    return {
        "generated": count,
        "total_events": total,
        "message": f"Generated and ingested {count} sample events.",
        "hint": "Now run the detection engine and correlation to see alerts and incidents.",
    }


@app.get("/api/events")
def list_events(
    skip: int = 0,
    limit: int = Query(50, le=500),
    event_type: str = "",
    severity: str = "",
    account: str = "",
    db: Session = Depends(get_db),
):
    q = db.query(SecurityEvent)
    if event_type:
        q = q.filter(SecurityEvent.event_type.ilike(f"%{event_type}%"))
    if severity:
        q = q.filter(SecurityEvent.severity.ilike(f"%{severity}%"))
    if account:
        q = q.filter(SecurityEvent.account.ilike(f"%{account}%"))
    total = q.count()
    events = q.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit).all()
    return {"events": [_event_out(e) for e in events], "total": total}


# NOTE: /stats must stay above /{event_id} — FastAPI matches routes in
# registration order, so a later declaration would be shadowed by the
# dynamic path and return 422 "event_id must be an integer".
@app.get("/api/events/stats")
def event_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(SecurityEvent.id)).scalar() or 0
    by_type = dict(db.query(SecurityEvent.event_type, func.count(SecurityEvent.id))
                   .group_by(SecurityEvent.event_type).all())
    by_severity = dict(db.query(SecurityEvent.severity, func.count(SecurityEvent.id))
                       .group_by(SecurityEvent.severity).all())
    recent = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(20).all()
    return {
        "total": total,
        "by_type": by_type,
        "by_severity": by_severity,
        "recent": [_event_out(e) for e in recent],
    }


@app.get("/api/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    e = db.get(SecurityEvent, event_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_out(e)


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
def list_alerts(
    skip: int = 0,
    limit: int = Query(50, le=500),
    severity: str = "",
    status: str = "",
    db: Session = Depends(get_db),
):
    q = db.query(Alert)
    if severity:
        q = q.filter(func.lower(Alert.severity) == severity.lower())
    if status:
        q = q.filter(func.lower(Alert.status) == status.lower())
    total = q.count()
    alerts = q.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    return {"alerts": [_alert_out(a) for a in alerts], "total": total}


@app.get("/api/alerts/stats")
def alert_stats(db: Session = Depends(get_db)):
    return {
        "total": db.query(func.count(Alert.id)).scalar() or 0,
        "by_severity": dict(db.query(Alert.severity, func.count(Alert.id))
                            .group_by(Alert.severity).all()),
        "by_status": dict(db.query(Alert.status, func.count(Alert.id))
                          .group_by(Alert.status).all()),
        "by_rule": dict(db.query(Alert.rule_id, func.count(Alert.id))
                        .group_by(Alert.rule_id).all()),
    }


# NOTE: /stats must stay above /{alert_id} — see the events note above.
@app.get("/api/alerts/metrics")
def alert_metrics(db: Session = Depends(get_db)):
    """Operational metrics analysts actually track: volume, MTTA, MTTR, FP rate."""
    alerts = db.query(Alert).all()
    now = _utcnow()

    acknowledged = [a for a in alerts if a.acknowledged_at and a.created_at]
    resolved = [a for a in alerts if a.resolved_at and a.created_at]

    def _seconds(items, end_attr):
        values = []
        for alert in items:
            end = getattr(alert, end_attr)
            if end is None:
                continue
            delta = (end - alert.created_at).total_seconds()
            values.append(max(0.0, delta))
        return values

    mtta_values = _seconds(acknowledged, "acknowledged_at")
    mttr_values = _seconds(resolved, "resolved_at")

    false_positives = sum(1 for a in alerts if a.status == "False Positive")
    closed = sum(1 for a in alerts if a.status in _TERMINAL_STATUSES)

    daily: Dict[str, int] = {}
    for offset in range(13, -1, -1):
        day = (now - timedelta(days=offset)).date().isoformat()
        daily[day] = 0
    for alert in alerts:
        if alert.created_at:
            day = alert.created_at.date().isoformat()
            if day in daily:
                daily[day] += 1

    by_rule: Dict[str, int] = {}
    for alert in alerts:
        by_rule[alert.rule_id] = by_rule.get(alert.rule_id, 0) + 1

    return {
        "total_alerts": len(alerts),
        "open_alerts": sum(1 for a in alerts if a.status not in _TERMINAL_STATUSES),
        "false_positives": false_positives,
        "false_positive_rate": round(false_positives / closed, 3) if closed else 0.0,
        "mtta_seconds": round(sum(mtta_values) / len(mtta_values), 1) if mtta_values else None,
        "mttr_seconds": round(sum(mttr_values) / len(mttr_values), 1) if mttr_values else None,
        "acknowledged_alerts": len(acknowledged),
        "resolved_alerts": len(resolved),
        "duplicate_suppressed": sum(max(0, (a.dedup_count or 1) - 1) for a in alerts),
        "daily_volume": daily,
        "top_rules": sorted(
            ({"rule_id": rid, "count": count} for rid, count in by_rule.items()),
            key=lambda item: item["count"],
            reverse=True,
        )[:10],
    }





@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_out(a)


_STATUS_MAP = {
    "new": "New", "investigating": "Investigating", "resolved": "Resolved",
    "false_positive": "False Positive", "false positive": "False Positive",
    "contained": "Contained", "open": "Open", "closed": "Resolved",
}

_ALLOWED_STATUSES = {"New", "Investigating", "Contained", "Resolved", "False Positive"}
_TERMINAL_STATUSES = {"Resolved", "False Positive"}


@app.patch("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, payload: dict, db: Session = Depends(get_db)):
    """Move an alert through its lifecycle and stamp the audit timestamps.

    Accepted payload::

        {"status": "Investigating", "assigned_to": "analyst1", "note": "..."}
    """
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    if "status" in payload:
        raw = str(payload["status"])
        status = _STATUS_MAP.get(raw.lower(), raw)
        if status not in _ALLOWED_STATUSES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status {raw!r}. Allowed: {sorted(_ALLOWED_STATUSES)}",
            )
        previous = a.status
        a.status = status

        if status != "New" and a.acknowledged_at is None:
            a.acknowledged_at = _utcnow()
        if status in _TERMINAL_STATUSES:
            a.resolved_at = a.resolved_at or _utcnow()
        elif previous in _TERMINAL_STATUSES and status not in _TERMINAL_STATUSES:
            # Re-opening a closed alert clears the resolution timestamp.
            a.resolved_at = None

    if "assigned_to" in payload:
        a.assigned_to = (payload["assigned_to"] or None)
    if "note" in payload:
        a.resolution_note = payload["note"]

    db.commit()
    return _alert_out(a)


def _load_rule_configs(db: Session) -> Dict[str, Dict[str, Any]]:
    configs: Dict[str, Dict[str, Any]] = {}
    for r in db.query(DetectionRule).all():
        cfg = r.config
        try:
            cfg = json.loads(cfg) if isinstance(cfg, str) else cfg
        except Exception:
            cfg = {}
        configs[r.id] = {"enabled": r.enabled, "config": cfg}
    return configs


def _sigma_engine(db: Session):
    """Build a Sigma engine honouring per-rule enable/disable stored in the DB."""
    loaded = SigmaEngine.load_rules([SIGMA_RULES_DIR])
    configs = _load_rule_configs(db)
    enabled = {
        rule.id: bool(configs.get(rule.id, {}).get("enabled", True))
        for rule in loaded.rules
    }
    return SigmaEngine(loaded.rules, enabled=enabled), loaded


@app.post("/api/detection/run")
def run_detection(db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).all()

    sigma_engine, loaded = _sigma_engine(db)
    sigma_alerts = sigma_engine.run(events)

    # Legacy imperative rules are still executed when an analyst enables them.
    legacy_alerts = RulesEngine(rule_configs=_load_rule_configs(db)).run_all_rules(events)

    outcome = dedup.upsert_alerts(db, sigma_alerts + legacy_alerts)
    total = db.query(func.count(Alert.id)).scalar() or 0

    return {
        "alerts_created": outcome["created"],
        "alerts_deduplicated": outcome["deduplicated"],
        "total_alerts": total,
        "events_scanned": len(events),
        "sigma_rules_loaded": len(loaded.rules),
        "sigma_rule_errors": loaded.errors,
        "message": (
            f"Detection ran {len(loaded.rules)} Sigma rule(s) over {len(events)} events; "
            f"{outcome['created']} new alert(s), {outcome['deduplicated']} duplicate(s) suppressed."
        ),
    }


@app.post("/api/detection/reload")
def reload_rules(
    db: Session = Depends(get_db),
    _: User = Depends(auth.require_role("admin")),
):
    """Re-read Sigma YAML from disk without restarting the API."""
    loaded = _sync_sigma_rules(db)
    return {
        "loaded": len(loaded.rules),
        "rules": [rule.id for rule in loaded.rules],
        "errors": loaded.errors,
        "rules_dir": SIGMA_RULES_DIR,
    }


@app.get("/api/detection/rules/{rule_id}/yaml")
def get_rule_yaml(rule_id: str, db: Session = Depends(get_db)):
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if not rule.yaml_source:
        raise HTTPException(status_code=404, detail="Rule has no Sigma source (legacy Python rule)")
    return PlainTextResponse(rule.yaml_source, media_type="text/yaml")


@app.get("/api/detection/rules")
def list_rules(db: Session = Depends(get_db)):
    rules = db.query(DetectionRule).all()
    return {"rules": [_rule_out(r) for r in rules], "total": len(rules)}


@app.patch("/api/detection/rules/{rule_id}")
def update_rule(
    rule_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    _: User = Depends(auth.require_role("admin")),
):
    r = db.get(DetectionRule, rule_id)
    if r is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    if "enabled" in payload:
        r.enabled = bool(payload["enabled"])
    if "config" in payload:
        r.config = json.dumps(payload["config"])
    db.commit()
    return _rule_out(r)


# ── Incidents ─────────────────────────────────────────────────────────────────

def _alert_event_times(db: Session, alerts: List[Alert]) -> Dict[int, datetime]:
    """Map alert id -> timestamp of the earliest event that triggered it.

    Correlation must window on event time, not on the moment the rule ran: a
    batch scan gives every alert the same creation timestamp, which collapses
    the time dimension entirely.
    """
    parsed: Dict[int, List[int]] = {}
    wanted: set = set()

    for alert in alerts:
        try:
            ids = json.loads(alert.event_ids or "[]")
        except (ValueError, TypeError):
            ids = []
        cleaned = [int(i) for i in ids if isinstance(i, (int, str)) and str(i).isdigit()]
        if cleaned:
            parsed[alert.id] = cleaned
            wanted.update(cleaned)

    if not wanted:
        return {}

    by_event: Dict[int, datetime] = {}
    ordered = sorted(wanted)
    for start in range(0, len(ordered), 500):
        chunk = ordered[start:start + 500]
        rows = (
            db.query(SecurityEvent.id, SecurityEvent.timestamp)
            .filter(SecurityEvent.id.in_(chunk))
            .all()
        )
        by_event.update({row[0]: row[1] for row in rows})

    times: Dict[int, datetime] = {}
    for alert_id, event_ids in parsed.items():
        stamps = [by_event[event_id] for event_id in event_ids if event_id in by_event]
        if stamps:
            times[alert_id] = min(stamps)
    return times


@app.post("/api/incidents/correlate")
def run_correlation(
    window_minutes: int = Query(60, ge=1, le=1440, description="Correlation window in minutes"),
    rebuild: bool = Query(
        False,
        description="Delete existing incidents before correlating. Discards status and notes.",
    ),
    db: Session = Depends(get_db),
    user: User = Depends(auth.require_user),
):
    alerts = db.query(Alert).all()

    removed = 0
    if rebuild:
        if auth.ROLE_RANK.get(user.role, 0) < auth.ROLE_RANK["admin"]:
            raise HTTPException(
                status_code=403,
                detail="Rebuilding incidents discards analyst work and requires the 'admin' role",
            )
        removed = db.query(Incident).delete()
        db.commit()

    engine = CorrelationEngine(
        alerts=alerts,
        time_window_minutes=window_minutes,
        event_times=_alert_event_times(db, alerts),
    )
    incident_dicts = engine.correlate()
    outcome = dedup.upsert_incidents(db, incident_dicts)
    total = db.query(func.count(Incident.id)).scalar() or 0

    message = (
        f"Correlation analysed {len(alerts)} alerts; {outcome['created']} new incident(s), "
        f"{outcome['deduplicated']} duplicate(s) suppressed."
    )
    if rebuild:
        message += f" Rebuilt from scratch ({removed} previous incident(s) removed)."

    return {
        "incidents_created": outcome["created"],
        "incidents_deduplicated": outcome["deduplicated"],
        "incidents_removed": removed,
        "total_incidents": total,
        "alerts_analysed": len(alerts),
        "window_minutes": window_minutes,
        "message": message,
    }


@app.get("/api/entities")
def list_entities(
    limit: int = Query(25, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Most frequently alerted-on entities across all alerts."""
    import entities as entity_mod

    alerts = db.query(Alert).all()
    index = entity_mod.entity_index(alerts)
    graph = entity_mod.build_graph(index)

    rows = []
    for node in graph["nodes"][:limit]:
        related = [edge for edge in graph["edges"] if node["key"] in (edge["source"], edge["target"])]
        rows.append(
            {
                **node,
                "connections": len(related),
                "related": [
                    edge["target"] if edge["source"] == node["key"] else edge["source"]
                    for edge in related[:10]
                ],
            }
        )

    return {
        "entities": rows,
        "total_entities": len(graph["nodes"]),
        "edges": graph["edges"][:200],
    }


@app.get("/api/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return {"incidents": [_incident_out(i) for i in incidents], "total": len(incidents)}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = _incident_out(inc, with_alerts=True)
    alert_ids = data["alert_ids"]
    data["alerts"] = []
    for aid in alert_ids:
        a = db.get(Alert, aid)
        if a is not None:
            data["alerts"].append(_alert_out(a))
    return data


@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(incident_id: int, payload: dict, db: Session = Depends(get_db)):
    inc = db.get(Incident, incident_id)
    if inc is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    raw = payload.get("status", "")
    inc.status = _STATUS_MAP.get(raw.lower(), raw)
    db.commit()
    return _incident_out(inc, with_alerts=True)


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

@app.get("/api/mitre/techniques")
def mitre_techniques(db: Session = Depends(get_db)):
    counts = dict(db.query(Alert.mitre_technique_id, func.count(Alert.id))
                  .group_by(Alert.mitre_technique_id).all())
    out = []
    for t in get_all_techniques():
        out.append({
            "id": t["id"],
            "name": t["name"],
            "tactic": t["tactic"].split(",")[0].strip(),
            "description": t["description"],
            "alert_count": counts.get(t["id"], 0),
        })
    return {"techniques": out, "total": len(out)}


@app.get("/api/mitre/techniques/{technique_id}")
def mitre_technique_detail(technique_id: str, db: Session = Depends(get_db)):
    t = get_technique(technique_id)
    if t is None:
        raise HTTPException(status_code=404, detail="Technique not found")
    alerts = db.query(Alert).filter(Alert.mitre_technique_id == technique_id).all()
    return {
        "id": t["id"],
        "name": t["name"],
        "tactic": t["tactic"],
        "description": t["description"],
        "detection_guidance": t["detection"],
        "investigation_steps": t["investigation_steps"],
        "recommended_response": t["recommended_response"],
        "alerts": [_alert_out(a) for a in alerts],
    }


@app.get("/api/mitre/coverage")
def mitre_coverage(db: Session = Depends(get_db)):
    all_tech = get_all_techniques()
    counts = dict(db.query(Alert.mitre_technique_id, func.count(Alert.id))
                  .group_by(Alert.mitre_technique_id).all())
    covered = [t for t in all_tech if counts.get(t["id"], 0) > 0]
    tactics: Dict[str, int] = {}
    for t in all_tech:
        for tac in [x.strip() for x in t["tactic"].split(",")]:
            tactics[tac] = tactics.get(tac, 0) + counts.get(t["id"], 0)
    return {
        "total_techniques": len(all_tech),
        "covered_techniques": len(covered),
        "coverage_percentage": round(len(covered) / len(all_tech) * 100, 1) if all_tech else 0,
        "tactics": tactics,
        "techniques": [{"id": t["id"], "name": t["name"], "tactic": t["tactic"], "alert_count": counts.get(t["id"], 0)} for t in all_tech],
    }


# ── AI Assistant ──────────────────────────────────────────────────────────────

class AIAskRequest(BaseModel):
    question: str
    context_type: str = ""
    context_id: Optional[int] = None


class AIContextRequest(BaseModel):
    context_type: str = ""
    context_id: Optional[int] = None
    type: str = ""  # alias used by some clients
    id: Optional[int] = None


class AIReportRequest(BaseModel):
    incident_id: int


@app.post("/api/ai/ask")
def ai_ask(payload: AIAskRequest, db: Session = Depends(get_db)):
    ctx_type = payload.context_type or ""
    ctx_id = payload.context_id
    if ctx_type not in ("alert", "incident"):
        return {
            "answer": "Select an alert or incident as context so I can answer from actual evidence.",
            "sections": [],
        }
    result = ai_assistant.answer_question(db, payload.question, ctx_type, ctx_id)
    return result


@app.post("/api/ai/summary")
def ai_summary(payload: AIContextRequest, db: Session = Depends(get_db)):
    ctx_type = payload.context_type or payload.type or ""
    ctx_id = payload.context_id if payload.context_id is not None else payload.id
    return ai_assistant.summarize(db, ctx_type, ctx_id)


@app.post("/api/ai/report")
def ai_report(payload: AIReportRequest, db: Session = Depends(get_db)):
    return ai_assistant.generate_report(db, payload.incident_id)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    active_alerts = db.query(func.count(Alert.id)).filter(
        func.lower(Alert.status).in_(["new", "investigating"])
    ).scalar() or 0
    open_incidents = db.query(func.count(Incident.id)).filter(
        func.lower(Incident.status).in_(["open", "investigating", "contained"])
    ).scalar() or 0
    rules = db.query(DetectionRule).all()
    active_rules = sum(1 for r in rules if r.enabled)
    alert_severity = dict(db.query(Alert.severity, func.count(Alert.id))
                          .group_by(Alert.severity).all())
    alert_severity_breakdown = {k.lower(): v for k, v in alert_severity.items()}
    return {
        "total_events": total_events,
        "total_alerts": total_alerts,
        "active_alerts": active_alerts,
        "open_incidents": open_incidents,
        "active_rules": active_rules,
        "total_rules": len(rules),
        "alert_severity_breakdown": alert_severity_breakdown,
        "alerts_by_status": dict(db.query(Alert.status, func.count(Alert.id))
                                 .group_by(Alert.status).all()),
        "incidents_by_status": dict(db.query(Incident.status, func.count(Incident.id))
                                    .group_by(Incident.status).all()),
        "recent_alerts": [_alert_out(a) for a in
                          db.query(Alert).order_by(Alert.created_at.desc()).limit(10).all()],
        "recent_incidents": [_incident_out(i) for i in
                             db.query(Incident).order_by(Incident.created_at.desc()).limit(5).all()],
    }


# ── Export ─────────────────────────────────────────────────────────────────────

@app.get("/api/export/events.csv")
def export_events_csv(db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "timestamp", "event_id", "event_type", "account", "source_ip", "computer_name", "severity"])
    for e in events:
        writer.writerow([e.id, e.timestamp, e.event_id, e.event_type, e.account,
                         e.source_ip or "", e.computer_name, e.severity])
    return {"filename": "siem_events.csv", "mime": "text/csv",
            "content": buf.getvalue(), "count": len(events)}


@app.get("/api/export/events.json")
def export_events_json(db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp).all()
    return {"filename": "siem_events.json", "mime": "application/json",
            "content": json.dumps([_event_out(e) for e in events], default=str), "count": len(events)}


@app.get("/api/export/alerts.json")
def export_alerts_json(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(Alert.created_at).all()
    return {"filename": "siem_alerts.json", "mime": "application/json",
            "content": json.dumps([_alert_out(a) for a in alerts], default=str), "count": len(alerts)}


@app.get("/api/export/incidents.json")
def export_incidents_json(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at).all()
    return {"filename": "siem_incidents.json", "mime": "application/json",
            "content": json.dumps([_incident_out(i) for i in incidents], default=str), "count": len(incidents)}


# ── IoC enrichment ────────────────────────────────────────────────────────────

class IoCLookupRequest(BaseModel):
    value: str
    type: Optional[str] = None


@app.post("/api/ioc/lookup")
def ioc_lookup(payload: IoCLookupRequest):
    return ioc.lookup(payload.value, payload.type)


@app.post("/api/ioc/alert/{alert_id}")
def ioc_alert(alert_id: int, db: Session = Depends(get_db)):
    return ioc.enrich_alert(db, alert_id)


@app.post("/api/ioc/scan")
def ioc_scan(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    all_hits: List[Dict[str, Any]] = []
    for a in alerts:
        res = ioc.enrich_alert(db, a.id)
        if res.get("hits"):
            all_hits.append({"alert_id": a.id, "rule_name": res.get("rule_name"),
                             "risk_level": res.get("risk_level"), "hits": res["hits"]})
    return {"alerts_scanned": len(alerts), "alerts_with_hits": len(all_hits), "results": all_hits}
