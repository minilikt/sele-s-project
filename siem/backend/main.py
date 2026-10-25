"""
SENTINEL SIEM Platform — FastAPI application.

Wires together the detection engine, correlation engine, MITRE ATT&CK mapping,
sample data generator and the AI investigation assistant into a single API.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import ai_assistant
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
from models import Alert, DetectionRule, Incident, SecurityEvent

app = FastAPI(title="SENTINEL SIEM Platform API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Startup ───────────────────────────────────────────────────────────────────

def _seed_rules(db: Session) -> None:
    for rec in RulesEngine.get_default_rule_records():
        if db.get(DetectionRule, rec["id"]) is None:
            db.add(DetectionRule(**rec))
    db.commit()


@app.on_event("startup")
def startup() -> None:
    init_db()
    db = SessionLocal()
    try:
        _seed_rules(db)
    finally:
        db.close()


# ── Serialization helpers ─────────────────────────────────────────────────────

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


@app.post("/api/events/ingest")
def ingest_events(events: List[EventIngest], db: Session = Depends(get_db)):
    count = 0
    for ev in events:
        raw = ev.raw_data if ev.raw_data is not None else {}
        db.add(SecurityEvent(
            timestamp=_parse_ts(ev.timestamp),
            event_id=ev.event_id,
            source=ev.source,
            account=ev.account,
            source_ip=ev.source_ip,
            computer_name=ev.computer_name,
            event_type=ev.event_type,
            severity=ev.severity,
            raw_data=json.dumps(raw),
        ))
        count += 1
    db.commit()
    return {"ingested": count, "message": f"{count} event(s) ingested."}


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


@app.get("/api/events/{event_id}")
def get_event(event_id: int, db: Session = Depends(get_db)):
    e = db.get(SecurityEvent, event_id)
    if e is None:
        raise HTTPException(status_code=404, detail="Event not found")
    return _event_out(e)


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


@app.patch("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, payload: dict, db: Session = Depends(get_db)):
    a = db.get(Alert, alert_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    raw = payload.get("status", "")
    a.status = _STATUS_MAP.get(raw.lower(), raw)
    db.commit()
    return _alert_out(a)


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


# ── Detection ─────────────────────────────────────────────────────────────────

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


@app.post("/api/detection/run")
def run_detection(db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).all()
    engine = RulesEngine(rule_configs=_load_rule_configs(db))
    alert_dicts = engine.run_all_rules(events)
    created = 0
    for ad in alert_dicts:
        db.add(Alert(**ad))
        created += 1
    db.commit()
    total = db.query(func.count(Alert.id)).scalar() or 0
    return {
        "alerts_created": created,
        "total_alerts": total,
        "message": f"Detection ran over {len(events)} events; {created} new alert(s) created.",
    }


@app.get("/api/detection/rules")
def list_rules(db: Session = Depends(get_db)):
    rules = db.query(DetectionRule).all()
    return {"rules": [_rule_out(r) for r in rules], "total": len(rules)}


@app.patch("/api/detection/rules/{rule_id}")
def update_rule(rule_id: str, payload: dict, db: Session = Depends(get_db)):
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

@app.post("/api/incidents/correlate")
def run_correlation(db: Session = Depends(get_db)):
    alerts = db.query(Alert).all()
    engine = CorrelationEngine(alerts=alerts, time_window_minutes=60)
    incident_dicts = engine.correlate()
    created = 0
    for inc in incident_dicts:
        db.add(Incident(**inc))
        created += 1
    db.commit()
    total = db.query(func.count(Incident.id)).scalar() or 0
    return {
        "incidents_created": created,
        "total_incidents": total,
        "message": f"Correlation analysed {len(alerts)} alerts; {created} incident(s) created.",
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
