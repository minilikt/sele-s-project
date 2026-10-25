"""
ARGUS — Attack Surface Intelligence API.

Runs discovery scans, stores assets and findings, computes risk, and exposes
the deterministic AI assistant. The default scan uses the built-in lab domain;
real scanning is only for domains you are authorised to assess.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

import ai_assistant
import discovery_engine
from database import SessionLocal, get_db, init_db
from models import Asset, Finding, Scan
import risk_engine
from risk_engine import domain_risk, rank_findings

app = FastAPI(title="ARGUS Attack Surface Intelligence API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup() -> None:
    init_db()


# ── Serialization ─────────────────────────────────────────────────────────────

def _asset_out(a: Asset) -> Dict[str, Any]:
    return {
        "id": a.id,
        "hostname": a.hostname,
        "asset_type": a.asset_type,
        "ip": a.ip,
        "status": a.status,
        "first_seen": a.first_seen,
        "last_seen": a.last_seen,
        "is_new": a.is_new,
        "http_status": a.http_status,
        "is_web": a.is_web,
        "open_ports": json.loads(a.open_ports) if a.open_ports else [],
        "tls_expiry": a.tls_expiry,
        "security_headers": json.loads(a.security_headers) if a.security_headers else {},
        "findings": None,
    }


def _finding_out(f: Finding) -> Dict[str, Any]:
    risk_score = f.risk_score if f.risk_score else risk_engine.risk_score_for(
        f.severity, f.exposure, f.confidence)
    return {
        "id": f.id,
        "asset_id": f.asset_id,
        "asset_hostname": f.asset_hostname,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "severity": f.severity,
        "risk_score": risk_score,
        "exposure": f.exposure,
        "confidence": f.confidence,
        "recommendation": f.recommendation,
        "status": f.status,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
    }


def _scan_out(s: Scan) -> Dict[str, Any]:
    return {
        "id": s.id,
        "domain": s.domain,
        "started_at": s.started_at,
        "finished_at": s.finished_at,
        "status": s.status,
        "assets_discovered": s.assets_discovered,
        "new_assets": s.new_assets,
        "findings_discovered": s.findings_discovered,
        "new_findings": s.new_findings,
        "risk_score": s.risk_score or 0.0,
        "summary": s.summary,
    }


def _current_domain_risk(db: Session) -> float:
    """Aggregate current domain risk score across open findings."""
    findings = db.query(Finding).all()
    return domain_risk([_finding_out(f) for f in findings])["domain_risk_score"]


# ── Scan ─────────────────────────────────────────────────────────────────────

def _upsert_scan(db: Session, domain: str) -> Scan:
    scan_index = db.query(func.count(Scan.id)).filter(Scan.domain == domain).scalar() or 0
    lab = discovery_engine.scan_lab(domain, scan_index)
    assets = lab["assets"]

    existing = {a.hostname: a for a in db.query(Asset).all()}
    new_asset_count = 0
    findings_created = 0

    for asset_dict in assets:
        host = asset_dict["hostname"]
        if host in existing:
            a = existing[host]
            a.last_seen = datetime.now(timezone.utc)
            a.is_new = False
            a.status = asset_dict["status"]
            a.http_status = asset_dict.get("http_status")
            a.open_ports = json.dumps(asset_dict.get("open_ports", []))
        else:
            a = Asset(hostname=host, is_new=True, first_seen=datetime.now(timezone.utc),
                     asset_type=asset_dict.get("asset_type", "Subdomain"),
                     ip=asset_dict.get("ip"),
                     status=asset_dict.get("status", "Unknown"),
                     http_status=asset_dict.get("http_status"),
                     is_web=asset_dict.get("is_web", False),
                     open_ports=json.dumps(asset_dict.get("open_ports", [])),
                     tls_expiry=datetime.fromisoformat(asset_dict["tls_expiry"]) if asset_dict.get("tls_expiry") else None,
                     security_headers=json.dumps(asset_dict.get("security_headers", {})))
            db.add(a)
            db.flush()
            existing[host] = a
            new_asset_count += 1
            for fd in discovery_engine.generate_lab_findings(asset_dict, scan_index):
                fd = dict(fd)
                fd["asset_id"] = a.id
                fd["asset_hostname"] = host
                fd["risk_score"] = risk_engine.risk_score_for(
                    fd.get("severity", "Info"), fd.get("exposure", "Internet"), fd.get("confidence", 0.8))
                db.add(Finding(**fd))
                findings_created += 1

    scan = Scan(domain=domain, status="Complete",
               finished_at=datetime.now(timezone.utc),
               assets_discovered=len(assets),
               new_assets=new_asset_count,
               findings_discovered=findings_created,
               new_findings=findings_created,
               risk_score=_current_domain_risk(db),
               summary=f"Scanned {len(assets)} assets; {new_asset_count} new.")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@app.post("/api/scan")
def run_scan(payload: dict | None = None, db: Session = Depends(get_db)):
    domain = (payload or {}).get("domain") or discovery_engine.LAB_DOMAIN
    scan = _upsert_scan(db, domain)
    return _scan_out(scan)


# ── Assets ────────────────────────────────────────────────────────────────────

@app.get("/api/assets")
def list_assets(
    asset_type: str = "",
    status: str = "",
    is_new: bool | None = None,
    db: Session = Depends(get_db),
):
    q = db.query(Asset)
    if asset_type:
        q = q.filter(Asset.asset_type.ilike(f"%{asset_type}%"))
    if status:
        q = q.filter(Asset.status.ilike(f"%{status}%"))
    if is_new is not None:
        q = q.filter(Asset.is_new == is_new)
    assets = q.order_by(Asset.hostname).all()
    return {"assets": [_asset_out(a) for a in assets], "total": len(assets)}


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    out = _asset_out(a)
    findings = db.query(Finding).filter(Finding.asset_id == asset_id).all()
    out["findings"] = [_finding_out(f) for f in findings]
    return out


# ── Findings ──────────────────────────────────────────────────────────────────

@app.get("/api/findings")
def list_findings(
    severity: str = "",
    category: str = "",
    status: str = "",
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category.ilike(f"%{category}%"))
    if status:
        q = q.filter(Finding.status.ilike(f"%{status}%"))
    findings = q.order_by(Finding.risk_score.desc()).all()
    return {"findings": [_finding_out(f) for f in findings], "total": len(findings)}


@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(finding_id: int, payload: dict, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    raw = payload.get("status", "")
    f.status = raw if raw in ("Open", "Acknowledged", "Resolved") else raw.title()
    db.commit()
    return _finding_out(f)


@app.get("/api/scan/history")
def scan_history(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(50).all()
    return {"scans": [_scan_out(s) for s in scans], "total": len(scans)}


# ── Dashboard / risk ──────────────────────────────────────────────────────────

@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    risk = domain_risk([_finding_out(f) for f in findings])
    scans = db.query(Scan).order_by(Scan.started_at.desc()).all()
    by_severity = dict(db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity).all())
    new_assets = [a for a in assets if a.is_new]
    trend = [{"label": s.started_at, "assets": s.assets_discovered, "findings": s.findings_discovered,
              "risk": s.risk_score or 0.0}
             for s in scans[-10:]]
    return {
        "total_assets": len(assets),
        "new_assets": len(new_assets),
        "risk": risk,
        "findings_by_severity": {k: v for k, v in by_severity.items()},
        "scan_history": [_scan_out(s) for s in scans[-10:]],
        "trend": trend,
    }


# ── Export ─────────────────────────────────────────────────────────────────────

@app.get("/api/export/findings.json")
def export_findings_json(db: Session = Depends(get_db)):
    findings = db.query(Finding).order_by(Finding.risk_score.desc()).all()
    return {"filename": "argus_findings.json", "mime": "application/json",
            "content": json.dumps([_finding_out(f) for f in findings], default=str),
            "count": len(findings)}


@app.get("/api/export/assets.json")
def export_assets_json(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.hostname).all()
    return {"filename": "argus_assets.json", "mime": "application/json",
            "content": json.dumps([_asset_out(a) for a in assets], default=str),
            "count": len(assets)}


@app.get("/api/export/report.txt")
def export_report_txt(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    latest = db.query(Scan).order_by(Scan.started_at.desc()).first()
    report = ai_assistant.generate_report(assets, findings, latest)["report"]
    return {"filename": "argus_security_report.txt", "mime": "text/plain",
            "content": report, "count": len(report)}


# ── AI assistant ─────────────────────────────────────────────────────────────

class AIAskRequest(BaseModel):
    question: str


@app.post("/api/ai/ask")
def ai_ask(payload: AIAskRequest, db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    latest = db.query(Scan).order_by(Scan.started_at.desc()).first()
    return ai_assistant.answer_question(payload.question, assets, findings, latest)


@app.post("/api/ai/report")
def ai_report(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    latest = db.query(Scan).order_by(Scan.started_at.desc()).first()
    return ai_assistant.generate_report(assets, findings, latest)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ARGUS backend"}
