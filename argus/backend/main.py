"""
ARGUS — Attack Surface Intelligence API.

Runs deterministic lab scans, stores assets and deduplicated findings, computes
risk, and exposes a citation-style deterministic assistant. Real network
discovery is not wired into the API; every scan is clearly labelled as lab data.
Only use ARGUS against domains you own or are explicitly authorised to assess.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

import ai_assistant
import auth
import discovery_engine
import lifecycle
import risk_engine
from database import SessionLocal, get_db, init_db
from models import Asset, Finding, Scan, User
from risk_engine import domain_risk

app = FastAPI(title="ARGUS Attack Surface Intelligence API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

auth.install(app)
app.include_router(auth.router)


@app.on_event("startup")
def startup() -> None:
    init_db()
    db = SessionLocal()
    try:
        auth.ensure_bootstrap_admin(db)
        lifecycle.backfill_fingerprints(db)
    finally:
        db.close()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _latest_scan_id(db: Session) -> Optional[int]:
    return db.query(func.max(Scan.id)).scalar()


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
        "last_scan_id": a.last_scan_id,
        "is_new": a.is_new,
        "http_status": a.http_status,
        "is_web": a.is_web,
        "open_ports": json.loads(a.open_ports) if a.open_ports else [],
        "tls_expiry": a.tls_expiry,
        "security_headers": json.loads(a.security_headers) if a.security_headers else {},
        "risk_score": a.risk_score or 0.0,
        "findings": None,
    }


def _finding_out(f: Finding, latest_scan_id: Optional[int] = None) -> Dict[str, Any]:
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
        "fingerprint": f.fingerprint,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
        "last_scan_id": f.last_scan_id,
        "dedup_count": f.dedup_count or 1,
        "reopened_count": f.reopened_count or 0,
        "acknowledged_at": f.acknowledged_at,
        "resolved_at": f.resolved_at,
        "assigned_to": f.assigned_to,
        "resolution_note": f.resolution_note,
        "stale": bool(latest_scan_id and f.last_scan_id != latest_scan_id),
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
        "reopened_findings": s.reopened_findings,
        "risk_score": s.risk_score or 0.0,
        "summary": s.summary,
    }


def _current_domain_risk(db: Session) -> float:
    """Aggregate current domain risk across open findings."""
    findings = db.query(Finding).all()
    return domain_risk([_finding_out(f) for f in findings])["domain_risk_score"]


# ── Scan ─────────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    domain: str = Field(default=discovery_engine.LAB_DOMAIN, min_length=1, max_length=500)


def _upsert_scan(db: Session, domain: str) -> Scan:
    now = _utcnow()
    scan_index = db.query(func.count(Scan.id)).filter(Scan.domain == domain).scalar() or 0

    scan = Scan(domain=domain, status="Running", started_at=now)
    db.add(scan)
    db.flush()

    lab = discovery_engine.scan_lab(domain, scan_index)
    assets = lab["assets"]
    existing = {a.hostname: a for a in db.query(Asset).all()}

    new_assets = 0
    observed = 0
    new_findings = 0
    reopened = 0

    for asset_dict in assets:
        host = asset_dict["hostname"]
        tls_value = asset_dict.get("tls_expiry")

        asset = existing.get(host)
        is_new_asset = asset is None
        if asset is None:
            asset = Asset(hostname=host, first_seen=now)
            db.add(asset)
            new_assets += 1

        # Refresh every field, not only on first discovery: a fixed certificate
        # or a newly added header must clear the old finding on the next scan.
        asset.asset_type = asset_dict.get("asset_type", "Subdomain")
        asset.ip = asset_dict.get("ip")
        asset.status = asset_dict.get("status", "Unknown")
        asset.http_status = asset_dict.get("http_status")
        asset.is_web = bool(asset_dict.get("is_web"))
        asset.open_ports = json.dumps(asset_dict.get("open_ports", []))
        asset.tls_expiry = datetime.fromisoformat(tls_value) if tls_value else None
        asset.security_headers = json.dumps(asset_dict.get("security_headers", {}))
        asset.last_seen = now
        asset.last_scan_id = scan.id
        asset.is_new = is_new_asset
        db.flush()
        existing[host] = asset

        candidates: List[Dict[str, Any]] = []
        for candidate in discovery_engine.generate_lab_findings(asset_dict, scan_index):
            candidate = dict(candidate)
            candidate["risk_score"] = risk_engine.risk_score_for(
                candidate.get("severity", "Info"),
                candidate.get("exposure", "Internet"),
                candidate.get("confidence", 0.8),
            )
            candidates.append(candidate)

        observed += len(candidates)
        stats = lifecycle.upsert_findings(db, asset, candidates, scan.id, now)
        new_findings += stats["new"]
        reopened += stats["reopened"]
        db.flush()

        mine = db.query(Finding).filter(Finding.asset_id == asset.id).all()
        asset.risk_score = risk_engine.asset_risk(
            host, [_finding_out(f) for f in mine]
        )["risk_score"]

    # Assets absent from a scan are not deleted; last_seen stays at the last
    # observation and the UI can flag them as stale.
    scan.status = "Complete"
    scan.finished_at = _utcnow()
    scan.assets_discovered = len(assets)
    scan.new_assets = new_assets
    scan.findings_discovered = observed
    scan.new_findings = new_findings
    scan.reopened_findings = reopened
    scan.risk_score = _current_domain_risk(db)
    scan.summary = (
        f"Lab scan of {len(assets)} asset(s): {new_assets} new, "
        f"{new_findings} new finding(s), {reopened} reopened."
    )

    db.commit()
    db.refresh(scan)
    return scan


@app.post("/api/scan")
def run_scan(payload: ScanRequest | None = None, db: Session = Depends(get_db)):
    domain = (payload.domain if payload else discovery_engine.LAB_DOMAIN).strip().lower()
    if domain != discovery_engine.LAB_DOMAIN:
        raise HTTPException(
            status_code=400,
            detail=(
                "This build only runs the deterministic lab inventory for "
                f"'{discovery_engine.LAB_DOMAIN}'. Real network discovery is "
                "not exposed by the API; only scan systems you are authorised to assess."
            ),
        )
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
    assets = q.order_by(Asset.risk_score.desc(), Asset.hostname).all()
    return {"assets": [_asset_out(a) for a in assets], "total": len(assets)}


@app.get("/api/assets/{asset_id}")
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    latest = _latest_scan_id(db)
    out = _asset_out(a)
    findings = (
        db.query(Finding)
        .filter(Finding.asset_id == asset_id)
        .order_by(Finding.risk_score.desc())
        .all()
    )
    out["findings"] = [_finding_out(f, latest) for f in findings]
    out["risk"] = risk_engine.asset_risk(
        a.hostname, [_finding_out(f) for f in findings]
    )
    return out


# ── Findings ──────────────────────────────────────────────────────────────────

@app.get("/api/findings/stats")
def finding_stats(db: Session = Depends(get_db)):
    latest = _latest_scan_id(db)
    findings = db.query(Finding).all()

    by_severity: Dict[str, int] = {}
    by_status: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    stale = 0
    suppressed = 0

    for finding in findings:
        if str(finding.status).lower() == "resolved":
            suppressed += 1
            continue
        by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
        by_status[finding.status] = by_status.get(finding.status, 0) + 1
        by_category[finding.category] = by_category.get(finding.category, 0) + 1
        if latest and finding.last_scan_id != latest:
            stale += 1

    return {
        "total": len(findings),
        "open": len(findings) - suppressed,
        "resolved": suppressed,
        "stale": stale,
        "dismissed_duplicates": sum(max(0, (f.dedup_count or 1) - 1) for f in findings),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_category": by_category,
        "risk": domain_risk([_finding_out(f) for f in findings]),
    }


@app.get("/api/findings/metrics")
def finding_metrics(db: Session = Depends(get_db)):
    findings = db.query(Finding).all()
    resolved = [f for f in findings if str(f.status).lower() == "resolved" and f.resolved_at]
    durations = [
        (f.resolved_at - f.first_seen).total_seconds()
        for f in resolved
        if f.first_seen and f.resolved_at and f.resolved_at >= f.first_seen
    ]
    open_findings = [f for f in findings if str(f.status).lower() != "resolved"]
    reopened = sum(1 for f in findings if (f.reopened_count or 0) > 0)
    total_observations = sum(f.dedup_count or 1 for f in findings)

    return {
        "total_findings": len(findings),
        "open_findings": len(open_findings),
        "resolved_findings": len(resolved),
        "mean_time_to_remediate_hours": round(sum(durations) / len(durations) / 3600, 2)
        if durations else None,
        "reopened_findings": reopened,
        "reopen_rate": round(reopened / len(findings), 3) if findings else 0.0,
        "observations": total_observations,
        "deduplicated_observations": max(0, total_observations - len(findings)),
        "dedup_ratio": round(total_observations / len(findings), 2) if findings else 0.0,
    }


@app.get("/api/findings")
def list_findings(
    severity: str = "",
    category: str = "",
    status: str = "",
    include_resolved: bool = True,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    latest = _latest_scan_id(db)
    q = db.query(Finding)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category.ilike(f"%{category}%"))
    if status:
        q = q.filter(Finding.status.ilike(f"%{status}%"))
    if not include_resolved:
        q = q.filter(func.lower(Finding.status) != "resolved")
    findings = q.order_by(Finding.risk_score.desc()).limit(limit).all()
    return {
        "findings": [_finding_out(f, latest) for f in findings],
        "total": len(findings),
        "latest_scan_id": latest,
    }


class FindingStatusUpdate(BaseModel):
    status: Literal["Open", "Acknowledged", "Resolved"]
    assigned_to: Optional[str] = Field(default=None, max_length=120)
    note: Optional[str] = Field(default=None, max_length=2000)


@app.patch("/api/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    payload: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    now = _utcnow()
    finding.status = payload.status
    if payload.assigned_to is not None:
        finding.assigned_to = payload.assigned_to.strip() or None
    if payload.note is not None:
        finding.resolution_note = payload.note.strip() or None

    if payload.status == "Acknowledged":
        finding.acknowledged_at = finding.acknowledged_at or now
        finding.resolved_at = None
    elif payload.status == "Resolved":
        finding.resolved_at = finding.resolved_at or now
    else:
        finding.acknowledged_at = None
        finding.resolved_at = None

    db.commit()
    db.refresh(finding)
    return _finding_out(finding, _latest_scan_id(db))


# ── Scans ─────────────────────────────────────────────────────────────────────

@app.get("/api/scan/history")
def scan_history(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(limit).all()
    return {"scans": [_scan_out(s) for s in scans], "total": len(scans)}


@app.get("/api/scan/latest")
def latest_scan(db: Session = Depends(get_db)):
    scan = db.query(Scan).order_by(Scan.started_at.desc()).first()
    if scan is None:
        return {"scan": None, "new_findings": []}
    latest = _latest_scan_id(db)
    findings = (
        db.query(Finding)
        .filter(Finding.last_scan_id == scan.id)
        .order_by(Finding.risk_score.desc())
        .all()
    )
    return {"scan": _scan_out(scan), "new_findings": [_finding_out(f, latest) for f in findings]}


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    latest = _latest_scan_id(db)
    findings = (
        db.query(Finding)
        .filter(Finding.last_scan_id == scan_id)
        .order_by(Finding.risk_score.desc())
        .all()
    )
    return {"scan": _scan_out(scan), "findings": [_finding_out(f, latest) for f in findings]}


# ── Dashboard / risk ──────────────────────────────────────────────────────────

@app.get("/api/dashboard/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    latest = _latest_scan_id(db)
    serialized = [_finding_out(f, latest) for f in findings]
    risk = domain_risk(serialized)
    scans = db.query(Scan).order_by(Scan.started_at.desc()).all()

    open_findings = [f for f in serialized if str(f["status"]).lower() != "resolved"]
    by_severity: Dict[str, int] = {}
    for finding in open_findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1

    trend = [
        {
            "label": s.started_at,
            "assets": s.assets_discovered,
            "findings": s.findings_discovered,
            "risk": s.risk_score or 0.0,
        }
        for s in scans[:10]
    ]

    return {
        "total_assets": len(assets),
        "new_assets": sum(1 for a in assets if a.is_new),
        "open_findings": len(open_findings),
        "resolved_findings": len(serialized) - len(open_findings),
        "stale_findings": sum(1 for f in open_findings if f["stale"]),
        "risk": risk,
        "findings_by_severity": by_severity,
        "scan_history": [_scan_out(s) for s in scans[:10]],
        "trend": trend,
    }


# ── Export ─────────────────────────────────────────────────────────────────────

@app.get("/api/export/findings.json")
def export_findings_json(db: Session = Depends(get_db)):
    latest = _latest_scan_id(db)
    findings = db.query(Finding).order_by(Finding.risk_score.desc()).all()
    return {
        "filename": "argus_findings.json",
        "mime": "application/json",
        "content": json.dumps([_finding_out(f, latest) for f in findings], default=str),
        "count": len(findings),
    }


@app.get("/api/export/assets.json")
def export_assets_json(db: Session = Depends(get_db)):
    assets = db.query(Asset).order_by(Asset.hostname).all()
    return {
        "filename": "argus_assets.json",
        "mime": "application/json",
        "content": json.dumps([_asset_out(a) for a in assets], default=str),
        "count": len(assets),
    }


@app.get("/api/export/report.txt")
def export_report_txt(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    findings = db.query(Finding).all()
    latest = db.query(Scan).order_by(Scan.started_at.desc()).first()
    report = ai_assistant.generate_report(assets, findings, latest)["report"]
    return {
        "filename": "argus_security_report.txt",
        "mime": "text/plain",
        "content": report,
        "count": len(report),
    }


# ── AI assistant ─────────────────────────────────────────────────────────────

class AIAskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


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
