"""
Finding identity, deduplication and lifecycle for ARGUS.

A fingerprint is the SHA-256 of ``hostname | category | title``. Re-running a
scan updates the existing finding (detail, score, last_seen, dedup_count)
instead of creating a duplicate. Two lifecycle rules matter:

* A **resolved** finding that reappears is reopened and ``reopened_count`` is
  incremented. A fix that silently regresses is security-relevant.
* An **acknowledged** finding stays acknowledged; its evidence is refreshed but
  an analyst decision is not overwritten.

Findings that are simply absent from a scan are *not* auto-resolved. A partial
or failed scan should never close real issues; analysts resolve findings
explicitly, and the UI shows ``stale`` when a finding was not observed in the
latest scan.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from models import Finding

_MUTABLE_FIELDS = (
    "detail",
    "severity",
    "risk_score",
    "exposure",
    "confidence",
    "recommendation",
)


def fingerprint(hostname: str, category: str, title: str) -> str:
    raw = f"{hostname.strip().lower()}|{category.strip().lower()}|{title.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def find_existing(db: Session, fp: str) -> Optional[Finding]:
    return db.query(Finding).filter(Finding.fingerprint == fp).order_by(Finding.id).first()


def upsert_findings(
    db: Session,
    asset,
    candidates: Iterable[Dict[str, Any]],
    scan_id: int,
    now: Optional[datetime] = None,
) -> Dict[str, int]:
    """Create or refresh findings for *asset*. Returns counters."""
    now = now or datetime.now(timezone.utc)
    stats = {"new": 0, "updated": 0, "reopened": 0}

    for candidate in candidates:
        data = dict(candidate)
        fp = fingerprint(asset.hostname, data["category"], data["title"])
        existing = find_existing(db, fp)

        if existing is None:
            db.add(
                Finding(
                    asset_id=asset.id,
                    asset_hostname=asset.hostname,
                    fingerprint=fp,
                    status="Open",
                    first_seen=now,
                    last_seen=now,
                    dedup_count=1,
                    last_scan_id=scan_id,
                    **data,
                )
            )
            stats["new"] += 1
            continue

        existing.asset_id = asset.id
        existing.asset_hostname = asset.hostname
        for field in _MUTABLE_FIELDS:
            if field in data:
                setattr(existing, field, data[field])

        existing.last_seen = now
        existing.last_scan_id = scan_id
        existing.dedup_count = (existing.dedup_count or 1) + 1

        if existing.status == "Resolved":
            existing.status = "Open"
            existing.resolved_at = None
            existing.reopened_count = (existing.reopened_count or 0) + 1
            stats["reopened"] += 1

        stats["updated"] += 1

    return stats


def backfill_fingerprints(db: Session) -> Dict[str, int]:
    """Assign fingerprints to findings created before deduplication existed.

    Duplicate rows that share a fingerprint are merged into the oldest row so
    that the same issue is not counted twice. This only runs on legacy data.
    """
    pending = db.query(Finding).filter(Finding.fingerprint.is_(None)).all()
    if not pending:
        return {"backfilled": 0, "merged": 0}

    groups: Dict[str, List[Finding]] = {}
    for finding in pending:
        fp = fingerprint(finding.asset_hostname, finding.category, finding.title)
        groups.setdefault(fp, []).append(finding)

    merged = 0
    for fp, rows in groups.items():
        rows.sort(key=lambda row: (row.first_seen.timestamp() if row.first_seen else 0.0, row.id))
        keeper = rows[0]
        keeper.fingerprint = fp
        for duplicate in rows[1:]:
            keeper.dedup_count = (keeper.dedup_count or 1) + (duplicate.dedup_count or 1)
            if duplicate.last_seen and (not keeper.last_seen or duplicate.last_seen > keeper.last_seen):
                keeper.last_seen = duplicate.last_seen
            if duplicate.last_scan_id and (not keeper.last_scan_id or duplicate.last_scan_id > keeper.last_scan_id):
                keeper.last_scan_id = duplicate.last_scan_id
            if duplicate.status != "Resolved":
                keeper.status = duplicate.status
                keeper.resolved_at = None
            if duplicate.resolved_at and keeper.status == "Resolved":
                keeper.resolved_at = duplicate.resolved_at
            keeper.reopened_count = (keeper.reopened_count or 0) + (duplicate.reopened_count or 0)
            db.delete(duplicate)
            merged += 1

    db.commit()
    return {"backfilled": len(groups), "merged": merged}
