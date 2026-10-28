"""
Idempotent alert and incident persistence.

A SIEM must be safe to re-run. Analysts and schedulers trigger detection
repeatedly over overlapping event windows; if every run appends new rows, the
alert queue fills with duplicates and MTTA/MTTR metrics become meaningless.

Every alert therefore carries a deterministic ``fingerprint`` derived from the
rule id and the exact set of events that triggered it. Re-running detection over
unchanged data increments ``dedup_count`` instead of creating a second alert.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Sequence

from sqlalchemy.orm import Session

from models import Alert, Incident


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalise_ids(event_ids: Any) -> List[int]:
    """Accept a list, a JSON string or ``None`` and return sorted unique ints."""
    if event_ids is None:
        return []
    if isinstance(event_ids, str):
        try:
            event_ids = json.loads(event_ids)
        except (ValueError, TypeError):
            return []
    if not isinstance(event_ids, (list, tuple, set)):
        return []

    cleaned = []
    for value in event_ids:
        try:
            cleaned.append(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(set(cleaned))


def _fingerprint(*parts: Any) -> str:
    payload = "|".join(str(part) for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def alert_fingerprint(rule_id: str, event_ids: Any) -> str:
    """Stable identity for an alert: same rule over the same events."""
    return _fingerprint("alert", rule_id, ",".join(str(i) for i in _normalise_ids(event_ids)))


def incident_fingerprint(alert_ids: Any) -> str:
    """Stable identity for an incident: same set of contributing alerts."""
    ids = sorted(set(int(i) for i in (alert_ids or [])))
    return _fingerprint("incident", ",".join(str(i) for i in ids))


def upsert_alerts(db: Session, alert_dicts: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """Insert new alerts, collapse repeats into ``dedup_count``.

    Returns ``{"created": n, "deduplicated": n}``.
    """
    created = 0
    deduplicated = 0
    now = _utcnow()

    for alert in alert_dicts:
        fingerprint = alert_fingerprint(alert["rule_id"], alert.get("event_ids"))
        existing = (
            db.query(Alert)
            .filter(Alert.fingerprint == fingerprint)
            .first()
        )

        if existing is not None:
            existing.dedup_count = (existing.dedup_count or 1) + 1
            existing.last_seen_at = now
            # A resolved or false-positive alert must not silently reopen.
            deduplicated += 1
            continue

        payload = dict(alert)
        payload["fingerprint"] = fingerprint
        payload["dedup_count"] = 1
        payload["last_seen_at"] = payload.get("created_at") or now
        payload.pop("occurred_at", None)
        db.add(Alert(**payload))
        created += 1

    db.commit()
    return {"created": created, "deduplicated": deduplicated}


def upsert_incidents(db: Session, incident_dicts: Sequence[Dict[str, Any]]) -> Dict[str, int]:
    """Insert new incidents, skipping ones whose alert set was already grouped."""
    created = 0
    deduplicated = 0
    now = _utcnow()

    for incident in incident_dicts:
        raw_ids = incident.get("alert_ids")
        if isinstance(raw_ids, str):
            try:
                raw_ids = json.loads(raw_ids)
            except (ValueError, TypeError):
                raw_ids = []
        fingerprint = incident_fingerprint(raw_ids)

        existing = db.query(Incident).filter(Incident.fingerprint == fingerprint).first()
        if existing is not None:
            existing.last_seen_at = now
            deduplicated += 1
            continue

        payload = dict(incident)
        payload["fingerprint"] = fingerprint
        payload["last_seen_at"] = payload.get("created_at") or now
        db.add(Incident(**payload))
        created += 1

    db.commit()
    return {"created": created, "deduplicated": deduplicated}


def backfill_fingerprints(db: Session) -> Dict[str, int]:
    """Give legacy rows a fingerprint so they participate in dedup.

    Older databases predate the fingerprint column; recomputing it on startup
    keeps a single code path instead of special-casing legacy alerts forever.
    """
    filled_alerts = 0
    for alert in db.query(Alert).filter(Alert.fingerprint.is_(None)).all():
        alert.fingerprint = alert_fingerprint(alert.rule_id, alert.event_ids)
        alert.dedup_count = alert.dedup_count or 1
        alert.last_seen_at = alert.last_seen_at or alert.created_at
        filled_alerts += 1

    filled_incidents = 0
    for incident in db.query(Incident).filter(Incident.fingerprint.is_(None)).all():
        try:
            ids = json.loads(incident.alert_ids) if incident.alert_ids else []
        except (ValueError, TypeError):
            ids = []
        incident.fingerprint = incident_fingerprint(ids)
        incident.last_seen_at = incident.last_seen_at or incident.created_at
        filled_incidents += 1

    db.commit()
    return {"alerts": filled_alerts, "incidents": filled_incidents}
