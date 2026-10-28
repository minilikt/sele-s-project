"""Finding fingerprints, upserts and lifecycle transitions."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from lifecycle import backfill_fingerprints, fingerprint, upsert_findings
from models import Asset, Finding


def _now():
    return datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)


def _asset(db, host="www.acme-lab.local"):
    asset = Asset(hostname=host, asset_type="Subdomain", status="Online")
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def _candidate(**overrides):
    data = {
        "category": "TLS",
        "title": "Expired TLS certificate",
        "detail": "Certificate expired 3 days ago.",
        "severity": "High",
        "risk_score": 71.3,
        "exposure": "Internet",
        "confidence": 0.95,
        "recommendation": "Renew the certificate.",
    }
    data.update(overrides)
    return data


def _legacy(asset, title="Missing HSTS header", host=None, fp=None, status="Open", dedup=1, days=0):
    return Finding(
        asset_id=asset.id,
        asset_hostname=host or asset.hostname,
        category="Headers",
        title=title,
        detail="detail",
        severity="Low",
        risk_score=20.0,
        exposure="Internet",
        confidence=0.8,
        recommendation="recommendation",
        status=status,
        first_seen=_now() + timedelta(days=days),
        last_seen=_now() + timedelta(days=days),
        fingerprint=fp,
        dedup_count=dedup,
    )


class TestFingerprint:
    def test_deterministic(self):
        assert fingerprint("a.example", "TLS", "Expired") == fingerprint("a.example", "TLS", "Expired")

    def test_case_and_whitespace_insensitive(self):
        assert fingerprint(" A.Example ", " tls ", "Expired ") == fingerprint("a.example", "TLS", "Expired")

    def test_changes_with_each_component(self):
        base = fingerprint("a.example", "TLS", "Expired")
        assert fingerprint("b.example", "TLS", "Expired") != base
        assert fingerprint("a.example", "Headers", "Expired") != base
        assert fingerprint("a.example", "TLS", "Expiring soon") != base


class TestUpsert:
    def test_creates_new_finding(self, db_session):
        asset = _asset(db_session)
        stats = upsert_findings(db_session, asset, [_candidate()], scan_id=1, now=_now())
        db_session.commit()

        assert stats == {"new": 1, "updated": 0, "reopened": 0}
        stored = db_session.query(Finding).one()
        assert stored.status == "Open"
        assert stored.dedup_count == 1
        assert stored.last_scan_id == 1
        assert stored.fingerprint == fingerprint(asset.hostname, "TLS", "Expired TLS certificate")

    def test_second_scan_updates_instead_of_duplicating(self, db_session):
        asset = _asset(db_session)
        upsert_findings(db_session, asset, [_candidate()], scan_id=1, now=_now())
        db_session.commit()

        later = _now() + timedelta(hours=6)
        stats = upsert_findings(
            db_session,
            asset,
            [_candidate(severity="Critical", risk_score=95.0)],
            scan_id=2,
            now=later,
        )
        db_session.commit()

        assert stats == {"new": 0, "updated": 1, "reopened": 0}
        stored = db_session.query(Finding).one()
        assert stored.dedup_count == 2
        assert stored.last_scan_id == 2
        assert stored.last_seen == later.replace(tzinfo=None)
        assert stored.severity == "Critical"

    def test_resolved_finding_reopens_and_counts_regression(self, db_session):
        asset = _asset(db_session)
        upsert_findings(db_session, asset, [_candidate()], scan_id=1, now=_now())
        db_session.commit()
        stored = db_session.query(Finding).one()
        stored.status = "Resolved"
        stored.resolved_at = _now()
        db_session.commit()

        stats = upsert_findings(db_session, asset, [_candidate()], scan_id=2, now=_now())
        db_session.commit()

        assert stats["reopened"] == 1
        assert stored.status == "Open"
        assert stored.resolved_at is None
        assert stored.reopened_count == 1

    def test_acknowledged_decision_is_not_overwritten(self, db_session):
        asset = _asset(db_session)
        upsert_findings(db_session, asset, [_candidate()], scan_id=1, now=_now())
        db_session.commit()
        stored = db_session.query(Finding).one()
        stored.status = "Acknowledged"
        db_session.commit()

        upsert_findings(
            db_session, asset, [_candidate(detail="new evidence", severity="Critical")],
            scan_id=2, now=_now(),
        )
        db_session.commit()

        assert stored.status == "Acknowledged"
        assert stored.detail == "new evidence"
        assert stored.severity == "Critical"

    def test_multiple_assets_do_not_collide(self, db_session):
        a = _asset(db_session, "a.acme-lab.local")
        b = _asset(db_session, "b.acme-lab.local")
        upsert_findings(db_session, a, [_candidate()], scan_id=1, now=_now())
        upsert_findings(db_session, b, [_candidate()], scan_id=1, now=_now())
        db_session.commit()
        assert db_session.query(Finding).count() == 2


class TestBackfill:
    def test_assigns_fingerprints_and_merges_duplicates(self, db_session):
        asset = _asset(db_session)
        db_session.add_all(
            [
                _legacy(asset, fp=None, dedup=1, days=0),
                _legacy(asset, fp=None, dedup=2, days=1),
                _legacy(asset, title="Different issue", fp=None),
            ]
        )
        db_session.commit()

        result = backfill_fingerprints(db_session)

        assert result == {"backfilled": 2, "merged": 1}
        stored = db_session.query(Finding).order_by(Finding.id).all()
        assert len(stored) == 2
        merged = next(f for f in stored if f.title == "Missing HSTS header")
        assert merged.dedup_count == 3
        assert merged.fingerprint
        assert all(f.fingerprint for f in stored)

    def test_prefers_open_status_when_merging(self, db_session):
        asset = _asset(db_session)
        db_session.add_all(
            [
                _legacy(asset, status="Resolved", days=0),
                _legacy(asset, status="Open", days=1),
            ]
        )
        db_session.commit()
        backfill_fingerprints(db_session)
        stored = db_session.query(Finding).one()
        assert stored.status == "Open"
        assert stored.resolved_at is None

    def test_no_legacy_rows_is_a_noop(self, db_session):
        asset = _asset(db_session)
        db_session.add(_legacy(asset, fp="already-set"))
        db_session.commit()
        assert backfill_fingerprints(db_session) == {"backfilled": 0, "merged": 0}
