"""Alert/incident deduplication guarantees."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from dedup import (
    alert_fingerprint,
    incident_fingerprint,
    upsert_alerts,
    upsert_incidents,
)


def _alert(rule_id="sigma-test", event_ids=(1, 2, 3)):
    return {
        "rule_id": rule_id,
        "rule_name": "Test Rule",
        "severity": "High",
        "confidence": 0.8,
        "description": "test alert",
        "evidence": json.dumps({"account": "user1"}),
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "status": "New",
        "created_at": datetime.now(timezone.utc),
        "event_ids": json.dumps(list(event_ids)),
    }


class TestFingerprints:
    def test_event_order_does_not_matter(self):
        assert alert_fingerprint("r1", [3, 1, 2]) == alert_fingerprint("r1", "[1,2,3]")

    def test_different_rules_differ(self):
        assert alert_fingerprint("r1", [1]) != alert_fingerprint("r2", [1])

    def test_different_events_differ(self):
        assert alert_fingerprint("r1", [1]) != alert_fingerprint("r1", [2])

    def test_incident_fingerprint_order_independent(self):
        assert incident_fingerprint([2, 1]) == incident_fingerprint([1, 2])


class TestAlertUpsert:
    def test_first_insert_creates(self, client):
        from database import SessionLocal

        db = SessionLocal()
        try:
            result = upsert_alerts(db, [_alert()])
        finally:
            db.close()
        assert result == {"created": 1, "deduplicated": 0}

    def test_rerun_deduplicates(self, client):
        from database import SessionLocal

        db = SessionLocal()
        try:
            upsert_alerts(db, [_alert()])
            second = upsert_alerts(db, [_alert()])
            third = upsert_alerts(db, [_alert()])
        finally:
            db.close()

        assert second == {"created": 0, "deduplicated": 1}
        assert third == {"created": 0, "deduplicated": 1}

    def test_dedup_count_increments(self, client):
        from database import SessionLocal
        from models import Alert

        db = SessionLocal()
        try:
            upsert_alerts(db, [_alert()])
            upsert_alerts(db, [_alert()])
            alert = db.query(Alert).one()
            assert alert.dedup_count == 2
            assert alert.fingerprint is not None
            assert alert.last_seen_at is not None
        finally:
            db.close()

    def test_new_events_create_new_alert(self, client):
        from database import SessionLocal
        from models import Alert

        db = SessionLocal()
        try:
            upsert_alerts(db, [_alert(event_ids=(1, 2))])
            result = upsert_alerts(db, [_alert(event_ids=(1, 2, 3))])
            assert result["created"] == 1
            assert db.query(Alert).count() == 2
        finally:
            db.close()

    def test_resolved_alert_is_not_reopened(self, client):
        from database import SessionLocal
        from models import Alert

        db = SessionLocal()
        try:
            upsert_alerts(db, [_alert()])
            alert = db.query(Alert).one()
            alert.status = "Resolved"
            db.commit()

            upsert_alerts(db, [_alert()])
            db.refresh(alert)
            assert alert.status == "Resolved"
            assert alert.dedup_count == 2
        finally:
            db.close()


class TestIncidentUpsert:
    def test_same_alert_set_is_deduplicated(self, client):
        from database import SessionLocal

        incident = {
            "title": "Correlated Alerts - user1",
            "description": "test",
            "severity": "High",
            "status": "Open",
            "alert_ids": json.dumps([1, 2]),
            "timeline": json.dumps([]),
            "mitre_techniques": json.dumps([]),
            "investigation_notes": None,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        db = SessionLocal()
        try:
            first = upsert_incidents(db, [incident])
            second = upsert_incidents(db, [incident])
        finally:
            db.close()

        assert first["created"] == 1
        assert second["created"] == 0
        assert second["deduplicated"] == 1


class TestBackfill:
    def test_legacy_rows_get_fingerprints(self, client):
        from database import SessionLocal
        from dedup import backfill_fingerprints
        from models import Alert

        db = SessionLocal()
        try:
            legacy = Alert(
                rule_id="legacy-rule",
                rule_name="Legacy",
                severity="Low",
                confidence=0.5,
                description="old",
                evidence="{}",
                mitre_tactic="",
                mitre_technique_id="",
                mitre_technique_name="",
                status="New",
                created_at=datetime.now(timezone.utc),
                event_ids=json.dumps([7, 8]),
                fingerprint=None,
                dedup_count=None,
            )
            db.add(legacy)
            db.commit()

            summary = backfill_fingerprints(db)
            db.refresh(legacy)
            assert summary["alerts"] == 1
            assert legacy.fingerprint is not None
            assert legacy.dedup_count == 1
        finally:
            db.close()
