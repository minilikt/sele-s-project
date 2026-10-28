"""API contract tests, including the route-shadowing regression."""

from __future__ import annotations

from conftest import make_event


FAILURES = [
    make_event(4625, account="svc_backup", timestamp=f"2026-10-24T10:0{i}:00+00:00",
               source_ip="198.98.54.12", raw={"failure_reason": "bad password"})
    for i in range(5)
]


class TestRoutes:
    def test_health(self, client):
        assert client.get("/api/health").json()["status"] == "ok"

    def test_event_stats_is_not_shadowed_by_event_id(self, client):
        # Regression: /api/events/{event_id} used to swallow /api/events/stats (422).
        response = client.get("/api/events/stats")
        assert response.status_code == 200
        assert "total" in response.json()

    def test_alert_stats_is_not_shadowed_by_alert_id(self, client):
        response = client.get("/api/alerts/stats")
        assert response.status_code == 200
        assert "total" in response.json()

    def test_alert_metrics(self, client):
        response = client.get("/api/alerts/metrics")
        assert response.status_code == 200
        body = response.json()
        assert body["total_alerts"] == 0
        assert "daily_volume" in body

    def test_missing_alert_returns_404(self, client):
        assert client.get("/api/alerts/999999").status_code == 404

    def test_missing_event_returns_404(self, client):
        assert client.get("/api/events/999999").status_code == 404


class TestIngestAndDetect:
    def test_ingest(self, seeded_client):
        client, seed = seeded_client
        assert seed(FAILURES)["ingested"] == 5
        assert client.get("/api/events").json()["total"] == 5

    def test_detection_creates_alert(self, seeded_client):
        client, seed = seeded_client
        seed(FAILURES)
        result = client.post("/api/detection/run").json()
        assert result["alerts_created"] >= 1
        assert result["sigma_rules_loaded"] >= 8

        alerts = client.get("/api/alerts").json()["alerts"]
        assert any(a["rule_id"] == "sigma-win-4625-bruteforce" for a in alerts)

    def test_detection_is_idempotent(self, seeded_client):
        client, seed = seeded_client
        seed(FAILURES)

        first = client.post("/api/detection/run").json()
        second = client.post("/api/detection/run").json()

        assert first["alerts_created"] >= 1
        assert second["alerts_created"] == 0
        assert second["alerts_deduplicated"] == first["alerts_created"]
        assert second["total_alerts"] == first["total_alerts"]

    def test_correlation_is_idempotent(self, seeded_client):
        client, seed = seeded_client
        seed(FAILURES)
        client.post("/api/detection/run")

        first = client.post("/api/incidents/correlate").json()
        second = client.post("/api/incidents/correlate").json()

        assert second["incidents_created"] == 0
        assert second["total_incidents"] == first["total_incidents"]

    def test_sigma_rule_errors_are_reported(self, client):
        body = client.post("/api/detection/run").json()
        assert body["sigma_rule_errors"] == []


class TestRuleCatalogue:
    def test_rules_expose_engine_and_source(self, client):
        body = client.get("/api/detection/rules").json()
        assert body["total"] >= 14
        engines = {rule["engine"] for rule in body["rules"]}
        assert {"sigma", "python"} <= engines

        sigma_rules = [r for r in body["rules"] if r["engine"] == "sigma"]
        assert all(r["enabled"] for r in sigma_rules)
        assert all(r["tags"] for r in sigma_rules)

    def test_legacy_rules_are_retired(self, client):
        body = client.get("/api/detection/rules").json()
        legacy = [r for r in body["rules"] if r["engine"] == "python"]
        assert legacy and not any(r["enabled"] for r in legacy)

    def test_rule_yaml_is_available(self, client):
        body = client.get("/api/detection/rules").json()
        sigma_id = next(r["id"] for r in body["rules"] if r["engine"] == "sigma")
        response = client.get(f"/api/detection/rules/{sigma_id}/yaml")
        assert response.status_code == 200
        assert "title:" in response.text

    def test_reload_endpoint(self, client):
        body = client.post("/api/detection/reload").json()
        assert body["loaded"] >= 8
        assert body["errors"] == []

    def test_rule_can_be_disabled(self, client):
        client.patch(
            "/api/detection/rules/sigma-win-1102-audit-log-cleared",
            json={"enabled": False},
        )
        rules = client.get("/api/detection/rules").json()["rules"]
        rule = next(r for r in rules if r["id"] == "sigma-win-1102-audit-log-cleared")
        assert rule["enabled"] is False

        # Restore state for the rest of the session.
        client.patch(
            "/api/detection/rules/sigma-win-1102-audit-log-cleared",
            json={"enabled": True},
        )


class TestAlertLifecycle:
    def _one_alert(self, client, seed):
        seed(FAILURES)
        client.post("/api/detection/run")
        return client.get("/api/alerts").json()["alerts"][0]

    def test_transition_records_acknowledgement(self, seeded_client):
        client, seed = seeded_client
        alert = self._one_alert(client, seed)

        response = client.patch(
            f"/api/alerts/{alert['id']}/status",
            json={"status": "Investigating", "assigned_to": "analyst1"},
        )
        body = response.json()
        assert body["status"] == "Investigating"
        assert body["assigned_to"] == "analyst1"
        assert body["acknowledged_at"] is not None

    def test_resolution_sets_timestamp(self, seeded_client):
        client, seed = seeded_client
        alert = self._one_alert(client, seed)

        body = client.patch(
            f"/api/alerts/{alert['id']}/status",
            json={"status": "Resolved", "note": "benign"},
        ).json()
        assert body["status"] == "Resolved"
        assert body["resolved_at"] is not None
        assert body["resolution_note"] == "benign"

    def test_false_positive_counts_in_metrics(self, seeded_client):
        client, seed = seeded_client
        alert = self._one_alert(client, seed)
        client.patch(f"/api/alerts/{alert['id']}/status", json={"status": "False Positive"})

        metrics = client.get("/api/alerts/metrics").json()
        assert metrics["false_positives"] == 1
        assert metrics["false_positive_rate"] == 1.0

    def test_invalid_status_rejected(self, seeded_client):
        client, seed = seeded_client
        alert = self._one_alert(client, seed)

        response = client.patch(
            f"/api/alerts/{alert['id']}/status", json={"status": "DefinitelyNotAStatus"}
        )
        assert response.status_code == 400

    def test_metrics_report_mtta(self, seeded_client):
        client, seed = seeded_client
        alert = self._one_alert(client, seed)
        client.patch(f"/api/alerts/{alert['id']}/status", json={"status": "Investigating"})

        metrics = client.get("/api/alerts/metrics").json()
        assert metrics["acknowledged_alerts"] == 1
        assert metrics["mtta_seconds"] is not None
