"""API behaviour: scans, deduplication, lifecycle, exports and RBAC."""

from __future__ import annotations

import json

LAB = "acme-lab.local"


def scan(client):
    response = client.post("/api/scan", json={"domain": LAB})
    assert response.status_code == 200, response.text
    return response.json()


def scan_twice(client):
    return scan(client), scan(client)


def all_findings(client, **params):
    response = client.get("/api/findings", params=params)
    assert response.status_code == 200, response.text
    return response.json()


def stable_finding(client):
    findings = all_findings(client)["findings"]
    return next(
        f
        for f in findings
        if f["asset_hostname"] == LAB and f["title"] == "Missing Content-Security-Policy header"
    )


class TestAuth:
    def test_health_is_public(self, anon_client):
        assert anon_client.get("/api/health").status_code == 200

    def test_data_requires_a_token(self, anon_client):
        assert anon_client.get("/api/findings").status_code == 401

    def test_login_failure(self, anon_client):
        response = anon_client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        )
        assert response.status_code == 401

    def test_me(self, client):
        body = client.get("/api/auth/me").json()
        assert body["role"] == "admin"

    def test_viewer_is_read_only(self, viewer_client):
        assert viewer_client.get("/api/findings").status_code == 200
        assert viewer_client.post("/api/scan", json={"domain": LAB}).status_code == 403
        assert viewer_client.patch(
            "/api/findings/1/status", json={"status": "Resolved"}
        ).status_code == 403

    def test_analyst_can_scan_but_manages_no_users(self, analyst_client):
        assert analyst_client.post("/api/scan", json={"domain": LAB}).status_code == 200
        assert analyst_client.get("/api/auth/users").status_code == 403

    def test_admin_cannot_demote_self(self, client):
        me = client.get("/api/auth/me").json()
        response = client.patch(f"/api/auth/users/{me['id']}", json={"role": "viewer"})
        assert response.status_code == 400


class TestScan:
    def test_only_the_lab_domain_is_allowed(self, client):
        response = client.post("/api/scan", json={"domain": "example.com"})
        assert response.status_code == 400
        assert "authorised" in response.json()["detail"].lower()

    def test_first_scan_discovers_assets_and_findings(self, client):
        result = scan(client)
        assert result["status"] == "Complete"
        assert result["assets_discovered"] == 41  # apex + 40 subdomains
        assert result["new_assets"] == 41
        assert result["findings_discovered"] > 0
        assert result["new_findings"] == result["findings_discovered"]
        assert result["risk_score"] > 0

    def test_second_scan_is_incremental(self, client):
        first, second = scan_twice(client)
        assert second["assets_discovered"] == 42
        assert second["new_assets"] == 1
        assert second["new_findings"] < first["new_findings"]
        assert second["reopened_findings"] == 0

    def test_repeated_scans_do_not_duplicate_findings(self, client):
        scan(client)
        before = all_findings(client)["total"]
        scan(client)
        after = all_findings(client)["total"]
        assert after < before * 2
        assert len({f["fingerprint"] for f in all_findings(client)["findings"]}) == after

    def test_dedup_counts_are_exposed(self, client):
        scan_twice(client)
        findings = all_findings(client)["findings"]
        assert any(f["dedup_count"] >= 2 for f in findings)

    def test_third_scan_adds_the_second_late_asset(self, client):
        scan(client)
        scan(client)
        third = scan(client)
        assert third["assets_discovered"] == 43
        hosts = {a["hostname"] for a in client.get("/api/assets").json()["assets"]}
        assert f"unsecured-admin.{LAB}" in hosts

    def test_scan_history_and_latest(self, client):
        scan_twice(client)
        history = client.get("/api/scan/history").json()
        assert history["total"] == 2
        latest = client.get("/api/scan/latest").json()
        assert latest["scan"]["id"] == history["scans"][0]["id"]
        detail = client.get(f"/api/scan/{latest['scan']['id']}").json()
        assert detail["scan"]["id"] == latest["scan"]["id"]
        assert isinstance(detail["findings"], list)

    def test_unknown_scan_is_404(self, client):
        assert client.get("/api/scan/99999").status_code == 404


class TestFindings:
    def test_stats_and_filters(self, client):
        scan(client)
        stats = client.get("/api/findings/stats").json()
        assert stats["open"] == stats["total"] > 0
        assert stats["resolved"] == 0
        assert sum(stats["by_severity"].values()) == stats["open"]

        critical = all_findings(client, severity="Critical")
        assert all(f["severity"] == "Critical" for f in critical["findings"])

        exposure = all_findings(client, category="Exposure")
        assert all(f["category"] == "Exposure" for f in exposure["findings"])

    def test_resolve_lifecycle(self, client):
        scan(client)
        finding = stable_finding(client)

        response = client.patch(
            f"/api/findings/{finding['id']}/status",
            json={"status": "Resolved", "assigned_to": "analyst-1", "note": "CSP deployed"},
        )
        assert response.status_code == 200, response.text
        updated = response.json()
        assert updated["status"] == "Resolved"
        assert updated["resolved_at"] is not None
        assert updated["assigned_to"] == "analyst-1"
        assert updated["resolution_note"] == "CSP deployed"

        stats = client.get("/api/findings/stats").json()
        assert stats["resolved"] == 1
        open_only = all_findings(client, include_resolved=False)
        assert all(f["status"] != "Resolved" for f in open_only["findings"])

        metrics = client.get("/api/findings/metrics").json()
        assert metrics["resolved_findings"] == 1
        assert metrics["mean_time_to_remediate_hours"] is not None

    def test_resolved_finding_reopens_on_regression(self, client):
        scan(client)
        finding = stable_finding(client)
        client.patch(f"/api/findings/{finding['id']}/status", json={"status": "Resolved"})

        second = scan(client)
        refreshed = next(
            f for f in all_findings(client)["findings"] if f["id"] == finding["id"]
        )
        assert refreshed["status"] == "Open"
        assert refreshed["reopened_count"] == 1
        assert refreshed["resolved_at"] is None
        assert second["reopened_findings"] >= 1

    def test_acknowledged_is_kept_on_next_scan(self, client):
        scan(client)
        finding = stable_finding(client)
        client.patch(f"/api/findings/{finding['id']}/status", json={"status": "Acknowledged"})
        scan(client)
        refreshed = next(
            f for f in all_findings(client)["findings"] if f["id"] == finding["id"]
        )
        assert refreshed["status"] == "Acknowledged"
        assert refreshed["acknowledged_at"] is not None

    def test_invalid_status_is_rejected(self, client):
        scan(client)
        finding = all_findings(client)["findings"][0]
        response = client.patch(
            f"/api/findings/{finding['id']}/status", json={"status": "Ignored"}
        )
        assert response.status_code == 422

    def test_unknown_finding_is_404(self, client):
        assert client.patch(
            "/api/findings/99999/status", json={"status": "Resolved"}
        ).status_code == 404

    def test_metrics_include_dedup_ratio(self, client):
        scan_twice(client)
        metrics = client.get("/api/findings/metrics").json()
        assert metrics["dedup_ratio"] > 1.0
        assert metrics["deduplicated_observations"] > 0


class TestAssetsAndDashboard:
    def test_asset_detail_includes_findings_and_risk(self, client):
        scan(client)
        assets = client.get("/api/assets").json()["assets"]
        assert assets[0]["risk_score"] >= assets[-1]["risk_score"]
        detail = client.get(f"/api/assets/{assets[0]['id']}").json()
        assert detail["risk"]["hostname"] == detail["hostname"]
        assert isinstance(detail["findings"], list)

    def test_unknown_asset_is_404(self, client):
        assert client.get("/api/assets/99999").status_code == 404

    def test_dashboard_excludes_resolved_findings(self, client):
        scan(client)
        finding = stable_finding(client)
        before = client.get("/api/dashboard/stats").json()
        client.patch(f"/api/findings/{finding['id']}/status", json={"status": "Resolved"})
        after = client.get("/api/dashboard/stats").json()

        assert after["resolved_findings"] == before["resolved_findings"] + 1
        assert after["open_findings"] == before["open_findings"] - 1
        assert sum(after["findings_by_severity"].values()) == after["open_findings"]

    def test_assets_are_marked_new_only_once(self, client):
        scan_twice(client)
        assets = client.get("/api/assets").json()["assets"]
        assert sum(1 for a in assets if a["is_new"]) == 1  # the late subdomain


class TestExportsAndAssistant:
    def test_findings_export_is_valid_json(self, client):
        scan(client)
        body = client.get("/api/export/findings.json").json()
        parsed = json.loads(body["content"])
        assert len(parsed) == body["count"] > 0
        assert "fingerprint" in parsed[0]

    def test_assets_export_is_valid_json(self, client):
        scan(client)
        body = client.get("/api/export/assets.json").json()
        assert len(json.loads(body["content"])) == body["count"] > 0

    def test_report_export_and_ai_endpoints(self, client):
        scan(client)
        report = client.get("/api/export/report.txt").json()
        assert "ARGUS" in report["content"]
        assert "Attack Surface" in report["content"]

        answer = client.post("/api/ai/ask", json={"question": "What is our risk?"}).json()
        assert "risk" in answer["answer"].lower()

        generated = client.post("/api/ai/report").json()
        assert generated["report"].startswith("# ARGUS")
