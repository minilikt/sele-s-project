"""Deterministic lab inventory and finding rules."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import discovery_engine
from discovery_engine import LAB_DOMAIN, findings_for_asset, generate_lab_findings, generate_lab_inventory

NOW = datetime(2026, 10, 28, tzinfo=timezone.utc)


def _asset(**overrides):
    asset = {
        "hostname": "www.acme-lab.local",
        "asset_type": "Subdomain",
        "ip": "10.20.1.2",
        "status": "Online",
        "is_web": True,
        "http_status": 200,
        "open_ports": [80, 443],
        "tls_expiry": (NOW + timedelta(days=120)).isoformat(),
        "security_headers": {
            "strict-transport-security": True,
            "content-security-policy": True,
        },
    }
    asset.update(overrides)
    return asset


def _findings(asset):
    return findings_for_asset(asset, NOW, None)


class TestInventory:
    def test_base_inventory_is_stable_across_scans(self):
        zero = {a["hostname"] for a in generate_lab_inventory(LAB_DOMAIN, 0)}
        one = {a["hostname"] for a in generate_lab_inventory(LAB_DOMAIN, 1)}
        two = {a["hostname"] for a in generate_lab_inventory(LAB_DOMAIN, 2)}
        assert zero <= one <= two

    def test_late_subdomains_appear_once(self):
        zero = {a["hostname"] for a in generate_lab_inventory(LAB_DOMAIN, 0)}
        one = {a["hostname"] for a in generate_lab_inventory(LAB_DOMAIN, 1)}
        two = {a["hostname"] for a in generate_lab_inventory(LAB_DOMAIN, 2)}
        assert f"new-portal.{LAB_DOMAIN}" not in zero
        assert f"new-portal.{LAB_DOMAIN}" in one
        assert f"new-portal.{LAB_DOMAIN}" in two
        assert f"unsecured-admin.{LAB_DOMAIN}" not in one
        assert f"unsecured-admin.{LAB_DOMAIN}" in two

    def test_inventory_has_apex_and_web_assets(self):
        assets = generate_lab_inventory(LAB_DOMAIN, 0)
        assert assets[0]["hostname"] == LAB_DOMAIN
        assert assets[0]["asset_type"] == "Apex"
        assert any(a["is_web"] for a in assets)
        assert any(not a["is_web"] for a in assets)

    def test_asset_attributes_are_stable_for_a_scan_index(self):
        first = {a["hostname"]: a for a in generate_lab_inventory(LAB_DOMAIN, 1)}
        second = {a["hostname"]: a for a in generate_lab_inventory(LAB_DOMAIN, 1)}
        for host, asset in first.items():
            assert second[host]["open_ports"] == asset["open_ports"]
            assert second[host]["security_headers"] == asset["security_headers"]
            assert second[host]["status"] == asset["status"]

    def test_scan_lab_reports_only_the_new_late_asset(self):
        result = discovery_engine.scan_lab(LAB_DOMAIN, 1)
        assert [a["hostname"] for a in result["new_assets"]] == [f"new-portal.{LAB_DOMAIN}"]


class TestFindingRules:
    def test_clean_asset_has_no_findings(self):
        assert _findings(_asset()) == []

    def test_expired_certificate_is_critical_when_long_expired(self):
        asset = _asset(tls_expiry=(NOW - timedelta(days=30)).isoformat())
        findings = _findings(asset)
        expired = next(f for f in findings if f["title"] == "Expired TLS certificate")
        assert expired["severity"] == "Critical"

    def test_recently_expired_certificate_is_high(self):
        asset = _asset(tls_expiry=(NOW - timedelta(days=2)).isoformat())
        expired = next(f for f in _findings(asset) if f["title"] == "Expired TLS certificate")
        assert expired["severity"] == "High"

    def test_certificate_expiring_soon_is_medium(self):
        asset = _asset(tls_expiry=(NOW + timedelta(days=10)).isoformat())
        soon = next(f for f in _findings(asset) if f["title"] == "TLS certificate expires soon")
        assert soon["severity"] == "Medium"

    def test_far_future_certificate_has_no_tls_finding(self):
        titles = [f["title"] for f in _findings(_asset(tls_expiry=(NOW + timedelta(days=300)).isoformat()))]
        assert "Expired TLS certificate" not in titles
        assert "TLS certificate expires soon" not in titles

    def test_missing_security_headers(self):
        asset = _asset(
            security_headers={"strict-transport-security": False, "content-security-policy": False}
        )
        titles = [f["title"] for f in _findings(asset)]
        assert "Missing HSTS header" in titles
        assert "Missing Content-Security-Policy header" in titles

    def test_admin_portal_exposure(self):
        findings = _findings(_asset(hostname="admin.acme-lab.local"))
        exposure = next(f for f in findings if f["title"] == "Administrative portal exposed")
        assert exposure["severity"] == "High"

    def test_rdp_exposure(self):
        findings = _findings(_asset(hostname="remote.acme-lab.local", is_web=False, open_ports=[3389]))
        rdp = next(f for f in findings if f["title"] == "RDP exposed to the internet")
        assert rdp["severity"] == "High"

    def test_mysql_exposure_is_critical(self):
        findings = _findings(_asset(hostname="db.acme-lab.local", is_web=False, open_ports=[3306]))
        mysql = next(f for f in findings if f["title"] == "MySQL port exposed")
        assert mysql["severity"] == "Critical"

    def test_generate_lab_findings_is_stable_for_same_asset_and_index(self):
        asset = _asset(tls_expiry=(NOW - timedelta(days=30)).isoformat())
        first = generate_lab_findings(asset, 0)
        second = generate_lab_findings(asset, 0)
        assert [f["title"] for f in first] == [f["title"] for f in second]
