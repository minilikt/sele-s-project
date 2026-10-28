"""End-to-end behaviour of the shipped Sigma rule set against real event shapes."""

from __future__ import annotations

import os

import pytest

from sigma import SigmaEngine

RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")


def ev(event_id: int, timestamp: str, account: str = "user1", computer: str = "WS-001",
       source_ip: str | None = None, raw: dict | None = None, identifier: int = 1) -> dict:
    return {
        "id": identifier,
        "timestamp": timestamp,
        "event_id": event_id,
        "source": "Windows Security",
        "account": account,
        "source_ip": source_ip,
        "computer_name": computer,
        "event_type": "Test",
        "severity": "Low",
        "raw_data": raw or {},
    }


@pytest.fixture(scope="module")
def engine():
    loaded = SigmaEngine.load_rules([RULES_DIR])
    assert loaded.errors == [], loaded.errors
    return SigmaEngine(loaded.rules)


def triggered(alerts: list[dict]) -> set[str]:
    return {alert["rule_id"] for alert in alerts}


class TestRuleLoading:
    def test_all_rules_are_valid_yaml(self):
        loaded = SigmaEngine.load_rules([RULES_DIR])
        assert loaded.errors == []
        assert len(loaded.rules) >= 8

    def test_rule_ids_are_unique(self):
        loaded = SigmaEngine.load_rules([RULES_DIR])
        ids = [rule.id for rule in loaded.rules]
        assert len(ids) == len(set(ids))

    def test_every_rule_maps_to_attack(self):
        loaded = SigmaEngine.load_rules([RULES_DIR])
        for rule in loaded.rules:
            assert rule.mitre_techniques, f"{rule.id} has no ATT&CK technique tag"
            assert rule.mitre_tactics, f"{rule.id} has no ATT&CK tactic tag"


class TestBruteForce:
    def test_threshold_fires(self, engine):
        events = [
            ev(4625, f"2026-10-24T10:0{i}:00+00:00", account="svc_backup", identifier=i + 1)
            for i in range(5)
        ]
        alerts = engine.run(events)
        ids = triggered(alerts)
        assert "sigma-win-4625-bruteforce" in ids
        alert = next(a for a in alerts if a["rule_id"] == "sigma-win-4625-bruteforce")
        assert alert["severity"] == "High"
        assert alert["mitre_technique_id"] == "T1110"
        assert len(__import__("json").loads(alert["evidence"])["events"]) == 5

    def test_below_threshold_does_not_fire(self, engine):
        events = [
            ev(4625, f"2026-10-24T10:0{i}:00+00:00", account="user1", identifier=i + 1)
            for i in range(4)
        ]
        assert "sigma-win-4625-bruteforce" not in triggered(engine.run(events))

    def test_outside_window_does_not_fire(self, engine):
        events = [
            ev(4625, f"2026-10-24T{hour:02d}:00:00+00:00", account="user1", identifier=hour + 1)
            for hour in (10, 11, 12, 13, 14)
        ]
        assert "sigma-win-4625-bruteforce" not in triggered(engine.run(events))

    def test_machine_accounts_are_filtered(self, engine):
        events = [
            ev(4625, f"2026-10-24T10:0{i}:00+00:00", account="DC01$", identifier=i + 1)
            for i in range(6)
        ]
        assert "sigma-win-4625-bruteforce" not in triggered(engine.run(events))


class TestSuccessfulLogonAfterFailures:
    def _failure_sequence(self, success_first: bool):
        base = [
            ev(4625, "2026-10-24T10:01:00+00:00", account="a.kim", identifier=1),
            ev(4625, "2026-10-24T10:02:00+00:00", account="a.kim", identifier=2),
            ev(4625, "2026-10-24T10:03:00+00:00", account="a.kim", identifier=3),
        ]
        # A "success first" case must genuinely precede the failures in time.
        success_time = "2026-10-24T09:55:00+00:00" if success_first else "2026-10-24T10:05:00+00:00"
        success = ev(4624, success_time, account="a.kim", identifier=4)
        return [success] + base if success_first else base + [success]

    def test_ordered_sequence_fires(self, engine):
        alerts = engine.run(self._failure_sequence(success_first=False))
        assert "sigma-win-bruteforce-success" in triggered(alerts)

    def test_success_before_failures_does_not_fire(self, engine):
        alerts = engine.run(self._failure_sequence(success_first=True))
        assert "sigma-win-bruteforce-success" not in triggered(alerts)

    def test_different_accounts_do_not_correlate(self, engine):
        events = [
            ev(4625, "2026-10-24T10:01:00+00:00", account="alice", identifier=1),
            ev(4625, "2026-10-24T10:02:00+00:00", account="alice", identifier=2),
            ev(4625, "2026-10-24T10:03:00+00:00", account="alice", identifier=3),
            ev(4624, "2026-10-24T10:04:00+00:00", account="bob", identifier=4),
        ]
        assert "sigma-win-bruteforce-success" not in triggered(engine.run(events))


class TestPowerShell:
    def test_encoded_hidden_command_fires(self, engine):
        events = [
            ev(
                4688,
                "2026-10-24T17:35:00+00:00",
                raw={
                    "process_name": "powershell.exe",
                    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
                },
            )
        ]
        alerts = engine.run(events)
        assert "sigma-win-4688-suspicious-powershell" in triggered(alerts)

    def test_plain_powershell_does_not_fire(self, engine):
        events = [
            ev(
                4688,
                "2026-10-24T17:35:00+00:00",
                raw={"process_name": "powershell.exe", "command_line": "powershell.exe Get-Date"},
            )
        ]
        assert "sigma-win-4688-suspicious-powershell" not in triggered(engine.run(events))


class TestAccountAndPrivilegeChain:
    def test_account_creation_fires(self, engine):
        alerts = engine.run([ev(4720, "2026-10-24T20:23:00+00:00", account="temp_support")])
        assert "sigma-win-4720-account-created" in triggered(alerts)

    def test_creation_then_privilege_chain_fires(self, engine):
        events = [
            ev(4720, "2026-10-24T02:41:00+00:00", account="temp_support", identifier=1),
            ev(
                4672,
                "2026-10-24T02:45:00+00:00",
                account="temp_support",
                identifier=2,
                raw={"privileges": ["SeDebugPrivilege", "SeTcbPrivilege"]},
            ),
        ]
        assert "sigma-win-4720-4672-privilege-chain" in triggered(engine.run(events))

    def test_privileges_without_creation_do_not_chain(self, engine):
        assert "sigma-win-4720-4672-privilege-chain" not in triggered(
            engine.run([ev(4672, "2026-10-24T02:45:00+00:00", account="admin")])
        )


class TestOtherRules:
    def test_audit_log_cleared(self, engine):
        alerts = engine.run([ev(1102, "2026-10-24T03:00:00+00:00", account="admin")])
        assert "sigma-win-1102-audit-log-cleared" in triggered(alerts)

    def test_service_installed(self, engine):
        alerts = engine.run(
            [ev(7045, "2026-10-24T03:00:00+00:00", raw={"service_name": "EvilSvc"})]
        )
        assert "sigma-win-7045-service-installed" in triggered(alerts)

    def test_benign_logon_produces_no_alerts(self, engine):
        assert engine.run([ev(4624, "2026-10-24T10:00:00+00:00")]) == []


class TestEngineContract:
    def test_alert_shape_matches_model(self, engine):
        alert = engine.run([ev(1102, "2026-10-24T03:00:00+00:00")])[0]
        required = {
            "rule_id", "rule_name", "severity", "confidence", "description",
            "evidence", "status", "created_at", "event_ids",
        }
        assert required.issubset(alert.keys())
        assert 0.0 <= alert["confidence"] <= 1.0

    def test_disabled_rule_is_skipped(self):
        loaded = SigmaEngine.load_rules([RULES_DIR])
        disabled = {rule.id: False for rule in loaded.rules}
        engine = SigmaEngine(loaded.rules, enabled=disabled)
        assert engine.run([ev(1102, "2026-10-24T03:00:00+00:00")]) == []
