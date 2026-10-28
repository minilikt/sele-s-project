"""Kill-chain analysis tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from killchain import TACTIC_ORDER, analyse, normalise_tactic


class _Alert:
    def __init__(self, alert_id, tactic, technique, severity="High", minutes=0):
        self.id = alert_id
        self.mitre_tactic = tactic
        self.mitre_technique_id = technique
        self.mitre_technique_name = technique
        self.severity = severity
        self.created_at = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc) + timedelta(minutes=minutes)


class TestTacticNormalisation:
    def test_snake_case(self):
        assert normalise_tactic("credential_access") == "Credential Access"

    def test_title_case(self):
        assert normalise_tactic("Credential Access") == "Credential Access"

    def test_command_and_control_alias(self):
        assert normalise_tactic("command_and_control") == "Command and Control"
        assert normalise_tactic("Command and Control") == "Command and Control"

    def test_unknown(self):
        assert normalise_tactic("interpretive_dance") is None
        assert normalise_tactic(None) is None

    def test_order_is_attack_order(self):
        assert TACTIC_ORDER.index("Initial Access") < TACTIC_ORDER.index("Execution")
        assert TACTIC_ORDER.index("Credential Access") < TACTIC_ORDER.index("Impact")


class TestAnalyse:
    def test_empty(self):
        result = analyse([])
        assert result["covered_count"] == 0
        assert result["score"] == 0
        assert result["stage_reached"] is None

    def test_single_stage(self):
        result = analyse([_Alert(1, "Credential Access", "T1110", "High")])
        assert result["covered_count"] == 1
        assert result["stages"][0]["tactic"] == "Credential Access"
        assert result["stage_reached"] == "Credential Access"
        assert 0 < result["score"] < 70

    def test_multi_stage_ordered_chain(self):
        alerts = [
            _Alert(1, "Execution", "T1059.001", "High", minutes=0),
            _Alert(2, "Persistence", "T1136", "High", minutes=5),
            _Alert(3, "Privilege Escalation", "T1078", "Critical", minutes=10),
        ]
        result = analyse(alerts)
        assert result["covered_count"] == 3
        assert result["ordered"] is True
        assert result["stage_reached"] == "Privilege Escalation"
        assert result["score"] >= 70
        assert [stage["tactic"] for stage in result["stages"]] == [
            "Execution",
            "Persistence",
            "Privilege Escalation",
        ]

    def test_out_of_order_chain_is_flagged(self):
        # Credential Access (later tactic) happens before Persistence (earlier
        # tactic), so the progression is not monotonic.
        alerts = [
            _Alert(1, "Credential Access", "T1110", "High", minutes=0),
            _Alert(2, "Persistence", "T1136", "High", minutes=5),
        ]
        result = analyse(alerts)
        assert result["ordered"] is False
        assert "without a clear order" in result["summary"]

    def test_stages_sorted_by_attack_order(self):
        alerts = [
            _Alert(1, "Impact", "T1486", "Critical", minutes=0),
            _Alert(2, "Execution", "T1059", "High", minutes=1),
        ]
        result = analyse(alerts)
        assert [s["tactic"] for s in result["stages"]] == ["Execution", "Impact"]

    def test_techniques_are_deduplicated(self):
        alerts = [
            _Alert(1, "Credential Access", "T1110", minutes=0),
            _Alert(2, "Credential Access", "T1110", minutes=1),
        ]
        result = analyse(alerts)
        assert len(result["techniques"]) == 1

    def test_unmapped_alerts_are_reported(self):
        result = analyse([_Alert(1, None, None)])
        assert result["unmapped_alerts"] == [1]
        assert result["covered_count"] == 0

    def test_ordering_uses_event_time_over_alert_time(self):
        alerts = [
            _Alert(1, "Persistence", "T1136", minutes=0),
            _Alert(2, "Credential Access", "T1110", minutes=5),
        ]
        # Alert timestamps say "in order" (Persistence then Credential Access),
        # but the events happened the other way round.
        event_times = {
            1: datetime(2026, 10, 24, 10, 10, tzinfo=timezone.utc),
            2: datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc),
        }
        assert analyse(alerts, event_times)["ordered"] is False
