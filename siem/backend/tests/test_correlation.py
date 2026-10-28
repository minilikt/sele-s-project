"""Entity-graph correlation tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from correlation_engine import CorrelationEngine
from models import Alert

BASE = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)


def make_alert(alert_id, account="a.kim", computer="WS-001", source_ip=None,
               tactic="Credential Access", technique="T1110", severity="High",
               minutes=0, rule_id="sigma-test"):
    evidence = {
        "account": account,
        "computer": computer,
        "events": [{"event_id": 4625, "account": account, "computer": computer, "ip": source_ip}],
    }
    if source_ip:
        evidence["source_ips"] = [source_ip]

    return Alert(
        id=alert_id,
        rule_id=rule_id,
        rule_name=f"Rule {alert_id}",
        severity=severity,
        confidence=0.8,
        description=f"alert {alert_id}",
        evidence=json.dumps(evidence),
        mitre_tactic=tactic,
        mitre_technique_id=technique,
        mitre_technique_name=technique,
        status="New",
        created_at=BASE + timedelta(minutes=minutes),
        event_ids=json.dumps([alert_id]),
    )


def ids(incident):
    return sorted(json.loads(incident["alert_ids"]))


class TestGrouping:
    def test_shared_user_groups_alerts(self):
        alerts = [make_alert(1, minutes=0), make_alert(2, minutes=5)]
        incidents = CorrelationEngine(alerts).correlate()
        assert len(incidents) == 1
        assert ids(incidents[0]) == [1, 2]

    def test_shared_ip_groups_different_accounts(self):
        alerts = [
            make_alert(1, account="alice", source_ip="45.77.12.204", minutes=0),
            make_alert(2, account="bob", source_ip="45.77.12.204", minutes=5),
        ]
        incidents = CorrelationEngine(alerts).correlate()
        assert len(incidents) == 1
        assert ids(incidents[0]) == [1, 2]

    def test_user_pivots_across_hosts(self):
        alerts = [
            make_alert(1, account="a.kim", computer="WS-001", minutes=0),
            make_alert(2, account="a.kim", computer="WS-002", minutes=5),
        ]
        incidents = CorrelationEngine(alerts).correlate()
        assert len(incidents) == 1

    def test_unrelated_alerts_do_not_group(self):
        alerts = [
            make_alert(1, account="alice", computer="WS-001", minutes=0),
            make_alert(2, account="bob", computer="WS-002", minutes=5),
        ]
        assert CorrelationEngine(alerts).correlate() == []

    def test_window_is_enforced(self):
        alerts = [make_alert(1, minutes=0), make_alert(2, minutes=120)]
        assert CorrelationEngine(alerts, time_window_minutes=60).correlate() == []

    def test_transitive_chain_is_bounded_by_window(self):
        # 1-2 and 2-3 each sit inside the window, but 1..3 spans two hours.
        # An incident must not stretch past the requested window.
        alerts = [make_alert(1, minutes=0), make_alert(2, minutes=55), make_alert(3, minutes=110)]
        incidents = CorrelationEngine(alerts, time_window_minutes=60).correlate()
        assert len(incidents) == 1
        assert ids(incidents[0]) == [1, 2]

    def test_event_time_drives_the_window_not_alert_creation_time(self):
        # Both alerts are created by the same batch scan (identical timestamp),
        # but their events are 90 minutes apart and must not be grouped.
        alerts = [make_alert(1, minutes=0), make_alert(2, minutes=0)]
        far = {1: BASE, 2: BASE + timedelta(minutes=90)}
        assert CorrelationEngine(
            alerts, time_window_minutes=60, event_times=far
        ).correlate() == []

        near = {1: BASE, 2: BASE + timedelta(minutes=10)}
        incidents = CorrelationEngine(
            alerts, time_window_minutes=60, event_times=near
        ).correlate()
        assert len(incidents) == 1

    def test_timeline_uses_event_time(self):
        alerts = [make_alert(1, minutes=0), make_alert(2, minutes=0)]
        times = {1: BASE, 2: BASE + timedelta(minutes=10)}
        incident = CorrelationEngine(alerts, event_times=times).correlate()[0]
        timeline = json.loads(incident["timeline"])
        assert timeline[0]["time"] == BASE.isoformat()
        assert timeline[1]["time"] == (BASE + timedelta(minutes=10)).isoformat()

    def test_single_alert_is_not_an_incident(self):
        assert CorrelationEngine([make_alert(1)]).correlate() == []

    def test_busy_host_does_not_merge_everything(self):
        alerts = [
            make_alert(index, account=f"user{index}", computer="DC01", minutes=index)
            for index in range(1, 11)
        ]
        # The only shared entity is DC01, which exceeds the fan-out guard.
        assert CorrelationEngine(alerts, max_host_fanout=6).correlate() == []


class TestIncidentContent:
    def _incident(self):
        alerts = [
            make_alert(1, tactic="Execution", technique="T1059.001", minutes=0),
            make_alert(2, tactic="Persistence", technique="T1136", minutes=5),
            make_alert(3, tactic="Privilege Escalation", technique="T1078",
                       severity="Critical", minutes=10),
        ]
        return CorrelationEngine(alerts).correlate()[0]

    def test_entities_are_stored(self):
        incident = self._incident()
        entities = json.loads(incident["entities"])
        values = {(e["type"], e["value"]) for e in entities}
        assert ("user", "a.kim") in values
        assert ("host", "WS-001") in values

    def test_entity_graph_has_nodes_and_edges(self):
        graph = json.loads(self._incident()["entity_graph"])
        assert len(graph["nodes"]) == 2
        assert len(graph["edges"]) == 1

    def test_attack_chain_is_stored(self):
        chain = json.loads(self._incident()["attack_chain"])
        assert chain["covered_count"] == 3
        assert chain["ordered"] is True

    def test_chain_score_is_populated(self):
        incident = self._incident()
        assert incident["chain_score"] >= 70

    def test_multi_stage_incident_is_titled_attack_chain(self):
        assert self._incident()["title"].startswith("Attack Chain")

    def test_timeline_is_ordered(self):
        timeline = json.loads(self._incident()["timeline"])
        times = [entry["time"] for entry in timeline]
        assert times == sorted(times)

    def test_timeline_contains_tactic(self):
        timeline = json.loads(self._incident()["timeline"])
        assert timeline[0]["tactic"] in ("Execution", "Persistence", "Privilege Escalation")

    def test_credential_chain_title_for_bruteforce(self):
        alerts = [
            make_alert(1, rule_id="sigma-win-4625-bruteforce", minutes=0),
            make_alert(2, rule_id="sigma-win-4720-account-created",
                       tactic="Persistence", technique="T1136", minutes=5),
        ]
        incident = CorrelationEngine(alerts).correlate()[0]
        assert "Credential Compromise" in incident["title"] or "Attack Chain" in incident["title"]
