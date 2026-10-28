"""Entity extraction and graph construction tests."""

from __future__ import annotations

import json

from entities import (
    Entity,
    build_graph,
    describe,
    entities_from_alert,
    entities_from_event,
    entity_index,
    make_host,
    make_ip,
    make_user,
    primary_entity,
)


class TestEntityFactories:
    def test_user_is_typed(self):
        assert make_user("a.kim") == Entity("user", "a.kim")

    def test_system_accounts_ignored(self):
        assert make_user("SYSTEM") is None
        assert make_user("") is None
        assert make_user(None) is None

    def test_host_is_uppercased(self):
        assert make_host("ws-001") == Entity("host", "WS-001")

    def test_ip_is_validated(self):
        assert make_ip("192.168.1.10") == Entity("ip", "192.168.1.10")
        assert make_ip("not-an-ip") is None
        assert make_ip("127.0.0.1") is None

    def test_windows_ip_suffix_stripped(self):
        assert make_ip("192.168.1.10%2") == Entity("ip", "192.168.1.10")

    def test_key_is_case_insensitive(self):
        assert Entity("user", "A.Kim").key == Entity("user", "a.kim").key


class TestEventExtraction:
    def test_dict_event(self):
        event = {
            "account": "svc_backup",
            "computer_name": "DC01",
            "source_ip": "198.98.54.12",
            "raw_data": {},
        }
        keys = {entity.key for entity in entities_from_event(event)}
        assert keys == {"user:svc_backup", "host:dc01", "ip:198.98.54.12"}

    def test_raw_data_fallbacks(self):
        event = {"account": "x", "computer_name": "WS-1", "raw_data": {"IpAddress": "10.0.0.5"}}
        assert Entity("ip", "10.0.0.5") in entities_from_event(event)

    def test_missing_ip_is_fine(self):
        event = {"account": "x", "computer_name": "WS-1", "source_ip": None, "raw_data": {}}
        assert {e.type for e in entities_from_event(event)} == {"user", "host"}


class _Alert:
    def __init__(self, alert_id, evidence):
        self.id = alert_id
        self.evidence = json.dumps(evidence)


class TestAlertExtraction:
    def test_sigma_style_evidence(self):
        alert = _Alert(
            1,
            {
                "account": "temp_support",
                "computer": "WS-003",
                "events": [
                    {"event_id": 4720, "account": "temp_support", "computer": "WS-003", "ip": None},
                    {"event_id": 4672, "account": "temp_support", "computer": "WS-003", "ip": None},
                ],
            },
        )
        keys = {entity.key for entity in entities_from_alert(alert)}
        assert keys == {"user:temp_support", "host:ws-003"}

    def test_legacy_source_ips(self):
        alert = _Alert(2, {"account": "a.kim", "source_ips": ["45.77.12.204"]})
        keys = {entity.key for entity in entities_from_alert(alert)}
        assert "ip:45.77.12.204" in keys

    def test_actor_links_operator_to_target_account(self):
        # Account-creation events name both the new account and the operator who
        # created it. Both must become entities, otherwise the operator's earlier
        # brute-force alerts cannot be pivoted onto this one.
        alert = _Alert(
            4,
            {
                "account": "svc_shadow",
                "events": [
                    {
                        "event_id": 4720,
                        "account": "svc_shadow",
                        "actor": "j.pierce",
                        "computer": "DC01",
                    }
                ],
            },
        )
        keys = {entity.key for entity in entities_from_alert(alert)}
        assert {"user:svc_shadow", "user:j.pierce"} <= keys

    def test_broken_evidence_is_tolerated(self):
        alert = _Alert(3, {})
        alert.evidence = "{not json"
        assert entities_from_alert(alert) == set()


class TestGraph:
    def _alerts(self):
        return [
            _Alert(1, {"account": "a.kim", "computer": "WS-001", "source_ips": ["1.2.3.4"]}),
            _Alert(2, {"account": "a.kim", "computer": "WS-002"}),
        ]

    def test_index_maps_entity_to_alerts(self):
        index = entity_index(self._alerts())
        assert index["user:a.kim"] == {1, 2}
        assert index["host:ws-001"] == {1}

    def test_graph_nodes_and_edges(self):
        graph = build_graph(entity_index(self._alerts()))
        assert len(graph["nodes"]) == 4
        # a.kim and WS-001 co-occur; a.kim and WS-002 co-occur.
        sources = {frozenset((edge["source"], edge["target"])) for edge in graph["edges"]}
        assert frozenset(("user:a.kim", "host:ws-001")) in sources
        assert frozenset(("user:a.kim", "host:ws-002")) in sources

    def test_primary_entity_prefers_user(self):
        ents = {Entity("host", "WS-1"), Entity("ip", "1.2.3.4"), Entity("user", "a.kim")}
        assert primary_entity(ents) == Entity("user", "a.kim")

    def test_describe(self):
        text = describe({Entity("user", "a.kim"), Entity("host", "WS-001")})
        assert "user a.kim" in text and "host WS-001" in text
