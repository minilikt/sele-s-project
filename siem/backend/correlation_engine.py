"""
Entity-graph correlation engine.

Alerts are grouped when they share a *strong* entity — a user account or an IP
address — inside a configurable time window. Hosts are also used, but only when
a host is not so busy that everything on it would collapse into one incident.
This replaces the previous account-string grouping, which missed lateral
movement (same user, different hosts) and credential reuse (same IP, different
accounts).

Each resulting incident carries:

* the entity graph that explains *why* the alerts were grouped,
* an ordered ATT&CK kill-chain analysis and confidence score,
* a timeline ordered by detection time.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import entities as entity_mod
import killchain
from models import Alert


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    try:
        parsed = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return _utcnow()
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _worst_severity(severities: Iterable[str]) -> str:
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0), default="Medium")


class _UnionFind:
    def __init__(self, items: Iterable[int]):
        self.parent = {item: item for item in items}

    def find(self, item: int) -> int:
        root = item
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[item] != root:
            self.parent[item], item = root, self.parent[item]
        return root

    def union(self, left: int, right: int) -> None:
        left_root, right_root = self.find(left), self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root

    def groups(self) -> List[List[int]]:
        grouped: Dict[int, List[int]] = defaultdict(list)
        for item in self.parent:
            grouped[self.find(item)].append(item)
        return list(grouped.values())


class CorrelationEngine:
    """Group alerts by shared entities and score their ATT&CK progression."""

    def __init__(
        self,
        alerts: List[Alert],
        events: list | None = None,
        *,
        time_window_minutes: int = 60,
        max_host_fanout: int = 6,
        event_times: Dict[int, datetime] | None = None,
    ):
        self.alerts = list(alerts)
        self.events = events or []
        self.window = timedelta(minutes=time_window_minutes)
        self.max_host_fanout = max_host_fanout
        # Alert creation time is when the rule ran, which for a batch scan is
        # identical for every alert. Window ordering must use the time of the
        # underlying event instead.
        self.event_times = event_times or {}

    def _alert_time(self, alert: Alert) -> datetime:
        return _parse_ts(self.event_times.get(alert.id) or alert.created_at)

    # ── Public entry point ────────────────────────────────────────────────

    def correlate(self) -> List[Dict[str, Any]]:
        """Return one incident dict per connected group of two or more alerts."""
        if not self.alerts:
            return []

        by_id = {alert.id: alert for alert in self.alerts}
        alert_entities: Dict[int, Set[entity_mod.Entity]] = {
            alert.id: entity_mod.entities_from_alert(alert) for alert in self.alerts
        }

        index: Dict[str, Set[int]] = defaultdict(set)
        for alert_id, ents in alert_entities.items():
            for entity in ents:
                index[entity.key].add(alert_id)

        union = _UnionFind(by_id.keys())
        for key, alert_ids in index.items():
            if not alert_ids:
                continue
            entity_type = key.split(":", 1)[0]
            if entity_type == "host" and len(alert_ids) > self.max_host_fanout:
                # A domain controller legitimately sees everyone; linking on it
                # would merge unrelated incidents.
                continue
            ordered = sorted(
                alert_ids, key=lambda alert_id: self._alert_time(by_id[alert_id])
            )
            self._connect_within_window(ordered, by_id, union)

        incidents: List[Dict[str, Any]] = []
        for group_ids in union.groups():
            group = sorted(
                (by_id[alert_id] for alert_id in group_ids if alert_id in by_id),
                key=self._alert_time,
            )
            # Union-find chains alerts transitively (A~B, B~C), which can span
            # much longer than the requested window. Partition each component so
            # every incident is bounded by the window as analysts expect.
            for chunk in self._window_slices(group):
                if len(chunk) < 2:
                    continue
                incidents.append(self._build_incident(chunk, alert_entities, index))

        incidents.sort(key=lambda inc: (-inc["chain_score"], inc["title"]))
        return incidents

    # ── Grouping ──────────────────────────────────────────────────────────

    def _window_slices(self, group: List[Alert]) -> List[List[Alert]]:
        """Split a time-sorted group into chunks that each fit the window."""
        chunks: List[List[Alert]] = []
        current: List[Alert] = []
        anchor: Optional[datetime] = None

        for alert in group:
            timestamp = self._alert_time(alert)
            if anchor is None or timestamp - anchor <= self.window:
                current.append(alert)
                anchor = anchor or timestamp
            else:
                chunks.append(current)
                current = [alert]
                anchor = timestamp

        if current:
            chunks.append(current)
        return chunks

    def _connect_within_window(self, alert_ids: List[int], by_id: Dict[int, Alert],
                               union: _UnionFind) -> None:
        previous_id: Optional[int] = None
        previous_ts: Optional[datetime] = None

        for alert_id in alert_ids:
            timestamp = self._alert_time(by_id[alert_id])
            if previous_ts is not None and timestamp - previous_ts <= self.window:
                union.union(previous_id, alert_id)
            previous_id, previous_ts = alert_id, timestamp

    # ── Incident construction ─────────────────────────────────────────────

    def _build_incident(self, group: List[Alert],
                        alert_entities: Dict[int, Set[entity_mod.Entity]],
                        global_index: Dict[str, Set[int]]) -> Dict[str, Any]:
        group.sort(key=self._alert_time)

        shared: Set[entity_mod.Entity] = set()
        for alert in group:
            shared |= alert_entities.get(alert.id, set())

        graph = entity_mod.build_graph(
            {entity.key: (global_index.get(entity.key, set()) & {a.id for a in group})
             for entity in shared}
        )

        chain = killchain.analyse(
            group, event_times={alert.id: self._alert_time(alert) for alert in group}
        )
        severity = chain["severity"]
        if chain["score"] >= 70 and severity != "Critical":
            severity = "Critical" if severity == "High" else "High"

        title = self._title(group, shared, chain)
        description = self._description(group, shared, chain)

        return {
            "title": title,
            "description": description,
            "severity": severity,
            "status": "Open",
            "alert_ids": json.dumps([alert.id for alert in group]),
            "timeline": json.dumps(self._build_timeline(group)),
            "mitre_techniques": json.dumps(chain["techniques"]),
            "investigation_notes": None,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
            "entities": json.dumps([entity.to_dict() for entity in sorted(shared, key=lambda e: e.key)]),
            "entity_graph": json.dumps(graph),
            "attack_chain": json.dumps(chain),
            "chain_score": chain["score"],
        }

    @staticmethod
    def _title(group: List[Alert], shared: Set[entity_mod.Entity],
               chain: Dict[str, Any]) -> str:
        primary = entity_mod.primary_entity(shared)
        subject = f"{primary.type} {primary.value}" if primary else f"{len(group)} alerts"

        if chain["covered_count"] >= 3:
            return f"Attack Chain: {subject}"
        if any("brute" in (alert.rule_id or "").lower() or "1110" in (alert.mitre_technique_id or "")
               for alert in group):
            return f"Credential Compromise Chain: {subject}"
        return f"Correlated Activity: {subject}"

    @staticmethod
    def _description(group: List[Alert], shared: Set[entity_mod.Entity],
                     chain: Dict[str, Any]) -> str:
        entity_text = entity_mod.describe(shared) or "unknown entities"
        return (
            f"{len(group)} alert(s) linked by shared entities ({entity_text}). "
            f"{chain['summary']}"
        )

    # ── Serialisation helpers ─────────────────────────────────────────────

    def _build_timeline(self, group: List[Alert]) -> List[Dict[str, Any]]:
        timeline: List[Dict[str, Any]] = []
        for alert in group:
            timeline.append(
                {
                    "time": self._alert_time(alert).isoformat(),
                    "alert_id": alert.id,
                    "rule": alert.rule_name,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity,
                    "tactic": killchain.normalise_tactic(getattr(alert, "mitre_tactic", None)),
                    "technique": alert.mitre_technique_id,
                    "description": (alert.description or "")[:200],
                }
            )
        return timeline
