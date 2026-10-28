"""
Entity extraction and graph construction.

Alerts are only useful when they can be pivoted on. This module turns events and
alerts into typed entities — user accounts, hosts and IP addresses — and
projects them into a graph where two entities are linked when they appear in the
same alert.

The graph is what lets correlation ask "what else touched this identity?" rather
than the much weaker "what else had the same account string?".
"""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Entity:
    """A typed, normalised entity. ``key`` is stable and case-insensitive."""

    type: str  # "user" | "host" | "ip"
    value: str

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value.lower()}"

    def to_dict(self) -> Dict[str, str]:
        return {"type": self.type, "value": self.value, "key": self.key}


# Machine accounts and well-known identities that create noise in a graph.
_IGNORED_USERS = {"system", "local service", "network service", "anonymous logon", "-"}
_IGNORED_HOSTS = {"", "-", "unknown"}


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "unknown", "-"}:
        return None
    return text


def make_user(value: Any) -> Optional[Entity]:
    text = _clean(value)
    if not text or text.lower() in _IGNORED_USERS:
        return None
    return Entity("user", text)


def make_host(value: Any) -> Optional[Entity]:
    text = _clean(value)
    if not text or text.lower() in _IGNORED_HOSTS:
        return None
    return Entity("host", text.upper())


def make_ip(value: Any) -> Optional[Entity]:
    text = _clean(value)
    if not text:
        return None
    text = text.split("%")[0].strip()  # Windows sometimes appends "%2"
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return Entity("ip", str(address))


def _event_fields(event: Any) -> Dict[str, Any]:
    """Read the fields we care about from an ORM row or a plain mapping."""
    if isinstance(event, dict):
        raw = event.get("raw_data") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError):
                raw = {}
        return {
            "account": event.get("account"),
            "computer": event.get("computer_name") or event.get("computer"),
            "ip": event.get("source_ip"),
            "raw": raw if isinstance(raw, dict) else {},
        }

    raw = getattr(event, "raw_data", None)
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (ValueError, TypeError):
            raw = {}
    return {
        "account": getattr(event, "account", None),
        "computer": getattr(event, "computer_name", None),
        "ip": getattr(event, "source_ip", None),
        "raw": raw if isinstance(raw, dict) else {},
    }


def entities_from_event(event: Any) -> Set[Entity]:
    """Extract entities from a single security event."""
    fields = _event_fields(event)
    raw = fields["raw"]

    entities: Set[Entity] = set()

    for candidate in (
        fields["account"],
        raw.get("TargetUserName"),
        raw.get("SubjectUserName"),
        raw.get("creator"),
    ):
        user = make_user(candidate)
        if user:
            entities.add(user)

    host = make_host(fields["computer"])
    if host:
        entities.add(host)

    for candidate in (
        fields["ip"],
        raw.get("IpAddress"),
        raw.get("SourceIp"),
        raw.get("ClientAddress"),
        raw.get("WorkstationName"),
    ):
        address = make_ip(candidate)
        if address:
            entities.add(address)

    return entities


def _alert_evidence(alert: Any) -> Dict[str, Any]:
    evidence = getattr(alert, "evidence", None)
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except (ValueError, TypeError):
            evidence = {}
    return evidence if isinstance(evidence, dict) else {}


def entities_from_alert(alert: Any) -> Set[Entity]:
    """Extract every entity an alert references.

    Both native Sigma alerts (which embed a list of matched events) and legacy
    alerts (which expose ``account`` / ``source_ips`` at the top level) are
    supported.
    """
    evidence = _alert_evidence(alert)
    entities: Set[Entity] = set()

    user = make_user(evidence.get("account"))
    if user:
        entities.add(user)

    host = make_host(evidence.get("computer"))
    if host:
        entities.add(host)

    for candidate in evidence.get("source_ips") or []:
        address = make_ip(candidate)
        if address:
            entities.add(address)

    for event in evidence.get("events") or []:
        if not isinstance(event, dict):
            continue
        for candidate in (event.get("account"), event.get("actor")):
            user = make_user(candidate)
            if user:
                entities.add(user)
        host = make_host(event.get("computer"))
        if host:
            entities.add(host)
        address = make_ip(event.get("ip"))
        if address:
            entities.add(address)

    for event in evidence.get("matched_events") or []:
        if isinstance(event, dict):
            entities |= entities_from_event(event)

    return entities


def entity_index(alerts: Iterable[Any]) -> Dict[str, Set[int]]:
    """Map ``entity key`` -> set of alert ids."""
    index: Dict[str, Set[int]] = defaultdict(set)
    for alert in alerts:
        for entity in entities_from_alert(alert):
            index[entity.key].add(alert.id)
    return dict(index)


def build_graph(index: Dict[str, Set[int]]) -> Dict[str, Any]:
    """Project the alert→entity mapping into an entity↔entity graph.

    Two entities are connected when they were observed in the same alert.
    Edge weight is the number of alerts that reference both.
    """
    edge_weights: Dict[Tuple[str, str], int] = defaultdict(int)
    node_alert_counts: Dict[str, int] = defaultdict(int)

    for key, alert_ids in index.items():
        node_alert_counts[key] += len(alert_ids)

    by_alert: Dict[int, List[str]] = defaultdict(list)
    for key, alert_ids in index.items():
        for alert_id in alert_ids:
            by_alert[alert_id].append(key)

    for keys in by_alert.values():
        unique = sorted(set(keys))
        for i in range(len(unique)):
            for j in range(i + 1, len(unique)):
                edge_weights[(unique[i], unique[j])] += 1

    nodes = [
        {
            "key": key,
            "type": key.split(":", 1)[0],
            "value": key.split(":", 1)[1],
            "alert_count": count,
        }
        for key, count in sorted(node_alert_counts.items(), key=lambda item: -item[1])
    ]
    edges = [
        {"source": a, "target": b, "weight": weight}
        for (a, b), weight in sorted(edge_weights.items(), key=lambda item: -item[1])
    ]

    return {"nodes": nodes, "edges": edges}


def primary_entity(entities: Set[Entity]) -> Optional[Entity]:
    """Pick the most analyst-relevant entity: user, then IP, then host."""
    for wanted in ("user", "ip", "host"):
        for entity in sorted(entities, key=lambda e: e.value.lower()):
            if entity.type == wanted:
                return entity
    return None


def describe(entities: Iterable[Entity]) -> str:
    """Human-readable label such as ``user a.kim on WS-004``."""
    users = sorted({e.value for e in entities if e.type == "user"})
    hosts = sorted({e.value for e in entities if e.type == "host"})
    addresses = sorted({e.value for e in entities if e.type == "ip"})

    parts: List[str] = []
    if users:
        parts.append("user " + ", ".join(users[:3]))
    if hosts:
        parts.append("host " + ", ".join(hosts[:3]))
    if addresses:
        parts.append("ip " + ", ".join(addresses[:3]))
    return " / ".join(parts)
