"""
ATT&CK kill-chain progression analysis.

Correlation answers "which alerts belong together". This module answers the more
useful question: "how far along the intrusion lifecycle does this incident
reach?" It orders the tactics observed in an incident, measures progression and
scores how closely the evidence resembles a coherent attack chain rather than a
pile of unrelated alerts.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

# ATT&CK Enterprise tactics in the order an intrusion typically advances.
TACTIC_ORDER: List[str] = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

_TACTIC_ALIASES = {
    "command_and_control": "Command and Control",
    "command and control": "Command and Control",
    "c2": "Command and Control",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "lateral_movement": "Lateral Movement",
    "initial_access": "Initial Access",
    "resource_development": "Resource Development",
}

_SEVERITY_WEIGHT = {"Low": 0, "Medium": 4, "High": 8, "Critical": 15}


def normalise_tactic(value: Optional[str]) -> Optional[str]:
    """Map ``credential_access`` / ``Credential Access`` to a canonical tactic."""
    if not value:
        return None
    text = str(value).strip()
    key = text.lower().replace("-", " ").replace("_", " ")
    if key in _TACTIC_ALIASES:
        return _TACTIC_ALIASES[key]
    for tactic in TACTIC_ORDER:
        if tactic.lower() == key:
            return tactic
    return None


def _parse_ts(value: Any):
    from datetime import datetime, timezone

    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def analyse(alerts: List[Any], event_times: Dict[int, Any] | None = None) -> Dict[str, Any]:
    """Build the stage-by-stage kill-chain view for a set of alerts.

    ``event_times`` maps alert id -> time of the underlying event. Alert
    creation time is unusable for ordering because a batch scan stamps every
    alert with the same timestamp.
    """
    event_times = event_times or {}
    by_tactic: Dict[str, Dict[str, Any]] = {
        tactic: {"tactic": tactic, "order": index, "alert_ids": [], "techniques": set()}
        for index, tactic in enumerate(TACTIC_ORDER)
    }

    techniques: List[Dict[str, str]] = []
    seen_techniques: set = set()
    unknown_tactic_alerts: List[int] = []

    for alert in alerts:
        tactic = normalise_tactic(getattr(alert, "mitre_tactic", None))
        if tactic is None:
            unknown_tactic_alerts.append(getattr(alert, "id", 0) or 0)
        else:
            by_tactic[tactic]["alert_ids"].append(getattr(alert, "id", None))

        technique_id = getattr(alert, "mitre_technique_id", None)
        if technique_id and technique_id not in seen_techniques:
            seen_techniques.add(technique_id)
            techniques.append(
                {
                    "id": technique_id,
                    "name": getattr(alert, "mitre_technique_name", "") or "",
                    "tactic": tactic or "",
                }
            )

    stages = []
    for tactic, data in by_tactic.items():
        if not data["alert_ids"]:
            continue
        # Collect the techniques observed at this stage.
        stage_techniques = sorted(
            {
                getattr(alert, "mitre_technique_id", None)
                for alert in alerts
                if normalise_tactic(getattr(alert, "mitre_tactic", None)) == tactic
                and getattr(alert, "mitre_technique_id", None)
            }
        )
        stages.append(
            {
                "tactic": tactic,
                "order": data["order"],
                "covered": True,
                "alert_ids": sorted(a for a in data["alert_ids"] if a is not None),
                "techniques": stage_techniques,
                "alert_count": len([a for a in data["alert_ids"] if a is not None]),
            }
        )

    stages.sort(key=lambda stage: stage["order"])
    covered_orders = [stage["order"] for stage in stages]

    ordered = _is_ordered(alerts, event_times)
    severity = _worst_severity([getattr(alert, "severity", "Medium") for alert in alerts])

    # Score: stage breadth dominates, an ordered progression and severe
    # findings add confidence. Deliberately capped so a single noisy alert
    # cannot look like a full intrusion.
    score = 0.0
    if stages:
        score += 18.0 * len(stages)
        score += _SEVERITY_WEIGHT.get(severity, 0)
        if ordered and len(stages) >= 3:
            score += 10.0
    score = int(max(0, min(100, round(score))))

    stage_reached = stages[-1]["tactic"] if stages else None

    return {
        "stages": stages,
        "covered_count": len(stages),
        "stage_reached": stage_reached,
        "score": score,
        "ordered": ordered,
        "severity": severity,
        "techniques": techniques,
        "unmapped_alerts": unknown_tactic_alerts,
        "summary": _summary(stages, ordered, score),
    }


def _is_ordered(alerts: List[Any], event_times: Dict[int, Any] | None = None) -> bool:
    """True when tactics advance monotonically with time."""
    event_times = event_times or {}
    timed = []
    for alert in alerts:
        tactic = normalise_tactic(getattr(alert, "mitre_tactic", None))
        timestamp = _parse_ts(
            event_times.get(getattr(alert, "id", None)) or getattr(alert, "created_at", None)
        )
        if tactic and timestamp:
            timed.append((timestamp, TACTIC_ORDER.index(tactic)))

    if len(timed) < 2:
        return False

    timed.sort(key=lambda item: item[0])
    orders = [order for _, order in timed]
    return all(orders[i] <= orders[i + 1] for i in range(len(orders) - 1))


def _worst_severity(severities: List[str]) -> str:
    weights = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    return max(severities, key=lambda s: weights.get(s, 0), default="Medium")


def _summary(stages: List[Dict[str, Any]], ordered: bool, score: int) -> str:
    if not stages:
        return "No ATT&CK-mapped activity in this incident."
    names = " -> ".join(stage["tactic"] for stage in stages)
    progression = "in order" if ordered and len(stages) >= 3 else "without a clear order"
    return (
        f"{len(stages)} ATT&CK stage(s) observed {progression}: {names}. "
        f"Chain confidence score {score}/100."
    )


def from_json(value: Any) -> Dict[str, Any]:
    """Defensive loader for the stored ``attack_chain`` column."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return {}
    return {}
