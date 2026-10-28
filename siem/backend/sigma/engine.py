"""
Execution engine for Sigma rules.

Responsibilities:

* load every ``*.yml`` / ``*.yaml`` rule from disk and report broken rules
  instead of silently skipping them,
* evaluate rules against a batch of normalised events,
* aggregate noisy single-event matches into one alert per entity/threshold,
* evaluate ordered multi-step correlation rules,
* emit alert dictionaries shaped for the ``Alert`` ORM model.

The engine is deliberately free of database access so it can be unit-tested
against plain dictionaries.
"""

from __future__ import annotations

import glob
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .event import build_sigma_event, lookup
from .matcher import SigmaRuleError
from .parser import SigmaRule, load_rule_file

DEFAULT_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules")

_SEVERITY_BY_LEVEL = {
    "informational": "Low",
    "info": "Low",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

_BASE_CONFIDENCE = {
    "informational": 30.0,
    "info": 30.0,
    "low": 45.0,
    "medium": 65.0,
    "high": 80.0,
    "critical": 92.0,
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass
class LoadResult:
    """Outcome of loading a rule directory."""

    rules: List[SigmaRule] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)


class SigmaEngine:
    """Runs a set of parsed Sigma rules over a batch of events."""

    def __init__(self, rules: Sequence[SigmaRule], enabled: Optional[Dict[str, bool]] = None):
        self.all_rules = list(rules)
        enabled = enabled or {}
        self.rules = [rule for rule in self.all_rules if enabled.get(rule.id, True)]

    # â”€â”€ Loading â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def load_rules(paths: Iterable[str]) -> LoadResult:
        """Load every YAML rule from the given files and/or directories."""
        result = LoadResult()
        seen: Dict[str, str] = {}

        for path in paths:
            if not path or not os.path.exists(path):
                continue
            candidates: List[str] = []
            if os.path.isdir(path):
                for pattern in ("**/*.yml", "**/*.yaml"):
                    candidates.extend(glob.glob(os.path.join(path, pattern), recursive=True))
            else:
                candidates.append(path)

            for candidate in sorted(set(candidates)):
                try:
                    rule = load_rule_file(candidate)
                except (SigmaRuleError, OSError, ValueError) as exc:
                    result.errors.append({"path": candidate, "error": str(exc)})
                    continue

                if rule.id in seen:
                    result.errors.append(
                        {
                            "path": candidate,
                            "error": f"Duplicate rule id {rule.id!r} (already loaded from {seen[rule.id]})",
                        }
                    )
                    continue

                seen[rule.id] = candidate
                result.rules.append(rule)

        return result

    @classmethod
    def from_directory(cls, directory: str = DEFAULT_RULES_DIR,
                       enabled: Optional[Dict[str, bool]] = None) -> "SigmaEngine":
        loaded = cls.load_rules([directory])
        return cls(loaded.rules, enabled=enabled)

    # â”€â”€ Execution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def run(self, events: Sequence[Any]) -> List[Dict[str, Any]]:
        """Evaluate every enabled rule and return alert dictionaries."""
        normalised: List[Tuple[Any, Dict[str, Any], datetime]] = []
        for event in events:
            sigma_event = build_sigma_event(event)
            try:
                timestamp = _as_utc(sigma_event.get("Timestamp") or _utcnow())
            except (ValueError, TypeError):
                timestamp = _utcnow()
            normalised.append((event, sigma_event, timestamp))

        normalised.sort(key=lambda item: item[2])

        alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            try:
                if rule.is_correlation:
                    alerts.extend(self._run_correlation(rule, normalised))
                elif rule.threshold > 1 or rule.group_by:
                    alerts.extend(self._run_aggregated(rule, normalised))
                else:
                    alerts.extend(self._run_simple(rule, normalised))
            except Exception as exc:  # keep one bad rule from killing the run
                alerts.append(self._error_alert(rule, exc))
        return alerts

    # â”€â”€ Strategies â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _run_simple(self, rule: SigmaRule, normalised: List[Tuple[Any, Dict[str, Any], datetime]]
                    ) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for event, sigma_event, timestamp in normalised:
            if rule.matches(sigma_event):
                alerts.append(
                    self._alert(
                        rule,
                        matched=[sigma_event],
                        event_ids=self._event_ids([sigma_event]),
                        description=f"{rule.title}  -  matched event {sigma_event.get('EventID')} "
                                    f"on {sigma_event.get('Computer') or 'unknown host'}.",
                        timestamp=timestamp,
                    )
                )
        return alerts

    def _run_aggregated(self, rule: SigmaRule, normalised: List[Tuple[Any, Dict[str, Any], datetime]]
                        ) -> List[Dict[str, Any]]:
        matches = [item for item in normalised if rule.matches(item[1])]
        if not matches:
            return []

        grouped: Dict[Tuple, List[Tuple[Any, Dict[str, Any], datetime]]] = {}
        for item in matches:
            key = self._group_key(rule, item[1])
            grouped.setdefault(key, []).append(item)

        alerts: List[Dict[str, Any]] = []
        for key, group in grouped.items():
            group.sort(key=lambda item: item[2])
            hit = self._sliding_window(group, rule.threshold, rule.timeframe)
            if hit is None:
                continue
            entity = ", ".join(f"{field}={value}" for field, value in zip(rule.group_by, key)) \
                if rule.group_by else "any entity"
            alerts.append(
                self._alert(
                    rule,
                    matched=[item[1] for item in hit],
                    event_ids=self._event_ids([item[1] for item in hit]),
                    description=(
                        f"{rule.title}  -  {len(hit)} matching event(s) for {entity} "
                        f"within {self._humanise(rule.timeframe)}."
                    ),
                    timestamp=hit[-1][2],
                    extra={"threshold": rule.threshold,
                           "timeframe_seconds": int(rule.timeframe.total_seconds()),
                           "group": dict(zip(rule.group_by, key))},
                )
            )
        return alerts

    def _run_correlation(self, rule: SigmaRule, normalised: List[Tuple[Any, Dict[str, Any], datetime]]
                         ) -> List[Dict[str, Any]]:
        grouped: Dict[Tuple, List[Tuple[Any, Dict[str, Any], datetime]]] = {}
        for item in normalised:
            key = self._group_key(rule, item[1])
            grouped.setdefault(key, []).append(item)

        alerts: List[Dict[str, Any]] = []
        for key, group in grouped.items():
            group.sort(key=lambda item: item[2])
            sequence = self._match_sequence(rule, group)
            if sequence is None:
                continue
            matched = [item[1] for item in sequence]
            entity = ", ".join(f"{field}={value}" for field, value in zip(rule.group_by, key)) \
                if rule.group_by else "any entity"
            step_summary = " -> ".join(
                f"{step.name} x{step.min_count}" for step in rule.correlation_steps
            )
            alerts.append(
                self._alert(
                    rule,
                    matched=matched,
                    event_ids=self._event_ids(matched),
                    description=(
                        f"{rule.title}  -  ordered sequence detected for {entity} "
                        f"({step_summary}) within {self._humanise(rule.timeframe)}."
                    ),
                    timestamp=sequence[-1][2],
                    extra={
                        "correlation": True,
                        "steps": [
                            {"name": step.name, "min_count": step.min_count}
                            for step in rule.correlation_steps
                        ],
                        "sequence_start": sequence[0][1].get("Timestamp"),
                        "sequence_end": sequence[-1][1].get("Timestamp"),
                    },
                )
            )
        return alerts

    # â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def _group_key(rule: SigmaRule, sigma_event: Dict[str, Any]) -> Tuple:
        if not rule.group_by:
            return ()
        key: List[Any] = []
        for field in rule.group_by:
            values = lookup(sigma_event, field)
            key.append(values[0] if values else None)
        return tuple(key)

    @staticmethod
    def _sliding_window(group: List[Tuple[Any, Dict[str, Any], datetime]], threshold: int,
                        timeframe: timedelta) -> Optional[List[Tuple[Any, Dict[str, Any], datetime]]]:
        for start in range(len(group)):
            window = [
                item for item in group[start:]
                if item[2] - group[start][2] <= timeframe
            ]
            if len(window) >= threshold:
                return window
        return None

    @staticmethod
    def _match_sequence(rule: SigmaRule, group: List[Tuple[Any, Dict[str, Any], datetime]]
                        ) -> Optional[List[Tuple[Any, Dict[str, Any], datetime]]]:
        """Find the first ordered sequence satisfying every step's min_count."""
        cursor = 0
        used: List[Tuple[Any, Dict[str, Any], datetime]] = []
        window_start: Optional[datetime] = None
        last_time: Optional[datetime] = None

        for step in rule.correlation_steps:
            collected = 0
            while cursor < len(group) and collected < step.min_count:
                item = group[cursor]
                cursor += 1

                if last_time is not None and item[2] < last_time:
                    continue
                if window_start is not None and item[2] - window_start > rule.timeframe:
                    return None
                if not any(predicate(item[1]) for predicate in step.selections):
                    continue

                if window_start is None:
                    window_start = item[2]
                last_time = item[2]
                used.append(item)
                collected += 1

            if collected < step.min_count:
                return None

        return used

    @staticmethod
    def _event_ids(matched: List[Dict[str, Any]]) -> List[int]:
        ids: List[int] = []
        for sigma_event in matched:
            value = sigma_event.get("_event_id")
            if isinstance(value, int) and value not in ids:
                ids.append(value)
        return ids

    @staticmethod
    def _humanise(delta: timedelta) -> str:
        seconds = int(delta.total_seconds())
        if seconds % 3600 == 0:
            return f"{seconds // 3600}h"
        if seconds % 60 == 0:
            return f"{seconds // 60}m"
        return f"{seconds}s"

    def _alert(self, rule: SigmaRule, *, matched: List[Dict[str, Any]], event_ids: List[int],
               description: str, timestamp: datetime,
               extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        techniques = rule.mitre_techniques
        tactics = rule.mitre_tactics
        technique_id = techniques[0] if techniques else None
        technique_name = _technique_name(technique_id)

        confidence = _BASE_CONFIDENCE.get(rule.level, 60.0)
        confidence += min(10.0, 2.0 * max(0, len(matched) - 1))
        confidence = float(max(0.0, min(100.0, confidence)))

        evidence = {
            "rule_id": rule.id,
            "rule_title": rule.title,
            "level": rule.level,
            "account": matched[0].get("TargetUserName") if matched else None,
            "computer": matched[0].get("Computer") if matched else None,
            "matched_event_count": len(matched),
            "matched_fields": self._matched_fields(rule, matched[0]) if matched else {},
            "events": [
                {
                    "event_id": sigma_event.get("EventID"),
                    "timestamp": sigma_event.get("Timestamp"),
                    "account": sigma_event.get("TargetUserName"),
                    "actor": sigma_event.get("SubjectUserName"),
                    "computer": sigma_event.get("Computer"),
                    "ip": sigma_event.get("IpAddress"),
                }
                for sigma_event in matched
            ],
            "falsepositives": rule.falsepositives,
        }
        if extra:
            evidence.update(extra)

        return {
            "rule_id": rule.id,
            "rule_name": rule.title,
            "severity": _SEVERITY_BY_LEVEL.get(rule.level, "Medium"),
            "confidence": round(confidence / 100.0, 2),
            "description": description,
            "evidence": json.dumps(evidence, default=str),
            "mitre_tactic": tactics[0] if tactics else None,
            "mitre_technique_id": technique_id,
            "mitre_technique_name": technique_name,
            "status": "New",
            "created_at": _utcnow(),
            "event_ids": json.dumps(event_ids),
        }

    def _matched_fields(self, rule: SigmaRule, sigma_event: Dict[str, Any]) -> Dict[str, Any]:
        fields: List[str] = []
        for specs in rule.selection_specs.values():
            for spec in specs:
                name = spec.split("|", 1)[0]
                if name not in fields:
                    fields.append(name)

        out: Dict[str, Any] = {}
        for field in fields[:12]:
            values = lookup(sigma_event, field)
            if values:
                out[field] = values[0] if len(values) == 1 else values
        return out

    def _error_alert(self, rule: SigmaRule, exc: Exception) -> Dict[str, Any]:
        return {
            "rule_id": rule.id,
            "rule_name": f"{rule.title} (evaluation error)",
            "severity": "Low",
            "confidence": 0.0,
            "description": f"Rule {rule.id} failed to evaluate: {exc}",
            "evidence": json.dumps({"error": str(exc), "rule_id": rule.id}),
            "mitre_tactic": None,
            "mitre_technique_id": None,
            "mitre_technique_name": None,
            "status": "New",
            "created_at": _utcnow(),
            "event_ids": json.dumps([]),
        }


def _technique_name(technique_id: Optional[str]) -> Optional[str]:
    if not technique_id:
        return None
    try:
        from mitre_attack import get_technique  # imported lazily to avoid a cycle

        record = get_technique(technique_id)
    except Exception:
        return None
    return record.get("name") if record else None


def severity_for_level(level: str) -> str:
    """Map a Sigma ``level`` to the SIEM's severity vocabulary."""
    return _SEVERITY_BY_LEVEL.get(str(level).lower(), "Medium")


def technique_name(technique_id: Optional[str]) -> Optional[str]:
    """Public wrapper used when seeding rules into the database."""
    return _technique_name(technique_id)
