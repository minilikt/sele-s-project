"""
Normalise stored ``SecurityEvent`` rows into Sigma-matchable field dictionaries.

Sigma rules are written against Windows field names (``EventID``,
``TargetUserName``, ``CommandLine``, ...). Our ingest format stores the same
information partly in dedicated columns and partly in a snake_case ``raw_data``
blob. This module bridges the two so a rule copied from the SigmaHQ repository
can be dropped in without rewriting field names.

Every event is exposed as a plain ``dict`` containing:

* the canonical Windows/Sigma field names,
* the original ``raw_data`` keys (so custom fields still work),
* a few convenience aliases.

Lookups are case-insensitive and support dotted paths (``Event.System.EventID``).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

# snake_case keys produced by our ingest format -> canonical Sigma field name
_RAW_ALIASES: Dict[str, str] = {
    "command_line": "CommandLine",
    "process_name": "Image",
    "parent_process_name": "ParentImage",
    "creator": "SubjectUserName",
    "task_name": "TaskName",
    "task_content": "TaskContent",
    "privileges": "Privileges",
    "logon_type": "LogonType",
    "failure_reason": "FailureReason",
    "object": "ObjectName",
    "access": "AccessMask",
    "logon_process": "LogonProcessName",
    "service_name": "ServiceName",
    "service_image_path": "ImagePath",
    "target_image": "TargetImage",
    "new_account": "TargetUserName",
    "group_name": "TargetUserName",
    "status": "Status",
    "sub_status": "SubStatus",
    "workstation": "WorkstationName",
}


def build_sigma_event(event: Any) -> Dict[str, Any]:
    """Return a Sigma-friendly dictionary for a ``SecurityEvent`` ORM row.

    ``event`` may also be a plain mapping (used by tests and by the ingestion
    path before rows are persisted).
    """
    if isinstance(event, dict):
        raw = event.get("raw_data") or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (ValueError, TypeError):
                raw = {}
        get = event.get
        event_id = event.get("event_id")
        source = event.get("source")
        account = event.get("account")
        source_ip = event.get("source_ip")
        computer = event.get("computer_name")
        timestamp = event.get("timestamp")
        plain_id = event.get("id")
    else:
        try:
            raw = json.loads(event.raw_data) if isinstance(event.raw_data, str) else (event.raw_data or {})
        except (ValueError, TypeError):
            raw = {}
        if not isinstance(raw, dict):
            raw = {}
        event_id = event.event_id
        source = event.source
        account = event.account
        source_ip = event.source_ip
        computer = event.computer_name
        timestamp = event.timestamp
        plain_id = event.id

    out: Dict[str, Any] = dict(raw)

    # Expose canonical names for the data living in dedicated columns.
    out.update(
        {
            "EventID": event_id,
            "Channel": source,
            "Computer": computer,
            "ComputerName": computer,
            "TargetUserName": account,
            "AccountName": account,
            "SubjectUserName": raw.get("SubjectUserName", account),
            "IpAddress": source_ip,
            "SourceIp": source_ip,
            "SourceIP": source_ip,
            "Timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else timestamp,
            "_event_id": plain_id,
            "_raw": raw,
        }
    )

    # Mirror snake_case keys under their Windows names without clobbering
    # anything the ingest payload already provided explicitly.
    for snake, canonical in _RAW_ALIASES.items():
        if snake in raw and canonical not in out:
            out[canonical] = raw[snake]

    return out


def lookup(event: Dict[str, Any], field: str) -> List[Any]:
    """Return every value bound to *field*, case-insensitively.

    Returns an empty list when the field is absent. A list-valued field yields
    its elements as separate candidates.
    """
    if not isinstance(event, dict):
        return []

    candidates: List[Any] = []

    def add(value: Any) -> None:
        if isinstance(value, list):
            candidates.extend(value)
        else:
            candidates.append(value)

    if field in event:
        add(event[field])
        return candidates

    # Dotted path traversal (e.g. ``Event.System.EventID``).
    if "." in field:
        node: Any = event
        for part in field.split("."):
            if not isinstance(node, dict):
                node = None
                break
            match = _ci_get(node, part)
            if match is _MISSING:
                node = None
                break
            node = match
        if node is not None:
            add(node)
            return candidates

    match = _ci_get(event, field)
    if match is not _MISSING:
        add(match)

    return candidates


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


_MISSING = _Missing()


def _ci_get(mapping: Dict[str, Any], key: str) -> Any:
    """Case-insensitive ``dict.get`` that distinguishes missing from ``None``."""
    if key in mapping:
        return mapping[key]
    lowered = key.lower()
    for candidate_key, value in mapping.items():
        if isinstance(candidate_key, str) and candidate_key.lower() == lowered:
            return value
    return _MISSING
