"""
Windows event log import.

Supports three input shapes:

* binary ``.evtx`` files (Windows Vista+ log format), parsed with ``python-evtx``,
* XML exports (``Get-WinEvent | ConvertTo-Xml``, ``wevtutil`` XML output),
* JSON arrays already in this platform's ingest format.

Everything is normalised into the same payload the ingest API accepts, so
imported logs flow through the identical detection pipeline as live data.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree import ElementTree

EVTX_MAGIC = b"ElfFile\x00"
MAX_RECORDS = 200_000

# Event ID -> (event_type, severity). Deliberately conservative: unknown IDs
# are retained as generic events rather than dropped.
_EVENT_CATALOGUE: Dict[int, Tuple[str, str]] = {
    104: ("Defense Evasion", "Critical"),
    1102: ("Defense Evasion", "Critical"),
    4624: ("Authentication", "Low"),
    4625: ("Authentication", "Low"),
    4634: ("Authentication", "Low"),
    4647: ("Authentication", "Low"),
    4648: ("Authentication", "High"),
    4672: ("Privilege", "High"),
    4688: ("Process", "Medium"),
    4689: ("Process", "Low"),
    4698: ("Persistence", "Medium"),
    4699: ("Persistence", "Medium"),
    4700: ("Persistence", "Medium"),
    4702: ("Persistence", "Medium"),
    4720: ("Account Management", "Medium"),
    4722: ("Account Management", "Medium"),
    4723: ("Account Management", "Medium"),
    4724: ("Account Management", "High"),
    4725: ("Account Management", "Medium"),
    4726: ("Account Management", "Medium"),
    4728: ("Privilege", "High"),
    4732: ("Privilege", "High"),
    4738: ("Account Management", "Medium"),
    4740: ("Authentication", "High"),
    4756: ("Privilege", "High"),
    4767: ("Account Management", "Medium"),
    4104: ("Scripting", "Medium"),
    7045: ("Service", "High"),
}

_ACCOUNT_FIELDS = ("TargetUserName", "SubjectUserName", "AccountName", "UserName", "param1")
_IP_FIELDS = ("IpAddress", "SourceIp", "ClientAddress", "SourceNetworkAddress")


@dataclass
class ParseResult:
    events: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    skipped: int = 0
    source_format: str = "unknown"

    @property
    def ok(self) -> bool:
        return bool(self.events)


# ── XML helpers ───────────────────────────────────────────────────────────────

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _flatten_user_data(node: ElementTree.Element, out: Dict[str, Any]) -> None:
    for child in node:
        name = _local(child.tag)
        if len(child):
            _flatten_user_data(child, out)
        else:
            out[name] = (child.text or "").strip()


def _extract_event_data(root: ElementTree.Element) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    for node in root.iter():
        if _local(node.tag) != "Data":
            continue
        name = node.get("Name")
        value = (node.text or "").strip()
        if name:
            data[name] = value

    for node in root.iter():
        if _local(node.tag) == "UserData":
            _flatten_user_data(node, data)

    return data


def _first(data: Dict[str, Any], names: Iterable[str]) -> Optional[str]:
    for name in names:
        value = data.get(name)
        if value:
            text = str(value).strip()
            if text and text != "-":
                return text
    return None


def _parse_system_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip().replace("Z", "+00:00")
    # Windows emits 7 fractional digits; fromisoformat handles 6 on older
    # Python versions, so trim.
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def normalise_event_xml(xml_text: str) -> Optional[Dict[str, Any]]:
    """Convert one Windows event XML document into an ingest payload."""
    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return None

    system: Dict[str, Any] = {}
    for node in root.iter():
        tag = _local(node.tag)
        if tag == "EventID":
            try:
                system["EventID"] = int((node.text or "").strip())
            except (TypeError, ValueError):
                pass
        elif tag == "TimeCreated":
            system["TimeCreated"] = node.get("SystemTime")
        elif tag == "Computer":
            system["Computer"] = (node.text or "").strip()
        elif tag == "Channel":
            system["Channel"] = (node.text or "").strip()
        elif tag == "Provider":
            system["Provider"] = node.get("Name")

    event_id = system.get("EventID")
    timestamp = _parse_system_time(system.get("TimeCreated"))
    if event_id is None or timestamp is None:
        return None

    data = _extract_event_data(root)

    event_type, severity = _EVENT_CATALOGUE.get(event_id, ("Other", "Low"))
    account = _first(data, _ACCOUNT_FIELDS) or "unknown"
    source_ip = _first(data, _IP_FIELDS)

    raw = dict(data)
    for key, value in system.items():
        raw.setdefault(key, value)

    return {
        "timestamp": timestamp.isoformat(),
        "event_id": event_id,
        "source": system.get("Channel") or "Windows Security",
        "account": account,
        "source_ip": source_ip,
        "computer_name": system.get("Computer") or "UNKNOWN",
        "event_type": event_type,
        "severity": severity,
        "raw_data": raw,
    }


# ── Format parsers ────────────────────────────────────────────────────────────

def parse_evtx_xml(text: str) -> ParseResult:
    """Parse a document containing one or more ``<Event>`` elements."""
    result = ParseResult(source_format="xml")

    # Fast path: a single event document.
    stripped = text.lstrip()
    if stripped.startswith("<") and _local(_root_tag(stripped)) == "Event":
        event = normalise_event_xml(text)
        if event:
            result.events.append(event)
        else:
            result.skipped += 1
        return result

    # Sequence of events, possibly wrapped in <Events>.
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        result.errors.append(f"Invalid XML: {exc}")
        return result

    for node in root.iter():
        if _local(node.tag) != "Event":
            continue
        event = normalise_event_xml(ElementTree.tostring(node, encoding="unicode"))
        if event:
            result.events.append(event)
        else:
            result.skipped += 1

    if not result.events and not result.errors:
        result.errors.append("No <Event> elements found in XML document")

    return result


def _root_tag(text: str) -> str:
    match = re.search(r"<([A-Za-z_][\w:.-]*)", text)
    return match.group(1) if match else ""


def parse_evtx_bytes(data: bytes) -> ParseResult:
    """Parse a binary ``.evtx`` file using ``python-evtx``."""
    result = ParseResult(source_format="evtx")

    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError:
        result.errors.append(
            "python-evtx is not installed; install it with 'pip install python-evtx' "
            "or import an XML export instead."
        )
        return result

    try:
        import os
        import tempfile

        # python-evtx expects a filesystem path, not a file object.
        handle = tempfile.NamedTemporaryFile(delete=False, suffix=".evtx")
        try:
            handle.write(data)
            handle.close()
            with Evtx(handle.name) as log:
                for count, record in enumerate(log.records()):
                    if count >= MAX_RECORDS:
                        result.errors.append(
                            f"Record limit reached ({MAX_RECORDS}); remaining events were not imported."
                        )
                        break
                    try:
                        event = normalise_event_xml(record.xml())
                    except Exception as exc:  # corrupt record
                        result.errors.append(f"Record {count}: {exc}")
                        continue
                    if event:
                        result.events.append(event)
                    else:
                        result.skipped += 1
        finally:
            handle.close()
            try:
                os.unlink(handle.name)
            except OSError:
                pass
    except Exception as exc:
        result.errors.append(f"Could not parse EVTX file: {exc}")

    if not result.events and not result.errors:
        result.errors.append("No event records found in EVTX file")

    return result


def parse_json_export(text: str) -> ParseResult:
    result = ParseResult(source_format="json")
    try:
        payload = json.loads(text)
    except ValueError as exc:
        result.errors.append(f"Invalid JSON: {exc}")
        return result

    if isinstance(payload, dict):
        payload = payload.get("events") or payload.get("Events") or []

    if not isinstance(payload, list):
        result.errors.append("JSON payload must be a list of events")
        return result

    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            result.skipped += 1
            continue
        try:
            result.events.append(
                {
                    "timestamp": item["timestamp"],
                    "event_id": int(item["event_id"]),
                    "source": item.get("source", "Windows Security"),
                    "account": item.get("account") or "unknown",
                    "source_ip": item.get("source_ip"),
                    "computer_name": item.get("computer_name") or item.get("computer") or "UNKNOWN",
                    "event_type": item.get("event_type", "Other"),
                    "severity": item.get("severity", "Low"),
                    "raw_data": item.get("raw_data") or {},
                }
            )
        except (KeyError, TypeError, ValueError) as exc:
            result.errors.append(f"Item {index}: {exc}")
            result.skipped += 1

    return result


def parse_upload(filename: str, data: bytes) -> ParseResult:
    """Dispatch on file content, falling back to the extension."""
    name = (filename or "").lower()

    if data.startswith(EVTX_MAGIC) or name.endswith(".evtx"):
        return parse_evtx_bytes(data)

    text = _decode(data)

    if name.endswith(".json") or text.lstrip().startswith(("[", "{")):
        return parse_json_export(text)

    return parse_evtx_xml(text)


def _decode(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    if data[:2] == b"<\x00":
        return data.decode("utf-16-le", errors="replace")
    if data[:2] == b"\x00<":
        return data.decode("utf-16-be", errors="replace")

    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("latin-1")
