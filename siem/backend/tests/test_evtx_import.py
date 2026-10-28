"""Windows log import tests (XML, JSON and EVTX dispatch)."""

from __future__ import annotations

import json

import pytest

import evtx_import

NS = "http://schemas.microsoft.com/win/2004/08/events/event"

EVENT_TEMPLATE = """<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="{ns}">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>{event_id}</EventID>
    <TimeCreated SystemTime="{system_time}"/>
    <Computer>WS-001.corp.local</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">{account}</Data>
    <Data Name="IpAddress">{ip}</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""


def make_xml(event_id=4625, account="a.kim", ip="45.77.12.204",
             system_time="2026-10-24T10:01:02.1234567Z"):
    return EVENT_TEMPLATE.format(
        ns=NS, event_id=event_id, account=account, ip=ip, system_time=system_time
    )


class TestXmlNormalisation:
    def test_extracts_core_fields(self):
        event = evtx_import.normalise_event_xml(make_xml())
        assert event["event_id"] == 4625
        assert event["account"] == "a.kim"
        assert event["source_ip"] == "45.77.12.204"
        assert event["computer_name"] == "WS-001.corp.local"
        assert event["source"] == "Security"
        assert event["event_type"] == "Authentication"
        assert event["severity"] == "Low"

    def test_timestamp_parsed_with_seven_fractional_digits(self):
        event = evtx_import.normalise_event_xml(make_xml())
        assert event["timestamp"].startswith("2026-10-24T10:01:02")
        assert event["timestamp"].endswith("+00:00")

    def test_raw_data_keeps_all_fields(self):
        event = evtx_import.normalise_event_xml(make_xml())
        assert event["raw_data"]["LogonType"] == "3"
        assert event["raw_data"]["EventID"] == 4625

    def test_account_creation_maps_to_medium(self):
        event = evtx_import.normalise_event_xml(make_xml(event_id=4720))
        assert event["event_type"] == "Account Management"
        assert event["severity"] == "Medium"

    def test_log_cleared_maps_to_critical(self):
        event = evtx_import.normalise_event_xml(make_xml(event_id=1102))
        assert event["event_type"] == "Defense Evasion"
        assert event["severity"] == "Critical"

    def test_unmapped_event_id_is_retained(self):
        event = evtx_import.normalise_event_xml(make_xml(event_id=9999))
        assert event["event_id"] == 9999
        assert event["event_type"] == "Other"

    def test_missing_timestamp_returns_none(self):
        broken = make_xml().replace(
            '<TimeCreated SystemTime="2026-10-24T10:01:02.1234567Z"/>', ""
        )
        assert evtx_import.normalise_event_xml(broken) is None

    def test_invalid_xml_returns_none(self):
        assert evtx_import.normalise_event_xml("<Event><System>") is None

    def test_namespaceless_xml_also_works(self):
        plain = make_xml().replace(f' xmlns="{NS}"', "")
        event = evtx_import.normalise_event_xml(plain)
        assert event["event_id"] == 4625


class TestXmlDocuments:
    def test_single_event_document(self):
        result = evtx_import.parse_evtx_xml(make_xml())
        assert len(result.events) == 1
        assert result.source_format == "xml"

    def test_wrapped_event_list(self):
        document = f"<Events>{make_xml()}{make_xml(event_id=4720)}</Events>"
        # Nested Event documents each carry their own declaration, which is not
        # legal XML; strip them for the wrapper case.
        document = document.replace('<?xml version="1.0" encoding="utf-8"?>', "")
        result = evtx_import.parse_evtx_xml(document)
        assert len(result.events) == 2

    def test_invalid_document_reports_error(self):
        result = evtx_import.parse_evtx_xml("not xml at all")
        assert result.events == []
        assert result.errors

    def test_empty_document_reports_error(self):
        result = evtx_import.parse_evtx_xml("<Events></Events>")
        assert result.events == []
        assert "No <Event> elements" in result.errors[0]


class TestJsonExport:
    def test_parses_platform_format(self):
        payload = json.dumps(
            [
                {
                    "timestamp": "2026-10-24T10:00:00+00:00",
                    "event_id": 4625,
                    "account": "a.kim",
                    "computer_name": "WS-1",
                }
            ]
        )
        result = evtx_import.parse_json_export(payload)
        assert len(result.events) == 1
        assert result.events[0]["account"] == "a.kim"

    def test_accepts_wrapper_object(self):
        payload = json.dumps({"events": [{"timestamp": "t", "event_id": 1, "account": "x"}]})
        result = evtx_import.parse_json_export(payload)
        assert len(result.events) == 1

    def test_invalid_items_are_skipped(self):
        payload = json.dumps([{"timestamp": "t", "event_id": 1}, {"nope": True}])
        result = evtx_import.parse_json_export(payload)
        assert len(result.events) == 1
        assert result.skipped == 1

    def test_invalid_json_reports_error(self):
        result = evtx_import.parse_json_export("{oops")
        assert result.errors


class TestBinaryParser:
    def test_python_evtx_receives_a_filesystem_path(self, monkeypatch):
        # python-evtx rejects file objects; the parser must hand it a real path
        # and clean that temporary file up afterwards.
        import os

        captured = {}

        class FakeEvtx:
            def __init__(self, path):
                captured["path"] = path

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                return False

            def records(self):
                return iter([])

        monkeypatch.setattr("Evtx.Evtx.Evtx", FakeEvtx)
        result = evtx_import.parse_evtx_bytes(evtx_import.EVTX_MAGIC + b"x" * 32)

        assert result.source_format == "evtx"
        assert isinstance(captured["path"], str)
        assert os.path.exists(captured["path"]) is False

    def test_corrupt_binary_never_raises(self):
        result = evtx_import.parse_evtx_bytes(evtx_import.EVTX_MAGIC + b"\x00" * 128)
        assert result.events == []
        assert result.errors


class TestUploadDispatch:
    def test_xml_is_detected_by_content(self):
        result = evtx_import.parse_upload("events.txt", make_xml().encode("utf-8"))
        assert result.source_format == "xml"
        assert len(result.events) == 1

    def test_json_is_detected_by_extension(self):
        payload = json.dumps([{"timestamp": "2026-10-24T10:00:00+00:00", "event_id": 4625}])
        result = evtx_import.parse_upload("events.json", payload.encode("utf-8"))
        assert result.source_format == "json"

    def test_evtx_magic_routes_to_binary_parser(self):
        result = evtx_import.parse_upload("security.evtx", evtx_import.EVTX_MAGIC + b"\x00" * 64)
        assert result.source_format == "evtx"
        # A truncated/garbage file must fail gracefully, never raise.
        assert result.events == []
        assert result.errors

    def test_utf16_xml_is_decoded(self):
        result = evtx_import.parse_upload(
            "events.xml", make_xml().encode("utf-16-le")
        )
        assert len(result.events) == 1
