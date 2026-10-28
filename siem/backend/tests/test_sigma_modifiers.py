"""Field-modifier semantics for Sigma selection matching."""

from __future__ import annotations

import pytest

from sigma import SigmaRuleError
from sigma.matcher import compile_mapping, parse_field_spec


def matches(selection: dict, event: dict) -> bool:
    return compile_mapping(selection)(event)


class TestFieldSpec:
    def test_splits_field_and_modifiers(self):
        assert parse_field_spec("CommandLine|contains|all") == (
            "CommandLine",
            ["contains", "all"],
        )

    def test_unknown_modifier_rejected(self):
        with pytest.raises(SigmaRuleError, match="Unsupported Sigma modifier"):
            parse_field_spec("CommandLine|fuzzy")

    def test_conflicting_string_modifiers_rejected(self):
        with pytest.raises(SigmaRuleError, match="Conflicting"):
            parse_field_spec("CommandLine|contains|startswith")


class TestStringMatching:
    def test_equality_is_case_insensitive(self):
        assert matches({"TargetUserName": "Admin"}, {"TargetUserName": "admin"})
        assert not matches({"TargetUserName": "admin"}, {"TargetUserName": "administrator"})

    def test_wildcards_in_default_value(self):
        assert matches({"Image": "*\\powershell.exe"}, {"Image": "C:\\Windows\\System32\\powershell.exe"})
        assert matches({"Image": "power?hell.exe"}, {"Image": "powershell.exe"})
        assert not matches({"Image": "*.exe"}, {"Image": "powershell.dll"})

    def test_contains(self):
        assert matches({"CommandLine|contains": "-enc"}, {"CommandLine": "powershell -enc AAAA"})
        assert not matches({"CommandLine|contains": "-enc"}, {"CommandLine": "powershell"})

    def test_startswith_and_endswith(self):
        assert matches({"Image|startswith": "C:\\Windows"}, {"Image": "C:\\Windows\\System32\\cmd.exe"})
        assert matches({"Image|endswith": "\\cmd.exe"}, {"Image": "C:\\Windows\\System32\\cmd.exe"})
        assert not matches({"Image|endswith": "\\cmd.exe"}, {"Image": "C:\\Windows\\System32\\powershell.exe"})

    def test_list_values_are_ored(self):
        assert matches({"CommandLine|contains": ["-enc", "-w hidden"]}, {"CommandLine": "x -w hidden y"})

    def test_all_modifier_requires_every_value(self):
        selection = {"CommandLine|contains|all": ["-enc", "-w hidden"]}
        assert matches(selection, {"CommandLine": "powershell -enc AAAA -w hidden"})
        assert not matches(selection, {"CommandLine": "powershell -enc AAAA"})

    def test_regex(self):
        assert matches({"CommandLine|re": "enc.*hidden"}, {"CommandLine": "x enc y hidden z"})
        assert not matches({"CommandLine|re": "^enc"}, {"CommandLine": "x enc"})

    def test_windash_equivalence(self):
        assert matches({"CommandLine|windash|contains": "-enc"}, {"CommandLine": "powershell /enc AAAA"})

    def test_base64(self):
        # base64('whoami') == d2hvYW1p
        assert matches({"CommandLine|base64|contains": "whoami"}, {"CommandLine": "powershell d2hvYW1p"})

    def test_fieldref(self):
        assert matches({"TargetUserName|fieldref": "SubjectUserName"},
                       {"TargetUserName": "bob", "SubjectUserName": "bob"})
        assert not matches({"TargetUserName|fieldref": "SubjectUserName"},
                           {"TargetUserName": "bob", "SubjectUserName": "alice"})


class TestNumericAndNetworkMatching:
    def test_numeric_equality_coerces_strings(self):
        assert matches({"EventID": 4625}, {"EventID": "4625"})
        assert not matches({"EventID": 4625}, {"EventID": "4624"})

    def test_gt_and_lt(self):
        assert matches({"LogonType|gt": 2}, {"LogonType": 3})
        assert not matches({"LogonType|gt": 3}, {"LogonType": 3})
        assert matches({"LogonType|lte": 3}, {"LogonType": 3})

    def test_cidr(self):
        assert matches({"IpAddress|cidr": "192.168.0.0/16"}, {"IpAddress": "192.168.1.10"})
        assert not matches({"IpAddress|cidr": "192.168.0.0/16"}, {"IpAddress": "10.0.0.5"})

    def test_exists(self):
        assert matches({"CommandLine|exists": True}, {"CommandLine": "x"})
        assert not matches({"CommandLine|exists": True}, {"CommandLine": None})
        assert matches({"CommandLine|exists": False}, {})


class TestListValuedFields:
    def test_any_privilege_can_match(self):
        assert matches({"Privileges|contains": "SeDebugPrivilege"},
                       {"Privileges": ["SeShutdownPrivilege", "SeDebugPrivilege"]})

    def test_all_requires_each_value_present(self):
        selection = {"Privileges|contains|all": ["SeDebugPrivilege", "SeTcbPrivilege"]}
        assert matches(selection, {"Privileges": ["SeDebugPrivilege", "SeTcbPrivilege"]})
        assert not matches(selection, {"Privileges": ["SeDebugPrivilege"]})
