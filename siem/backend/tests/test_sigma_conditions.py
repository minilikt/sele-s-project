"""Condition parsing and evaluation tests for the Sigma engine."""

from __future__ import annotations

import pytest

from sigma import SigmaRuleError
from sigma.parser import parse_condition


class TestConditionParsing:
    def test_simple_reference(self):
        node = parse_condition("selection", ["selection"])
        assert node == ("ref", "selection")

    def test_and_not(self):
        node = parse_condition("selection and not filter", ["selection", "filter"])
        assert node[0] == "and"
        assert node[2][0] == "not"

    def test_or_precedence(self):
        node = parse_condition("a or b and c", ["a", "b", "c"])
        assert node[0] == "or"
        assert node[2][0] == "and"

    def test_parentheses(self):
        node = parse_condition("(a or b) and c", ["a", "b", "c"])
        assert node[0] == "and"
        assert node[1][0] == "or"

    def test_one_of_wildcard(self):
        node = parse_condition("1 of selection_*", ["selection_a", "selection_b", "filter"])
        assert node[0] == "quantifier"
        assert node[1] == 1

    def test_all_of_them(self):
        node = parse_condition("all of them", ["selection", "filter"])
        assert node[0] == "quantifier"
        assert node[1] == -1

    def test_unknown_selection_rejected(self):
        with pytest.raises(SigmaRuleError, match="unknown selection"):
            parse_condition("missing", ["selection"])

    def test_garbage_rejected(self):
        with pytest.raises(SigmaRuleError):
            parse_condition("selection and and", ["selection"])

    def test_unbalanced_parenthesis_rejected(self):
        with pytest.raises(SigmaRuleError):
            parse_condition("(selection", ["selection"])


class TestConditionEvaluation:
    @staticmethod
    def _rule(condition: str, detection: dict):
        from sigma.parser import parse_rule

        return parse_rule(
            {
                "title": "test",
                "id": "test-rule",
                "detection": {**detection, "condition": condition},
            }
        )

    def test_and_not(self):
        rule = self._rule(
            "selection and not filter",
            {
                "selection": {"EventID": 4625},
                "filter": {"TargetUserName": "svc_known"},
            },
        )
        assert rule.matches({"EventID": 4625, "TargetUserName": "user1"}) is True
        assert rule.matches({"EventID": 4625, "TargetUserName": "svc_known"}) is False
        assert rule.matches({"EventID": 4624, "TargetUserName": "user1"}) is False

    def test_one_of(self):
        rule = self._rule(
            "1 of selection_*",
            {
                "selection_a": {"EventID": 4625},
                "selection_b": {"EventID": 4624},
            },
        )
        assert rule.matches({"EventID": 4624}) is True
        assert rule.matches({"EventID": 9999}) is False

    def test_all_of_them(self):
        rule = self._rule(
            "all of them",
            {
                "selection_a": {"EventID": 4625},
                "selection_b": {"TargetUserName": "admin"},
            },
        )
        assert rule.matches({"EventID": 4625, "TargetUserName": "admin"}) is True
        assert rule.matches({"EventID": 4625, "TargetUserName": "bob"}) is False
