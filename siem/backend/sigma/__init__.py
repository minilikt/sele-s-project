"""Sigma-compatible detection rule engine for the SIEM backend."""

from .engine import LoadResult, SigmaEngine
from .event import build_sigma_event, lookup
from .matcher import SigmaRuleError, compile_selection, parse_field_spec
from .parser import SigmaRule, load_rule_file, parse_condition, parse_rule

__all__ = [
    "LoadResult",
    "SigmaEngine",
    "SigmaRule",
    "SigmaRuleError",
    "build_sigma_event",
    "compile_selection",
    "load_rule_file",
    "lookup",
    "parse_condition",
    "parse_field_spec",
    "parse_rule",
]
