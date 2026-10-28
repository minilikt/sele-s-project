"""
Compile Sigma ``detection`` selections into Python predicates.

Supported field modifiers (the subset that covers the overwhelming majority of
real-world Sigma rules):

    contains, startswith, endswith, all, re, cidr, gt, gte, lt, lte,
    exists, base64, base64offset, windash, fieldref

Semantics follow the Sigma specification:

* a selection mapping ANDs its fields,
* a field holding a list ORs its values, unless ``|all`` is used,
* unmodified string values are case-insensitive and may contain ``*`` / ``?``
  wildcards.

Anything unsupported raises :class:`SigmaRuleError` at load time rather than
silently never matching — a detection rule that can never fire is worse than
one that fails loudly.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Tuple

from .event import lookup

Predicate = Callable[[Dict[str, Any]], bool]

_SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "all",
    "re",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "base64",
    "base64offset",
    "windash",
    "fieldref",
}

_COMPARISON_MODIFIERS = {"gt", "gte", "lt", "lte"}


class SigmaRuleError(ValueError):
    """Raised when a Sigma rule cannot be parsed or compiled."""


# ── Field reference parsing ───────────────────────────────────────────────────

def parse_field_spec(spec: str) -> Tuple[str, List[str]]:
    """Split ``CommandLine|contains|all`` into ``("CommandLine", [...])``."""
    parts = str(spec).split("|")
    field = parts[0].strip()
    modifiers = [p.strip().lower() for p in parts[1:] if p.strip()]

    if not field:
        raise SigmaRuleError(f"Empty field name in spec: {spec!r}")

    unknown = [m for m in modifiers if m not in _SUPPORTED_MODIFIERS]
    if unknown:
        raise SigmaRuleError(
            f"Unsupported Sigma modifier(s) {unknown} in field spec {spec!r}. "
            f"Supported: {sorted(_SUPPORTED_MODIFIERS)}"
        )

    conflicting = [m for m in ("contains", "startswith", "endswith", "re") if m in modifiers]
    if len(conflicting) > 1:
        raise SigmaRuleError(f"Conflicting string modifiers {conflicting} in {spec!r}")

    return field, modifiers


# ── Value matching ────────────────────────────────────────────────────────────

@lru_cache(maxsize=4096)
def _wildcard_regex(pattern: str) -> re.Pattern:
    """Translate a Sigma wildcard pattern to a case-insensitive regex."""
    out = ["^"]
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    out.append("$")
    return re.compile("".join(out), re.IGNORECASE | re.DOTALL)


def _to_number(value: Any) -> Any:
    """Return a comparable number for numeric strings, else ``None``."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    try:
        text = str(value).strip()
        return float(text) if "." in text else int(text)
    except (TypeError, ValueError):
        return None


def _scalar_equals(candidate: Any, expected: Any) -> bool:
    if candidate is None or expected is None:
        return candidate is None and expected is None

    left_num, right_num = _to_number(candidate), _to_number(expected)
    if left_num is not None and right_num is not None:
        return float(left_num) == float(right_num)

    if isinstance(candidate, bool) or isinstance(expected, bool):
        return bool(candidate) == bool(expected)

    return str(candidate).lower() == str(expected).lower()


def _normalise_dashes(text: str) -> str:
    return text.replace("\u2013", "-").replace("\u2014", "-").replace("\u2212", "-")


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _b64_offsets(text: str) -> List[str]:
    """Approximate the three base64 alignment variants of *text*.

    A token can start at any of three byte offsets relative to the encoded
    stream, so a fixed encoding will not always match. We generate the three
    padded encodings and keep their stable middle sections.
    """
    raw = text.encode("utf-8")
    variants: List[str] = []
    for offset in range(3):
        encoded = base64.b64encode(b"\x00" * offset + raw).decode("ascii")
        head = {0: 0, 1: 2, 2: 3}[offset]
        variants.append(encoded[head:])
    return variants


def _match_string(candidate: str, expected: Any, modifiers: List[str]) -> bool:
    text = str(candidate)
    pattern = str(expected)

    if "re" in modifiers:
        try:
            return re.search(pattern, text, re.IGNORECASE) is not None
        except re.error as exc:  # pragma: no cover - defensive
            raise SigmaRuleError(f"Invalid regex {pattern!r}: {exc}") from exc

    if "windash" in modifiers:
        text, pattern = _normalise_dashes(text), _normalise_dashes(pattern)
        # ``-enc`` and ``/enc`` are equivalent command-line switches.
        text = re.sub(r"(?<=\s)/(?=[A-Za-z])", "-", text)
        pattern = re.sub(r"(?<=\s)/(?=[A-Za-z])", "-", pattern)

    if "base64offset" in modifiers:
        needle = _b64(pattern)
        return any(variant.lower() in _b64(text).lower() or variant.lower() in text.lower()
                   for variant in _b64_offsets(pattern)) or needle.lower() in text.lower()

    if "base64" in modifiers:
        return _b64(pattern).lower() in _b64(text).lower() or _b64(pattern).lower() in text.lower()

    if "contains" in modifiers:
        return pattern.lower() in text.lower()
    if "startswith" in modifiers:
        return text.lower().startswith(pattern.lower())
    if "endswith" in modifiers:
        return text.lower().endswith(pattern.lower())

    # Default Sigma string comparison: case-insensitive wildcard match.
    return _wildcard_regex(pattern).match(text) is not None


def _match_cidr(candidate: Any, expected: Any) -> bool:
    try:
        network = ipaddress.ip_network(str(expected), strict=False)
        address = ipaddress.ip_address(str(candidate).strip())
    except ValueError:
        return False
    return address.version == network.version and address in network


def _match_comparison(candidate: Any, expected: Any, modifier: str) -> bool:
    left, right = _to_number(candidate), _to_number(expected)
    if left is None or right is None:
        left, right = str(candidate), str(expected)
    if modifier == "gt":
        return left > right
    if modifier == "gte":
        return left >= right
    if modifier == "lt":
        return left < right
    return left <= right


def _match_scalar(candidate: Any, expected: Any, modifiers: List[str]) -> bool:
    if "exists" in modifiers:
        present = candidate is not None and candidate != ""
        return present is bool(expected)

    if "cidr" in modifiers:
        return _match_cidr(candidate, expected)

    comparison = next((m for m in modifiers if m in _COMPARISON_MODIFIERS), None)
    if comparison:
        return _match_comparison(candidate, expected, comparison)

    if isinstance(candidate, (list, tuple, set)):
        return any(_match_scalar(item, expected, modifiers) for item in candidate)

    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        return _scalar_equals(candidate, expected)

    if expected is None:
        return candidate is None

    if isinstance(candidate, str) or isinstance(expected, str):
        return _match_string(candidate, expected, modifiers)

    return _scalar_equals(candidate, expected)


def _match_field(event: Dict[str, Any], spec: str, expected: Any) -> bool:
    field, modifiers = parse_field_spec(spec)

    if "fieldref" in modifiers:
        targets = lookup(event, str(expected))
        sources = lookup(event, field)
        return any(_scalar_equals(s, t) for s in sources for t in targets)

    values = lookup(event, field)

    if "exists" in modifiers:
        present = any(v is not None and v != "" for v in values)
        return present is bool(expected)

    if not values:
        # A rule asking for a field the event does not have simply misses.
        return False

    expected_items: Iterable[Any] = expected if isinstance(expected, list) else [expected]

    if isinstance(expected, list) and "all" in modifiers:
        return all(
            any(_match_scalar(value, item, modifiers) for value in values)
            for item in expected_items
        )

    return any(
        _match_scalar(value, item, modifiers)
        for value in values
        for item in expected_items
    )


# ── Selection compilation ─────────────────────────────────────────────────────

def compile_mapping(mapping: Dict[str, Any]) -> Predicate:
    """Compile a single Sigma selection map (fields are ANDed)."""
    if not isinstance(mapping, dict):
        raise SigmaRuleError(f"Selection must be a mapping, got {type(mapping).__name__}")

    clauses = [(_field_spec, value) for _field_spec, value in mapping.items()]

    def predicate(event: Dict[str, Any]) -> bool:
        return all(_match_field(event, spec, value) for spec, value in clauses)

    return predicate


def compile_selection(selection: Any) -> Predicate:
    """Compile a ``detection`` entry into a predicate.

    A selection may be a single mapping, a list of mappings (ORed), or a list
    of scalars (useful for keyword searches such as ``keywords: [mimikatz]``).
    """
    if isinstance(selection, dict):
        return compile_mapping(selection)

    if isinstance(selection, list):
        if all(isinstance(item, dict) for item in selection):
            compiled = [compile_mapping(item) for item in selection]
            return lambda event: any(pred(event) for pred in compiled)

        if all(not isinstance(item, (dict, list)) for item in selection):
            needles = [str(item).lower() for item in selection]

            def keyword_predicate(event: Dict[str, Any]) -> bool:
                haystack = " ".join(
                    str(value) for value in event.values() if isinstance(value, (str, int))
                ).lower()
                return any(needle in haystack for needle in needles)

            return keyword_predicate

        raise SigmaRuleError("Mixed list selection types are not supported")

    raise SigmaRuleError(f"Unsupported selection type: {type(selection).__name__}")
