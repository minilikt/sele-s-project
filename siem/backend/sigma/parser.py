"""
Sigma rule parsing: YAML -> :class:`SigmaRule` with a compiled condition tree.

The condition grammar implemented here is the one used across the SigmaHQ rule
repository::

    condition: selection
    condition: selection and not filter
    condition: 1 of selection_*
    condition: all of them
    condition: (selection_a or selection_b) and not filter

A small, documented extension (``correlation:``) adds ordered multi-step
sequences, because single-event rules cannot express "failures *then* success".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .matcher import Predicate, SigmaRuleError, compile_selection

# ── Condition tokenizer / parser ──────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<lparen>\()|"
    r"(?P<rparen>\))|"
    r"(?P<op>and|or|not|of|all|any|them)\b|"
    r"(?P<int>\d+)|"
    r"(?P<ident>[A-Za-z_][A-Za-z0-9_.\-*]*)"
    r")",
    re.IGNORECASE,
)

ConditionNode = Tuple


def _tokenize(condition: str) -> List[Tuple[str, str]]:
    tokens: List[Tuple[str, str]] = []
    position = 0
    text = condition.strip()

    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if not match or match.end() == position:
            raise SigmaRuleError(
                f"Cannot tokenize condition at position {position}: {text[position:]!r}"
            )
        kind = match.lastgroup or ""
        value = match.group()
        tokens.append((kind, value.strip()))
        position = match.end()

    return tokens


class _ConditionParser:
    def __init__(self, tokens: List[Tuple[str, str]]):
        self.tokens = tokens
        self.index = 0

    def peek(self) -> Optional[Tuple[str, str]]:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def take(self) -> Tuple[str, str]:
        token = self.peek()
        if token is None:
            raise SigmaRuleError("Unexpected end of condition")
        self.index += 1
        return token

    def accept(self, value: str) -> bool:
        token = self.peek()
        if token and token[1].lower() == value:
            self.index += 1
            return True
        return False

    def parse(self) -> ConditionNode:
        node = self.parse_or()
        if self.peek() is not None:
            raise SigmaRuleError(f"Trailing tokens in condition: {self.peek()[1]!r}")
        return node

    def parse_or(self) -> ConditionNode:
        node = self.parse_and()
        while self.peek() and self.peek()[1].lower() == "or":
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self) -> ConditionNode:
        node = self.parse_unary()
        while self.peek() and self.peek()[1].lower() == "and":
            self.take()
            node = ("and", node, self.parse_unary())
        return node

    def parse_unary(self) -> ConditionNode:
        token = self.peek()
        if token and token[1].lower() == "not":
            self.take()
            return ("not", self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> ConditionNode:
        token = self.peek()
        if token is None:
            raise SigmaRuleError("Unexpected end of condition")

        kind, value = token

        if value == "(":
            self.take()
            node = self.parse_or()
            if not self.accept(")"):
                raise SigmaRuleError("Missing closing parenthesis in condition")
            return node

        if kind == "int":
            self.take()
            count = int(value)
            if not self.accept("of"):
                raise SigmaRuleError(f"Expected 'of' after '{value}' in condition")
            return ("quantifier", count, self.parse_target())

        if kind == "op" and value.lower() in ("all", "any"):
            self.take()
            if not self.accept("of"):
                raise SigmaRuleError(f"Expected 'of' after '{value}' in condition")
            count = -1 if value.lower() == "all" else 1
            return ("quantifier", count, self.parse_target())

        if kind in ("ident", "op"):
            self.take()
            return ("ref", value)

        raise SigmaRuleError(f"Unexpected token {value!r} in condition")

    def parse_target(self) -> str:
        token = self.take()
        if token[0] not in ("ident", "op"):
            raise SigmaRuleError(f"Expected a selection name, got {token[1]!r}")
        return token[1]


def parse_condition(condition: str, selection_names: List[str]) -> ConditionNode:
    """Parse a Sigma condition string and validate its references."""
    node = _ConditionParser(_tokenize(condition)).parse()
    _validate_node(node, selection_names)
    return node


def _matching_names(pattern: str, selection_names: List[str]) -> List[str]:
    if pattern.lower() == "them":
        return list(selection_names)
    if "*" in pattern or "?" in pattern:
        regex = re.compile(
            "^" + re.escape(pattern).replace("\\*", ".*").replace("\\?", ".") + "$",
            re.IGNORECASE,
        )
        return [name for name in selection_names if regex.match(name)]
    return [name for name in selection_names if name.lower() == pattern.lower()]


def _validate_node(node: ConditionNode, selection_names: List[str]) -> None:
    kind = node[0]
    if kind in ("and", "or"):
        _validate_node(node[1], selection_names)
        _validate_node(node[2], selection_names)
    elif kind == "not":
        _validate_node(node[1], selection_names)
    elif kind == "ref":
        if not _matching_names(node[1], selection_names):
            raise SigmaRuleError(
                f"Condition references unknown selection {node[1]!r}. "
                f"Known selections: {selection_names}"
            )
    elif kind == "quantifier":
        if not _matching_names(node[2], selection_names):
            raise SigmaRuleError(
                f"Condition references unknown selection pattern {node[2]!r}. "
                f"Known selections: {selection_names}"
            )


def _evaluate(node: ConditionNode, results: Dict[str, bool]) -> bool:
    kind = node[0]
    if kind == "and":
        return _evaluate(node[1], results) and _evaluate(node[2], results)
    if kind == "or":
        return _evaluate(node[1], results) or _evaluate(node[2], results)
    if kind == "not":
        return not _evaluate(node[1], results)
    if kind == "ref":
        return any(value for key, value in results.items() if key.lower() == node[1].lower())
    if kind == "quantifier":
        count, pattern = node[1], node[2]
        names = _matching_names(pattern, list(results.keys()))
        matching = [results[name] for name in names]
        matched = sum(1 for value in matching if value)
        if count == -1:  # "all of"
            return bool(matching) and matched == len(matching)
        return matched >= count
    raise SigmaRuleError(f"Unknown condition node: {kind}")


# ── Rule model ────────────────────────────────────────────────────────────────

_TIMEFRAME_RE = re.compile(r"^\s*(?P<amount>\d+)\s*(?P<unit>s|m|h|d|sec|secs|second|seconds|min|mins|minute|minutes|hour|hours|day|days)?\s*$", re.I)

_UNIT_SECONDS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
}


def parse_timeframe(value: Any, default: str = "10m") -> timedelta:
    if value is None:
        value = default
    text = str(value)
    match = _TIMEFRAME_RE.match(text)
    if not match:
        raise SigmaRuleError(f"Invalid timeframe {value!r} (expected e.g. 10m, 30s, 2h, 1d)")
    amount = int(match.group("amount"))
    unit = (match.group("unit") or "m").lower()
    return timedelta(seconds=amount * _UNIT_SECONDS[unit])


@dataclass
class CorrelationStep:
    """One ordered stage of a multi-step correlation rule."""

    name: str
    selections: List[Predicate]
    min_count: int = 1


@dataclass
class SigmaRule:
    """A parsed, compiled Sigma rule."""

    id: str
    title: str
    description: str
    level: str
    tags: List[str]
    logsource: Dict[str, Any]
    selections: Dict[str, Predicate]
    condition_node: ConditionNode
    condition_text: str
    author: str = ""
    status: str = "experimental"
    references: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    source_path: Optional[str] = None
    raw_yaml: str = ""
    selection_specs: Dict[str, List[str]] = field(default_factory=dict)

    # Aggregation extension (event_count style detection)
    group_by: List[str] = field(default_factory=list)
    threshold: int = 1
    timeframe: timedelta = timedelta(minutes=10)

    # Ordered sequence extension
    correlation_steps: List[CorrelationStep] = field(default_factory=list)

    @property
    def is_correlation(self) -> bool:
        return bool(self.correlation_steps)

    @property
    def mitre_tactics(self) -> List[str]:
        return [_tactic_from_tag(tag) for tag in self.tags if _is_tactic_tag(tag)]

    @property
    def mitre_techniques(self) -> List[str]:
        return [_technique_from_tag(tag) for tag in self.tags if _is_technique_tag(tag)]

    def matches(self, event: Dict[str, Any]) -> bool:
        """Evaluate the rule condition against a normalised event."""
        results = {name: predicate(event) for name, predicate in self.selections.items()}
        return _evaluate(self.condition_node, results)


# ── Tag helpers ───────────────────────────────────────────────────────────────

_TACTIC_TAGS = {
    "reconnaissance", "resource_development", "initial_access", "execution",
    "persistence", "privilege_escalation", "defense_evasion", "credential_access",
    "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact",
}


def _is_tactic_tag(tag: str) -> bool:
    lowered = tag.lower()
    return lowered.startswith("attack.") and lowered.split(".", 1)[1] in _TACTIC_TAGS


def _is_technique_tag(tag: str) -> bool:
    lowered = tag.lower()
    if not lowered.startswith("attack."):
        return False
    return bool(re.fullmatch(r"t\d{4}(\.\d{3})?", lowered.split(".", 1)[1]))


def _tactic_from_tag(tag: str) -> str:
    return tag.split(".", 1)[1].replace("_", " ").title()


def _technique_from_tag(tag: str) -> str:
    return tag.split(".", 1)[1].upper()


# ── Loading ───────────────────────────────────────────────────────────────────

def parse_rule(data: Dict[str, Any], *, source_path: Optional[str] = None,
               raw_yaml: str = "") -> SigmaRule:
    """Build a :class:`SigmaRule` from an already-loaded YAML mapping."""
    if not isinstance(data, dict):
        raise SigmaRuleError("Rule document must be a mapping")

    for required in ("title", "detection"):
        if required not in data:
            raise SigmaRuleError(f"Rule is missing required field {required!r}")

    detection = data["detection"]
    if not isinstance(detection, dict):
        raise SigmaRuleError("'detection' must be a mapping")

    condition_text = detection.get("condition") or data.get("condition")
    correlation_block = data.get("correlation")
    if not condition_text and not correlation_block:
        raise SigmaRuleError("Rule has no 'condition' (and no 'correlation' block)")

    selection_raw = {
        key: value
        for key, value in detection.items()
        if key.lower() not in ("condition", "timeframe")
    }
    if not selection_raw:
        raise SigmaRuleError("Rule defines no selections")

    selections = {name: compile_selection(value) for name, value in selection_raw.items()}

    condition_node: ConditionNode
    if condition_text:
        condition_node = parse_condition(str(condition_text), list(selections.keys()))
    else:
        # Correlation-only rule: no single-event condition is needed, but the
        # node must still evaluate without raising.
        condition_node = ("quantifier", 1, "them")

    group_by = data.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]

    rule = SigmaRule(
        id=str(data.get("id") or _slugify(str(data["title"]))),
        title=str(data["title"]),
        description=str(data.get("description", "")),
        level=str(data.get("level", "medium")).lower(),
        tags=[str(tag) for tag in (data.get("tags") or [])],
        logsource=data.get("logsource") or {},
        selections=selections,
        condition_node=condition_node,
        condition_text=str(condition_text or ""),
        author=str(data.get("author", "")),
        status=str(data.get("status", "experimental")),
        references=[str(r) for r in (data.get("references") or [])],
        falsepositives=[str(f) for f in (data.get("falsepositives") or [])],
        source_path=source_path,
        raw_yaml=raw_yaml,
        selection_specs={
            name: _field_specs(value) for name, value in selection_raw.items()
        },
        group_by=[str(field) for field in group_by],
        threshold=int(data.get("threshold", 1) or 1),
        timeframe=parse_timeframe(data.get("timeframe")),
    )

    if correlation_block:
        correlation = _parse_correlation(correlation_block, selections)
        rule.correlation_steps = correlation["steps"]
        if correlation["group_by"]:
            rule.group_by = correlation["group_by"]
        if correlation["timeframe"] is not None:
            rule.timeframe = correlation["timeframe"]

    return rule


def _parse_correlation(block: Any, selections: Dict[str, Predicate]) -> Dict[str, Any]:
    """Parse the ordered-sequence extension.

    Example::

        correlation:
          type: temporal_ordered
          group_by: [TargetUserName]
          timeframe: 15m
          steps:
            - name: failures
              selection: {EventID: 4625}
              min_count: 3
            - name: success
              selection: {EventID: 4624}
    """
    if not isinstance(block, dict):
        raise SigmaRuleError("'correlation' must be a mapping")

    steps_raw = block.get("steps")
    if not isinstance(steps_raw, list) or not steps_raw:
        raise SigmaRuleError("'correlation.steps' must be a non-empty list")

    steps: List[CorrelationStep] = []
    for index, step in enumerate(steps_raw):
        if not isinstance(step, dict):
            raise SigmaRuleError(f"correlation.steps[{index}] must be a mapping")
        if "selection" not in step:
            raise SigmaRuleError(f"correlation.steps[{index}] is missing 'selection'")
        steps.append(
            CorrelationStep(
                name=str(step.get("name", f"step{index + 1}")),
                selections=[compile_selection(step["selection"])],
                min_count=int(step.get("min_count", 1) or 1),
            )
        )

    group_by = block.get("group_by") or []
    if isinstance(group_by, str):
        group_by = [group_by]

    timeframe = parse_timeframe(block["timeframe"]) if block.get("timeframe") else None

    return {"steps": steps, "group_by": [str(f) for f in group_by], "timeframe": timeframe}


def load_rule_file(path: str) -> SigmaRule:
    """Load and parse a single Sigma YAML file."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SigmaRuleError(f"Invalid YAML in {path}: {exc}") from exc
    return parse_rule(data, source_path=path, raw_yaml=text)


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "sigma-rule"


def _field_specs(selection: Any) -> List[str]:
    """Collect the field names of a selection, for evidence reporting."""
    specs: List[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key.lower() == "condition":
                    continue
                if isinstance(value, (dict, list)):
                    walk(value)
                else:
                    specs.append(str(key))
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(selection)
    return specs
