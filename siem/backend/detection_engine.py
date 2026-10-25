"""
Detection engine for the SIEM backend.

Implements configurable detection rules that analyse SecurityEvent records and
produce Alert objects when suspicious patterns are found.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from models import Alert, DetectionRule


# ── Helpers ───────────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts) -> datetime:
    """Normalise a timestamp (datetime or str) to a tz-aware datetime."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    return datetime.fromisoformat(str(ts)).replace(tzinfo=timezone.utc)


def _is_business_hours(ts: datetime) -> bool:
    """Return True if *ts* falls within 07:00 – 19:00 (inclusive)."""
    return 7 <= ts.hour < 19


def _raw(evt) -> Dict[str, Any]:
    """Extract raw_data as a dict."""
    if isinstance(evt.raw_data, dict):
        return evt.raw_data
    try:
        return json.loads(evt.raw_data)
    except Exception:
        return {}


# ── Base Rule ─────────────────────────────────────────────────────────────────

class BaseRule:
    """Abstract base for every detection rule."""

    RULE_ID: str = ""
    RULE_NAME: str = ""
    DESCRIPTION: str = ""
    SEVERITY: str = "Medium"
    MITRE_TACTIC: str = ""
    MITRE_TECHNIQUE_ID: str = ""
    MITRE_TECHNIQUE_NAME: str = ""
    DEFAULT_CONFIG: Dict[str, Any] = {}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config: Dict[str, Any] = {**self.DEFAULT_CONFIG, **(config or {})}

    def detect(self, events: list) -> List[Dict[str, Any]]:
        """Return a list of alert dicts.  Override in subclasses."""
        raise NotImplementedError

    def _make_alert(
        self,
        description: str,
        evidence: Any,
        event_ids: List[int],
        confidence: float = 0.8,
    ) -> Dict[str, Any]:
        return {
            "rule_id": self.RULE_ID,
            "rule_name": self.RULE_NAME,
            "severity": self.SEVERITY,
            "confidence": round(min(max(confidence, 0.0), 1.0), 2),
            "description": description,
            "evidence": json.dumps(evidence),
            "mitre_tactic": self.MITRE_TACTIC,
            "mitre_technique_id": self.MITRE_TECHNIQUE_ID,
            "mitre_technique_name": self.MITRE_TECHNIQUE_NAME,
            "status": "New",
            "created_at": _utcnow(),
            "event_ids": json.dumps(event_ids),
        }

    def to_rule_record(self) -> Dict[str, Any]:
        """Return a dict suitable for upserting into the DetectionRule table."""
        return {
            "id": self.RULE_ID,
            "name": self.RULE_NAME,
            "description": self.DESCRIPTION,
            "severity": self.SEVERITY,
            "enabled": True,
            "config": json.dumps(self.DEFAULT_CONFIG),
            "mitre_tactic": self.MITRE_TACTIC,
            "mitre_technique_id": self.MITRE_TECHNIQUE_ID,
            "mitre_technique_name": self.MITRE_TECHNIQUE_NAME,
            "created_at": _utcnow(),
        }


# ── Rule 1 – Brute Force ─────────────────────────────────────────────────────

class BruteForceRule(BaseRule):
    RULE_ID = "BRUTE_FORCE_001"
    RULE_NAME = "Brute Force Detection"
    DESCRIPTION = (
        "Detects N or more failed login attempts (Event ID 4625) for the same "
        "account within a configurable time window."
    )
    SEVERITY = "High"
    MITRE_TACTIC = "Credential Access"
    MITRE_TECHNIQUE_ID = "T1110"
    MITRE_TECHNIQUE_NAME = "Brute Force"
    DEFAULT_CONFIG = {"threshold": 5, "time_window_minutes": 10}

    def detect(self, events: list) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        threshold = self.config["threshold"]
        window = timedelta(minutes=self.config["time_window_minutes"])

        # Group 4625 events by account
        failed: Dict[str, list] = {}
        for e in events:
            if e.event_id == 4625:
                failed.setdefault(e.account, []).append(e)

        for account, acct_events in failed.items():
            acct_events.sort(key=lambda e: _parse_ts(e.timestamp))
            # Sliding-window check
            for i in range(len(acct_events)):
                window_events = [
                    ev for ev in acct_events[i:]
                    if _parse_ts(ev.timestamp) - _parse_ts(acct_events[i].timestamp) <= window
                ]
                if len(window_events) >= threshold:
                    ids = [ev.id for ev in window_events]
                    confidence = min(0.5 + 0.1 * (len(window_events) - threshold), 1.0)
                    source_ips = list({ev.source_ip for ev in window_events if ev.source_ip})
                    alerts.append(self._make_alert(
                        description=(
                            f"Brute force detected: {len(window_events)} failed logins "
                            f"for account '{account}' within "
                            f"{self.config['time_window_minutes']} minutes."
                        ),
                        evidence={
                            "account": account,
                            "failed_count": len(window_events),
                            "source_ips": source_ips,
                            "time_range": {
                                "start": _parse_ts(window_events[0].timestamp).isoformat(),
                                "end": _parse_ts(window_events[-1].timestamp).isoformat(),
                            },
                            "event_ids": ids,
                        },
                        event_ids=ids,
                        confidence=confidence,
                    ))
                    break  # One alert per account

        return alerts


# ── Rule 2 – Successful Login After Failures ─────────────────────────────────

class BruteForceSuccessRule(BaseRule):
    RULE_ID = "BRUTE_FORCE_002"
    RULE_NAME = "Successful Login After Failures"
    DESCRIPTION = (
        "Detects a successful login (Event ID 4624) preceded by multiple "
        "failed attempts for the same account, suggesting credential compromise."
    )
    SEVERITY = "Critical"
    MITRE_TACTIC = "Credential Access"
    MITRE_TECHNIQUE_ID = "T1110"
    MITRE_TECHNIQUE_NAME = "Brute Force"
    DEFAULT_CONFIG = {"min_failures": 3, "time_window_minutes": 15}

    def detect(self, events: list) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        window = timedelta(minutes=self.config["time_window_minutes"])
        min_fail = self.config["min_failures"]

        failed: Dict[str, list] = {}
        success: Dict[str, list] = {}
        for e in events:
            if e.event_id == 4625:
                failed.setdefault(e.account, []).append(e)
            elif e.event_id == 4624:
                success.setdefault(e.account, []).append(e)

        for account, successes in success.items():
            fails = failed.get(account, [])
            if len(fails) < min_fail:
                continue
            for s in successes:
                s_ts = _parse_ts(s.timestamp)
                preceding = [
                    f for f in fails
                    if s_ts - window <= _parse_ts(f.timestamp) <= s_ts
                ]
                if len(preceding) >= min_fail:
                    ids = [f.id for f in preceding] + [s.id]
                    confidence = min(0.7 + 0.05 * (len(preceding) - min_fail), 1.0)
                    alerts.append(self._make_alert(
                        description=(
                            f"Possible credential compromise: {len(preceding)} failed "
                            f"logins followed by successful login for account "
                            f"'{account}'."
                        ),
                        evidence={
                            "account": account,
                            "failed_count": len(preceding),
                            "success_event_id": s.id,
                            "success_time": s_ts.isoformat(),
                            "source_ips": list({
                                f.source_ip for f in preceding if f.source_ip
                            }),
                            "event_ids": ids,
                        },
                        event_ids=ids,
                        confidence=confidence,
                    ))
                    break  # One alert per account

        return alerts


# ── Rule 3 – Suspicious Account Creation ─────────────────────────────────────

class SuspiciousAccountCreationRule(BaseRule):
    RULE_ID = "ACCOUNT_MANIP_001"
    RULE_NAME = "Suspicious Account Creation"
    DESCRIPTION = (
        "Detects account creation (Event ID 4720) outside business hours "
        "(before 07:00 or after 19:00)."
    )
    SEVERITY = "High"
    MITRE_TACTIC = "Persistence"
    MITRE_TECHNIQUE_ID = "T1136"
    MITRE_TECHNIQUE_NAME = "Create Account"
    DEFAULT_CONFIG = {}

    def detect(self, events: list) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for e in events:
            if e.event_id == 4720:
                ts = _parse_ts(e.timestamp)
                if not _is_business_hours(ts):
                    raw = _raw(e)
                    alerts.append(self._make_alert(
                        description=(
                            f"Account '{e.account}' created outside business hours "
                            f"at {ts.strftime('%H:%M:%S')} on {ts.strftime('%Y-%m-%d')}."
                        ),
                        evidence={
                            "account": e.account,
                            "created_at": ts.isoformat(),
                            "hour": ts.hour,
                            "computer": e.computer_name,
                            "created_by": raw.get("creator", "unknown"),
                        },
                        event_ids=[e.id],
                        confidence=0.75,
                    ))
        return alerts


# ── Rule 4 – Privilege Escalation ─────────────────────────────────────────────

class PrivilegeEscalationRule(BaseRule):
    RULE_ID = "PRIV_ESC_001"
    RULE_NAME = "Privilege Escalation – New Account + Privilege Assignment"
    DESCRIPTION = (
        "Detects a new account creation (4720) followed by privilege "
        "assignment (4672) for the same account within a configurable window."
    )
    SEVERITY = "Critical"
    MITRE_TACTIC = "Privilege Escalation"
    MITRE_TECHNIQUE_ID = "T1078"
    MITRE_TECHNIQUE_NAME = "Valid Accounts"
    DEFAULT_CONFIG = {"time_window_minutes": 30}

    def detect(self, events: list) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        window = timedelta(minutes=self.config["time_window_minutes"])

        creations: Dict[str, list] = {}
        privs: Dict[str, list] = {}
        for e in events:
            if e.event_id == 4720:
                creations.setdefault(e.account, []).append(e)
            elif e.event_id == 4672:
                privs.setdefault(e.account, []).append(e)

        for account, creates in creations.items():
            priv_list = privs.get(account, [])
            for c in creates:
                c_ts = _parse_ts(c.timestamp)
                following = [
                    p for p in priv_list
                    if c_ts <= _parse_ts(p.timestamp) <= c_ts + window
                ]
                if following:
                    ids = [c.id] + [p.id for p in following]
                    alerts.append(self._make_alert(
                        description=(
                            f"Privilege escalation chain: account '{account}' was "
                            f"created and assigned special privileges within "
                            f"{self.config['time_window_minutes']} minutes."
                        ),
                        evidence={
                            "account": account,
                            "creation_time": c_ts.isoformat(),
                            "privilege_times": [
                                _parse_ts(p.timestamp).isoformat() for p in following
                            ],
                            "event_ids": ids,
                        },
                        event_ids=ids,
                        confidence=0.9,
                    ))
                    break
        return alerts


# ── Rule 5 – Suspicious PowerShell ───────────────────────────────────────────

class SuspiciousPowerShellRule(BaseRule):
    RULE_ID = "EXEC_001"
    RULE_NAME = "Suspicious PowerShell Execution"
    DESCRIPTION = (
        "Detects process creation (Event ID 4688) involving powershell.exe "
        "with suspicious command-line patterns such as encoded commands, "
        "execution policy bypass, or download cradles."
    )
    SEVERITY = "High"
    MITRE_TACTIC = "Execution"
    MITRE_TECHNIQUE_ID = "T1059.001"
    MITRE_TECHNIQUE_NAME = "PowerShell"
    DEFAULT_CONFIG = {}

    _SUSPICIOUS_PATTERNS = [
        "-enc", "-encodedcommand",
        "bypass",
        "downloadstring", "invoke-webrequest",
        "invoke-expression", "iex",
        "-windowstyle hidden", "-w hidden",
    ]

    def detect(self, events: list) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for e in events:
            if e.event_id != 4688:
                continue
            raw = _raw(e)
            cmd = raw.get("command_line", raw.get("description", "")).lower()
            process = raw.get("process_name", "").lower()
            if "powershell" not in process and "powershell" not in cmd:
                continue
            matched = [p for p in self._SUSPICIOUS_PATTERNS if p in cmd]
            if not matched:
                continue
            confidence = min(0.5 + 0.15 * len(matched), 1.0)
            alerts.append(self._make_alert(
                description=(
                    f"Suspicious PowerShell execution on {e.computer_name} by "
                    f"account '{e.account}'. Matched patterns: {matched}"
                ),
                evidence={
                    "account": e.account,
                    "computer": e.computer_name,
                    "command_line": raw.get("command_line", ""),
                    "matched_patterns": matched,
                    "timestamp": _parse_ts(e.timestamp).isoformat(),
                    "event_ids": [e.id],
                },
                event_ids=[e.id],
                confidence=confidence,
            ))
        return alerts


# ── Rule 6 – Suspicious Scheduled Task ───────────────────────────────────────

class SuspiciousScheduledTaskRule(BaseRule):
    RULE_ID = "PERSIST_001"
    RULE_NAME = "Suspicious Scheduled Task Creation"
    DESCRIPTION = (
        "Detects scheduled task creation (Event ID 4698) outside business hours."
    )
    SEVERITY = "Medium"
    MITRE_TACTIC = "Persistence"
    MITRE_TECHNIQUE_ID = "T1053.005"
    MITRE_TECHNIQUE_NAME = "Scheduled Task"
    DEFAULT_CONFIG = {}

    def detect(self, events: list) -> List[Dict[str, Any]]:
        alerts: List[Dict[str, Any]] = []
        for e in events:
            if e.event_id == 4698:
                ts = _parse_ts(e.timestamp)
                if not _is_business_hours(ts):
                    raw = _raw(e)
                    alerts.append(self._make_alert(
                        description=(
                            f"Scheduled task created outside business hours at "
                            f"{ts.strftime('%H:%M:%S')} by account '{e.account}' "
                            f"on {e.computer_name}."
                        ),
                        evidence={
                            "account": e.account,
                            "computer": e.computer_name,
                            "task_name": raw.get("task_name", "unknown"),
                            "created_at": ts.isoformat(),
                            "hour": ts.hour,
                            "event_ids": [e.id],
                        },
                        event_ids=[e.id],
                        confidence=0.65,
                    ))
        return alerts


# ── Rules Engine ──────────────────────────────────────────────────────────────

ALL_RULE_CLASSES = [
    BruteForceRule,
    BruteForceSuccessRule,
    SuspiciousAccountCreationRule,
    PrivilegeEscalationRule,
    SuspiciousPowerShellRule,
    SuspiciousScheduledTaskRule,
]


class RulesEngine:
    """Load detection rules and run them against a batch of events."""

    def __init__(self, rule_configs: Optional[Dict[str, Dict[str, Any]]] = None):
        """
        Args:
            rule_configs: Mapping of rule_id → {enabled: bool, config: dict}.
                          If *None*, every rule uses its defaults.
        """
        self.rules: List[BaseRule] = []
        configs = rule_configs or {}
        for cls in ALL_RULE_CLASSES:
            cfg_entry = configs.get(cls.RULE_ID, {})
            enabled = cfg_entry.get("enabled", True)
            if not enabled:
                continue
            config = cfg_entry.get("config")
            if isinstance(config, str):
                config = json.loads(config)
            self.rules.append(cls(config=config))

    def run_all_rules(self, events: list) -> List[Dict[str, Any]]:
        """Run every enabled rule against *events* and return alert dicts."""
        all_alerts: List[Dict[str, Any]] = []
        for rule in self.rules:
            all_alerts.extend(rule.detect(events))
        return all_alerts

    @staticmethod
    def get_default_rule_records() -> List[Dict[str, Any]]:
        """Return default DetectionRule dicts for seeding the database."""
        return [cls().to_rule_record() for cls in ALL_RULE_CLASSES]
