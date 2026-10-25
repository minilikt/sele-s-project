"""
Correlation engine for the SIEM backend.

Groups related alerts into Incidents, builds timelines, detects attack chains,
and maps MITRE ATT&CK techniques.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set

from models import Alert, Incident


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_ts(ts) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    return datetime.fromisoformat(str(ts)).replace(tzinfo=timezone.utc)


_SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _worst_severity(severities: List[str]) -> str:
    """Return the highest severity from a list."""
    return max(severities, key=lambda s: _SEVERITY_ORDER.get(s, 0), default="Medium")


class CorrelationEngine:
    """
    Correlate alerts into incidents by detecting attack chains and grouping
    related activity.
    """

    def __init__(
        self,
        alerts: List[Alert],
        events: list | None = None,
        *,
        time_window_minutes: int = 60,
    ):
        self.alerts = alerts
        self.events = events or []
        self.window = timedelta(minutes=time_window_minutes)

    # ── Public entry point ────────────────────────────────────────────────

    def correlate(self) -> List[Dict[str, Any]]:
        """Run all correlation patterns and return incident dicts."""
        incidents: List[Dict[str, Any]] = []
        used_alert_ids: Set[int] = set()

        # Run specific chains first (more specific = higher priority)
        for chain_fn in (
            self._credential_compromise_chain,
            self._persistence_chain,
        ):
            for inc in chain_fn():
                inc_alert_ids = set(json.loads(inc["alert_ids"]))
                if not inc_alert_ids & used_alert_ids:
                    incidents.append(inc)
                    used_alert_ids |= inc_alert_ids

        # General correlation for remaining alerts
        remaining = [a for a in self.alerts if a.id not in used_alert_ids]
        for inc in self._general_correlation(remaining):
            inc_alert_ids = set(json.loads(inc["alert_ids"]))
            if not inc_alert_ids & used_alert_ids:
                incidents.append(inc)
                used_alert_ids |= inc_alert_ids

        return incidents

    # ── Chain 1: Credential Compromise ────────────────────────────────────

    def _credential_compromise_chain(self) -> List[Dict[str, Any]]:
        """
        Brute-force alerts + successful-login alert + any subsequent suspicious
        activity from the same account.
        """
        incidents: List[Dict[str, Any]] = []

        brute_alerts = [a for a in self.alerts if a.rule_id in ("BRUTE_FORCE_001", "BRUTE_FORCE_002")]
        if not brute_alerts:
            return incidents

        # Index all alerts by account extracted from evidence
        account_alerts: Dict[str, List[Alert]] = {}
        for a in self.alerts:
            acct = self._extract_account(a)
            if acct:
                account_alerts.setdefault(acct, []).append(a)

        seen_accounts: Set[str] = set()
        for ba in brute_alerts:
            acct = self._extract_account(ba)
            if not acct or acct in seen_accounts:
                continue
            seen_accounts.add(acct)

            related = account_alerts.get(acct, [])
            if len(related) < 2:
                continue

            related.sort(key=lambda a: _parse_ts(a.created_at))
            alert_ids = [a.id for a in related]
            timeline = self._build_timeline(related)
            techniques = self._collect_techniques(related)

            incidents.append({
                "title": f"Credential Compromise Chain — {acct}",
                "description": (
                    f"A credential-based attack chain targeting account '{acct}' "
                    f"was detected. {len(related)} related alerts were correlated, "
                    f"starting with brute-force activity."
                ),
                "severity": _worst_severity([a.severity for a in related]),
                "status": "Open",
                "alert_ids": json.dumps(alert_ids),
                "timeline": json.dumps(timeline),
                "mitre_techniques": json.dumps(techniques),
                "investigation_notes": None,
                "created_at": _utcnow(),
                "updated_at": _utcnow(),
            })
        return incidents

    # ── Chain 2: Persistence ──────────────────────────────────────────────

    def _persistence_chain(self) -> List[Dict[str, Any]]:
        """
        Account creation + privilege escalation + scheduled-task creation.
        """
        incidents: List[Dict[str, Any]] = []

        acct_create = [a for a in self.alerts if a.rule_id == "ACCOUNT_MANIP_001"]
        priv_esc = [a for a in self.alerts if a.rule_id == "PRIV_ESC_001"]
        sched = [a for a in self.alerts if a.rule_id == "PERSIST_001"]

        if not acct_create:
            return incidents

        # Try to combine
        chain: List[Alert] = []
        chain.extend(acct_create)
        chain.extend(priv_esc)
        chain.extend(sched)

        if len(chain) < 2:
            return incidents

        chain.sort(key=lambda a: _parse_ts(a.created_at))
        alert_ids = [a.id for a in chain]
        timeline = self._build_timeline(chain)
        techniques = self._collect_techniques(chain)

        incidents.append({
            "title": "Persistence Chain — Account Creation + Privilege Escalation",
            "description": (
                f"A persistence chain was detected involving account creation, "
                f"privilege escalation, and/or scheduled task creation. "
                f"{len(chain)} alerts correlated."
            ),
            "severity": _worst_severity([a.severity for a in chain]),
            "status": "Open",
            "alert_ids": json.dumps(alert_ids),
            "timeline": json.dumps(timeline),
            "mitre_techniques": json.dumps(techniques),
            "investigation_notes": None,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
        })
        return incidents

    # ── General Correlation ───────────────────────────────────────────────

    def _general_correlation(self, alerts: List[Alert]) -> List[Dict[str, Any]]:
        """
        Group remaining alerts that share the same account within the time
        window.
        """
        incidents: List[Dict[str, Any]] = []
        if not alerts:
            return incidents

        by_account: Dict[str, List[Alert]] = {}
        for a in alerts:
            acct = self._extract_account(a) or "unknown"
            by_account.setdefault(acct, []).append(a)

        for acct, group in by_account.items():
            if len(group) < 2:
                continue
            group.sort(key=lambda a: _parse_ts(a.created_at))
            # Check if they fall within the time window
            first_ts = _parse_ts(group[0].created_at)
            last_ts = _parse_ts(group[-1].created_at)
            if last_ts - first_ts > self.window:
                continue
            alert_ids = [a.id for a in group]
            timeline = self._build_timeline(group)
            techniques = self._collect_techniques(group)
            incidents.append({
                "title": f"Correlated Alerts — {acct}",
                "description": (
                    f"{len(group)} alerts for account '{acct}' were detected "
                    f"within a {int(self.window.total_seconds() // 60)}-minute window."
                ),
                "severity": _worst_severity([a.severity for a in group]),
                "status": "Open",
                "alert_ids": json.dumps(alert_ids),
                "timeline": json.dumps(timeline),
                "mitre_techniques": json.dumps(techniques),
                "investigation_notes": None,
                "created_at": _utcnow(),
                "updated_at": _utcnow(),
            })
        return incidents

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_account(alert: Alert) -> str | None:
        try:
            ev = json.loads(alert.evidence) if isinstance(alert.evidence, str) else alert.evidence
            return ev.get("account")
        except Exception:
            return None

    @staticmethod
    def _build_timeline(alerts: List[Alert]) -> List[Dict[str, str]]:
        timeline: List[Dict[str, str]] = []
        for a in alerts:
            timeline.append({
                "time": _parse_ts(a.created_at).isoformat(),
                "alert_id": a.id,
                "rule": a.rule_name,
                "severity": a.severity,
                "description": a.description[:200],
            })
        return timeline

    @staticmethod
    def _collect_techniques(alerts: List[Alert]) -> List[Dict[str, str]]:
        seen: Set[str] = set()
        techniques: List[Dict[str, str]] = []
        for a in alerts:
            tid = a.mitre_technique_id
            if tid and tid not in seen:
                seen.add(tid)
                techniques.append({
                    "id": tid,
                    "name": a.mitre_technique_name or "",
                    "tactic": a.mitre_tactic or "",
                })
        return techniques
