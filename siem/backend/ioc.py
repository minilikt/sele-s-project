"""
IoC (Indicators of Compromise) enrichment for SENTINEL SIEM.

A small, built-in threat-intelligence store with reputation lookup. It matches
observables (IPs, hashes, domains) found in alerts and events against known
indicators and returns a reputation verdict. Fully deterministic — no external
API in this first version.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from models import Alert

# ── Built-in threat intelligence ──────────────────────────────────────────────

# Known-bad hashes (deterministic, for the lab — replace with a real feed)
_KNOWN_MALICIOUS_HASHES: Dict[str, Dict[str, Any]] = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {
        "name": "Mimikatz (lab sample)",
        "family": "Credential Dumping",
        "verdict": "malicious",
        "source": "local-lab-feed",
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR test file",
        "family": "AV Test Signature",
        "verdict": "malicious",
        "source": "local-lab-feed",
    },
    "5df19dfe29e9b0ed3c45ad4db68d95e4": {
        "name": "PowerShell download cradle",
        "family": "Execution",
        "verdict": "suspicious",
        "source": "local-lab-feed",
    },
}

_KNOWN_BAD_IPS = {
    "45.77.12.204": {"verdict": "suspicious", "source": "scan-lab", "name": "Observed brute-force source"},
    "185.220.101.34": {"verdict": "suspicious", "source": "scan-lab", "name": "Observed scanning source"},
    "91.219.236.88": {"verdict": "malicious", "source": "scan-lab", "name": "Known C2 (lab)"},
}

_KNOWN_BAD_DOMAINS = {
    "evil.example.com": {"verdict": "malicious", "source": "local-lab-feed"},
    "pwn.example.net": {"verdict": "malicious", "source": "local-lab-feed"},
}


def _normalise_hash(value: str) -> str:
    return value.lower().strip()


def _classify(value: str, value_type: str) -> Dict[str, Any]:
    if value_type == "hash":
        h = _normalise_hash(value)
        rec = _KNOWN_MALICIOUS_HASHES.get(h)
        if rec:
            return {"verdict": rec["verdict"], "source": rec["source"], "name": rec.get("name", ""), "family": rec.get("family", "")}
        return {"verdict": "clean", "source": "no-match", "name": "Hash not found in local feed"}
    if value_type == "ip":
        rec = _KNOWN_BAD_IPS.get(value.strip())
        if rec:
            return {"verdict": rec["verdict"], "source": rec["source"], "name": rec.get("name", "")}
        return {"verdict": "clean", "source": "no-match", "name": "IP not found in local feed"}
    if value_type == "domain":
        rec = _KNOWN_BAD_DOMAINS.get(value.strip().lower())
        if rec:
            return {"verdict": rec["verdict"], "source": rec["source"], "name": ""}
        return {"verdict": "clean", "source": "no-match", "name": "Domain not found in local feed"}
    return {"verdict": "unknown", "source": "unknown-type", "name": "Unsupported observable type"}


def detect_type(value: str) -> str:
    v = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{32}", v):
        return "hash"
    if re.fullmatch(r"[0-9a-fA-F]{40}", v):
        return "hash"
    if re.fullmatch(r"[0-9a-fA-F]{64}", v):
        return "hash"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
        return "ip"
    if re.search(r"\.[a-z]{2,}$", v, re.IGNORECASE):
        return "domain"
    return "unknown"


def lookup(value: str, value_type: Optional[str] = None) -> Dict[str, Any]:
    t = (value_type or detect_type(value)).lower()
    verdict = _classify(value, t)
    return {
        "value": value.strip(),
        "type": t,
        "verdict": verdict["verdict"],
        "source": verdict["source"],
        "name": verdict.get("name", ""),
        "family": verdict.get("family", ""),
    }


_HASH_RE = re.compile(r"(?i)(?:sha256|sha1|md5)[=:\s]*([0-9a-f]{32,64})|([0-9a-f]{64})|([0-9a-f]{32})")


def extract_observables_from_alert(alert: Alert) -> List[str]:
    """Pull candidate hashes/IPs from an alert's evidence."""
    out: List[str] = []
    try:
        evidence = json.loads(alert.evidence) if isinstance(alert.evidence, str) else alert.evidence
    except Exception:
        evidence = {}
    # IPs from evidence
    source_ips = evidence.get("source_ips") if isinstance(evidence, dict) else None
    if isinstance(source_ips, list):
        out.extend(source_ips)
    # hashes from raw text
    raw = json.dumps(evidence)
    for m in _HASH_RE.finditer(raw):
        token = next((g for g in m.groups() if g), None)
        if token:
            out.append(token)
    return list(dict.fromkeys(out))


def enrich_alert(db, alert_id: int) -> Dict[str, Any]:
    alert = db.get(Alert, alert_id)
    if alert is None:
        return {"error": "Alert not found"}
    observables = extract_observables_from_alert(alert)
    results = [lookup(o) for o in observables]
    hits = [r for r in results if r["verdict"] in ("malicious", "suspicious")]
    return {
        "alert_id": alert_id,
        "rule_name": alert.rule_name,
        "observables": results,
        "hits": hits,
        "risk_level": "malicious" if any(r["verdict"] == "malicious" for r in hits)
        else ("suspicious" if hits else "clean"),
    }
