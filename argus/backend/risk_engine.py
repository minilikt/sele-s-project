"""
Risk scoring engine for ARGUS.

Computes a 0–100 risk score for each finding from severity, exposure and
confidence, and rolls findings up into per-asset and per-domain risk.

Severity is illustrative and should be re-ranked by an analyst based on the
actual business context.
"""

from __future__ import annotations

from typing import Any, Dict, List

_SEVERITY_WEIGHT = {
    "Critical": 100.0,
    "High": 75.0,
    "Medium": 50.0,
    "Low": 25.0,
    "Info": 5.0,
}

_EXPOSURE_WEIGHT = {
    "Internet": 1.0,
    "Internal": 0.55,
    "Local": 0.25,
    "None": 0.1,
}


def risk_score_for(severity: str, exposure: str = "Internet", confidence: float = 0.8) -> float:
    sev = _SEVERITY_WEIGHT.get(severity, 25.0)
    exp = _EXPOSURE_WEIGHT.get(exposure, 0.5)
    conf = max(0.0, min(1.0, confidence))
    score = sev * exp * (0.5 + 0.5 * conf)
    return round(min(100.0, max(0.0, score)), 1)


def rank_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Attach a computed risk_score to each finding and sort by risk."""
    ranked = []
    for f in findings:
        f = dict(f)
        f["risk_score"] = risk_score_for(f.get("severity", "Info"),
                                         f.get("exposure", "Internet"),
                                         f.get("confidence", 0.8))
        ranked.append(f)
    ranked.sort(key=lambda x: x["risk_score"], reverse=True)
    return ranked


def domain_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate risk across all findings into a domain-level summary."""
    ranked = rank_findings(findings)
    total = sum(f["risk_score"] for f in ranked)
    count = len(ranked)
    avg = round(total / count, 1) if count else 0.0
    if avg >= 60:
        level = "High"
    elif avg >= 35:
        level = "Medium"
    elif avg >= 10:
        level = "Low"
    else:
        level = "Low"
    return {
        "domain_risk_score": round(min(100.0, total), 1),
        "average_risk": avg,
        "risk_level": level,
        "total_findings": count,
        "critical": sum(1 for f in ranked if f["severity"] == "Critical"),
        "high": sum(1 for f in ranked if f["severity"] == "High"),
        "medium": sum(1 for f in ranked if f["severity"] == "Medium"),
        "low": sum(1 for f in ranked if f["severity"] == "Low"),
        "top_findings": ranked[:10],
    }


def asset_risk(asset_hostname: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    mine = [f for f in findings if f.get("asset_hostname") == asset_hostname]
    ranked = rank_findings(mine)
    total = sum(f["risk_score"] for f in ranked)
    return {
        "hostname": asset_hostname,
        "risk_score": round(total, 1),
        "finding_count": len(ranked),
        "critical": sum(1 for f in ranked if f["severity"] == "Critical"),
        "high": sum(1 for f in ranked if f["severity"] == "High"),
    }
