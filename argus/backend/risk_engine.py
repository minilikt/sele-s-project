"""
Risk scoring engine for ARGUS.

Two numbers are computed:

* **Finding risk** (0-100): severity x exposure x confidence. A critical
  internet-facing issue found with high confidence scores near 100; the same
  issue behind an internal-only control scores about half.

* **Aggregate risk** (0-100): 80% of the weighted mean of the five highest open
  findings (weights 5:4:3:2:1) plus a breadth term capped at 20 for having many
  open issues. A single critical finding therefore scores ~84, not 100; volume
  alone can never manufacture a critical rating. Resolved findings are excluded.

Severity is illustrative and should be re-ranked by an analyst based on the
actual business context.
"""

from __future__ import annotations

import math
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

_TOP_N_WEIGHTS = (5, 4, 3, 2, 1)
_DEPTH_WEIGHT = 0.8
_BREADTH_SCALE = 4.0
_BREADTH_CAP = 20.0

_RISK_LEVELS = (
    (75.0, "Critical"),
    (50.0, "High"),
    (25.0, "Medium"),
    (5.0, "Low"),
    (0.0, "Minimal"),
)


def is_open(finding: Dict[str, Any]) -> bool:
    return str(finding.get("status", "Open")).lower() != "resolved"


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


def aggregate_score(ranked_findings: List[Dict[str, Any]]) -> float:
    """Score 0-100 from already-ranked findings (highest first).

    Depth is deliberately damped to 80% of the weighted top-5 mean. Without
    that headroom a single critical finding (97.5) would already clip at 100,
    and the number would stop distinguishing "one severe issue" from
    "twenty severe issues". Breadth is capped at 20 so volume alone never
    manufactures a critical rating.
    """
    scores = [float(f["risk_score"]) for f in ranked_findings]
    if not scores:
        return 0.0

    top = scores[: len(_TOP_N_WEIGHTS)]
    weights = _TOP_N_WEIGHTS[: len(top)]
    depth = sum(score * weight for score, weight in zip(top, weights)) / sum(weights)
    breadth = min(_BREADTH_CAP, _BREADTH_SCALE * math.log2(1 + len(scores)))
    return round(min(100.0, depth * _DEPTH_WEIGHT + breadth), 1)


def risk_level_for(score: float) -> str:
    for threshold, label in _RISK_LEVELS:
        if score >= threshold:
            return label
    return "Minimal"


def domain_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate risk across all *open* findings into a domain summary."""
    open_findings = [f for f in findings if is_open(f)]
    resolved = len(findings) - len(open_findings)
    ranked = rank_findings(open_findings)
    score = aggregate_score(ranked)
    average = round(sum(f["risk_score"] for f in ranked) / len(ranked), 1) if ranked else 0.0

    return {
        "domain_risk_score": score,
        "average_risk": average,
        "risk_level": risk_level_for(score),
        "total_findings": len(ranked),
        "resolved_findings": resolved,
        "critical": sum(1 for f in ranked if f["severity"] == "Critical"),
        "high": sum(1 for f in ranked if f["severity"] == "High"),
        "medium": sum(1 for f in ranked if f["severity"] == "Medium"),
        "low": sum(1 for f in ranked if f["severity"] == "Low"),
        "top_findings": ranked[:10],
    }


def asset_risk(asset_hostname: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    mine = [f for f in findings if f.get("asset_hostname") == asset_hostname and is_open(f)]
    ranked = rank_findings(mine)
    return {
        "hostname": asset_hostname,
        "risk_score": aggregate_score(ranked),
        "finding_count": len(ranked),
        "critical": sum(1 for f in ranked if f["severity"] == "Critical"),
        "high": sum(1 for f in ranked if f["severity"] == "High"),
        "top_finding": ranked[0]["title"] if ranked else None,
    }
