"""
Deterministic AI assistant for ARGUS.

Summarises the organisation's attack surface and recommends remediation steps
based strictly on the assets, findings and risk scores stored in the database.
It never invents findings and never takes action on its own.

A paid LLM can be dropped in behind the same interface later.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from models import Asset, Finding, Scan
from risk_engine import domain_risk, rank_findings

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _finding_dict(f: Finding) -> Dict[str, Any]:
    return {
        "id": f.id,
        "asset_hostname": f.asset_hostname,
        "category": f.category,
        "title": f.title,
        "detail": f.detail,
        "severity": f.severity,
        "risk_score": f.risk_score,
        "exposure": f.exposure,
        "confidence": f.confidence,
        "recommendation": f.recommendation,
        "status": f.status,
        "first_seen": f.first_seen,
    }


def _asset_dict(a: Asset) -> Dict[str, Any]:
    return {
        "id": a.id,
        "hostname": a.hostname,
        "asset_type": a.asset_type,
        "ip": a.ip,
        "status": a.status,
        "first_seen": a.first_seen,
        "last_seen": a.last_seen,
        "is_new": a.is_new,
        "http_status": a.http_status,
        "is_web": a.is_web,
    }


def posture_summary(assets: List[Asset], findings: List[Finding]) -> Dict[str, Any]:
    """Generate a deterministic summary of the current attack surface."""
    f_dicts = [_finding_dict(f) for f in findings]
    risk = domain_risk(f_dicts)
    open_findings = [f for f in f_dicts if f["status"] != "Resolved"]
    new_assets = [a for a in assets if a.is_new]

    return {
        "summary": (
            f"ARGUS currently tracks {len(assets)} asset(s). "
            f"{len(open_findings)} open finding(s) exist, with "
            f"{risk['critical']} critical and {risk['high']} high severity. "
            f"The domain risk score is {risk['domain_risk_score']} / 100 "
            f"({risk['risk_level']})."
        ),
        "risk": risk,
        "new_assets": [_asset_dict(a) for a in new_assets],
        "top_recommendations": _recommendations(open_findings),
    }


def _recommendations(findings: List[Dict[str, Any]]) -> List[str]:
    """Turn top findings into concrete, evidence-based recommendations."""
    recs: List[str] = []
    seen: set = set()
    for f in sorted(findings, key=lambda x: x["risk_score"], reverse=True):
        key = f["recommendation"]
        if key in seen:
            continue
        seen.add(key)
        recs.append(f"{f['asset_hostname']}: {f['recommendation']}")
        if len(recs) >= 6:
            break
    return recs


def answer_question(question: str, assets: List[Asset], findings: List[Finding],
                    scan: Scan | None = None) -> Dict[str, Any]:
    """Answer a free-form question from stored data."""
    q = question.lower()
    f_dicts = [_finding_dict(f) for f in findings]
    risk = domain_risk(f_dicts)

    if any(w in q for w in ["risk", "posture", "score", "how bad"]):
        return {
            "answer": (
                f"Overall domain risk is {risk['risk_level']} (score "
                f"{risk['domain_risk_score']} / 100) across {risk['total_findings']} "
                f"finding(s): {risk['critical']} critical, {risk['high']} high, "
                f"{risk['medium']} medium, {risk['low']} low."
            ),
            "sections": [{"title": "Top findings", "content": "\n".join(
                f"- [{f['severity']}] {f['title']} — {f['asset_hostname']} (risk {f['risk_score']})"
                for f in risk["top_findings"][:8]
            )}],
        }
    if any(w in q for w in ["new", "changed", "change", "added"]):
        new = [a for a in assets if a.is_new]
        return {
            "answer": (
                f"{len(new)} newly discovered asset(s)." if new
                else "No new assets detected since the last scan."
            ),
            "sections": [{"title": "New assets", "content": "\n".join(
                f"- {a.hostname} (first seen {a.first_seen})" for a in new
            ) or "None"}],
        }
    if any(w in q for w in ["critical", "high", "worst", "urgent"]):
        high = [f for f in f_dicts if f["severity"] in ("Critical", "High") and f["status"] != "Resolved"]
        return {
            "answer": f"{len(high)} critical/high finding(s) require attention.",
            "sections": [{"title": "Critical / High findings", "content": "\n".join(
                f"- {f['title']} on {f['asset_hostname']}: {f['recommendation']}"
                for f in sorted(high, key=lambda x: x["risk_score"], reverse=True)[:10]
            ) or "None"}],
        }
    if any(w in q for w in ["recommend", "fix", "remediate", "action", "do"]):
        return {
            "answer": "Prioritised remediation recommendations based on stored findings:",
            "sections": [{"title": "Recommendations", "content": "\n".join(
                f"- {r}" for r in _recommendations([f for f in f_dicts if f["status"] != "Resolved"])
            ) or "No open findings."}],
        }
    if any(w in q for w in ["report", "summary"]):
        return generate_report(assets, findings, scan)
    return {
        "answer": posture_summary(assets, findings)["summary"],
        "sections": [{"title": "Overview", "content": f"{len(assets)} assets tracked."}],
    }


def generate_report(assets: List[Asset], findings: List[Finding], scan: Scan | None = None) -> Dict[str, Any]:
    """Generate a markdown security posture report."""
    f_dicts = [_finding_dict(f) for f in findings]
    risk = domain_risk(f_dicts)
    open_f = [f for f in f_dicts if f["status"] != "Resolved"]
    new_assets = [a for a in assets if a.is_new]

    lines = [
        "# ARGUS — Attack Surface Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Assets tracked:** {len(assets)}",
        f"**Open findings:** {len(open_f)}",
        f"**Domain risk score:** {risk['domain_risk_score']} / 100 ({risk['risk_level']})",
        "",
        "## Risk Summary",
        "",
        f"- Critical: {risk['critical']}",
        f"- High: {risk['high']}",
        f"- Medium: {risk['medium']}",
        f"- Low: {risk['low']}",
        "",
        "## New Assets",
        "",
    ]
    if new_assets:
        lines.extend(f"- {a.hostname} (first seen {a.first_seen})" for a in new_assets)
    else:
        lines.append("- None")
    lines += ["", "## Open Findings (by risk)", ""]
    for f in sorted(open_f, key=lambda x: x["risk_score"], reverse=True)[:30]:
        lines.append(
            f"- [{f['severity']}] **{f['title']}** — {f['asset_hostname']} "
            f"(risk {f['risk_score']})\n  {f['detail']}\n  → {f['recommendation']}"
        )
    lines += ["", "## Recommended Actions", ""]
    for r in _recommendations(open_f):
        lines.append(f"- {r}")
    lines += [
        "",
        "> Generated by ARGUS. Findings should be validated by an analyst before action.",
    ]
    return {"report": "\n".join(lines), "summary": posture_summary(assets, findings)["summary"]}
