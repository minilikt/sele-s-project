"""Risk scoring: per-finding score, aggregation and levels."""

from __future__ import annotations

import pytest

from risk_engine import (
    aggregate_score,
    asset_risk,
    domain_risk,
    rank_findings,
    risk_level_for,
    risk_score_for,
)


def test_severity_ordering():
    critical = risk_score_for("Critical", "Internet", 0.95)
    high = risk_score_for("High", "Internet", 0.95)
    medium = risk_score_for("Medium", "Internet", 0.95)
    low = risk_score_for("Low", "Internet", 0.95)
    assert critical > high > medium > low


def test_exposure_reduces_score():
    internet = risk_score_for("High", "Internet", 0.9)
    internal = risk_score_for("High", "Internal", 0.9)
    local = risk_score_for("High", "Local", 0.9)
    assert internet > internal > local


def test_confidence_changes_score_and_is_clamped():
    low = risk_score_for("High", "Internet", 0.1)
    high = risk_score_for("High", "Internet", 0.9)
    assert low < high
    assert risk_score_for("High", "Internet", -5) == risk_score_for("High", "Internet", 0.0)
    assert risk_score_for("High", "Internet", 5) == risk_score_for("High", "Internet", 1.0)


def test_scores_stay_in_range():
    assert 0 <= risk_score_for("Critical", "Internet", 1.0) <= 100
    assert risk_score_for("Unknown", "Unknown", 0.5) >= 0


def test_rank_findings_sorts_descending():
    ranked = rank_findings(
        [
            {"severity": "Low", "exposure": "Internet", "confidence": 0.8},
            {"severity": "Critical", "exposure": "Internet", "confidence": 0.9},
            {"severity": "Medium", "exposure": "Internet", "confidence": 0.8},
        ]
    )
    assert [f["severity"] for f in ranked] == ["Critical", "Medium", "Low"]


def test_aggregate_empty_is_zero():
    assert aggregate_score([]) == 0.0


def test_single_finding_is_damped_not_saturated():
    assert aggregate_score([{"risk_score": 50.0}]) == 44.0
    assert aggregate_score([{"risk_score": 100.0}]) == 84.0
    assert aggregate_score([{"risk_score": 100.0}]) < 100.0


def test_many_critical_findings_score_higher_than_one():
    one = aggregate_score([{"risk_score": 95.0}])
    many = aggregate_score([{"risk_score": 95.0} for _ in range(50)])
    assert one < many
    assert many <= 100.0
    assert many >= 95.0


def test_aggregate_is_capped_and_weights_worst_finding():
    mostly_low = [{"risk_score": 25.0} for _ in range(20)]
    one_critical = [{"risk_score": 95.0}] + [{"risk_score": 10.0} for _ in range(20)]
    assert aggregate_score(mostly_low) < aggregate_score(one_critical)
    assert 0 <= aggregate_score(mostly_low) <= 100
    assert 0 <= aggregate_score(one_critical) <= 100


def test_aggregate_does_not_reach_100_for_lows():
    # The old sum-and-clip formula returned 100 for four low findings.
    assert aggregate_score([{"risk_score": 25.0}] * 10) < 60


def test_risk_levels():
    assert risk_level_for(100) == "Critical"
    assert risk_level_for(75) == "Critical"
    assert risk_level_for(74.9) == "High"
    assert risk_level_for(50) == "High"
    assert risk_level_for(49.9) == "Medium"
    assert risk_level_for(25) == "Medium"
    assert risk_level_for(24.9) == "Low"
    assert risk_level_for(5) == "Low"
    assert risk_level_for(4.9) == "Minimal"
    assert risk_level_for(0) == "Minimal"


def _finding(severity="High", status="Open", host="www.acme-lab.local"):
    return {
        "asset_hostname": host,
        "severity": severity,
        "exposure": "Internet",
        "confidence": 0.9,
        "status": status,
        "title": "t",
    }


def test_resolved_findings_are_excluded():
    open_only = domain_risk([_finding("Critical", "Open")])
    with_resolved = domain_risk(
        [_finding("Critical", "Open")] + [_finding("Critical", "Resolved") for _ in range(5)]
    )
    assert with_resolved["domain_risk_score"] == open_only["domain_risk_score"]
    assert with_resolved["total_findings"] == 1
    assert with_resolved["resolved_findings"] == 5
    assert with_resolved["critical"] == 1


def test_resolved_only_has_zero_risk():
    result = domain_risk([_finding("Critical", "Resolved")])
    assert result["domain_risk_score"] == 0.0
    assert result["total_findings"] == 0
    assert result["top_findings"] == []


def test_asset_risk_scopes_to_host_and_open_findings():
    findings = [
        _finding("Critical", "Open", "a.acme-lab.local"),
        _finding("Low", "Open", "a.acme-lab.local"),
        _finding("Critical", "Resolved", "a.acme-lab.local"),
        _finding("Critical", "Open", "b.acme-lab.local"),
    ]
    result = asset_risk("a.acme-lab.local", findings)
    assert result["finding_count"] == 2
    assert result["critical"] == 1
    assert result["risk_score"] > 0
    assert result["hostname"] == "a.acme-lab.local"
    assert asset_risk("missing", findings)["risk_score"] == 0.0
