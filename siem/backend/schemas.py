"""
Pydantic schemas for request / response validation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, List, Optional

from pydantic import BaseModel, Field


# ── SecurityEvent ─────────────────────────────────────────────────────────────

class EventIngest(BaseModel):
    """Payload for a single event during ingestion."""
    timestamp: str
    event_id: int
    source: str = "Windows Security"
    account: str
    source_ip: Optional[str] = None
    computer_name: str = "WORKSTATION-01"
    event_type: str = "Authentication"
    severity: str = "Low"
    raw_data: Optional[dict[str, Any]] = None


class EventOut(BaseModel):
    """Read-only representation of a SecurityEvent."""
    id: int
    timestamp: datetime
    event_id: int
    source: str
    account: str
    source_ip: Optional[str]
    computer_name: str
    event_type: str
    severity: str
    raw_data: str
    ingestion_time: Optional[datetime]

    class Config:
        from_attributes = True


class EventStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    recent: List[EventOut]


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: str
    confidence: float
    description: str
    evidence: str
    mitre_tactic: Optional[str]
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    status: str
    created_at: Optional[datetime]
    event_ids: str

    class Config:
        from_attributes = True


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern=r"^(New|Investigating|Resolved|False Positive)$")


class AlertStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_rule: dict[str, int]


# ── Incident ──────────────────────────────────────────────────────────────────

class IncidentOut(BaseModel):
    id: int
    title: str
    description: str
    severity: str
    status: str
    alert_ids: str
    timeline: str
    mitre_techniques: str
    investigation_notes: Optional[str]
    created_at: Optional[datetime]
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class IncidentStatusUpdate(BaseModel):
    status: str = Field(..., pattern=r"^(Open|Investigating|Contained|Resolved)$")


# ── Detection Rule ────────────────────────────────────────────────────────────

class DetectionRuleOut(BaseModel):
    id: str
    name: str
    description: str
    severity: str
    enabled: bool
    config: str
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


class DetectionRuleUpdate(BaseModel):
    enabled: Optional[bool] = None
    config: Optional[dict[str, Any]] = None


# ── AI Assistant ──────────────────────────────────────────────────────────────

class AIAskRequest(BaseModel):
    question: str
    context_type: str = Field(..., pattern=r"^(alert|incident)$")
    context_id: int


class AIReportRequest(BaseModel):
    incident_id: int


class AISummaryRequest(BaseModel):
    context_type: str = Field(..., pattern=r"^(alert|incident)$")
    context_id: int


class AIResponse(BaseModel):
    answer: str
    suggestions: List[str] = []


# ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_events: int
    total_alerts: int
    total_incidents: int
    events_by_severity: dict[str, int]
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    incidents_by_status: dict[str, int]
    recent_alerts: List[AlertOut]
    recent_incidents: List[IncidentOut]


# ── MITRE ─────────────────────────────────────────────────────────────────────

class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    tactic: str
    description: str
    detection: str
    investigation_steps: List[str]
    recommended_response: List[str]


class MitreCoverage(BaseModel):
    total_techniques: int
    covered_techniques: int
    coverage_percentage: float
    techniques: List[dict[str, Any]]
