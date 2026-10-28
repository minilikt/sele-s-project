"""
SQLAlchemy ORM models for the ARGUS backend.

Tables:
    - Asset: A discovered host/subdomain with its current state.
    - Finding: A security issue detected against an asset, deduplicated by
      fingerprint across scans.
    - Scan: A single discovery/analysis run.
    - User: Authentication and role assignment.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text

from database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(500), nullable=False, index=True, unique=True)
    asset_type = Column(String(100), nullable=False, default="Subdomain")
    ip = Column(String(45), nullable=True)
    status = Column(String(30), nullable=False, default="Unknown")  # Online / Offline / Unknown
    first_seen = Column(DateTime, default=_utcnow, index=True)
    last_seen = Column(DateTime, default=_utcnow, index=True)
    is_new = Column(Boolean, default=False)
    http_status = Column(Integer, nullable=True)
    is_web = Column(Boolean, default=False)
    open_ports = Column(Text, nullable=False, default="[]")  # JSON array
    tls_expiry = Column(DateTime, nullable=True)
    security_headers = Column(Text, nullable=False, default="{}")  # JSON dict
    last_result = Column(Text, nullable=True)
    last_scan_id = Column(Integer, nullable=True, index=True)
    risk_score = Column(Float, nullable=False, default=0.0)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, nullable=False, index=True)
    asset_hostname = Column(String(500), nullable=False)
    category = Column(String(100), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    detail = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # Critical/High/Medium/Low/Info
    risk_score = Column(Float, nullable=False, default=0.0)
    exposure = Column(String(50), nullable=False, default="Internet")
    confidence = Column(Float, nullable=False, default=0.8)
    recommendation = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="Open", index=True)  # Open/Acknowledged/Resolved
    first_seen = Column(DateTime, default=_utcnow, index=True)
    last_seen = Column(DateTime, default=_utcnow, index=True)
    fingerprint = Column(String(64), nullable=True, index=True)
    dedup_count = Column(Integer, nullable=False, default=1)
    last_scan_id = Column(Integer, nullable=True, index=True)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    reopened_count = Column(Integer, nullable=False, default=0)
    assigned_to = Column(String(120), nullable=True)
    resolution_note = Column(Text, nullable=True)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(500), nullable=False, index=True)
    started_at = Column(DateTime, default=_utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(30), nullable=False, default="Running")  # Running/Complete/Failed
    assets_discovered = Column(Integer, nullable=False, default=0)
    new_assets = Column(Integer, nullable=False, default=0)
    findings_discovered = Column(Integer, nullable=False, default=0)
    new_findings = Column(Integer, nullable=False, default=0)
    reopened_findings = Column(Integer, nullable=False, default=0)
    risk_score = Column(Float, nullable=False, default=0.0)
    summary = Column(Text, nullable=True)


class User(Base):
    """A platform user for JWT authentication and role-based access."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin | analyst | viewer
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=_utcnow)
    last_login_at = Column(DateTime, nullable=True)

