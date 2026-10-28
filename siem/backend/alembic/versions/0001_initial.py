"""Initial SENTINEL schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-27

This revision represents the schema as it stood before Alembic was introduced.
Existing SQLite databases are stamped with this revision by
``migrations.upgrade_database`` and then moved forward.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("event_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("account", sa.String(length=255), nullable=False),
        sa.Column("source_ip", sa.String(length=45), nullable=True),
        sa.Column("computer_name", sa.String(length=255), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("raw_data", sa.Text(), nullable=False),
        sa.Column("ingestion_time", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_events_id", "security_events", ["id"])
    op.create_index("ix_security_events_event_id", "security_events", ["event_id"])
    op.create_index("ix_security_events_account", "security_events", ["account"])
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_severity", "security_events", ["severity"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("rule_id", sa.String(length=100), nullable=False),
        sa.Column("rule_name", sa.String(length=255), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("mitre_tactic", sa.String(length=100), nullable=True),
        sa.Column("mitre_technique_id", sa.String(length=50), nullable=True),
        sa.Column("mitre_technique_name", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("event_ids", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=True),
        sa.Column("dedup_count", sa.Integer(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("assigned_to", sa.String(length=120), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alerts_id", "alerts", ["id"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["fingerprint"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("alert_ids", sa.Text(), nullable=False),
        sa.Column("timeline", sa.Text(), nullable=False),
        sa.Column("mitre_techniques", sa.Text(), nullable=False),
        sa.Column("investigation_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=True),
        sa.Column("assigned_to", sa.String(length=120), nullable=True),
        sa.Column("entities", sa.Text(), nullable=True),
        sa.Column("entity_graph", sa.Text(), nullable=True),
        sa.Column("attack_chain", sa.Text(), nullable=True),
        sa.Column("chain_score", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_incidents_id", "incidents", ["id"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_fingerprint", "incidents", ["fingerprint"])

    op.create_table(
        "detection_rules",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("config", sa.Text(), nullable=False),
        sa.Column("mitre_tactic", sa.String(length=100), nullable=False),
        sa.Column("mitre_technique_id", sa.String(length=50), nullable=False),
        sa.Column("mitre_technique_name", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("engine", sa.String(length=20), nullable=True),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("yaml_source", sa.Text(), nullable=True),
        sa.Column("rule_path", sa.String(length=500), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("detection_rules")
    op.drop_table("incidents")
    op.drop_table("alerts")
    op.drop_table("security_events")
