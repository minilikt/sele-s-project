"""Initial ARGUS schema (pre-Alembic baseline).

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-28
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
        "assets",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("hostname", sa.String(length=500), nullable=False),
        sa.Column("asset_type", sa.String(length=100), nullable=False),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("is_new", sa.Boolean(), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("is_web", sa.Boolean(), nullable=True),
        sa.Column("open_ports", sa.Text(), nullable=False),
        sa.Column("tls_expiry", sa.DateTime(), nullable=True),
        sa.Column("security_headers", sa.Text(), nullable=False),
        sa.Column("last_result", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_assets_id", "assets", ["id"])
    op.create_index("ix_assets_hostname", "assets", ["hostname"], unique=True)
    op.create_index("ix_assets_first_seen", "assets", ["first_seen"])
    op.create_index("ix_assets_last_seen", "assets", ["last_seen"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("asset_id", sa.Integer(), nullable=False),
        sa.Column("asset_hostname", sa.String(length=500), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("exposure", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_id", "findings", ["id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])
    op.create_index("ix_findings_first_seen", "findings", ["first_seen"])
    op.create_index("ix_findings_last_seen", "findings", ["last_seen"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("domain", sa.String(length=500), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("assets_discovered", sa.Integer(), nullable=False),
        sa.Column("new_assets", sa.Integer(), nullable=False),
        sa.Column("findings_discovered", sa.Integer(), nullable=False),
        sa.Column("new_findings", sa.Integer(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_id", "scans", ["id"])
    op.create_index("ix_scans_domain", "scans", ["domain"])
    op.create_index("ix_scans_started_at", "scans", ["started_at"])


def downgrade() -> None:
    op.drop_table("scans")
    op.drop_table("findings")
    op.drop_table("assets")
