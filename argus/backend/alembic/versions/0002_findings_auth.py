"""Finding deduplication, lifecycle fields and users.

Revision ID: 0002_findings_auth
Revises: 0001_initial
Create Date: 2026-10-28
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_findings_auth"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Findings: stable identity across scans and analyst lifecycle fields.
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.add_column(
        "findings",
        sa.Column("dedup_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column("findings", sa.Column("last_scan_id", sa.Integer(), nullable=True))
    op.add_column("findings", sa.Column("acknowledged_at", sa.DateTime(), nullable=True))
    op.add_column("findings", sa.Column("resolved_at", sa.DateTime(), nullable=True))
    op.add_column(
        "findings",
        sa.Column("reopened_count", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("findings", sa.Column("assigned_to", sa.String(length=120), nullable=True))
    op.add_column("findings", sa.Column("resolution_note", sa.Text(), nullable=True))
    op.create_index("ix_findings_fingerprint", "findings", ["fingerprint"])
    op.create_index("ix_findings_last_scan_id", "findings", ["last_scan_id"])

    # Assets: cached aggregate risk and last observation.
    op.add_column("assets", sa.Column("last_scan_id", sa.Integer(), nullable=True))
    op.add_column(
        "assets",
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0"),
    )
    op.create_index("ix_assets_last_scan_id", "assets", ["last_scan_id"])

    # Scans: regression tracking.
    op.add_column(
        "scans",
        sa.Column("reopened_findings", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=120), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_username", "users", ["username"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_table("users")

    op.drop_column("scans", "reopened_findings")

    op.drop_index("ix_assets_last_scan_id", table_name="assets")
    op.drop_column("assets", "risk_score")
    op.drop_column("assets", "last_scan_id")

    op.drop_index("ix_findings_last_scan_id", table_name="findings")
    op.drop_index("ix_findings_fingerprint", table_name="findings")
    op.drop_column("findings", "resolution_note")
    op.drop_column("findings", "assigned_to")
    op.drop_column("findings", "reopened_count")
    op.drop_column("findings", "resolved_at")
    op.drop_column("findings", "acknowledged_at")
    op.drop_column("findings", "last_scan_id")
    op.drop_column("findings", "dedup_count")
    op.drop_column("findings", "fingerprint")
