"""Add entity source tracking and freshness fields.

Revision ID: 0020_add_entity_source_tracking
Revises: 0019_add_content_safety_log
Create Date: 2025-04-30
"""
from alembic import op
import sqlalchemy as sa


revision = "0020_add_entity_source_tracking"
down_revision = "0019_add_content_safety_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "entities",
        sa.Column("source_count", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "entities",
        sa.Column("corroborating_sources", sa.Text(), nullable=True),
    )
    op.add_column(
        "entities",
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
        ),
    )
    op.add_column(
        "entities",
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("entities", "last_seen_at")
    op.drop_column("entities", "first_seen_at")
    op.drop_column("entities", "corroborating_sources")
    op.drop_column("entities", "source_count")