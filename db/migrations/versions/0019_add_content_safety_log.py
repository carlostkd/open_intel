"""Add content_safety_events table.

Revision ID: 0019_add_content_safety_log
Revises: 0018_user_id_investigations
Create Date: 2026-04-30
"""

import sqlalchemy as sa
from alembic import op

revision = "0019_add_content_safety_log"
down_revision = "0018_user_id_investigations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "content_safety_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_content_safety_events_event_type",
        "content_safety_events",
        ["event_type"],
    )
    op.create_index(
        "ix_content_safety_events_timestamp",
        "content_safety_events",
        ["timestamp"],
    )


def downgrade() -> None:
    op.drop_index("ix_content_safety_events_timestamp", table_name="content_safety_events")
    op.drop_index("ix_content_safety_events_event_type", table_name="content_safety_events")
    op.drop_table("content_safety_events")
