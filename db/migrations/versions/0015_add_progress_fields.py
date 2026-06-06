"""Add pipeline progress tracking fields to investigations table.

Revision ID: 0015_add_progress_fields
Revises: 0013_add_graph_status
Create Date: 2026-04-23
"""

from alembic import op
import sqlalchemy as sa


revision = "0015_add_progress_fields"
down_revision = "0013_add_graph_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("current_step", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "investigations",
        sa.Column("current_step_label", sa.String(200), nullable=False, server_default=""),
    )
    op.add_column(
        "investigations",
        sa.Column("entity_count", sa.Integer, nullable=False, server_default="0"),
    )
    op.add_column(
        "investigations",
        sa.Column("page_count", sa.Integer, nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("investigations", "page_count")
    op.drop_column("investigations", "entity_count")
    op.drop_column("investigations", "current_step_label")
    op.drop_column("investigations", "current_step")