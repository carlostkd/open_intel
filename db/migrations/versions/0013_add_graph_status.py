"""Add graph_status column to investigations table.

Revision ID: 0013_add_graph_status
Revises: 0012_add_page_extract_cache
Create Date: 2026-04-23
"""

from alembic import op
import sqlalchemy as sa


revision = "0013_add_graph_status"
down_revision = "0012_add_page_extract_cache"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column(
            "graph_status",
            sa.String(20),
            nullable=False,
            server_default="pending",
        ),
    )


def downgrade() -> None:
    op.drop_column("investigations", "graph_status")