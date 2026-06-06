"""Backfill graph_status for historical investigations.

Revision ID: 0016_backfill_graph_status
Revises: 0015_add_progress_fields
Create Date: 2026-04-24
"""

from alembic import op


revision = "0016_backfill_graph_status"
down_revision = "0015_add_progress_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        UPDATE investigations
        SET graph_status = 'built'
        WHERE status = 'completed'
        AND graph_status = 'pending'
    """)
    op.execute("""
        UPDATE investigations
        SET graph_status = 'no_data'
        WHERE status IN ('completed_no_results', 'failed')
        AND graph_status = 'pending'
    """)


def downgrade() -> None:
    pass  # data migration, no safe rollback
