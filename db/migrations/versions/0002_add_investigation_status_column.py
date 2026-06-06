"""Add status column to investigations.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_add_investigation_status"
down_revision: Union[str, None] = "0002_add_missing_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
    )


def downgrade() -> None:
    op.drop_column("investigations", "status")
