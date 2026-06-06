"""Add extraction_method to entities

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006_add_extraction_method"
down_revision: Union[str, None] = "0005_add_page_posted_at"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = [c["name"] for c in inspector.get_columns("entities")]
    if "extraction_method" not in existing:
        op.add_column(
            "entities",
            sa.Column("extraction_method", sa.String(length=10), nullable=True),
        )


def downgrade() -> None:
    op.drop_column("entities", "extraction_method")
