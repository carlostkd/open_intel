"""Add posted_at column to pages table

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_add_page_posted_at"
down_revision: Union[str, None] = "0004_add_canonical_val_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing = [c["name"] for c in inspector.get_columns("pages")]
    if "posted_at" not in existing:
        op.add_column(
            "pages",
            sa.Column(
                "posted_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
        )
    inspector = sa.inspect(conn)
    existing_indexes = [i["name"] for i in inspector.get_indexes("pages")]
    if "ix_pages_posted_at" not in existing_indexes:
        op.create_index("ix_pages_posted_at", "pages", ["posted_at"])


def downgrade() -> None:
    op.drop_index("ix_pages_posted_at", table_name="pages")
    op.drop_column("pages", "posted_at")
