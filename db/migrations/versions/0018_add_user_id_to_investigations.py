"""Add user_id to investigations.

Revision ID: 0018_add_user_id_to_investigations
Revises: 0017_add_user_api_keys
Create Date: 2026-04-25
"""

import sqlalchemy as sa
from alembic import op


revision = "0018_user_id_investigations"
down_revision = "0017_add_user_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_investigations_user_id", "investigations", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_investigations_user_id", table_name="investigations")
    op.drop_column("investigations", "user_id")
