"""Add page_extraction_cache table for LLM extraction caching.

Revision ID: 0011_add_page_extraction_cache
Revises: 0010_add_composite_index_entity_relationships
Create Date: 2026-04-21
"""

from alembic import op
import sqlalchemy as sa


revision = "0012_add_page_extract_cache"
down_revision = "0011_add_composite_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "page_extraction_cache",
        sa.Column(
            "page_hash",
            sa.String(64),
            primary_key=True,
        ),
        sa.Column(
            "entities_json",
            sa.Text,
            nullable=False,
        ),
        sa.Column(
            "extracted_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_page_extraction_cache_expires",
        "page_extraction_cache",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_page_extraction_cache_expires", table_name="page_extraction_cache")
    op.drop_table("page_extraction_cache")