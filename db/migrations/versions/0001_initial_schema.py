"""Initial schema — all Phase 1A tables.

Revision ID: 0001
Revises: (none — first migration)
Create Date: 2026-04-14

Tables created
--------------
  investigations
  sources
  investigation_sources  (junction)
  pages
  entities
  entity_relationships
  users
  monitor_alerts
  investigation_entity_links
  actor_style_profiles
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # investigations
    # ------------------------------------------------------------------
    op.create_table(
        "investigations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("run_id", sa.UUID(), nullable=False),
        sa.Column("query", sa.Text(), nullable=False),
        sa.Column("refined_query", sa.Text(), nullable=True),
        sa.Column("model_used", sa.String(100), nullable=True),
        sa.Column("preset", sa.String(50), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id"),
    )
    op.create_index("ix_investigations_run_id", "investigations", ["run_id"])

    # ------------------------------------------------------------------
    # sources
    # ------------------------------------------------------------------
    op.create_table(
        "sources",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("onion_address", sa.String(255), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="unknown"),
        sa.Column("source_type", sa.String(30), nullable=False, server_default="search_result"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("onion_address"),
    )
    op.create_index("ix_sources_onion_address", "sources", ["onion_address"])

    # ------------------------------------------------------------------
    # investigation_sources  (many-to-many junction)
    # ------------------------------------------------------------------
    op.create_table(
        "investigation_sources",
        sa.Column(
            "investigation_id",
            sa.UUID(),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "source_id",
            sa.UUID(),
            sa.ForeignKey("sources.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("investigation_id", "source_id"),
    )

    # ------------------------------------------------------------------
    # pages
    # ------------------------------------------------------------------
    op.create_table(
        "pages",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "source_id",
            sa.UUID(),
            sa.ForeignKey("sources.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("raw_content_hash", sa.String(64), nullable=True),
        sa.Column("cleaned_text", sa.Text(), nullable=True),
        sa.Column("scrape_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("language", sa.String(10), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("url"),
    )
    op.create_index("ix_pages_source_id", "pages", ["source_id"])
    op.create_index("ix_pages_raw_content_hash", "pages", ["raw_content_hash"])

    # ------------------------------------------------------------------
    # entities
    # ------------------------------------------------------------------
    op.create_table(
        "entities",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "page_id",
            sa.UUID(),
            sa.ForeignKey("pages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "investigation_id",
            sa.UUID(),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("context", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_entities_page_id", "entities", ["page_id"])
    op.create_index("ix_entities_investigation_id", "entities", ["investigation_id"])
    op.create_index("ix_entities_entity_type", "entities", ["entity_type"])

    # ------------------------------------------------------------------
    # entity_relationships
    # ------------------------------------------------------------------
    op.create_table(
        "entity_relationships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "entity_a_id",
            sa.UUID(),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "entity_b_id",
            sa.UUID(),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("relationship_type", sa.String(50), nullable=False),
        sa.Column(
            "source_page_id",
            sa.UUID(),
            sa.ForeignKey("pages.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_entity_relationships_entity_a_id", "entity_relationships", ["entity_a_id"])
    op.create_index("ix_entity_relationships_entity_b_id", "entity_relationships", ["entity_b_id"])
    op.create_index("ix_entity_relationships_relationship_type", "entity_relationships", ["relationship_type"])

    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("must_reset_password", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"])

    # ------------------------------------------------------------------
    # monitor_alerts
    # ------------------------------------------------------------------
    op.create_table(
        "monitor_alerts",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("monitor_name", sa.String(), nullable=False),
        sa.Column("triggered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_type", sa.String(50), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("diff_data", sa.JSON(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False, server_default="info"),
        sa.Column("entity_count_delta", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("delivered", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("delivery_channels", sa.JSON(), nullable=True),
        sa.Column("acknowledged", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_monitor_alerts_monitor_name", "monitor_alerts", ["monitor_name"])
    op.create_index("ix_monitor_alerts_triggered_at", "monitor_alerts", ["triggered_at"])
    op.create_index("ix_monitor_alerts_monitor_triggered", "monitor_alerts", ["monitor_name", "triggered_at"])

    # ------------------------------------------------------------------
    # investigation_entity_links
    # ------------------------------------------------------------------
    op.create_table(
        "investigation_entity_links",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "entity_id",
            sa.UUID(),
            sa.ForeignKey("entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "investigation_id",
            sa.UUID(),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("linked_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_id", "investigation_id"),
    )
    op.create_index("ix_investigation_entity_links_entity_id", "investigation_entity_links", ["entity_id"])
    op.create_index("ix_investigation_entity_links_investigation_id", "investigation_entity_links", ["investigation_id"])

    # ------------------------------------------------------------------
    # actor_style_profiles
    # ------------------------------------------------------------------
    op.create_table(
        "actor_style_profiles",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("canonical_value", sa.String(), nullable=False),
        sa.Column("entity_type", sa.String(), nullable=False),
        sa.Column("style_vector", sa.JSON(), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_chars", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_updated", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("canonical_value", "entity_type"),
    )
    op.create_index("ix_actor_style_profiles_canonical_value", "actor_style_profiles", ["canonical_value"])


def downgrade() -> None:
    op.drop_table("actor_style_profiles")
    op.drop_table("investigation_entity_links")
    op.drop_table("monitor_alerts")
    op.drop_table("users")
    op.drop_table("entity_relationships")
    op.drop_table("entities")
    op.drop_table("pages")
    op.drop_table("investigation_sources")
    op.drop_table("sources")
    op.drop_table("investigations")
