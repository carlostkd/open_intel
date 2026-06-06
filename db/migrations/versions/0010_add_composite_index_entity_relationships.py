"""Add composite index on (entity_a_id, entity_b_id) for neighbor lookups"""

from alembic import op
import sqlalchemy as sa


revision = "0011_add_composite_index"
down_revision = "0010_add_investigation_id_rel"
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        "ix_entity_relationships_source_target",
        "entity_relationships",
        ["entity_a_id", "entity_b_id"],
    )


def downgrade():
    op.drop_index("ix_entity_relationships_source_target", "entity_relationships")