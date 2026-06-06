"""Add investigation_id to entity_relationships"""

from alembic import op
import sqlalchemy as sa


revision = "0010_add_investigation_id_rel"
down_revision = "0009_add_users_table"
branch_labels = None
depends_on = None


def upgrade():
    # Calling add_column with index=True already creates the index
    # 'ix_entity_relationships_investigation_id'
    op.add_column(
        "entity_relationships",
        sa.Column(
            "investigation_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
    )


def downgrade():
    op.drop_column("entity_relationships", "investigation_id")