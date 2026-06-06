"""add canonical value and entity links

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-16

"""
from typing import Sequence, Union
import sqlalchemy as sa
from alembic import op

revision: str = "0004_add_canonical_val_links"
down_revision: Union[str, None] = "0003_add_investigation_status"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_columns = [c['name'] for c in inspector.get_columns('entities')]
    existing_inv_columns = [c['name'] for c in inspector.get_columns('investigations')]
    
    # 1. Add columns to entities if they don't exist
    if 'canonical_value' not in existing_columns:
        op.add_column('entities', sa.Column('canonical_value', sa.String(), nullable=True))
    if 'historical_context' not in existing_columns:
        op.add_column('entities', sa.Column('historical_context', sa.Text(), nullable=True))
    if 'context' in existing_columns and 'context_snippet' not in existing_columns:
        # Rename context to context_snippet
        op.alter_column('entities', 'context', new_column_name='context_snippet')
    
    # 2. Add is_seed to investigations if it doesn't exist
    if 'is_seed' not in existing_inv_columns:
        op.add_column('investigations', sa.Column('is_seed', sa.Boolean(), server_default='false', nullable=False))
    
    # 3. Tables handled in 0001_initial_schema:
    # investigation_entity_links
    pass
    
    # 4. Create indexes (ensure we don't duplicate them)
    existing_indexes = [i['name'] for i in inspector.get_indexes('entities')]
    if 'ix_entities_canonical_value' not in existing_indexes:
        op.create_index('ix_entities_canonical_value', 'entities', ['canonical_value'])
    if 'ix_entity_canonical' not in existing_indexes:
        op.create_index('ix_entity_canonical', 'entities', ['entity_type', 'canonical_value'])
    
    # 5. Backfill canonical_value with size limits to avoid B-tree index row size errors
    op.execute("UPDATE entities SET canonical_value = substring(lower(regexp_replace(value, '[\\s\\-_\\.]', '', 'g')), 1, 1024) WHERE entity_type IN ('THREAT_ACTOR', 'MALWARE', 'FORUM', 'THREAT_ACTOR_HANDLE', 'MALWARE_FAMILY', 'RANSOMWARE_GROUP', 'handle', 'malware', 'ransomware_group');")
    op.execute("UPDATE entities SET canonical_value = substring(lower(value), 1, 1024) WHERE entity_type IN ('EMAIL', 'ONION_URL', 'EMAIL_ADDRESS', 'email', 'onion_url');")
    op.execute("UPDATE entities SET canonical_value = substring(value, 1, 1024) WHERE canonical_value IS NULL;")


def downgrade() -> None:
    op.drop_index('ix_entity_canonical', table_name='entities')
    op.drop_index('ix_entities_canonical_value', table_name='entities')
    op.drop_table('investigation_entity_links')
    op.drop_column('investigations', 'is_seed')
    op.alter_column('entities', 'context_snippet', new_column_name='context')
    op.drop_column('entities', 'historical_context')
    op.drop_column('entities', 'canonical_value')
