"""Add actor_style_profiles table

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-17 19:55:00.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone

# revision identifiers, used by Alembic.
revision = '0008_add_actor_style_profiles'
down_revision = '0007_add_monitor_alerts'
branch_labels = None
depends_on = None

def upgrade():
    # Table actor_style_profiles already created in 0001_initial_schema
    pass

def downgrade():
    pass
