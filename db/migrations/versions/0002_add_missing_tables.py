"""Add missing tables — users, monitor_alerts, investigation_entity_links, actor_style_profiles.

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-20

Tables created
--------------
  users
  monitor_alerts
  investigation_entity_links
  actor_style_profiles
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_add_missing_tables"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Tables handled in 0001_initial_schema:
    # users, monitor_alerts, investigation_entity_links, actor_style_profiles
    pass


def downgrade() -> None:
    pass