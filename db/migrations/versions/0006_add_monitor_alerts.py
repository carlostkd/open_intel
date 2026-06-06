"""Add monitor_alerts table

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-17

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007_add_monitor_alerts"
down_revision: Union[str, None] = "0006_add_extraction_method"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Table 'monitor_alerts' already created in 0001_initial_schema
    pass


def downgrade() -> None:
    pass
