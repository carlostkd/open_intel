"""Add users table and seed default admin

Revision ID: 0008
Revises: 0007
Create Date: 2026-04-17 22:45:00.000000

"""
from alembic import op
import sqlalchemy as sa
from passlib.context import CryptContext
from datetime import datetime, timezone

# revision identifiers, used by Alembic.
revision = '0009_add_users_table'
down_revision = '0008_add_actor_style_profiles'
branch_labels = None
depends_on = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def upgrade():
    # Table 'users' already created in 0001_initial_schema
    # Seed default admin account with a secure placeholder
    # Password must be set during setup or changed on first login
    import secrets
    placeholder_password = secrets.token_urlsafe(32)
    hashed_pwd = pwd_context.hash(placeholder_password)
    now = datetime.now(timezone.utc).isoformat()
    
    op.execute(
        f"""
        INSERT INTO users (email, hashed_password, is_active, must_reset_password, created_at)
        VALUES (
            'admin@open_intel.tech',
            '{hashed_pwd}',
            true,
            true,
            '{now}'
        )
        """
    )


def downgrade():
    # We don't drop the table here as it belongs to 0001_initial_schema
    # Optional: Delete the seeded admin
    op.execute("DELETE FROM users WHERE email = 'admin@open_intel.tech'")
