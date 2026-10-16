"""Expand user-role constraint for tiered SOC roles while preserving existing users.

Revision ID: ae72c08d4e31
Revises: a91d4b67e302
"""
from alembic import op
import sqlalchemy as sa
revision = "ae72c08d4e31"
down_revision = "a91d4b67e302"
branch_labels = None
depends_on = None
NEW_ROLES = "role IN ('ADMIN','ANALYST','VIEWER','SOC_L1','SOC_L2','SOC_L3','SOC_MANAGER')"
OLD_ROLES = "role IN ('ADMIN','ANALYST','VIEWER')"

def upgrade():
    with op.batch_alter_table('users', recreate='auto') as batch:
        batch.drop_constraint('ck_user_role', type_='check')
        batch.alter_column('role', existing_type=sa.String(length=10), type_=sa.String(length=20), existing_nullable=False)
        batch.create_check_constraint('ck_user_role', NEW_ROLES)

def downgrade():
    bind = op.get_bind()
    expanded = bind.execute(sa.text("SELECT COUNT(*) FROM users WHERE role NOT IN ('ADMIN','ANALYST','VIEWER')")).scalar_one()
    if expanded:
        raise RuntimeError('Cannot downgrade: assign legacy roles to tiered SOC users first')
    with op.batch_alter_table('users', recreate='auto') as batch:
        batch.drop_constraint('ck_user_role', type_='check')
        batch.alter_column('role', existing_type=sa.String(length=20), type_=sa.String(length=10), existing_nullable=False)
        batch.create_check_constraint('ck_user_role', OLD_ROLES)
