"""Add persistent alert ownership.

Revision ID: c823a9d11f30
Revises: b72cf9d2e501
"""
from alembic import op
import sqlalchemy as sa

revision = "c823a9d11f30"
down_revision = "b72cf9d2e501"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("assigned_to", sa.String(80), nullable=True))
        batch.create_index("ix_alerts_assigned_to", ["assigned_to"])
        batch.create_foreign_key("fk_alert_assignee_user", "users", ["assigned_to"], ["username"], ondelete="RESTRICT")

def downgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.drop_constraint("fk_alert_assignee_user", type_="foreignkey")
        batch.drop_index("ix_alerts_assigned_to")
        batch.drop_column("assigned_to")
