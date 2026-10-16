"""Record first alert acknowledgement.

Revision ID: d40f1b9267ac
Revises: c823a9d11f30
"""
from alembic import op
import sqlalchemy as sa

revision = "d40f1b9267ac"
down_revision = "c823a9d11f30"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("acknowledged_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("acknowledged_by", sa.String(length=80), nullable=True))

def downgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.drop_column("acknowledged_by")
        batch.drop_column("acknowledged_at")
