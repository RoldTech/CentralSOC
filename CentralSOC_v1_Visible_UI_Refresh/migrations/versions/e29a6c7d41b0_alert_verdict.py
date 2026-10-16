"""Analyst alert outcome, not ground-truth dataset evaluation."""
from alembic import op
import sqlalchemy as sa
revision = "e29a6c7d41b0"
down_revision = "d40f1b9267ac"
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.add_column(sa.Column("analyst_verdict", sa.String(30), nullable=True))
        batch.add_column(sa.Column("verdict_reason", sa.Text(), nullable=True))
        batch.add_column(sa.Column("verdict_by", sa.String(80), nullable=True))
        batch.add_column(sa.Column("verdict_at", sa.DateTime(), nullable=True))
        batch.create_index("ix_alerts_analyst_verdict", ["analyst_verdict"])

def downgrade():
    with op.batch_alter_table("alerts") as batch:
        batch.drop_index("ix_alerts_analyst_verdict")
        for field in ("verdict_at", "verdict_by", "verdict_reason", "analyst_verdict"):
            batch.drop_column(field)
