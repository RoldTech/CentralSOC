"""Persist response and investigation runs."""
from alembic import op
import sqlalchemy as sa
revision = 'b04e8a9c1201'
down_revision = 'ae72c08d4e31'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('response_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('state', sa.String(20), nullable=False),
        sa.Column('requested_by', sa.String(80), nullable=False),
        sa.Column('approved_by', sa.String(80), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('snapshot', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.CheckConstraint("state IN ('PENDING','APPROVED','COMPLETED','REJECTED')", name='ck_response_run_state'))
    op.create_index('ix_response_runs_incident_id', 'response_runs', ['incident_id'])
    op.create_table('investigation_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('alert_id', sa.Integer(), sa.ForeignKey('alerts.id', ondelete='CASCADE'), nullable=False),
        sa.Column('requested_by', sa.String(80), nullable=False),
        sa.Column('mode', sa.String(20), nullable=False),
        sa.Column('state', sa.String(20), nullable=False),
        sa.Column('model', sa.String(120), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False))
    op.create_index('ix_investigation_runs_alert_id', 'investigation_runs', ['alert_id'])

def downgrade():
    op.drop_table('investigation_runs')
    op.drop_table('response_runs')
