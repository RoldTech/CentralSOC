"""Add metadata-only email investigation cases."""
from alembic import op
import sqlalchemy as sa
revision = 'f39b71a826d0'
down_revision = 'e29a6c7d41b0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('email_cases',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('sha256', sa.String(64), nullable=False),
        sa.Column('subject', sa.String(200), nullable=False),
        sa.Column('sender', sa.String(255), nullable=False),
        sa.Column('classification', sa.String(30), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('created_by', sa.String(80), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.CheckConstraint("status IN ('Open','Investigating','Escalated','Closed')", name='ck_email_case_status'))
    op.create_index('ix_email_cases_sha256', 'email_cases', ['sha256'])
    op.create_index('ix_email_cases_status', 'email_cases', ['status'])


def downgrade():
    op.drop_index('ix_email_cases_status', table_name='email_cases')
    op.drop_index('ix_email_cases_sha256', table_name='email_cases')
    op.drop_table('email_cases')
