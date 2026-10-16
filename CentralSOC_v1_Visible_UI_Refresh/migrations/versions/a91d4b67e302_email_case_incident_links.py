"""Link email cases to incidents without retaining raw message content."""
from alembic import op
import sqlalchemy as sa
revision = 'a91d4b67e302'
down_revision = 'f39b71a826d0'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('email_case_incidents',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email_case_id', sa.Integer(), sa.ForeignKey('email_cases.id', ondelete='CASCADE'), nullable=False),
        sa.Column('incident_id', sa.Integer(), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('linked_by', sa.String(80), nullable=False),
        sa.Column('linked_at', sa.DateTime(), nullable=False),
        sa.UniqueConstraint('email_case_id', 'incident_id', name='uq_email_case_incident'))
    op.create_index('ix_email_case_incidents_email_case_id', 'email_case_incidents', ['email_case_id'])
    op.create_index('ix_email_case_incidents_incident_id', 'email_case_incidents', ['incident_id'])

def downgrade():
    op.drop_index('ix_email_case_incidents_incident_id', table_name='email_case_incidents')
    op.drop_index('ix_email_case_incidents_email_case_id', table_name='email_case_incidents')
    op.drop_table('email_case_incidents')
