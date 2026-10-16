"""Add incident cases and explicit alert links.

Revision ID: b72cf9d2e501
Revises: 465a8453b4e0
"""
from alembic import op
import sqlalchemy as sa

revision = "b72cf9d2e501"
down_revision = "465a8453b4e0"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("owner", sa.String(80)),
        sa.Column("created_by", sa.String(80), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.Column("resolution", sa.Text()),
        sa.CheckConstraint("status IN ('Open','Investigating','Contained','Resolved','Closed')", name="ck_incident_status"),
        sa.CheckConstraint("severity IN ('LOW','MEDIUM','HIGH','CRITICAL')", name="ck_incident_severity"))
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_owner", "incidents", ["owner"])
    op.create_table("incident_alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_id", sa.Integer(), sa.ForeignKey("alerts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("linked_by", sa.String(80), nullable=False),
        sa.Column("linked_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("incident_id", "alert_id", name="uq_incident_alert"))
    op.create_index("ix_incident_alerts_incident_id", "incident_alerts", ["incident_id"])
    op.create_index("ix_incident_alerts_alert_id", "incident_alerts", ["alert_id"])


def downgrade():
    op.drop_table("incident_alerts")
    op.drop_table("incidents")
