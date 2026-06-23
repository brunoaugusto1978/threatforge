"""investigation_cases table

Revision ID: 20260624_01_cases
Revises: 20260623_01_brandstatus  (ajuste se o head do projeto for outro)
"""
from alembic import op
import sqlalchemy as sa

revision = "20260624_01_cases"
down_revision = "20260623_01_brandstatus"
branch_labels = None
depends_on = None

_STATUS = "status IN ('open','triage','investigating','contained','closed','false_positive')"
_SEV = "severity IN ('baixo','medio','alto','critico')"


def upgrade() -> None:
    op.create_table(
        "investigation_cases",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("brand_id", sa.Integer,
                  sa.ForeignKey("brands.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_id", sa.Integer,
                  sa.ForeignKey("brand_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("observable_id", sa.Integer,
                  sa.ForeignKey("observables.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_snapshot", sa.JSON, nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("severity", sa.String(length=10), nullable=False, server_default="medio"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("assignee_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_STATUS, name="ck_case_status"),
        sa.CheckConstraint(_SEV, name="ck_case_severity"),
    )
    for col in ("tenant_id", "brand_id", "finding_id", "observable_id",
                "status", "severity", "assignee_user_id", "created_at"):
        op.create_index(f"ix_investigation_cases_{col}", "investigation_cases", [col])
    op.create_index("ix_cases_tenant_status", "investigation_cases", ["tenant_id", "status"])
    op.create_index("ix_cases_tenant_created", "investigation_cases", ["tenant_id", "created_at"])


def downgrade() -> None:
    op.drop_table("investigation_cases")
