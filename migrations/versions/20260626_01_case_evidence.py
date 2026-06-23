"""case_evidence table (evidence attachments)

Revision ID: 20260626_01_evidence
Revises: 20260625_01_casenotes
"""
from alembic import op
import sqlalchemy as sa

revision = "20260626_01_evidence"
down_revision = "20260625_01_casenotes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_evidence",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.Integer,
                  sa.ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Integer,
                  sa.ForeignKey("brand_findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("mime_type", sa.String(length=120), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("origin", sa.String(length=30), nullable=False, server_default="manual_upload"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("storage_backend", sa.String(length=20), nullable=False, server_default="local"),
        sa.Column("storage_key", sa.String(length=512), nullable=True),
        sa.Column("uploaded_by_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(
            "origin IN ('manual_upload','authorized_export','whatsapp_intake',"
            "'telegram_public','email','other')", name="ck_evidence_origin"),
        sa.CheckConstraint("storage_backend IN ('local','none')", name="ck_evidence_backend"),
    )
    op.create_index("ix_evidence_tenant", "case_evidence", ["tenant_id"])
    op.create_index("ix_evidence_case", "case_evidence", ["case_id"])
    op.create_index("ix_evidence_finding", "case_evidence", ["finding_id"])
    op.create_index("ix_evidence_sha256", "case_evidence", ["sha256"])
    op.create_index("ix_evidence_created", "case_evidence", ["created_at"])


def downgrade() -> None:
    op.drop_table("case_evidence")
