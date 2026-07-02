"""exposure monitoring: monitored_asset + exposure_finding

Revision ID: 20260702_01_exposure
Revises: 20260626_01_evidence
"""
from alembic import op
import sqlalchemy as sa

revision = "20260702_01_exposure"
down_revision = "20260626_01_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "monitored_asset",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_type", sa.String(length=30), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("criticality", sa.String(length=10), nullable=False, server_default="medium"),
        sa.Column("consent_ref", sa.String(length=200), nullable=True),
        sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_by_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "asset_type IN ('identity','email','domain','keyword','secret_pattern','repo','ip_range')",
            name="ck_monitored_asset_type"),
        sa.CheckConstraint("criticality IN ('low','medium','high','critical')",
                           name="ck_monitored_asset_crit"),
    )
    op.create_index("ix_monitored_asset_tenant", "monitored_asset", ["tenant_id"])
    op.create_index("ix_monitored_asset_hash", "monitored_asset", ["value_hash"])
    op.create_index("ix_monitored_asset_type", "monitored_asset", ["asset_type"])

    op.create_table(
        "exposure_finding",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("exposure_type", sa.String(length=40), nullable=False),
        sa.Column("asset_id", sa.Integer,
                  sa.ForeignKey("monitored_asset.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("source", sa.String(length=60), nullable=False),
        sa.Column("source_reliability", sa.String(length=1), nullable=False, server_default="F"),
        sa.Column("info_credibility", sa.String(length=1), nullable=False, server_default="6"),
        sa.Column("severity", sa.String(length=10), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="new"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("redacted", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_by_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "exposure_type IN ('identity_exposure','credential_exposure','brand_exposure',"
            "'infrastructure_exposure','secret_exposure','source_code_exposure')",
            name="ck_exposure_type"),
        sa.CheckConstraint("source_reliability IN ('A','B','C','D','E','F')",
                           name="ck_exposure_reliability"),
        sa.CheckConstraint("info_credibility IN ('1','2','3','4','5','6')",
                           name="ck_exposure_credibility"),
        sa.CheckConstraint("severity IN ('low','medium','high','critical')",
                           name="ck_exposure_severity"),
        sa.CheckConstraint(
            "status IN ('new','triaging','confirmed','mitigated','closed','false_positive','duplicate')",
            name="ck_exposure_status"),
        sa.UniqueConstraint("tenant_id", "dedup_key", name="uq_exposure_dedup"),
    )
    op.create_index("ix_exposure_tenant", "exposure_finding", ["tenant_id"])
    op.create_index("ix_exposure_type", "exposure_finding", ["exposure_type"])
    op.create_index("ix_exposure_asset", "exposure_finding", ["asset_id"])
    op.create_index("ix_exposure_dedup", "exposure_finding", ["dedup_key"])
    op.create_index("ix_exposure_created", "exposure_finding", ["created_at"])


def downgrade() -> None:
    op.drop_table("exposure_finding")
    op.drop_table("monitored_asset")
