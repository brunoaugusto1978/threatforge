"""credential intelligence: credential_identity

Revision ID: 20260705_01_credid
Revises: 20260704_01_surface
"""
from alembic import op
import sqlalchemy as sa

revision = "20260705_01_credid"
down_revision = "20260704_01_surface"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "credential_identity",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("identity_hash", sa.String(length=64), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("leak_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("password_hashes", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("sources", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("stealer_families", sa.JSON, nullable=False, server_default="[]"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("vip_asset_id", sa.Integer,
                  sa.ForeignKey("monitored_asset.id", ondelete="SET NULL"), nullable=True),
        sa.Column("max_risk", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="new"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("status IN ('new','reviewing','mitigated','closed')", name="ck_credid_status"),
        sa.UniqueConstraint("tenant_id", "identity_hash", name="uq_credid_identity"),
    )
    op.create_index("ix_credid_tenant", "credential_identity", ["tenant_id"])
    op.create_index("ix_credid_hash", "credential_identity", ["identity_hash"])
    op.create_index("ix_credid_domain", "credential_identity", ["domain"])


def downgrade() -> None:
    op.drop_table("credential_identity")
