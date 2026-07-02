"""attack surface discovery: surface_asset

Revision ID: 20260704_01_surface
Revises: 20260703_01_ingest
"""
from alembic import op
import sqlalchemy as sa

revision = "20260704_01_surface"
down_revision = "20260703_01_ingest"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "surface_asset",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("brand_id", sa.Integer,
                  sa.ForeignKey("brands.id", ondelete="SET NULL"), nullable=True),
        sa.Column("asset_type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=512), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("parent_id", sa.Integer,
                  sa.ForeignKey("surface_asset.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source", sa.String(length=40), nullable=False, server_default="manual_import"),
        sa.Column("detail", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="new"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_by_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("asset_type IN ('subdomain','ip','certificate','netblock','port','service')",
                           name="ck_surface_type"),
        sa.CheckConstraint("status IN ('new','confirmed','ignored','resolved')", name="ck_surface_status"),
        sa.CheckConstraint("source IN ('ct_log','dns','rdap','tls','manual_import','active_scan')",
                           name="ck_surface_source"),
        sa.UniqueConstraint("tenant_id", "dedup_key", name="uq_surface_dedup"),
    )
    op.create_index("ix_surface_tenant", "surface_asset", ["tenant_id"])
    op.create_index("ix_surface_brand", "surface_asset", ["brand_id"])
    op.create_index("ix_surface_type", "surface_asset", ["asset_type"])
    op.create_index("ix_surface_hash", "surface_asset", ["value_hash"])
    op.create_index("ix_surface_parent", "surface_asset", ["parent_id"])
    op.create_index("ix_surface_created", "surface_asset", ["created_at"])


def downgrade() -> None:
    op.drop_table("surface_asset")
