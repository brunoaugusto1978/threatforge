"""integration_connections table

Revision ID: 20260706_01_intconn
Revises: 20260705_01_credid

Introduced by ThreatForge Community v0.9.2 to persist minimal, non-secret
connector configuration once an Enterprise license unlocks the corresponding
feature (integration.misp / integration.opencti / integration.generic).

Community never stores real credentials in this table. The router strips
api_key/api_token/token/secret/password fields before persistence and only
records their presence in ``secrets_metadata``.
"""
from alembic import op
import sqlalchemy as sa

revision = "20260706_01_intconn"
down_revision = "20260705_01_credid"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "integration_connections",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=60), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("config_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("secrets_metadata", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "name",
                            name="uq_integration_conn_tenant_name"),
    )
    op.create_index("ix_integration_conn_tenant",
                    "integration_connections", ["tenant_id"])
    op.create_index("ix_integration_conn_name",
                    "integration_connections", ["name"])


def downgrade() -> None:
    op.drop_index("ix_integration_conn_name", table_name="integration_connections")
    op.drop_index("ix_integration_conn_tenant", table_name="integration_connections")
    op.drop_table("integration_connections")
