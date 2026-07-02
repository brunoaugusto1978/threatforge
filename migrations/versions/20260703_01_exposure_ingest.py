"""exposure ingestion provenance: exposure_ingest_batch + finding provenance cols

Revision ID: 20260703_01_ingest
Revises: 20260702_01_exposure
"""
from alembic import op
import sqlalchemy as sa

revision = "20260703_01_ingest"
down_revision = "20260702_01_exposure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "exposure_ingest_batch",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(length=40), nullable=False),
        sa.Column("original_filename", sa.String(length=512), nullable=True),
        sa.Column("source_file_hash", sa.String(length=64), nullable=True),
        sa.Column("parser", sa.String(length=60), nullable=False),
        sa.Column("parser_version", sa.String(length=20), nullable=False),
        sa.Column("record_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("created_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("deduped_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="completed"),
        sa.Column("created_by_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("source IN ('manual_intake','authorized_upload','file_import')",
                           name="ck_ingest_source"),
        sa.CheckConstraint("status IN ('processing','completed','rolled_back')",
                           name="ck_ingest_status"),
    )
    op.create_index("ix_ingest_tenant", "exposure_ingest_batch", ["tenant_id"])
    op.create_index("ix_ingest_created", "exposure_ingest_batch", ["created_at"])

    op.add_column("exposure_finding",
                  sa.Column("ingest_id", sa.Integer,
                            sa.ForeignKey("exposure_ingest_batch.id", ondelete="SET NULL"), nullable=True))
    op.add_column("exposure_finding", sa.Column("record_number", sa.Integer, nullable=True))
    op.add_column("exposure_finding", sa.Column("parser_version", sa.String(length=20), nullable=True))
    op.create_index("ix_exposure_ingest", "exposure_finding", ["ingest_id"])


def downgrade() -> None:
    op.drop_index("ix_exposure_ingest", table_name="exposure_finding")
    op.drop_column("exposure_finding", "parser_version")
    op.drop_column("exposure_finding", "record_number")
    op.drop_column("exposure_finding", "ingest_id")
    op.drop_table("exposure_ingest_batch")
