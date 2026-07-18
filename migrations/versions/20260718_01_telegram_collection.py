"""telegram intelligence: collection + alerting tables (v0.11.0)

Revision ID: 20260718_01_tgcoll
Revises: 20260711_01_case_reviews
Create Date: 2026-07-18 (corrective revision of the Phase 1 delivery)

Creates the provider-neutral collection & alerting schema for the Telegram
Intelligence feature:

    collection_connection, collection_source, collection_event,
    collection_source_test_request, tenant_alert_channel, alert_outbox

Corrective audit findings incorporated:
  C1 — the Bot API cursor lives on ``collection_connection`` (shared by all
       sources of the connection), not on ``collection_source``.
  C2 — history preservation: connection→source, source→event,
       connection→test_request and channel→outbox use ON DELETE RESTRICT
       (never CASCADE); ``collection_source.enabled`` added.
  C3 — ``secret_refs`` (opaque Secret Resolver references) on
       ``collection_connection`` and ``tenant_alert_channel``.
  C8 — analysis state machine columns on ``collection_event``.

PostgreSQL/SQLite compatible; partial unique indexes for soft delete.
"""
from alembic import op
import sqlalchemy as sa


revision = "20260718_01_tgcoll"
down_revision = "20260711_01_case_reviews"
branch_labels = None
depends_on = None


def _is_sqlite() -> bool:
    return op.get_bind().dialect.name == "sqlite"


def upgrade() -> None:
    false_default = sa.text("0") if _is_sqlite() else sa.text("false")

    # ---- collection_connection -------------------------------------------
    op.create_table(
        "collection_connection",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=false_default),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("provider_account_ref", sa.String(length=128), nullable=True),
        sa.Column("cursor", sa.String(length=190), nullable=True),   # C1
        sa.Column("config_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("secret_refs", sa.JSON, nullable=False, server_default="{}"),  # C3
        sa.Column("secrets_metadata", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(length=255), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(length=255), nullable=True),
        sa.CheckConstraint("status IN ('pending','active','revoked')",
                           name="ck_coll_conn_status"),
        sa.UniqueConstraint("id", "tenant_id", name="uq_coll_conn_id_tenant"),
    )
    op.create_index("ix_coll_conn_tenant", "collection_connection", ["tenant_id"])
    op.create_index("ix_coll_conn_provider", "collection_connection", ["provider"])
    op.create_index(
        "uq_coll_conn_tenant_name_live", "collection_connection", ["tenant_id", "name"],
        unique=True, sqlite_where=sa.text("deleted_at IS NULL"),
        postgresql_where=sa.text("deleted_at IS NULL"),
    )
    op.create_index(
        "uq_coll_conn_active_identity", "collection_connection",
        ["provider", "provider_account_ref"], unique=True,
        sqlite_where=sa.text(
            "enabled = 1 AND deleted_at IS NULL AND provider_account_ref IS NOT NULL"),
        postgresql_where=sa.text(
            "enabled = true AND deleted_at IS NULL AND provider_account_ref IS NOT NULL"),
    )

    # ---- collection_source -----------------------------------------------
    op.create_table(
        "collection_source",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("connection_id", sa.Integer, nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("source_ref", sa.String(length=160), nullable=False),
        sa.Column("kind", sa.String(length=30), nullable=False, server_default="channel"),
        sa.Column("name", sa.String(length=120), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=false_default),  # C2
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("config_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(length=255), nullable=True),
        sa.CheckConstraint("status IN ('pending','active','paused','revoked')",
                           name="ck_coll_source_status"),
        sa.ForeignKeyConstraint(
            ["connection_id", "tenant_id"],
            ["collection_connection.id", "collection_connection.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_source_conn_same_tenant"),  # C2
        sa.UniqueConstraint("id", "tenant_id", name="uq_coll_source_id_tenant"),
        sa.UniqueConstraint("id", "connection_id", "tenant_id",
                            name="uq_coll_source_id_conn_tenant"),
    )
    op.create_index("ix_coll_source_tenant", "collection_source", ["tenant_id"])
    op.create_index("ix_coll_source_conn", "collection_source", ["connection_id"])
    op.create_index(
        "uq_coll_source_ref_live", "collection_source",
        ["tenant_id", "connection_id", "source_ref"], unique=True,
        sqlite_where=sa.text("deleted_at IS NULL"),
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # ---- collection_event ------------------------------------------------
    op.create_table(
        "collection_event",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_id", sa.Integer, nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("external_id_hash", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("processing_state", sa.String(length=20), nullable=False,
                  server_default="received"),
        sa.Column("normalized_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("raw_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("content_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("redaction_profile", sa.String(length=40), nullable=False,
                  server_default="default"),
        sa.Column("redacted_text", sa.Text, nullable=True),
        sa.Column("context_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_control", sa.Boolean, nullable=False, server_default=false_default),
        sa.Column("control_nonce_hash", sa.String(length=64), nullable=True),
        sa.Column("rejection_reason", sa.String(length=60), nullable=True),
        sa.Column("finding_id", sa.Integer,
                  sa.ForeignKey("exposure_finding.id", ondelete="SET NULL"), nullable=True),
        sa.Column("case_id", sa.Integer,
                  sa.ForeignKey("investigation_cases.id", ondelete="SET NULL"), nullable=True),
        # C8 — analysis state machine
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_by", sa.String(length=80), nullable=True),
        sa.Column("locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=60), nullable=True),
        sa.Column("analysis_version", sa.String(length=40), nullable=True),
        sa.Column("analysis_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("legal_hold", sa.Boolean, nullable=False, server_default=false_default),
        sa.Column("retention_policy", sa.String(length=60), nullable=True),
        sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(
            "processing_state IN ('received','normalized','control','rejected',"
            "'dead_letter','analyzing','analyzed','failed')",
            name="ck_coll_event_state"),
        sa.CheckConstraint("attempts >= 0", name="ck_coll_event_attempts"),
        sa.ForeignKeyConstraint(
            ["source_id", "tenant_id"],
            ["collection_source.id", "collection_source.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_event_source_same_tenant"),
    )
    op.create_index("ix_coll_event_tenant", "collection_event", ["tenant_id"])
    op.create_index("ix_coll_event_source", "collection_event", ["source_id"])
    op.create_index("ix_coll_event_state", "collection_event", ["processing_state"])
    op.create_index("ix_coll_event_finding", "collection_event", ["finding_id"])
    op.create_index("ix_coll_event_next", "collection_event", ["next_attempt_at"])
    op.create_index("ix_coll_event_locked", "collection_event", ["locked_at"])
    op.create_index(
        "uq_coll_event_external", "collection_event",
        ["tenant_id", "source_id", "external_id_hash"], unique=True,
        sqlite_where=sa.text("external_id_hash <> '' AND processing_state <> 'rejected'"),
        postgresql_where=sa.text("external_id_hash <> '' AND processing_state <> 'rejected'"),
    )

    # ---- collection_source_test_request ----------------------------------
    op.create_table(
        "collection_source_test_request",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("connection_id", sa.Integer, nullable=False),
        sa.Column("source_id", sa.Integer, nullable=True),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("telemetry_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('pending','awaiting','verified','failed','expired')",
            name="ck_coll_test_status"),
        sa.UniqueConstraint("tenant_id", "nonce_hash", name="uq_coll_test_nonce"),
        sa.ForeignKeyConstraint(
            ["connection_id", "tenant_id"],
            ["collection_connection.id", "collection_connection.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_test_conn_same_tenant"),
        sa.ForeignKeyConstraint(
            ["source_id", "connection_id", "tenant_id"],
            ["collection_source.id", "collection_source.connection_id",
             "collection_source.tenant_id"],
            ondelete="RESTRICT", name="fk_coll_test_source_same_scope"),
    )
    op.create_index("ix_coll_test_tenant", "collection_source_test_request", ["tenant_id"])
    op.create_index("ix_coll_test_conn", "collection_source_test_request", ["connection_id"])
    op.create_index("ix_coll_test_status", "collection_source_test_request", ["status"])

    # ---- tenant_alert_channel --------------------------------------------
    op.create_table(
        "tenant_alert_channel",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("channel_type", sa.String(length=20), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=false_default),
        sa.Column("config_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("secret_refs", sa.JSON, nullable=False, server_default="{}"),  # C3
        sa.Column("secrets_metadata", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(length=255), nullable=True),
        sa.UniqueConstraint("id", "tenant_id", name="uq_alert_channel_id_tenant"),
    )
    op.create_index("ix_alert_channel_tenant", "tenant_alert_channel", ["tenant_id"])
    op.create_index(
        "uq_alert_channel_name_live", "tenant_alert_channel", ["tenant_id", "name"],
        unique=True, sqlite_where=sa.text("deleted_at IS NULL"),
        postgresql_where=sa.text("deleted_at IS NULL"),
    )

    # ---- alert_outbox ----------------------------------------------------
    op.create_table(
        "alert_outbox",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("alert_channel_id", sa.Integer, nullable=False),
        sa.Column("finding_id", sa.Integer,
                  sa.ForeignKey("exposure_finding.id", ondelete="SET NULL"), nullable=True),
        sa.Column("external_channel_ref", sa.String(length=190), nullable=True),
        sa.Column("template", sa.String(length=80), nullable=False),
        sa.Column("template_version", sa.String(length=40), nullable=False, server_default="1"),
        sa.Column("dedup_key", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=60), nullable=True),
        sa.Column("payload_json", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.CheckConstraint(
            "status IN ('pending','sending','delivered','failed','dead_letter')",
            name="ck_alert_outbox_status"),
        sa.UniqueConstraint("dedup_key", name="uq_alert_outbox_dedup"),
        sa.ForeignKeyConstraint(
            ["alert_channel_id", "tenant_id"],
            ["tenant_alert_channel.id", "tenant_alert_channel.tenant_id"],
            ondelete="RESTRICT", name="fk_alert_outbox_channel_same_tenant"),  # C2
    )
    op.create_index("ix_alert_outbox_tenant", "alert_outbox", ["tenant_id"])
    op.create_index("ix_alert_outbox_channel", "alert_outbox", ["alert_channel_id"])
    op.create_index("ix_alert_outbox_status", "alert_outbox", ["status"])
    op.create_index("ix_alert_outbox_next", "alert_outbox", ["next_attempt_at"])


def downgrade() -> None:
    op.drop_table("alert_outbox")
    op.drop_table("tenant_alert_channel")
    op.drop_table("collection_source_test_request")
    op.drop_table("collection_event")
    op.drop_table("collection_source")
    op.drop_table("collection_connection")
