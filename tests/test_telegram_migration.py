from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa

MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations" / "versions" / "20260718_01_telegram_collection.py"
)
_TABLES = [
    "collection_connection", "collection_source", "collection_event",
    "collection_source_test_request", "tenant_alert_channel", "alert_outbox",
]


def _load():
    spec = importlib.util.spec_from_file_location("tg_migration", MIGRATION)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parents(conn):
    md = sa.MetaData()
    sa.Table("tenants", md, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table("exposure_finding", md, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table("investigation_cases", md, sa.Column("id", sa.Integer, primary_key=True))
    md.create_all(conn)


def _run(conn, mig, direction):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    ctx = MigrationContext.configure(conn)
    ops = Operations(ctx)
    old = mig.op
    mig.op = ops
    try:
        (mig.upgrade if direction == "up" else mig.downgrade)()
    finally:
        mig.op = old


def test_revision_chain():
    mig = _load()
    assert mig.revision == "20260718_01_tgcoll"
    assert mig.down_revision == "20260711_01_case_reviews"


def test_upgrade_creates_all_tables_and_partial_indexes():
    engine = sa.create_engine("sqlite:///:memory:")
    mig = _load()
    with engine.begin() as conn:
        _parents(conn)
        _run(conn, mig, "up")
        insp = sa.inspect(conn)
        for t in _TABLES:
            assert insp.has_table(t), t
        idx = {i["name"] for i in insp.get_indexes("collection_connection")}
        assert "uq_coll_conn_tenant_name_live" in idx
        assert "uq_coll_conn_active_identity" in idx
        # C1/C3 — cursor + secret_refs live on the connection
        conn_cols = {c["name"] for c in insp.get_columns("collection_connection")}
        assert {"cursor", "secret_refs"} <= conn_cols
        src_cols = {c["name"] for c in insp.get_columns("collection_source")}
        assert "cursor" not in src_cols and "enabled" in src_cols
        # C8 — analysis state machine columns
        ev_cols = {c["name"] for c in insp.get_columns("collection_event")}
        assert {"attempts", "next_attempt_at", "locked_by", "locked_at",
                "processed_at", "error_code", "analysis_version",
                "analysis_json"} <= ev_cols
        # C2 — RESTRICT (no cascade) on history-bearing FKs
        src_fks = insp.get_foreign_keys("collection_source")
        comp = [f for f in src_fks if set(f["constrained_columns"]) == {"connection_id", "tenant_id"}]
        assert comp and (comp[0]["options"].get("ondelete") or "").upper() == "RESTRICT"
        event_fks = insp.get_foreign_keys("collection_event")
        event_scope = [f for f in event_fks
                       if f["constrained_columns"] == ["source_id", "tenant_id"]]
        assert event_scope and event_scope[0]["referred_columns"] == ["id", "tenant_id"]
        test_fks = insp.get_foreign_keys("collection_source_test_request")
        assert any(f["constrained_columns"] == ["source_id", "connection_id", "tenant_id"]
                   for f in test_fks)
        channel_checks = {c["name"] for c in insp.get_check_constraints("tenant_alert_channel")}
        assert "ck_alert_channel_type" not in channel_checks
        outbox_idx = {i["name"] for i in insp.get_indexes("alert_outbox")}
        # dedup uniqueness present (as unique constraint or unique index)
        uconstraints = {c["name"] for c in insp.get_unique_constraints("alert_outbox")}
        assert "uq_alert_outbox_dedup" in (uconstraints | outbox_idx)


def test_downgrade_drops_all_tables():
    engine = sa.create_engine("sqlite:///:memory:")
    mig = _load()
    with engine.begin() as conn:
        _parents(conn)
        _run(conn, mig, "up")
        _run(conn, mig, "down")
        insp = sa.inspect(conn)
        for t in _TABLES:
            assert not insp.has_table(t), t
