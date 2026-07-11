from __future__ import annotations

import importlib.util
from pathlib import Path

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations


def _load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "migrations"
        / "versions"
        / "20260711_01_case_reviews.py"
    )
    spec = importlib.util.spec_from_file_location("case_reviews_migration", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_upgrade(conn, migration) -> None:
    ctx = MigrationContext.configure(conn)
    operations = Operations(ctx)

    old_op = migration.op
    migration.op = operations
    try:
        migration.upgrade()
    finally:
        migration.op = old_op


def _create_referenced_tables(conn) -> None:
    metadata = sa.MetaData()

    sa.Table("tenants", metadata, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table("users", metadata, sa.Column("id", sa.Integer, primary_key=True))
    sa.Table(
        "investigation_cases",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
    )

    metadata.create_all(conn)


def _create_existing_case_reviews_with_model_style_indexes(conn) -> None:
    metadata = sa.MetaData()

    case_reviews = sa.Table(
        "case_reviews",
        metadata,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer, nullable=False),
        sa.Column("case_id", sa.Integer, nullable=False),
        sa.Column("review_status", sa.String(30), nullable=False),
        sa.Column("reviewer_user_id", sa.Integer, nullable=True),
        sa.Column("created_by_user_id", sa.Integer, nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
    )

    sa.Index("ix_case_reviews_tenant_id", case_reviews.c.tenant_id)
    sa.Index("ix_case_reviews_case_id", case_reviews.c.case_id)
    sa.Index("ix_case_reviews_review_status", case_reviews.c.review_status)
    sa.Index("ix_case_reviews_reviewer_user_id", case_reviews.c.reviewer_user_id)
    sa.Index("ix_case_reviews_created_at", case_reviews.c.created_at)

    metadata.create_all(conn)


def test_case_reviews_migration_creates_table_on_clean_database():
    engine = sa.create_engine("sqlite:///:memory:")
    migration = _load_migration()

    with engine.begin() as conn:
        _create_referenced_tables(conn)

        _run_upgrade(conn, migration)

        inspector = sa.inspect(conn)
        assert inspector.has_table("case_reviews")

        columns = {col["name"] for col in inspector.get_columns("case_reviews")}
        assert {
            "id",
            "tenant_id",
            "case_id",
            "review_status",
            "reviewer_user_id",
            "created_by_user_id",
            "notes",
            "created_at",
            "reviewed_at",
        }.issubset(columns)

        indexed_columns = {
            tuple(idx.get("column_names") or ())
            for idx in inspector.get_indexes("case_reviews")
        }
        assert ("tenant_id",) in indexed_columns
        assert ("case_id",) in indexed_columns
        assert ("review_status",) in indexed_columns
        assert ("reviewer_user_id",) in indexed_columns
        assert ("created_at",) in indexed_columns


def test_case_reviews_migration_skips_existing_table_without_duplicate_indexes():
    engine = sa.create_engine("sqlite:///:memory:")
    migration = _load_migration()

    with engine.begin() as conn:
        _create_referenced_tables(conn)
        _create_existing_case_reviews_with_model_style_indexes(conn)

        _run_upgrade(conn, migration)

        inspector = sa.inspect(conn)
        names = {idx.get("name") for idx in inspector.get_indexes("case_reviews")}

        assert "ix_case_reviews_tenant_id" in names
        assert "ix_case_reviews_case_id" in names
        assert "ix_case_reviews_review_status" in names
        assert "ix_case_reviews_reviewer_user_id" in names
        assert "ix_case_reviews_created_at" in names

        assert "ix_case_reviews_tenant" not in names
        assert "ix_case_reviews_case" not in names
        assert "ix_case_reviews_status" not in names
        assert "ix_case_reviews_reviewer" not in names
        assert "ix_case_reviews_created" not in names
