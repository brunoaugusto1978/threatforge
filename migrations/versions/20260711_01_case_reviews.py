"""case reviews

Revision ID: 20260711_01_case_reviews
Revises: 20260706_01_intconn
Create Date: 2026-07-11

This migration is intentionally idempotent for existing POC databases where
SQLAlchemy metadata may already have created case_reviews before Alembic was
stamped. New installs still create the table through Alembic; existing installs
skip table creation and only add missing indexes when needed.
"""

from alembic import op
import sqlalchemy as sa


revision = "20260711_01_case_reviews"
down_revision = "20260706_01_intconn"
branch_labels = None
depends_on = None


_TABLE = "case_reviews"

_REVIEW_STATUSES = (
    "not_reviewed",
    "in_review",
    "needs_changes",
    "approved",
    "rejected",
)

_INDEXES = (
    ("ix_case_reviews_tenant", ("tenant_id",)),
    ("ix_case_reviews_case", ("case_id",)),
    ("ix_case_reviews_status", ("review_status",)),
    ("ix_case_reviews_reviewer", ("reviewer_user_id",)),
    ("ix_case_reviews_created", ("created_at",)),
)


def _table_exists(bind) -> bool:
    return sa.inspect(bind).has_table(_TABLE)


def _index_on_columns_exists(inspector, columns: tuple[str, ...]) -> bool:
    for idx in inspector.get_indexes(_TABLE):
        if tuple(idx.get("column_names") or ()) == columns:
            return True
    return False


def _create_missing_indexes(bind) -> None:
    inspector = sa.inspect(bind)
    existing_names = {idx.get("name") for idx in inspector.get_indexes(_TABLE)}

    for name, columns in _INDEXES:
        if name in existing_names:
            continue
        if _index_on_columns_exists(inspector, columns):
            continue
        op.create_index(name, _TABLE, list(columns))


def upgrade() -> None:
    bind = op.get_bind()

    if not _table_exists(bind):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.Integer(),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "case_id",
                sa.Integer(),
                sa.ForeignKey("investigation_cases.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("review_status", sa.String(length=30), nullable=False),
            sa.Column(
                "reviewer_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "created_by_user_id",
                sa.Integer(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "reviewed_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.CheckConstraint(
                "review_status IN "
                + str(_REVIEW_STATUSES).replace('"', "'"),
                name="ck_case_review_status",
            ),
        )

    _create_missing_indexes(bind)


def downgrade() -> None:
    bind = op.get_bind()

    if _table_exists(bind):
        inspector = sa.inspect(bind)
        existing_names = {idx.get("name") for idx in inspector.get_indexes(_TABLE)}

        for name, _columns in reversed(_INDEXES):
            if name in existing_names:
                op.drop_index(name, table_name=_TABLE)

        op.drop_table(_TABLE)
