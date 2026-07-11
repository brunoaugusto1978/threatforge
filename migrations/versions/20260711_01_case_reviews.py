"""case reviews

Revision ID: 20260711_01_case_reviews
Revises: 20260706_01_intconn
Create Date: 2026-07-11
"""
from alembic import op
import sqlalchemy as sa


revision = "20260711_01_case_reviews"
down_revision = "20260706_01_intconn"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_reviews",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("review_status", sa.String(length=30), nullable=False),
        sa.Column("reviewer_user_id", sa.Integer(), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "review_status IN ('not_reviewed','in_review','needs_changes','approved','rejected')",
            name="ck_case_review_status",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["case_id"], ["investigation_cases.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewer_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_reviews_tenant", "case_reviews", ["tenant_id"])
    op.create_index("ix_case_reviews_case", "case_reviews", ["case_id"])
    op.create_index("ix_case_reviews_status", "case_reviews", ["review_status"])
    op.create_index("ix_case_reviews_reviewer", "case_reviews", ["reviewer_user_id"])
    op.create_index("ix_case_reviews_created", "case_reviews", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_case_reviews_created", table_name="case_reviews")
    op.drop_index("ix_case_reviews_reviewer", table_name="case_reviews")
    op.drop_index("ix_case_reviews_status", table_name="case_reviews")
    op.drop_index("ix_case_reviews_case", table_name="case_reviews")
    op.drop_index("ix_case_reviews_tenant", table_name="case_reviews")
    op.drop_table("case_reviews")
