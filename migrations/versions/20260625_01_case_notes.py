"""case_notes table (analyst notes)

Revision ID: 20260625_01_casenotes
Revises: 20260624_01_cases  (ajuste se o head do projeto for outro)
"""
from alembic import op
import sqlalchemy as sa

revision = "20260625_01_casenotes"
down_revision = "20260624_01_cases"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "case_notes",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("tenant_id", sa.Integer,
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.Integer,
                  sa.ForeignKey("investigation_cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("author_user_id", sa.Integer,
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("is_internal", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )
    op.create_index("ix_case_notes_tenant", "case_notes", ["tenant_id"])
    op.create_index("ix_case_notes_case", "case_notes", ["case_id"])
    op.create_index("ix_case_notes_created", "case_notes", ["created_at"])


def downgrade() -> None:
    op.drop_table("case_notes")
