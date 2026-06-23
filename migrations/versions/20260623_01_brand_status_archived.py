"""brand status + archived_at (archive/delete feature)

Adiciona brands.status (active|archived) com backfill 'active' e CHECK constraint,
e brands.archived_at. Compatível com PostgreSQL e SQLite (batch mode).

Revision ID: 20260623_01_brandstatus
Revises:  (defina down_revision para o head atual do seu projeto; None = primeira)
"""
from alembic import op
import sqlalchemy as sa

revision = "20260623_01_brandstatus"
down_revision = None  # AJUSTE para o head atual se já houver migrações
branch_labels = None
depends_on = None


def upgrade() -> None:
    # coluna status com default no banco -> backfill automático de linhas existentes
    op.add_column("brands", sa.Column("status", sa.String(length=20),
                                      nullable=False, server_default="active"))
    op.add_column("brands", sa.Column("archived_at", sa.DateTime(timezone=True),
                                      nullable=True))
    # backfill explícito (defensivo)
    op.execute("UPDATE brands SET status = 'active' WHERE status IS NULL")
    # constraint de valores válidos (batch_alter_table => funciona no SQLite tb)
    with op.batch_alter_table("brands") as batch:
        batch.create_check_constraint("ck_brands_status", "status IN ('active', 'archived')")


def downgrade() -> None:
    with op.batch_alter_table("brands") as batch:
        batch.drop_constraint("ck_brands_status", type_="check")
    op.drop_column("brands", "archived_at")
    op.drop_column("brands", "status")
