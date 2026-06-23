-- ThreatForge — migração: brands.status + archived_at (archive/delete)
-- PostgreSQL. Idempotente nas colunas; a constraint pode falhar se já existir.
BEGIN;

ALTER TABLE brands ADD COLUMN IF NOT EXISTS status varchar(20) NOT NULL DEFAULT 'active';
ALTER TABLE brands ADD COLUMN IF NOT EXISTS archived_at timestamptz;

-- backfill explícito
UPDATE brands SET status = 'active' WHERE status IS NULL;

-- aceitar apenas active|archived (use DROP CONSTRAINT antes se re-executar)
ALTER TABLE brands
  ADD CONSTRAINT ck_brands_status CHECK (status IN ('active', 'archived'));

COMMIT;
