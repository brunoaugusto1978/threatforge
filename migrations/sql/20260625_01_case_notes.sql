-- ThreatForge — case_notes (analyst notes). PostgreSQL.
BEGIN;
CREATE TABLE IF NOT EXISTS case_notes (
  id              SERIAL PRIMARY KEY,
  tenant_id       integer NOT NULL REFERENCES tenants(id)              ON DELETE CASCADE,
  case_id         integer NOT NULL REFERENCES investigation_cases(id)  ON DELETE CASCADE,
  author_user_id  integer          REFERENCES users(id)                ON DELETE SET NULL,
  body            text    NOT NULL,
  is_internal     boolean NOT NULL DEFAULT true,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_case_notes_tenant  ON case_notes (tenant_id);
CREATE INDEX IF NOT EXISTS ix_case_notes_case    ON case_notes (case_id);
CREATE INDEX IF NOT EXISTS ix_case_notes_created ON case_notes (created_at);
COMMIT;
