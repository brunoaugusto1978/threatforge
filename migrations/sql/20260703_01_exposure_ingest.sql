-- ThreatForge — exposure ingestion provenance. PostgreSQL.
BEGIN;
CREATE TABLE IF NOT EXISTS exposure_ingest_batch (
  id                 SERIAL PRIMARY KEY,
  tenant_id          integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source             varchar(40)  NOT NULL,
  original_filename  varchar(512),
  source_file_hash   varchar(64),
  parser             varchar(60)  NOT NULL,
  parser_version     varchar(20)  NOT NULL,
  record_count       integer NOT NULL DEFAULT 0,
  created_count      integer NOT NULL DEFAULT 0,
  deduped_count      integer NOT NULL DEFAULT 0,
  error_count        integer NOT NULL DEFAULT 0,
  status             varchar(20)  NOT NULL DEFAULT 'completed',
  created_by_user_id integer REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_ingest_source CHECK (source IN ('manual_intake','authorized_upload','file_import')),
  CONSTRAINT ck_ingest_status CHECK (status IN ('processing','completed','rolled_back'))
);
CREATE INDEX IF NOT EXISTS ix_ingest_tenant  ON exposure_ingest_batch (tenant_id);
CREATE INDEX IF NOT EXISTS ix_ingest_created ON exposure_ingest_batch (created_at);

ALTER TABLE exposure_finding ADD COLUMN IF NOT EXISTS ingest_id integer REFERENCES exposure_ingest_batch(id) ON DELETE SET NULL;
ALTER TABLE exposure_finding ADD COLUMN IF NOT EXISTS record_number integer;
ALTER TABLE exposure_finding ADD COLUMN IF NOT EXISTS parser_version varchar(20);
CREATE INDEX IF NOT EXISTS ix_exposure_ingest ON exposure_finding (ingest_id);
COMMIT;
