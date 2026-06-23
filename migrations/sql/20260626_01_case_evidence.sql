-- ThreatForge — case_evidence (evidence attachments). PostgreSQL.
BEGIN;
CREATE TABLE IF NOT EXISTS case_evidence (
  id                  SERIAL PRIMARY KEY,
  tenant_id           integer NOT NULL REFERENCES tenants(id)              ON DELETE CASCADE,
  case_id             integer NOT NULL REFERENCES investigation_cases(id)  ON DELETE CASCADE,
  finding_id          integer          REFERENCES brand_findings(id)       ON DELETE SET NULL,
  filename            varchar(512) NOT NULL,
  mime_type           varchar(120) NOT NULL,
  size_bytes          integer NOT NULL,
  sha256              varchar(64)  NOT NULL,
  origin              varchar(30)  NOT NULL DEFAULT 'manual_upload',
  description         text,
  storage_backend     varchar(20)  NOT NULL DEFAULT 'local',
  storage_key         varchar(512),
  uploaded_by_user_id integer          REFERENCES users(id)                ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_evidence_origin  CHECK (origin IN ('manual_upload','authorized_export','whatsapp_intake','telegram_public','email','other')),
  CONSTRAINT ck_evidence_backend CHECK (storage_backend IN ('local','none'))
);
CREATE INDEX IF NOT EXISTS ix_evidence_tenant  ON case_evidence (tenant_id);
CREATE INDEX IF NOT EXISTS ix_evidence_case    ON case_evidence (case_id);
CREATE INDEX IF NOT EXISTS ix_evidence_finding ON case_evidence (finding_id);
CREATE INDEX IF NOT EXISTS ix_evidence_sha256  ON case_evidence (sha256);
CREATE INDEX IF NOT EXISTS ix_evidence_created ON case_evidence (created_at);
COMMIT;
