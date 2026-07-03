-- ThreatForge — credential intelligence (credential_identity). PostgreSQL.
BEGIN;
CREATE TABLE IF NOT EXISTS credential_identity (
  id               SERIAL PRIMARY KEY,
  tenant_id        integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  identity_hash    varchar(64)  NOT NULL,
  email            varchar(320) NOT NULL,
  domain           varchar(255),
  leak_count       integer NOT NULL DEFAULT 0,
  password_hashes  jsonb NOT NULL DEFAULT '[]'::jsonb,
  sources          jsonb NOT NULL DEFAULT '[]'::jsonb,
  stealer_families jsonb NOT NULL DEFAULT '[]'::jsonb,
  first_seen       timestamptz NOT NULL DEFAULT now(),
  last_seen        timestamptz NOT NULL DEFAULT now(),
  vip_asset_id     integer REFERENCES monitored_asset(id) ON DELETE SET NULL,
  max_risk         integer NOT NULL DEFAULT 0,
  status           varchar(20) NOT NULL DEFAULT 'new',
  created_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_credid_status CHECK (status IN ('new','reviewing','mitigated','closed')),
  CONSTRAINT uq_credid_identity UNIQUE (tenant_id, identity_hash)
);
CREATE INDEX IF NOT EXISTS ix_credid_tenant ON credential_identity (tenant_id);
CREATE INDEX IF NOT EXISTS ix_credid_hash   ON credential_identity (identity_hash);
CREATE INDEX IF NOT EXISTS ix_credid_domain ON credential_identity (domain);
COMMIT;
