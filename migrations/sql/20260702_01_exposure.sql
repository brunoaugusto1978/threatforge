-- ThreatForge — exposure monitoring (monitored_asset + exposure_finding). PostgreSQL.
BEGIN;
CREATE TABLE IF NOT EXISTS monitored_asset (
  id                 SERIAL PRIMARY KEY,
  tenant_id          integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  asset_type         varchar(30)  NOT NULL,
  label              varchar(200) NOT NULL,
  value              varchar(512) NOT NULL,
  value_hash         varchar(64)  NOT NULL,
  criticality        varchar(10)  NOT NULL DEFAULT 'medium',
  consent_ref        varchar(200),
  active             boolean NOT NULL DEFAULT true,
  created_by_user_id integer REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_monitored_asset_type CHECK (asset_type IN ('identity','email','domain','keyword','secret_pattern','repo','ip_range')),
  CONSTRAINT ck_monitored_asset_crit CHECK (criticality IN ('low','medium','high','critical'))
);
CREATE INDEX IF NOT EXISTS ix_monitored_asset_tenant ON monitored_asset (tenant_id);
CREATE INDEX IF NOT EXISTS ix_monitored_asset_hash   ON monitored_asset (value_hash);
CREATE INDEX IF NOT EXISTS ix_monitored_asset_type   ON monitored_asset (asset_type);

CREATE TABLE IF NOT EXISTS exposure_finding (
  id                 SERIAL PRIMARY KEY,
  tenant_id          integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  exposure_type      varchar(40) NOT NULL,
  asset_id           integer REFERENCES monitored_asset(id) ON DELETE SET NULL,
  title              varchar(300) NOT NULL,
  source             varchar(60)  NOT NULL,
  source_reliability varchar(1)   NOT NULL DEFAULT 'F',
  info_credibility   varchar(1)   NOT NULL DEFAULT '6',
  severity           varchar(10)  NOT NULL DEFAULT 'medium',
  status             varchar(20)  NOT NULL DEFAULT 'new',
  observed_at        timestamptz,
  first_seen         timestamptz NOT NULL DEFAULT now(),
  last_seen          timestamptz NOT NULL DEFAULT now(),
  dedup_key          varchar(64) NOT NULL,
  detail             jsonb NOT NULL DEFAULT '{}'::jsonb,
  redacted           boolean NOT NULL DEFAULT false,
  risk_score         integer NOT NULL DEFAULT 0,
  created_by_user_id integer REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_exposure_type CHECK (exposure_type IN ('identity_exposure','credential_exposure','brand_exposure','infrastructure_exposure','secret_exposure','source_code_exposure')),
  CONSTRAINT ck_exposure_reliability CHECK (source_reliability IN ('A','B','C','D','E','F')),
  CONSTRAINT ck_exposure_credibility CHECK (info_credibility IN ('1','2','3','4','5','6')),
  CONSTRAINT ck_exposure_severity CHECK (severity IN ('low','medium','high','critical')),
  CONSTRAINT ck_exposure_status CHECK (status IN ('new','triaging','confirmed','mitigated','closed','false_positive','duplicate')),
  CONSTRAINT uq_exposure_dedup UNIQUE (tenant_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS ix_exposure_tenant  ON exposure_finding (tenant_id);
CREATE INDEX IF NOT EXISTS ix_exposure_type    ON exposure_finding (exposure_type);
CREATE INDEX IF NOT EXISTS ix_exposure_asset   ON exposure_finding (asset_id);
CREATE INDEX IF NOT EXISTS ix_exposure_dedup   ON exposure_finding (dedup_key);
CREATE INDEX IF NOT EXISTS ix_exposure_created ON exposure_finding (created_at);
COMMIT;
