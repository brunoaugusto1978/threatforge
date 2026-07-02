-- ThreatForge — attack surface discovery (surface_asset). PostgreSQL.
BEGIN;
CREATE TABLE IF NOT EXISTS surface_asset (
  id                 SERIAL PRIMARY KEY,
  tenant_id          integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  brand_id           integer REFERENCES brands(id) ON DELETE SET NULL,
  asset_type         varchar(20)  NOT NULL,
  value              varchar(512) NOT NULL,
  value_hash         varchar(64)  NOT NULL,
  parent_id          integer REFERENCES surface_asset(id) ON DELETE SET NULL,
  source             varchar(40)  NOT NULL DEFAULT 'manual_import',
  detail             jsonb NOT NULL DEFAULT '{}'::jsonb,
  status             varchar(20)  NOT NULL DEFAULT 'new',
  first_seen         timestamptz NOT NULL DEFAULT now(),
  last_seen          timestamptz NOT NULL DEFAULT now(),
  dedup_key          varchar(64)  NOT NULL,
  risk_score         integer NOT NULL DEFAULT 0,
  created_by_user_id integer REFERENCES users(id) ON DELETE SET NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_surface_type   CHECK (asset_type IN ('subdomain','ip','certificate','netblock','port','service')),
  CONSTRAINT ck_surface_status CHECK (status IN ('new','confirmed','ignored','resolved')),
  CONSTRAINT ck_surface_source CHECK (source IN ('ct_log','dns','rdap','tls','manual_import','active_scan')),
  CONSTRAINT uq_surface_dedup  UNIQUE (tenant_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS ix_surface_tenant  ON surface_asset (tenant_id);
CREATE INDEX IF NOT EXISTS ix_surface_brand   ON surface_asset (brand_id);
CREATE INDEX IF NOT EXISTS ix_surface_type    ON surface_asset (asset_type);
CREATE INDEX IF NOT EXISTS ix_surface_hash    ON surface_asset (value_hash);
CREATE INDEX IF NOT EXISTS ix_surface_parent  ON surface_asset (parent_id);
CREATE INDEX IF NOT EXISTS ix_surface_created ON surface_asset (created_at);
COMMIT;
