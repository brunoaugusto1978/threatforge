-- ThreatForge — Telegram Intelligence collection + alerting (v0.11.0). PostgreSQL.
-- Mirror of migrations/versions/20260718_01_telegram_collection.py.
BEGIN;

-- collection_connection ------------------------------------------------------
CREATE TABLE IF NOT EXISTS collection_connection (
  id                    SERIAL PRIMARY KEY,
  tenant_id             integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider              varchar(40)  NOT NULL,
  name                  varchar(80)  NOT NULL,
  enabled               boolean      NOT NULL DEFAULT false,          -- req #1
  status                varchar(20)  NOT NULL DEFAULT 'pending',
  provider_account_ref  varchar(128),                                 -- req #7
  cursor                varchar(190),                                 -- C1: shared bot cursor
  config_json           jsonb        NOT NULL DEFAULT '{}'::jsonb,    -- req #3
  secret_refs           jsonb        NOT NULL DEFAULT '{}'::jsonb,    -- C3: opaque refs
  secrets_metadata      jsonb        NOT NULL DEFAULT '{}'::jsonb,
  created_at            timestamptz  NOT NULL DEFAULT now(),
  updated_at            timestamptz  NOT NULL DEFAULT now(),
  created_by            varchar(255),
  revoked_at            timestamptz,
  revoked_by            varchar(255),
  deleted_at            timestamptz,                                  -- req #9
  deleted_by            varchar(255),
  CONSTRAINT ck_coll_conn_status CHECK (status IN ('pending','active','revoked')),
  CONSTRAINT uq_coll_conn_id_tenant UNIQUE (id, tenant_id)
);
CREATE INDEX IF NOT EXISTS ix_coll_conn_tenant   ON collection_connection (tenant_id);
CREATE INDEX IF NOT EXISTS ix_coll_conn_provider ON collection_connection (provider);
-- req #9: uniqueness applies to live rows only.
CREATE UNIQUE INDEX IF NOT EXISTS uq_coll_conn_tenant_name_live
  ON collection_connection (tenant_id, name) WHERE deleted_at IS NULL;
-- req #7: one ACTIVE connection per bot identity across ALL tenants.
CREATE UNIQUE INDEX IF NOT EXISTS uq_coll_conn_active_identity
  ON collection_connection (provider, provider_account_ref)
  WHERE enabled = true AND deleted_at IS NULL AND provider_account_ref IS NOT NULL;

-- collection_source ----------------------------------------------------------
CREATE TABLE IF NOT EXISTS collection_source (
  id            SERIAL PRIMARY KEY,
  tenant_id     integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connection_id integer NOT NULL,
  provider      varchar(40)  NOT NULL,
  source_ref    varchar(160) NOT NULL,
  kind          varchar(30)  NOT NULL DEFAULT 'channel',
  name          varchar(120),
  enabled       boolean      NOT NULL DEFAULT false,               -- C2
  status        varchar(20)  NOT NULL DEFAULT 'pending',
  config_json   jsonb        NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz  NOT NULL DEFAULT now(),
  updated_at    timestamptz  NOT NULL DEFAULT now(),
  created_by    varchar(255),
  deleted_at    timestamptz,
  deleted_by    varchar(255),
  CONSTRAINT ck_coll_source_status CHECK (status IN ('pending','active','paused','revoked')),
  CONSTRAINT uq_coll_source_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT uq_coll_source_id_conn_tenant UNIQUE (id, connection_id, tenant_id),
  CONSTRAINT fk_coll_source_conn_same_tenant
    FOREIGN KEY (connection_id, tenant_id)
    REFERENCES collection_connection (id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ix_coll_source_tenant ON collection_source (tenant_id);
CREATE INDEX IF NOT EXISTS ix_coll_source_conn   ON collection_source (connection_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_coll_source_ref_live
  ON collection_source (tenant_id, connection_id, source_ref) WHERE deleted_at IS NULL;

-- collection_event -----------------------------------------------------------
CREATE TABLE IF NOT EXISTS collection_event (
  id                     SERIAL PRIMARY KEY,
  tenant_id              integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_id              integer NOT NULL REFERENCES collection_source(id) ON DELETE RESTRICT,
  provider               varchar(40) NOT NULL,
  external_id_hash       varchar(64) NOT NULL DEFAULT '',
  processing_state       varchar(20) NOT NULL DEFAULT 'received',
  normalized_fingerprint varchar(64),                                -- req #10
  raw_fingerprint        varchar(64),
  content_version        integer NOT NULL DEFAULT 1,
  redaction_profile      varchar(40) NOT NULL DEFAULT 'default',
  redacted_text          text,                                       -- req #11 (purged)
  context_json           jsonb NOT NULL DEFAULT '{}'::jsonb,         -- req #11 (purged)
  occurred_at            timestamptz,
  is_control             boolean NOT NULL DEFAULT false,             -- req #6
  control_nonce_hash     varchar(64),
  rejection_reason       varchar(60),                                -- req #8
  finding_id             integer REFERENCES exposure_finding(id) ON DELETE SET NULL,
  case_id                integer REFERENCES investigation_cases(id) ON DELETE SET NULL,
  attempts               integer NOT NULL DEFAULT 0,                 -- C8
  next_attempt_at        timestamptz,                                -- C8
  locked_by              varchar(80),                                -- C8
  locked_at              timestamptz,                                -- C8
  processed_at           timestamptz,                                -- C8
  error_code             varchar(60),                                -- C8
  analysis_version       varchar(40),                                -- C8
  analysis_json          jsonb NOT NULL DEFAULT '{}'::jsonb,         -- C8
  legal_hold             boolean NOT NULL DEFAULT false,             -- req #11
  retention_policy       varchar(60),                                -- req #11
  purged_at              timestamptz,                                -- req #11
  created_at             timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_coll_event_state CHECK (
    processing_state IN ('received','normalized','control','rejected','dead_letter','analyzing','analyzed','failed')),
  CONSTRAINT ck_coll_event_attempts CHECK (attempts >= 0),
  CONSTRAINT fk_coll_event_source_same_tenant
    FOREIGN KEY (source_id, tenant_id)
    REFERENCES collection_source (id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ix_coll_event_tenant  ON collection_event (tenant_id);
CREATE INDEX IF NOT EXISTS ix_coll_event_source  ON collection_event (source_id);
CREATE INDEX IF NOT EXISTS ix_coll_event_state   ON collection_event (processing_state);
CREATE INDEX IF NOT EXISTS ix_coll_event_finding ON collection_event (finding_id);
CREATE INDEX IF NOT EXISTS ix_coll_event_next    ON collection_event (next_attempt_at);
CREATE INDEX IF NOT EXISTS ix_coll_event_locked  ON collection_event (locked_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_coll_event_external
  ON collection_event (tenant_id, source_id, external_id_hash)
  WHERE external_id_hash <> '' AND processing_state <> 'rejected';

-- collection_source_test_request --------------------------------------------
CREATE TABLE IF NOT EXISTS collection_source_test_request (
  id            SERIAL PRIMARY KEY,
  tenant_id     integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connection_id integer NOT NULL REFERENCES collection_connection(id) ON DELETE RESTRICT,
  source_id     integer REFERENCES collection_source(id) ON DELETE SET NULL,
  provider      varchar(40) NOT NULL,
  nonce_hash    varchar(64) NOT NULL,                                -- req #6 (hash only)
  status        varchar(20) NOT NULL DEFAULT 'pending',
  requested_by  varchar(255),
  requested_at  timestamptz NOT NULL DEFAULT now(),
  verified_at   timestamptz,
  expires_at    timestamptz,
  telemetry_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_coll_test_status CHECK (
    status IN ('pending','awaiting','verified','failed','expired')),
  CONSTRAINT uq_coll_test_nonce UNIQUE (tenant_id, nonce_hash),
  CONSTRAINT fk_coll_test_conn_same_tenant
    FOREIGN KEY (connection_id, tenant_id)
    REFERENCES collection_connection (id, tenant_id) ON DELETE RESTRICT,
  CONSTRAINT fk_coll_test_source_same_scope
    FOREIGN KEY (source_id, connection_id, tenant_id)
    REFERENCES collection_source (id, connection_id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ix_coll_test_tenant ON collection_source_test_request (tenant_id);
CREATE INDEX IF NOT EXISTS ix_coll_test_conn   ON collection_source_test_request (connection_id);
CREATE INDEX IF NOT EXISTS ix_coll_test_status ON collection_source_test_request (status);

-- tenant_alert_channel -------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenant_alert_channel (
  id            SERIAL PRIMARY KEY,
  tenant_id     integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name          varchar(80) NOT NULL,
  channel_type  varchar(20) NOT NULL,
  enabled       boolean NOT NULL DEFAULT false,
  config_json   jsonb NOT NULL DEFAULT '{}'::jsonb,                  -- req #3
  secret_refs   jsonb NOT NULL DEFAULT '{}'::jsonb,                  -- C3: opaque refs
  secrets_metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  created_by    varchar(255),
  deleted_at    timestamptz,
  deleted_by    varchar(255),
  CONSTRAINT uq_alert_channel_id_tenant UNIQUE (id, tenant_id)
);
CREATE INDEX IF NOT EXISTS ix_alert_channel_tenant ON tenant_alert_channel (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_channel_name_live
  ON tenant_alert_channel (tenant_id, name) WHERE deleted_at IS NULL;

-- alert_outbox ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alert_outbox (
  id                   SERIAL PRIMARY KEY,
  tenant_id            integer NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_channel_id     integer NOT NULL,                             -- req #2 (FK below)
  finding_id           integer REFERENCES exposure_finding(id) ON DELETE SET NULL,
  external_channel_ref varchar(190),                                 -- req #2 (additive only)
  template             varchar(80) NOT NULL,
  template_version     varchar(40) NOT NULL DEFAULT '1',
  dedup_key            varchar(64) NOT NULL,                         -- req #5
  status               varchar(20) NOT NULL DEFAULT 'pending',       -- req #4 (column)
  attempts             integer NOT NULL DEFAULT 0,                   -- req #4
  next_attempt_at      timestamptz,                                  -- req #4
  delivered_at         timestamptz,                                  -- req #4
  error_code           varchar(60),                                  -- req #4
  payload_json         jsonb NOT NULL DEFAULT '{}'::jsonb,           -- req #4 (no delivery_state)
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_alert_outbox_status CHECK (
    status IN ('pending','sending','delivered','failed','dead_letter')),
  CONSTRAINT uq_alert_outbox_dedup UNIQUE (dedup_key),
  CONSTRAINT fk_alert_outbox_channel_same_tenant
    FOREIGN KEY (alert_channel_id, tenant_id)
    REFERENCES tenant_alert_channel (id, tenant_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ix_alert_outbox_tenant  ON alert_outbox (tenant_id);
CREATE INDEX IF NOT EXISTS ix_alert_outbox_channel ON alert_outbox (alert_channel_id);
CREATE INDEX IF NOT EXISTS ix_alert_outbox_status  ON alert_outbox (status);
CREATE INDEX IF NOT EXISTS ix_alert_outbox_next    ON alert_outbox (next_attempt_at);

COMMIT;
