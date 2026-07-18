-- ThreatForge — Telegram Intelligence collection + alerting (v0.11.0). SQLite mirror.
-- Mirror of migrations/versions/20260718_01_telegram_collection.py for SQLite.
-- Requires PRAGMA foreign_keys=ON (the app enables it on connect).
PRAGMA foreign_keys=ON;
BEGIN;

CREATE TABLE IF NOT EXISTS collection_connection (
  id                   INTEGER PRIMARY KEY,
  tenant_id            INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  provider             VARCHAR(40)  NOT NULL,
  name                 VARCHAR(80)  NOT NULL,
  enabled              BOOLEAN      NOT NULL DEFAULT 0,               -- req #1
  status               VARCHAR(20)  NOT NULL DEFAULT 'pending',
  provider_account_ref VARCHAR(128),                                 -- req #7
  "cursor"             VARCHAR(190),                                 -- C1: shared bot cursor
  config_json          JSON         NOT NULL DEFAULT '{}',           -- req #3
  secret_refs          JSON         NOT NULL DEFAULT '{}',           -- C3: opaque refs
  secrets_metadata     JSON         NOT NULL DEFAULT '{}',
  created_at           TIMESTAMP    NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  updated_at           TIMESTAMP    NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  created_by           VARCHAR(255),
  revoked_at           TIMESTAMP,
  revoked_by           VARCHAR(255),
  deleted_at           TIMESTAMP,                                    -- req #9
  deleted_by           VARCHAR(255),
  CONSTRAINT ck_coll_conn_status CHECK (status IN ('pending','active','revoked')),
  CONSTRAINT uq_coll_conn_id_tenant UNIQUE (id, tenant_id)
);
CREATE INDEX IF NOT EXISTS ix_coll_conn_tenant   ON collection_connection (tenant_id);
CREATE INDEX IF NOT EXISTS ix_coll_conn_provider ON collection_connection (provider);
CREATE UNIQUE INDEX IF NOT EXISTS uq_coll_conn_tenant_name_live
  ON collection_connection (tenant_id, name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_coll_conn_active_identity
  ON collection_connection (provider, provider_account_ref)
  WHERE enabled = 1 AND deleted_at IS NULL AND provider_account_ref IS NOT NULL;

CREATE TABLE IF NOT EXISTS collection_source (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connection_id INTEGER NOT NULL,
  provider      VARCHAR(40)  NOT NULL,
  source_ref    VARCHAR(160) NOT NULL,
  kind          VARCHAR(30)  NOT NULL DEFAULT 'channel',
  name          VARCHAR(120),
  enabled       BOOLEAN      NOT NULL DEFAULT 0,                   -- C2
  status        VARCHAR(20)  NOT NULL DEFAULT 'pending',
  config_json   JSON         NOT NULL DEFAULT '{}',
  created_at    TIMESTAMP    NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  updated_at    TIMESTAMP    NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  created_by    VARCHAR(255),
  deleted_at    TIMESTAMP,
  deleted_by    VARCHAR(255),
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

CREATE TABLE IF NOT EXISTS collection_event (
  id                     INTEGER PRIMARY KEY,
  tenant_id              INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  source_id              INTEGER NOT NULL,
  provider               VARCHAR(40) NOT NULL,
  external_id_hash       VARCHAR(64) NOT NULL DEFAULT '',
  processing_state       VARCHAR(20) NOT NULL DEFAULT 'received',
  normalized_fingerprint VARCHAR(64),                               -- req #10
  raw_fingerprint        VARCHAR(64),
  content_version        INTEGER NOT NULL DEFAULT 1,
  redaction_profile      VARCHAR(40) NOT NULL DEFAULT 'default',
  redacted_text          TEXT,                                      -- req #11 (purged)
  context_json           JSON NOT NULL DEFAULT '{}',                -- req #11 (purged)
  occurred_at            TIMESTAMP,
  is_control             BOOLEAN NOT NULL DEFAULT 0,                -- req #6
  control_nonce_hash     VARCHAR(64),
  rejection_reason       VARCHAR(60),                               -- req #8
  finding_id             INTEGER REFERENCES exposure_finding(id) ON DELETE SET NULL,
  case_id                INTEGER REFERENCES investigation_cases(id) ON DELETE SET NULL,
  attempts               INTEGER NOT NULL DEFAULT 0,                -- C8
  next_attempt_at        TIMESTAMP,                                 -- C8
  locked_by              VARCHAR(80),                               -- C8
  locked_at              TIMESTAMP,                                 -- C8
  processed_at           TIMESTAMP,                                 -- C8
  error_code             VARCHAR(60),                               -- C8
  analysis_version       VARCHAR(40),                               -- C8
  analysis_json          JSON NOT NULL DEFAULT '{}',                -- C8
  legal_hold             BOOLEAN NOT NULL DEFAULT 0,                -- req #11
  retention_policy       VARCHAR(60),                               -- req #11
  purged_at              TIMESTAMP,                                 -- req #11
  created_at             TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
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

CREATE TABLE IF NOT EXISTS collection_source_test_request (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  connection_id INTEGER NOT NULL,
  source_id     INTEGER,
  provider      VARCHAR(40) NOT NULL,
  nonce_hash    VARCHAR(64) NOT NULL,                               -- req #6 (hash only)
  status        VARCHAR(20) NOT NULL DEFAULT 'pending',
  requested_by  VARCHAR(255),
  requested_at  TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  verified_at   TIMESTAMP,
  expires_at    TIMESTAMP,
  telemetry_json JSON NOT NULL DEFAULT '{}',
  created_at    TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
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

CREATE TABLE IF NOT EXISTS tenant_alert_channel (
  id            INTEGER PRIMARY KEY,
  tenant_id     INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name          VARCHAR(80) NOT NULL,
  channel_type  VARCHAR(20) NOT NULL,
  enabled       BOOLEAN NOT NULL DEFAULT 0,
  config_json   JSON NOT NULL DEFAULT '{}',                         -- req #3
  secret_refs   JSON NOT NULL DEFAULT '{}',                         -- C3: opaque refs
  secrets_metadata JSON NOT NULL DEFAULT '{}',
  created_at    TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  updated_at    TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  created_by    VARCHAR(255),
  deleted_at    TIMESTAMP,
  deleted_by    VARCHAR(255),
  CONSTRAINT uq_alert_channel_id_tenant UNIQUE (id, tenant_id)
);
CREATE INDEX IF NOT EXISTS ix_alert_channel_tenant ON tenant_alert_channel (tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_alert_channel_name_live
  ON tenant_alert_channel (tenant_id, name) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS alert_outbox (
  id                   INTEGER PRIMARY KEY,
  tenant_id            INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  alert_channel_id     INTEGER NOT NULL,                            -- req #2 (FK below)
  finding_id           INTEGER REFERENCES exposure_finding(id) ON DELETE SET NULL,
  external_channel_ref VARCHAR(190),                                -- req #2 (additive only)
  template             VARCHAR(80) NOT NULL,
  template_version     VARCHAR(40) NOT NULL DEFAULT '1',
  dedup_key            VARCHAR(64) NOT NULL,                        -- req #5
  status               VARCHAR(20) NOT NULL DEFAULT 'pending',      -- req #4 (column)
  attempts             INTEGER NOT NULL DEFAULT 0,                  -- req #4
  next_attempt_at      TIMESTAMP,                                   -- req #4
  delivered_at         TIMESTAMP,                                   -- req #4
  error_code           VARCHAR(60),                                 -- req #4
  payload_json         JSON NOT NULL DEFAULT '{}',                  -- req #4 (no delivery_state)
  created_at           TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
  updated_at           TIMESTAMP NOT NULL DEFAULT (CURRENT_TIMESTAMP),
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
