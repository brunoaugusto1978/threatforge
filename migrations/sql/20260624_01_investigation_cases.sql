-- ThreatForge — investigation_cases (v0.7). PostgreSQL.
BEGIN;

CREATE TABLE IF NOT EXISTS investigation_cases (
  id                  SERIAL PRIMARY KEY,
  tenant_id           integer NOT NULL REFERENCES tenants(id)        ON DELETE CASCADE,
  brand_id            integer          REFERENCES brands(id)         ON DELETE SET NULL,
  finding_id          integer          REFERENCES brand_findings(id) ON DELETE SET NULL,
  observable_id       integer          REFERENCES observables(id)    ON DELETE SET NULL,
  finding_snapshot    jsonb,
  title               varchar(255) NOT NULL,
  description         text,
  severity            varchar(10)  NOT NULL DEFAULT 'medio',
  status              varchar(20)  NOT NULL DEFAULT 'open',
  assignee_user_id    integer          REFERENCES users(id)          ON DELETE SET NULL,
  created_by_user_id  integer          REFERENCES users(id)          ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  closed_at           timestamptz,
  CONSTRAINT ck_case_status   CHECK (status   IN ('open','triage','investigating','contained','closed','false_positive')),
  CONSTRAINT ck_case_severity CHECK (severity IN ('baixo','medio','alto','critico'))
);

CREATE INDEX IF NOT EXISTS ix_investigation_cases_tenant_id        ON investigation_cases (tenant_id);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_brand_id         ON investigation_cases (brand_id);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_finding_id       ON investigation_cases (finding_id);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_observable_id    ON investigation_cases (observable_id);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_status           ON investigation_cases (status);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_severity         ON investigation_cases (severity);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_assignee_user_id ON investigation_cases (assignee_user_id);
CREATE INDEX IF NOT EXISTS ix_investigation_cases_created_at       ON investigation_cases (created_at);
CREATE INDEX IF NOT EXISTS ix_cases_tenant_status                  ON investigation_cases (tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_cases_tenant_created                 ON investigation_cases (tenant_id, created_at);

COMMIT;
