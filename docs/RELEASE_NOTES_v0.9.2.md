# ThreatForge Community v0.9.2 — Enterprise Integration Configuration

Small feature release on top of `0.9.1`. Focus: unblock the **Integrations**
screen when the Enterprise licence overlay flags a connector as *Available*.
Before this release, clicking **Configure** on an unlocked integration returned
`Not implemented in this edition.` even though the badge said *Available* —
because the three POST endpoints unconditionally raised HTTP 501 after the
licence gate passed.

This release keeps Community behaviour identical for hosts **without** an
Enterprise licence: cards stay `Enterprise 🔒`, the button reads
`Configure (Enterprise)`, and the endpoints return **402** with the same upgrade
block as before.

## What changed

### `POST /integrations/{name}/connections`

- Validates that the descriptor exists (`404` on unknown name) and that the
  Enterprise licence unlocks the descriptor's `Feature` (`402` otherwise).
- Strips secret keys from the payload before persisting: `api_key`,
  `api_token`, `token`, `secret`, `password`, `client_secret`, `auth_key`,
  `private_key` (case-insensitive on the key name).
- Upserts a row in `integration_connections` keyed on `(tenant_id, name)`.
- Returns the row with `config` (non-secret fields) and `secrets_metadata`
  describing which secret keys were received — never the values.
- Audit action: `integration.config_saved`.

### `POST /integrations/{name}/test`

- Returns a controlled status payload — **no external call is made**:

  ```json
  {"name": "misp", "configured": true, "status": "ready",
   "message": "Configuration is present. Live connection testing is provided by the ThreatForge Enterprise connector."}
  ```

  or `configured=false, status="not_configured"` when nothing has been saved.
- Audit action: `integration.test_requested`.

### `POST /integrations/{name}/sync`

- Returns a controlled status payload — **no external call is made**:

  ```json
  {"name": "opencti", "accepted": true, "status": "queued",
   "message": "Sync intent recorded. Real pull/push execution is provided by the ThreatForge Enterprise connector."}
  ```

  or `accepted=false, status="not_configured"` when nothing has been saved.
- Audit action: `integration.sync_requested`.

### Database

New table `integration_connections` (migration
`20260706_01_integration_connections`, revises `20260705_01_credid`):

| column             | type                    | notes                                                     |
| ------------------ | ----------------------- | --------------------------------------------------------- |
| `id`               | integer PK              |                                                           |
| `tenant_id`        | integer FK tenants      | `ON DELETE CASCADE`, indexed                              |
| `name`             | varchar(60)             | descriptor name (`misp`, `opencti`, `generic`, …)         |
| `enabled`          | boolean                 | default `true` on save                                    |
| `config_json`      | JSON                    | non-secret configuration only                             |
| `secrets_metadata` | JSON                    | `{key: {"present": true, "masked": "***"}}` per secret    |
| `created_at`       | timestamptz             | default `now()`                                           |
| `updated_at`       | timestamptz             | default `now()`, `onupdate=now()`                         |

Constraints: `UNIQUE (tenant_id, name)` — one connection per integration per
tenant. Indexes on `tenant_id` and `name`.

## Explicit non-goals for v0.9.2

- **No real connector I/O.** MISP / OpenCTI / Generic push/pull, scheduled
  sync and anti-SSRF validation remain in `threatforge-enterprise`.
- **No encrypted secret storage in Community.** Community stores no secret
  values at all — it strips them and only records that they were present.
- **No frontend rewrite.** The existing Integrations screen already POSTs
  `{}` to `/connections` on click; that request now succeeds when the feature
  is unlocked and the *Integration configured* toast finally shows up.

## Migration & rollback

```bash
alembic upgrade head        # applies 20260706_01_integration_connections
alembic downgrade -1        # drops the table (safe: no cross-referenced rows)
```

## Security notes

- Even under a valid Enterprise licence, Community never persists nor echoes
  secrets in cleartext. The router strips them, the DB row does not contain
  them, and the audit `detail` only lists which secret keys were present.
- Tenant isolation is enforced at the query layer (rows are looked up by
  `tenant_id + name`) and by the model's `UNIQUE (tenant_id, name)`
  constraint. Tenant A cannot read, overwrite or test tenant B's connection.
- RBAC unchanged: `require_admin` still guards the three POST endpoints, so
  `support_operator` / `support_viewer` cannot manage connector credentials
  even with granted tenant access.
- The licence gate runs *before* persistence: hosts without the entitlement
  never reach the database and continue to return 402 + the upgrade block.

## Validation

```bash
git diff --stat
git diff
python -m pytest -q
python -m pytest tests/test_integrations* -q
```

Expected: existing tests keep passing, and the new
`tests/test_integrations_config.py` suite (unlicensed 402, MISP/OpenCTI/Generic
upsert, secret masking parametric matrix, `/test` and `/sync` transitions,
audit trail, unknown-name 404, viewer 403 even when licensed, cross-tenant
isolation) turns green.
