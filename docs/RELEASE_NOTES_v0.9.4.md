# ThreatForge Community v0.9.4 — Operational Dashboard Overview

Replaces the Dashboard's old Overview — which only called `GET /stats` and
rendered six basic counters (IOCs, malicious IOCs, brands, findings, priority
findings, users) — with a real operational view of CTI/DRP/Exposure
Monitoring state. Every number, distribution, list and status on the new
screen is computed live from the tenant's own rows; there is no mock/sample
data at any point, including on a brand-new, empty tenant.

## Why

The Community UI's landing screen was too thin to answer the question an
operator actually opens the dashboard for: *"what does today look like across
CTI, Digital Risk Protection and Exposure Monitoring?"* `/stats` only knew
about IOCs, brands and brand findings — it had no visibility into
investigation cases, exposure findings, monitored assets, credential
identities or integration connections, all of which already exist as
first-class tenant-scoped tables in `app/models.py`.

v0.9.4 adds a single aggregation endpoint that reads across all of those
tables and a redesigned Overview screen that turns the result into something
an operator can act on in a few seconds: what's open, what's severe, what
changed recently, and what still needs attention.

## What changed

### Backend — `app/routers/dashboard_routes.py` (new)

- **`GET /dashboard/overview`** — tenant-scoped, viewer+ (identical RBAC to
  `GET /stats`: `Depends(require_viewer)` + `current_tenant_id`). No new
  migration — every field is derived from existing tables with plain
  `SELECT`/`COUNT`/`GROUP BY`, filtered by `tenant_id == tid`. No audit log
  entry is written, mirroring `/stats` (a read-only, frequently-polled
  aggregate, not a state-changing action).
- **Summary counters**: `iocs_total`/`iocs_malicious`, `brands_total`/
  `brands_active`, `brand_findings_total`/`brand_findings_priority`,
  `cases_total`/`cases_open`, `exposure_findings_total`/
  `exposure_findings_open`, `monitored_assets_total`/`monitored_assets_active`,
  `credential_identities_total`/`credential_identities_active`/
  `credential_identities_high_risk`, and
  `integrations_catalog_total`/`integrations_connected`.
- **Distributions**: `cases_by_severity`, `cases_by_status`,
  `exposure_by_severity`, `exposure_by_status` — each pre-seeded with every
  known bucket (from the models' `CheckConstraint` vocabularies) at `0`, so
  the response shape is stable whether the tenant has zero rows or
  thousands.
- **Recent activity**: `recent_cases` and `recent_exposure_findings`, newest
  first, size controlled by `recent_limit` (default 5, max 20).
- **Top exposed assets**: `MonitoredAsset` rows ranked by how many
  `ExposureFinding` rows point at them, then by the highest `risk_score`
  among those findings (using the same `app.risk.band_of` thresholds as the
  rest of the app — no new/ad-hoc risk cutoff invented for the dashboard).
  Controlled by `top_assets_limit` (default 5, max 20).
- **Integrations status**: one entry per catalog connector (`misp`,
  `opencti`, `generic` in Community) with
  `{name, title, premium, license_enabled, connected, connection_enabled}`.
  `license_enabled` reflects `app.features.is_enabled`; `connected` reflects
  whether an `IntegrationConnection` row exists for the tenant;
  `connection_enabled` mirrors that row's `enabled` flag. The query itself is
  column-scoped (`select(IntegrationConnection.name, .enabled)`), so
  `config_json`/`secrets_metadata` are never loaded into the request at all —
  not merely omitted from the response.
- **Recent imports** (`recent_ingests`, plus `summary.exposure_ingests_total`):
  the tenant's most recent `ExposureIngestBatch` rows — source, parser,
  original filename, record/created/deduped/error counts and status. This
  surfaces the same import provenance already readable via
  `GET /exposure/ingests`, rounding out the "what happened recently" picture
  the dashboard is meant to answer.

### Security invariants

- **No PII in "top exposed assets".** `MonitoredAsset.value` can hold an
  e-mail or other identity value; the dashboard only ever returns `label`,
  `asset_type`, `criticality`, `active`, `finding_count` and
  `max_risk_score`/`max_risk_band`. The raw `value` field is never read into
  this response.
- **No secrets/config leakage from integrations.** The dashboard's
  integration entries are hand-built from `IntegrationConnection.name`/
  `enabled` only — the router never selects `config_json` or
  `secrets_metadata`, so there is no code path by which a saved MISP/OpenCTI/
  Generic credential could leak through this endpoint, even indirectly.
- **Tenant isolation** is enforced the same way as every other router:
  `current_tenant_id` resolves the effective tenant (a tenant user's own
  `tenant_id`, or an operator's `X-Tenant-Id` header validated against
  `operator_can_access_tenant`), and every query filters on it explicitly.
- **`recent_exposure_findings[].title` is masked, not raw.** Some ingestion
  paths (file-import parsers in `app/exposure_ingest.py`, e.g.
  `parse_csv_generic`/`parse_combolist`/`parse_breach`/`parse_stealer_log`)
  title a finding `"Credential exposure <email>"` / `"Identity exposure
  <email>"`. The dashboard resolves the caller's `Principal` and runs every
  title through `app.exposure_ingest.mask_value(..., ing.PII, role,
  config.EXPOSURE_PII_MASKING)` — the exact function/policy pair already used
  to mask `detail` on `GET /exposure/findings` — so a non-admin viewer under
  `EXPOSURE_PII_MASKING=by_role` never sees the raw address here either. The
  default Community policy (`off`) is unchanged: title behaves like the rest
  of Exposure Monitoring, and admins are never masked.

### UI — `app/static/app.js`, `app/static/index.html`

- **`viewDashboard()`** now calls `GET /dashboard/overview` and renders:
  - Nine summary cards (IOCs, malicious IOCs, active brands, priority brand
    findings, open cases, open exposure findings, active monitored assets,
    high-risk credential identities, connected integrations).
  - Four distribution panels (cases by severity/status, exposure findings by
    severity/status) as small horizontal bar lists.
  - Recent cases and recent exposure findings tables, each row linking back
    into the relevant existing screen (Cases / Exposure Monitoring tabs).
  - A top-exposed-assets table and an integrations-status table (with a
    "Manage integrations" shortcut into the existing Integrations screen).
- **CSP-safe, no inline handlers.** All new interactive elements use the
  existing `data-action` + `actBtn()` click-delegation pattern already used
  everywhere else in `app.js` (`document.addEventListener("click", ...)`
  dispatching through the `ACTIONS` map) — four new entries were added:
  `dashCaseView`, `dashFindingView`, `dashAssetView`, `dashGotoIntegrations`.
  Nothing was added as an inline `onclick="..."` string.
- **Minimal CSS.** `app/static/index.html` gained a small, targeted block
  (`.dashgrid`, `.distlist`, `.dist-row`, `.dist-label`, `.dist-bar`,
  `.dist-n`) reusing the existing CSS custom properties (`--red`, `--orange`,
  `--yellow`, `--green`, `--gray`, `--panel2`, `--line`, `--muted`) — no new
  external stylesheet or library.

### Tests — `tests/test_dashboard_overview.py` (new)

- Empty tenant returns real zeros/empty lists (not sample data).
- Real aggregation across IOCs, brands, cases, exposure findings, monitored
  assets and credential identities created through the normal API
  (`BrandCreate.official_domains` is `list[str]`, matching `app/schemas.py`).
- Distribution totals always sum to the real row count.
- Top-exposed-assets ranking order (finding count, then risk).
- `recent_ingests`/`summary.exposure_ingests_total` reflect a real
  `POST /exposure/import` batch (parser, record/created counts, status).
- `recent_exposure_findings[].title` is masked for a viewer (and left intact
  for an admin) once `EXPOSURE_PII_MASKING=by_role`, using a real
  file-import-generated, e-mail-bearing title as the fixture.
- RBAC: unauthenticated → 401; a plain `viewer` user can read the endpoint.
- Tenant isolation: two tenants' overviews never show each other's cases
  (tenant A sees only its own case; tenant B sees only its own two cases;
  cross-checked in both directions).
- A licensed integration connection configured with a real secret value never
  leaks that value, nor the `config_json`/`secrets_metadata`/`api_key`/
  `hashed_password`/`password_hash` keys, anywhere in the response.

### Fixed (post-review)

- Test fixture bug: brand creation used a comma-string `official_domains`;
  `BrandCreate.official_domains` is `list[str]` — fixed to
  `["acme.example"]`.
- `IntegrationConnection` rows are now read with a column-scoped `SELECT`
  (`name`, `enabled`) instead of loading the full ORM row, so
  `config_json`/`secrets_metadata` are never fetched for this endpoint at
  all.
- `recent_exposure_findings[].title` is now passed through the same PII
  masking as the rest of Exposure Monitoring instead of being returned raw.
- Added the `recent_ingests` block (see "What changed" above) instead of
  leaving it unimplemented.

## Upgrade notes

- No configuration changes, no new environment variables, no database
  migration.
- `GET /stats` is unchanged and still available; the Dashboard's Overview
  screen now calls `GET /dashboard/overview` instead.
- `app.config.APP_VERSION` bumped to `0.9.4`.
