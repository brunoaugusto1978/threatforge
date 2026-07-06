# Changelog

All notable changes to ThreatForge Community are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Historical entries group features by development milestone. Only the current
> public preview carries a release date; earlier version headings summarize the
> milestone in which each capability landed on `main`.

## [Unreleased]

Planned next (Enterprise, out of this repository — see [ROADMAP.md](ROADMAP.md)):
automated dark/deep-web feeds, real-time collection, k-anonymity breach
enrichment, real MISP/OpenCTI connector transport with encrypted secret vault
and anti-SSRF validation, premium PDF/export, and Enterprise packaging with
license activation.

## [0.9.3] — Real Integration Configuration UI

Small UX release on top of `0.9.2`. Focus: fix the misleading
"Integration configured" toast that fired after posting an empty body — the
UI now opens a real form driven by each connector's descriptor and the router
enforces the required-fields contract instead of accepting arbitrary payloads.

### Added
- **Integration configuration modal** in `app/static/app.js`. Clicking
  **Configure** on an unlocked Integrations card opens a modal built from the
  descriptor's `config_schema` (non-secret inputs) and `secrets_schema`
  (password-style inputs). Boolean/enum/integer/array types render as native
  form controls. Required fields marked with `*`. Save shows *Integration
  configuration saved*; missing required fields show *Configuration required:
  <fields>*. A **Test connection** button in the modal reports `ready` /
  `not_configured` without touching any external service. CSP-safe (no inline
  handlers): the click dispatcher already in the app.js drives every button.
- **`GET /integrations/{name}/connections`** — returns the tenant's stored row
  (masked; `null` if unsaved) so the modal can prefill non-secret fields on
  re-open. Viewer+ can read it; response never carries secret values.
- **`secrets_schema`** on `GET /integrations/{name}`: publishes
  `{ required, optional }` secret *names* per connector so the UI can render
  the credential section without ever inlining secret keys in the front-end.
- **`SecretSpec` / `SECRETS_SPEC`** in `app/integrations/schemas.py` —
  declares MISP's `api_key` (required), OpenCTI's `api_token` (required),
  Generic's optional `token`/`secret`. No value ever passes through this
  module; it's a name-only contract.
- **`ready` flag** on the connection response reflecting the new
  `_is_ready(row, descriptor, name)` predicate.

### Fixed
- **`POST /integrations/{name}/connections`** now enforces the descriptor's
  required config fields and required secret names. Missing keys yield **422**
  with `{ missing_fields, missing_config_fields, missing_required_secrets }`
  and audit `integration.config_rejected` — nothing is persisted, no
  `Integration configured` toast fires. The previous v0.9.2 behaviour of
  accepting `{}` and reporting success was misleading and is gone.
- **`/test`** and **`/sync`** now report `ready` / `queued` only when the
  stored row satisfies `_is_ready` (all required config + secret markers
  present). A row saved with just `base_url` for MISP correctly reports
  `not_configured` — before, any persisted row reported `ready`.
- **UI Save flow** no longer shows *Integration configured* when the operator
  submits an empty form. The button is disabled by the same required-fields
  check on the server; a client-side missing-fields toast shows exactly which
  fields to fill.
- **Merge-safe secret markers** on re-save: the router loads the existing
  row *before* running required-secret validation, so a re-save with a blank
  credential input is treated as satisfied by the ``present=True`` marker
  already on file. Editing non-secret fields keeps the *secret on file*
  marker and ``/test`` keeps reporting *Ready* instead of regressing to
  *not_configured*. First-configuration payloads without the required secret
  still 422 (there is no marker to inherit from).

### Security
- Secret values are never sent back to the client, never persisted in
  `config_json`, never landed in the audit trail, and — on save — the DOM
  inputs are wiped after the response is processed as defence in depth.
- `GET /integrations/{name}/connections` returns the same masked view as the
  POST response — viewer+ can see whether a secret is on file, never its
  value.
- Community without an Enterprise entitlement keeps returning **402** on all
  four endpoints (`POST /connections`, `GET /connections`, `POST /test`,
  `POST /sync`) with the existing upgrade block. A new
  `integration.read_denied` audit action covers the GET path.
- Locked *Configure (Enterprise)* cards short-circuit to the upgrade CTA
  without rendering the form, so unlicensed operators can't be tricked into
  typing a credential into a UI that would then 402.

### Tests
- `tests/test_integrations_config.py` reworked for the v0.9.3 contract:
  descriptor `secrets_schema` matrix (MISP/OpenCTI/Generic); 422 breakdowns
  for empty / missing-secret / missing-config payloads; `config_rejected`
  audit action; `GET /connections` before and after save; prefill without
  secret leakage; `ready` flag on the response; parametric secret masking
  (now uses `generic` so no unrelated required credential is needed); upsert
  preserves the *secret on file* marker across secret-less re-saves; unknown
  integration name still 404; viewer 403 on write, 200 (masked) on read; and
  tenant isolation for `POST`, `GET` and `POST /test`.

## [0.9.2] — Enterprise Integration Configuration

Small feature release on top of `0.9.1`. Focus: destravar the Integrations
screen when the Enterprise licence overlay unlocks `integration.misp`,
`integration.opencti` or `integration.generic`. No new Community-only capability
and no Enterprise/licensing contract change.

### Added
- **`integration_connections` table** (migration
  `20260706_01_integration_connections`) — one row per `(tenant_id, name)`
  storing `enabled`, `config_json` (non-secret configuration matching the
  descriptor's public schema) and `secrets_metadata` (masked presence hints).
  Community never persists real credentials; the encrypted secret vault stays
  in `threatforge-enterprise`.
- **`app.models.IntegrationConnection`** — SQLAlchemy model backing the new
  table, unique-constrained on `(tenant_id, name)` and indexed on both.

### Fixed
- **`POST /integrations/{name}/connections`**, **`.../test`**, **`.../sync`**
  no longer return **501 Not Implemented** when the Enterprise licence unlocks
  the descriptor's feature. The three endpoints now:
  - **`/connections`** — strip secret keys (`api_key`, `api_token`, `token`,
    `secret`, `password`, `client_secret`, `auth_key`, `private_key`), upsert
    the tenant's connection row and return it with `secrets_metadata`
    describing only *which* secrets were received (never the values). Audit
    `integration.config_saved`.
  - **`/test`** — return `{configured, status, message}` reflecting whether the
    tenant has a stored connection (`ready` vs `not_configured`); no external
    call is made. Audit `integration.test_requested`.
  - **`/sync`** — return `{accepted, status, message}` (`queued` vs
    `not_configured`); no external call is made. Audit
    `integration.sync_requested`.
- Community without an Enterprise entitlement keeps returning **402** with the
  existing upgrade block and keeps writing the `integration.*_denied` audit
  actions — the licence gate order was preserved so unlicensed hosts are
  unaffected by this release.

### Security
- Even under a valid Enterprise licence, Community never persists nor echoes
  secret fields in cleartext: the router strips them before hitting the
  database and before serialising the response, and the audit log records only
  the field *names* that were present, not their values.
- Tenant isolation: the connection row is looked up strictly by
  `(tenant_id, name)`. Tenant A cannot read, overwrite or test tenant B's
  connection.
- RBAC unchanged: viewer sees the catalogue only; configure/test/sync require
  admin effective role, which excludes `support_operator` and `support_viewer`
  (so tenant-support operators cannot manage connector credentials).

### Tests
- New `tests/test_integrations_config.py` covers the entire release contract:
  unlicensed 402 + `*_denied` audit; MISP / OpenCTI / Generic configuration
  upsert; empty-body minimal payload accepted; secret masking (parametric over
  every secret key, case-insensitive); `/test` and `/sync` transitions; audit
  actions on the licensed path; unknown integration `404`; viewer 403 even
  when licensed; and cross-tenant isolation for both `/connections` and
  `/test`.

## [0.9.1] — POC Hardening Release

Patch release on top of `0.9.0` consolidating fixes found during the CBG
Assessoria e Consultoria Community POC. No new premium features, no
Enterprise/licensing changes.

### Fixed
- **/health and FastAPI app version**: now sourced from `config.APP_VERSION`
  (`0.9.1`) instead of a hardcoded string that had drifted to `0.6.0` on
  `main` while the README still expected `0.6.9`.
- **README and `.env.example` — installation**: documented that
  `docker-compose.yml` overrides `DATABASE_URL` for the `api` service from
  `POSTGRES_PASSWORD` (so `POSTGRES_PASSWORD` is the single source of truth
  under Compose), and when/why `docker compose down -v` is required to reset
  a stale Postgres volume — with an explicit local-data-loss warning.
- **README — selftest example**: aligned with the real chain of scenarios
  currently emitted by `app/selftest_isolation.py`
  (`… + LICENSE: ALL TESTS PASSED ✅`).
- **Enrichment error UX** (`POST /observables/{id}/enrich`): external-source
  failures (e.g. URLhaus HTTP 403) no longer surface raw exception classes
  (`HTTPStatusError`) or return 502. The IOC is kept — never removed or
  corrupted — and, on a first enrichment attempt where every applicable
  source failed, its verdict is `unknown` (not a fabricated
  `no_known_threat`). Technical detail (source, HTTP status, exception type)
  is recorded via the audit trail; the UI receives a friendly,
  source-specific message via a new `enrichment_warnings` field.
- **Exposure Findings UI**: fixed `risk_breakdown` rendering as
  `[object Object]`. The generic detail renderer now skips `risk_breakdown`
  (already rendered by the dedicated Risk breakdown panel) and safely
  formats any other nested object, array, empty or null value.
- **Open investigation** (`POST /exposure/findings/{id}/case`): the new case
  now inherits `brand_id` when the finding's correlation graph resolves to
  exactly one brand (never guesses among multiple), assigns the
  authenticated user as `assignee_user_id` when the principal has one, and
  builds a description containing finding type, affected email/asset,
  source, risk score and ingest id (when available).
- **Exposure Dashboard — Top Exposed Assets**: also counts findings linked
  to a monitored asset through correlation (shared e-mail/domain), not just
  the direct `asset_id` FK — matching what the Correlate graph already
  shows for the same finding.

### Added
- `tests/test_observables_enrich.py` — pytest coverage for the URLhaus 403
  scenario (friendly message, IOC stays UNKNOWN, audit trail entry).
- `tests/test_exposure_open_case.py` — pytest coverage for the Open
  investigation `brand_id` inheritance when correlation is unique, and
  for the negative case with multiple candidate brands.
- `docs/RELEASE_NOTES_v0.9.1.md` — release notes with manual validation
  checklist covering the frontend-only fixes (risk_breakdown formatter,
  Top Exposed Assets) that have no automated coverage yet.

### Unchanged
- Historical `[0.7.0]` entry below (Investigation Cases, Evidence & Export
  milestone) is preserved as-is.
- Enterprise adapter, licensing, feature gates, PDF gate, integrations
  gates, STIX export — all untouched.

## [0.9.0] — Community Preview — 2026-07-04

First **public** Community release. Consolidates everything on `main` since the
multi-tenant baseline into a coherent, documented, publicly presentable project.

### Added
- **Attack Surface Discovery** — `surface_asset` model; passive discovery reusing
  the Brand scanner (crt.sh CT logs, DNS, RDAP, TLS); manual import; list/triage.
  Active scanning (ports/Shodan/Censys) is Enterprise-gated with a mandatory
  allowlist.
- **Surface → Exposure promote** — promote a `surface_asset` into an
  `infrastructure_exposure` finding, feeding Risk, Timeline and Correlation.
- **Credential Intelligence** — stealer-log/breach/combolist/paste parsers with
  stealer metadata (source kind, family, malware date, machine-id pseudonym,
  captured-type labels); `credential_identity` aggregation per email (leak count,
  sources, families, VIP link, max risk); password-reuse detection by
  `password_sha256`; VIP-hit alerts reusing Brand alerting; credential timeline
  source; Credential Intelligence UI (identities, dossier, reuse graph, timeline).
- **Credential Reports** — Markdown/JSON export of a credential dossier; premium
  PDF gated (HTTP 402). No plaintext ever leaves the system.
- **Licensing & commercial model** — relicensed Community to **AGPL-3.0-or-later**
  (full `LICENSE` in-repo), added `NOTICE`, `COMMERCIAL.md`,
  `docs/ENTERPRISE_INSTALL.md`, `docs/LICENSE_FAQ.md`; README dual-license section
  and Community × Enterprise feature matrix; `CONTRIBUTING` under AGPL + DCO/CLA.
- **Project governance & release materials** — `CHANGELOG.md`, `ROADMAP.md`,
  `GOVERNANCE.md`, GitHub issue/PR templates, `SECURITY.md` contact + 48h SLA,
  Contributor Covenant 2.1 Code of Conduct.

### Security
- Server-side redaction hardened across credential parsers: only `password_sha256`
  + partial mask + non-sensitive metadata are stored; cookies/tokens/session
  values are dropped, never persisted.
- Audit redaction extended for credential/cookie/session fields.

## [0.8.0] — Exposure, Risk, Timeline, Correlation & Gating

### Added
- **Feature gate** — single shared `app/features.py` (`Feature` enum,
  `ensure_enabled`/`is_enabled`), standardized **HTTP 402** upgrade response with
  configurable commercial-contact block.
- **Integrations catalog (gated)** — `app/integrations` registry + `/integrations`
  router; Community ships descriptors/stubs and the upgrade CTA; real MISP/OpenCTI
  connectors are Enterprise.
- **STIX 2.1 partial export** — local case export to STIX JSON.
- **Exposure Monitoring (DRP)** — `monitored_asset` + `exposure_finding` (one model
  for all exposure types); manual/authorized intake + file import; normalization,
  dedup, server-side redaction; ingestion provenance (`exposure_ingest_batch`) with
  import rollback; data classification + PII masking by role; Admiralty source
  reliability. Exposure UI (findings/assets/imports) with triage and open-case.
- **Timeline** — read-only aggregation via pluggable `TimelineSource` providers
  (Exposure/Cases/Audit); `GET /timeline?scope=tenant|case|finding`.
- **Risk score (explainable)** — transparent factors (asset criticality, exposure
  type, reliability, freshness, verification, sensitivity) with persisted
  breakdown; recompute on intake/import/triage.
- **Correlation engine** — logical graph linking findings, monitored assets,
  observables, brands and cases by shared identifiers; Correlate UI + radial graph
  view.
- **Exposure dashboard** — executive cards + risk-band chart + top exposed assets.

## [0.7.0] — Investigation Cases, Evidence & Export

### Added
- **Investigation cases** — model, schemas, RBAC, audit, state machine; a finding →
  case snapshot survives deletion of the source.
- **Evidence & notes** — file evidence upload/list/download with storage and
  provenance; analyst notes.
- **Case export** — free Markdown export; premium PDF export gated (HTTP 402).

## [0.6.0] — Multi-tenant Baseline

### Added
- Multi-tenant architecture with strong tenant isolation (`tenant_id` scoping;
  cross-tenant access returns 404).
- Platform operators (`platform_admin`, `support_operator`, `support_viewer`) with
  tenant-assignment-based support access and an effective-role model.
- Tenant-scoped API keys; invitation-based onboarding by email (hashed token,
  expiration, single use).
- Audit logs with user, operator, tenant, IP and user-agent context.
- Automated tenant-isolation selftest.

## [0.5.0] — Organization, Onboarding, Audit & Migrations

### Added
- Organization model, setup wizard (`/setup`) and org settings.
- Sector onboarding (Telecom catalog) with monitoring-seed generation and a
  scope taxonomy (global/sector/organization); Watchlist UI.
- Audit log (model, helper, wiring, endpoint) and Alembic versioned migrations.

## [0.4.0] — Authentication, RBAC & Web UI

### Added
- Password hashing (PBKDF2 → Argon2 with login-time rehash) and password policy;
  stdlib JWT sessions; password reset (self-service + admin) with session
  invalidation.
- `User` model and RBAC (`admin`/`analyst`/`viewer`) enforced across routes.
- Web UI: login, dashboard, IOCs, brands and user management.

## [0.3.0] — Brand Monitoring / DRP

### Added
- Brand model with typosquat generation and string-similarity matching.
- Passive scanner (DNS, crt.sh CT logs, RDAP).
- Alerting via Telegram, webhook and email.

## [0.2.0] — CTI Core

### Added
- IOC/observable intake (IP, domain, URL, hash, email, CVE) via API.
- Public connectors: CISA KEV, URLhaus/abuse.ch, MITRE ATT&CK, EPSS/FIRST.
- Explainable risk scoring (0–100) with transparent factors; Markdown reports.

## [0.1.0] — Project Bootstrap

### Added
- Initial FastAPI + SQLAlchemy project structure, configuration and Docker
  deployment scaffold.

[Unreleased]: https://cbgsecurity.com.br
