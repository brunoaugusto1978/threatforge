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
enrichment, premium integrations (MISP/OpenCTI), premium PDF/export, and
Enterprise packaging with license activation.

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
