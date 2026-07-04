# ThreatForge Roadmap

This is the canonical roadmap. It separates the open-source **Community** edition
(AGPL-3.0-or-later, this repository) from the commercial **Enterprise** edition
(private repository). For licensing details see [`COMMERCIAL.md`](COMMERCIAL.md)
and [`docs/LICENSE_FAQ.md`](docs/LICENSE_FAQ.md); for shipped history see
[`CHANGELOG.md`](CHANGELOG.md).

> This root file is the canonical roadmap. `docs/ROADMAP.md` is kept only as a
> compatibility pointer for older links.

## Where we are

**v0.9.0 — Community Preview** (first public release). Delivered on `main`:
multi-tenant/RBAC/audit, investigation cases/evidence/export, gated integrations
catalog, Exposure Monitoring, Attack Surface Discovery, Correlation, Credential
Intelligence and reports, plus the AGPL-3.0 / Enterprise licensing model.

## Community (open source, AGPL-3.0-or-later)

Community focuses on the CTI/DRP core and **manual/authorized** intake. It never
performs unauthorized scraping or active scanning, and never stores plaintext
secrets.

Next steps:

- **Release hardening** — dependency review, security headers/CORS review,
  reproducible Docker build, CI selftest coverage, first tagged public release.
- **Screenshots & GIFs** — visual walkthroughs of the main modules for the README
  and the website.
- **Onboarding** — smoother first-run: guided setup, sample data, a "getting
  started" tutorial.
- **UI polish** — consistency pass on badges, cards, the correlation graph and the
  credential dossier; accessibility basics.
- **Operational docs** — deployment, backup/restore, upgrade, environment
  reference and troubleshooting guides.
- **Community building** — issue triage, contribution guide refinement, discussion
  space, example integrations.

## Enterprise (commercial, private repository)

Enterprise is an overlay installed on top of Community. It shares the same
database and schema and unlocks capabilities through the feature gate
(`app/features.py`) and the pluggable registries. **Not started yet** — planned:

- **Dark/deep-web feeds** — automated collection connectors from lawful sources
  (behind the gate; connectors live outside this repository).
- **Real-time collection** — continuous monitoring and real-time alerting.
- **k-anonymity enrichment** — HIBP-style breach enrichment sending only a hash
  prefix; never email + password.
- **Premium integrations** — production MISP and OpenCTI connectors and generic
  threat-intel integration.
- **Premium PDF / export** — enterprise PDF export for cases and credential
  dossiers, and additional export formats.
- **Enterprise packaging & license activation** — installable package,
  `THREATFORGE_EDITION=enterprise` + license key resolution, entitlement checks.

## Principles

- **Same schema, no fork.** Enterprise never diverges the database; it plugs into
  existing seams. Upgrade/rollback needs no migration.
- **Locked features are visible.** Community shows Enterprise features with an
  upgrade call-to-action and returns HTTP 402 when invoked without a license.
- **Legal/ethical guardrails are non-negotiable** in both editions: no plaintext
  secrets, no credential stuffing, no purchase/redistribution of stolen data,
  consent for VIP monitoring, and authorized-only collection.
