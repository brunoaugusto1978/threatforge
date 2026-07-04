# ThreatForge v0.9.0 — Community Preview

**This is a preview release, not 1.0.** It is the first *public* release of the
ThreatForge Community edition, licensed under **AGPL-3.0-or-later**. The platform
is feature-rich and internally tested, but APIs, schema and UI may still change
before a stable 1.0. Run it in evaluation/authorized environments and expect
sharp edges.

Maintained by **CBG Assessoria e Consultoria** (founded by Bruno Augusto Lobo
Soares). Website: https://cbgsecurity.com.br

## What's ready

**Platform & security**
- Multi-tenant architecture with strong tenant isolation (cross-tenant → 404).
- RBAC (`admin`/`analyst`/`viewer`) plus platform operators
  (`platform_admin`/`support_operator`/`support_viewer`) with tenant-assignment
  support access.
- Argon2 password hashing (PBKDF2 compat), stdlib JWT sessions, password reset.
- Audit logging with secret redaction; tenant-scoped API keys; email invitations.

**CTI / DRP core**
- IOC intake and public connectors (CISA KEV, URLhaus, MITRE ATT&CK, EPSS);
  explainable scoring; Markdown reports.
- Brand monitoring (typosquat, passive scanner: DNS / crt.sh / RDAP) with alerting.

**Investigations**
- Investigation cases, evidence and notes; case Markdown export (premium PDF gated).
- Gated integrations catalog + partial STIX 2.1 export.

**Digital Risk Protection**
- Exposure Monitoring: one model for all exposure types; manual/authorized intake
  and file import; dedup, server-side redaction, ingestion provenance with
  rollback; PII masking by role; Admiralty source reliability.
- Attack Surface Discovery: passive discovery (crt.sh / DNS / RDAP / TLS) + manual
  import; promote to `infrastructure_exposure`.
- Correlation engine + radial graph view; explainable Risk Score; Timeline;
  Exposure dashboard.
- Credential Intelligence: identity aggregation, password-reuse detection, VIP-hit
  alerts, credential timeline and UI; credential reports (Markdown/JSON; PDF gated).

**Licensing & project**
- AGPL-3.0 Community + commercial Enterprise model; `LICENSE`, `NOTICE`,
  `COMMERCIAL.md`, `docs/LICENSE_FAQ.md`, `docs/ENTERPRISE_INSTALL.md`.
- Governance, changelog, roadmap, issue/PR templates, SECURITY policy, Code of
  Conduct.

## Known limitations

- **Preview quality.** Schema/API/UI may change before 1.0; no long-term
  backward-compatibility guarantees yet.
- **Community = manual/authorized intake only.** No automated scraping, active
  scanning or external collection. Those are Enterprise scope and are **not**
  included.
- **Premium features are locked.** Premium PDF export, real MISP/OpenCTI
  connectors and premium enrichment return **HTTP 402** without an Enterprise
  license.
- **Enterprise feeds not started.** Dark/deep-web feeds, real-time collection and
  k-anonymity enrichment are planned, not shipped.
- **Ops docs are still growing.** Backup/restore, upgrade and troubleshooting
  guides are being expanded (see ROADMAP).
- **Trademark pending.** "ThreatForge" is used with the ™ symbol; ® will apply
  only after formal registration.

## Upgrade / install

Standard Community install (Docker). Upgrading to Enterprise later is an overlay
that shares the **same database and schema** — no migration, no fork. See
[`docs/ENTERPRISE_INSTALL.md`](ENTERPRISE_INSTALL.md).

## Next steps

- Community: release hardening, screenshots/GIFs, onboarding, UI polish and
  operational docs (see [`ROADMAP.md`](../ROADMAP.md)).
- Enterprise (separate, private): dark/deep-web feeds, real-time collection,
  k-anonymity enrichment, premium integrations, premium export, packaging +
  license activation.

## Validation

- Docs-only release-readiness materials; no functional or schema change.
- CI selftest continues to pass on `main`.

Full history: [`CHANGELOG.md`](../CHANGELOG.md).
