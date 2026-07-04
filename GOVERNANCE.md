# Project Governance

This document describes how the ThreatForge Community project is maintained and
how decisions are made.

## Maintainer

ThreatForge is developed and maintained by **CBG Assessoria e Consultoria**,
founded by **Bruno Augusto Lobo Soares**. "ThreatForge" is a trademark of CBG
Assessoria e Consultoria (see [`NOTICE`](NOTICE)).

At this stage the project follows a **BDFL-style** model: the maintainer has final
say on technical direction, releases, and what belongs in Community vs Enterprise.
As the community grows, this document will evolve toward a committer/maintainer
group with documented roles.

## How decisions are made

- **Everyday changes** (bug fixes, docs, small features) are decided through pull
  request review by the maintainer.
- **Significant changes** (new modules, data-model changes, security-sensitive
  behavior, anything touching tenant isolation, RBAC, redaction or licensing) are
  discussed in an issue first, with a short design note, before implementation.
- **Releases** are cut by the maintainer and recorded in
  [`CHANGELOG.md`](CHANGELOG.md) with release notes under `docs/`.
- **Roadmap** priorities are tracked in [`ROADMAP.md`](ROADMAP.md); the
  edition split (Community vs Enterprise) is part of every feature decision.

## How contributions are accepted

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) first.
- Contributions are accepted under **AGPL-3.0-or-later** with a **Developer
  Certificate of Origin (DCO)** sign-off (`git commit -s`).
- Because ThreatForge is **dual-licensed**, contributions that may also ship in
  the commercial Enterprise Edition require a **Contributor License Agreement
  (CLA)** so the maintainer can relicense them commercially. The maintainer will
  request a CLA where applicable; without it, a contribution remains AGPL-only in
  Community.
- Every pull request must satisfy the checklist in
  [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md): selftest
  run, no plaintext secrets, tenant isolation preserved, RBAC validated, feature
  gates respected, docs updated, and no licensing change without approval.

## Community vs Enterprise classification

A capability is **Community** when it is part of the open CTI/DRP core and relies
only on manual/authorized intake and local intelligence. A capability is
**Enterprise** when it involves automated/continuous external collection,
real-time infrastructure, premium third-party enrichment/integrations, or
commercial packaging.

Enterprise features are gated through the single shared feature gate
(`app/features.py`) and the pluggable registries — never through ad-hoc checks.
Locked features stay visible in Community with an upgrade path (HTTP 402). New
proposals should state their intended edition up front; when in doubt, the
maintainer decides.

## Security issues

Security vulnerabilities must **not** be reported through public issues. Follow
[`SECURITY.md`](SECURITY.md): report privately to **security@cbgsecurity.com.br**
(or via a private GitHub Security Advisory). The project targets a 48-hour
acknowledgement and practices coordinated disclosure.

## Code of Conduct

Participation is governed by the [Contributor Covenant](CODE_OF_CONDUCT.md).
Conduct concerns can be raised at **contact@cbgsecurity.com.br**.

## Contact

- General: **contact@cbgsecurity.com.br**
- Commercial / Enterprise licensing: **commercial@cbgsecurity.com.br**
- Security: **security@cbgsecurity.com.br**
- Community & contributions: **opensource@cbgsecurity.com.br**
- Website: **https://cbgsecurity.com.br**
