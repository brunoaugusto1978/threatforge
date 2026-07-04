# ThreatForge — Licensing FAQ

This page answers the most common licensing questions. It is informational and
is **not legal advice**; the authoritative terms are in [`LICENSE`](../LICENSE)
(AGPL-3.0-or-later) and [`COMMERCIAL.md`](../COMMERCIAL.md).

## The two editions

- **Community Edition** — this repository, licensed under
  **AGPL-3.0-or-later**. Free to use, study, modify, and share under the AGPL.
- **Enterprise Edition** — a separate, private overlay package
  (`threatforge-enterprise`) under a **commercial license**. Same database and
  schema as Community; unlocks gated features via `app/features.py` and the
  pluggable registries.

## What is the AGPL, in one paragraph?

The GNU Affero General Public License is a strong copyleft license. You may run,
study, modify, and redistribute the software, but if you distribute it — or, per
**section 13**, make a **modified** version available to users **over a
network** — you must offer those users the Corresponding Source of your modified
version under the same AGPL terms. This "network use" clause is what
distinguishes the AGPL from the ordinary GPL and is the key thing to understand
before building a service on top of Community.

## When do I need a commercial license?

You need a commercial (Enterprise) license if you want to do something the AGPL
does **not** permit without publishing your source — most commonly, running a
**modified, closed-source SaaS** built on ThreatForge without offering your
modifications to your users. The commercial license removes the AGPL section 13
network-copyleft obligation and grants access to the Enterprise capabilities.

## Practical examples

| Scenario | Community (AGPL) | Needs commercial license? |
|---|---|---|
| Run unmodified Community internally for your SOC/team | OK | No |
| Modify Community and use it internally only (no external network users) | OK | No |
| Modify Community and offer it to external users over a network, **and** publish your modified source to those users | OK | No |
| Modify Community and run it as a **closed-source** SaaS without publishing your changes | Not permitted | **Yes** |
| Embed ThreatForge in a proprietary product you distribute without source | Not permitted | **Yes** |
| Want premium PDF export, MISP/OpenCTI connectors, feeds, realtime, enrichment | Locked (HTTP 402) | **Yes** |

## Contributing

Contributions to Community are accepted under **AGPL-3.0-or-later** with a
**Developer Certificate of Origin (DCO)** sign-off (`git commit -s`). Because the
project is **dual-licensed**, contributions that may also ship in the commercial
Enterprise Edition require a **Contributor License Agreement (CLA)** so the
maintainer can relicense them commercially. See [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Upgrading to Enterprise

1. Install the Enterprise package into the same environment as Community.
2. Set `THREATFORGE_EDITION=enterprise` and point `THREATFORGE_ENTERPRISE_LICENSE_FILE` / `THREATFORGE_ENTERPRISE_PUBLIC_KEY_FILE` / `THREATFORGE_ENTERPRISE_LICENSE_KEY_ID` at your signed license (see `docs/ENTERPRISE_INSTALL.md`).
3. Restart.

There is **no database migration**, no container swap, no tenant re-creation, and
no loss of configuration — the schema is shared and Enterprise plugs into the
existing seams. Full steps and rollback: [`docs/ENTERPRISE_INSTALL.md`](ENTERPRISE_INSTALL.md).

## Trademark

"ThreatForge" is a trademark of CBG Assessoria e Consultoria. The AGPL grants
copyright permissions but **no trademark rights** — you may not use the name or
logos to imply endorsement of a fork or derivative. See [`NOTICE`](../NOTICE).

## Contact

- General: **contact@cbgsecurity.com.br**
- Commercial / Enterprise licensing & license questions: **commercial@cbgsecurity.com.br**
- Security / vulnerability reports: **security@cbgsecurity.com.br**
- Community & contributions: **opensource@cbgsecurity.com.br**
- Official website: **https://cbgsecurity.com.br**

ThreatForge is developed and maintained by **CBG Assessoria e Consultoria** (founder:
**Bruno Augusto Lobo Soares**).
