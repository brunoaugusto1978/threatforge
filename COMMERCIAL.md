# ThreatForge — Licensing & Commercial (Enterprise)

ThreatForge is offered under a **dual-licensing** model.

## 1. Community Edition — AGPL-3.0-or-later

The code in this repository is licensed under the **GNU Affero General Public
License, version 3 or (at your option) any later version** (`SPDX-License-Identifier:
AGPL-3.0-or-later`). The full text is in [`LICENSE`](LICENSE).

The AGPL is a strong copyleft license. In particular, **section 13 ("Remote
Network Interaction")** applies to ThreatForge because it is normally run as a
network service: **if you modify ThreatForge and make it available to users over
a network, you must offer those users the Corresponding Source of your modified
version** under the AGPL. Internal, unmodified use has no such obligation beyond
the standard AGPL terms.

If the AGPL's network-copyleft obligations are incompatible with your
deployment (for example, you want to embed ThreatForge in a proprietary,
closed-source SaaS without publishing your modifications), you need a
**commercial license** — see below.

## 2. Enterprise Edition — Commercial license

The **Enterprise Edition** lives in a **separate, private repository**
(`threatforge-enterprise`) and is distributed under a **commercial license**,
not the AGPL. It is an overlay package that plugs into the same database and
schema as Community through the official extension seams (feature flags and
registries) — **no separate fork, no schema divergence.** See
[`docs/ENTERPRISE_INSTALL.md`](docs/ENTERPRISE_INSTALL.md).

A commercial license typically provides:

- A license that is **not** subject to AGPL section 13 network-copyleft, so you
  can run modified/proprietary deployments without publishing source.
- The Enterprise capabilities gated in Community via `app/features.py`
  (`Feature` enum): premium **PDF export**, **MISP** / **OpenCTI** integrations,
  generic threat-intel integration, and **premium enrichment** — plus the
  Enterprise-only collection modules (automated feeds, real-time monitoring,
  k-anonymity breach enrichment, dark/deep-web connectors).
- Commercial support, SLAs, and indemnification (per agreement).

## 3. How the editions relate

- **Same code base, same schema.** Enterprise does not replace Community; it
  installs alongside it and activates gated features by resolving a license.
- **One extension mechanism.** All paid capability flows through
  `app/features.py` (`ensure_enabled`/`is_enabled`) and the pluggable
  registries (integrations, ingest parsers, timeline sources, exporters). No
  ad-hoc license checks scattered in the code.
- **Locked features are visible, not hidden.** Community shows Enterprise
  features with an upgrade call-to-action and returns **HTTP 402** when a gated
  feature is invoked without an active license.

## 4. Contributions & relicensing (DCO / CLA)

To keep dual-licensing legally sound, inbound contributions to the Community
repository are accepted under the AGPL-3.0-or-later (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)) with a **Developer Certificate of Origin
(DCO)** sign-off, and — for code that may also ship in the commercial Enterprise
Edition — a **Contributor License Agreement (CLA)** granting the maintainer the
right to relicense that contribution commercially. Without this, third-party
AGPL contributions cannot be included in the proprietary Enterprise build.

## 5. Contact

- Commercial / Enterprise licensing & license questions: **commercial@cbgsecurity.com.br**
- General contact: **contact@cbgsecurity.com.br**
- Official website: **https://cbgsecurity.com.br**

ThreatForge is developed and maintained by **CBG Assessoria e Consultoria** (founder:
**Bruno Augusto Lobo Soares**). "ThreatForge" is a trademark of CBG Assessoria e Consultoria.
