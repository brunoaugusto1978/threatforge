# ThreatForge Enterprise — Installation & Upgrade

The Enterprise Edition is a **commercial overlay** installed **on top of** the
Community (AGPL) deployment. Upgrading does **not** require a data migration or a
fork: Enterprise reuses the **same database and the same schema** as Community
and activates additional capabilities through the official extension seams.

## 1. Model in one paragraph

Community is the open-source core (AGPL-3.0-or-later). Enterprise is a private,
commercially-licensed Python package (`threatforge-enterprise`) that is
installed into the same environment. It registers its providers into the
existing registries and overrides the license resolver in `app/features.py`.
When a valid license is present and `THREATFORGE_EDITION=enterprise`, the gated
features unlock. Remove the package (or the license) and you are back to
Community — **no schema change either way.**

## 2. Prerequisites

- A working Community deployment (same PostgreSQL database you already run).
- Access to the private `threatforge-enterprise` package (provided with your
  commercial license).
- A valid **license key**.

## 3. Upgrade (no data migration)

1. Install the Enterprise overlay into the same environment as Community:

   ```bash
   pip install threatforge-enterprise   # from your private index / provided artifact
   ```

2. Provide the edition and the signed license in the environment (e.g. `.env`
   or Docker/Podman secrets):

   ```dotenv
   THREATFORGE_EDITION=enterprise
   THREATFORGE_ENTERPRISE_LICENSE_FILE=/run/secrets/threatforge-license.json
   THREATFORGE_ENTERPRISE_PUBLIC_KEY_FILE=/run/secrets/threatforge-license-public.pem
   THREATFORGE_ENTERPRISE_LICENSE_KEY_ID=cbg-prod-2026-01
   THREATFORGE_ENTERPRISE_INSTALLATION_ID=tf_inst_customer_x   # optional binding
   ```

   > These variables are read by the private `threatforge-enterprise` package.
   > Community only records *whether* they are set (never their contents). The
   > older `THREATFORGE_LICENSE_KEY` name is **not** used.

3. Restart the application. On startup, `threatforge-enterprise` resolves the
   license through `app.enterprise_adapter`, which `app/features.py` consults;
   granted features unlock. No `alembic upgrade` is required for the edition
   switch — the schema is unchanged.

4. Verify:

   ```bash
   # License state (admin token) — no secrets are returned:
   curl -sS -H "Authorization: Bearer <token>" http://localhost:8000/license/status

   # A gated feature that returned HTTP 402 in Community now succeeds, e.g.:
   curl -sS -H "Authorization: Bearer <token>" \
        http://localhost:8000/cases/<id>/export.pdf -o case.pdf
   test "$(head -c 4 case.pdf)" = "%PDF" && echo "PDF OK"
   ```

## 4. What unlocks

Enterprise activates the features gated in `app/features.py` (`Feature` enum) and
the Enterprise-only modules:

- `export.pdf` — premium PDF export (cases, credential dossiers).
- `integration.misp`, `integration.opencti`, `integration.generic` — real
  connectors (Community ships descriptors/stubs + the 402 upgrade response).
- `enrichment.premium` — premium enrichment.
- Enterprise-only collection: automated feeds (stealer/breach/paste/dark-web),
  continuous monitoring, real-time alerts, and k-anonymity breach enrichment.

All of these flow through the same seam — `features.ensure_enabled(...)` and the
pluggable registries (integrations, ingest parsers, timeline sources,
exporters) — so Community and Enterprise never diverge in schema or wiring.

Administrators can inspect the current state at any time via
`GET /license/status` (admin/platform-admin), which reports the edition, whether
the Enterprise package is present, whether the license is valid, and the
allowed/blocked **canonical** feature keys — without exposing the license,
signature, keys or file paths.

## 5. Rollback (also no migration)

To return to Community:

1. Remove or disable the Enterprise package:

   ```bash
   pip uninstall threatforge-enterprise
   ```

2. Reset the environment:

   ```dotenv
   THREATFORGE_EDITION=community
   # unset THREATFORGE_ENTERPRISE_LICENSE_FILE / _PUBLIC_KEY_FILE / _LICENSE_KEY_ID
   ```

3. Restart. Gated features return to their Community behavior (locked, HTTP 402
   on premium seams). **Your data and schema are untouched.**

## 6. Licensing note

The Enterprise package is distributed under a **commercial license**, not the
AGPL. See [`COMMERCIAL.md`](../COMMERCIAL.md). Operating Community over a network
carries AGPL-3.0 section 13 obligations; the commercial license removes that
network-copyleft requirement for Enterprise deployments.
