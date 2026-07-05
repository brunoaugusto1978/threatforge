# ThreatForge Community v0.9.1 — POC Hardening Release

Patch release on top of the **Community Preview 0.9.0** (2026-07-04),
consolidating the fixes found during the CBG Assessoria e Consultoria
Community POC ahead of the Enterprise trial phase. It focuses on documentation
accuracy, error-handling UX and small correctness bugs surfaced by real usage
— no new premium features, no Enterprise/licensing changes.

## Highlights

* **Version consistency**: `/health` and the FastAPI app now report `0.9.1`
  from a single source of truth (`config.APP_VERSION`) instead of a stale
  hardcoded string, so this class of drift can't recur.
* **README / installation**: documented that under Docker Compose the
  `DATABASE_URL` for the `api` service is built from `POSTGRES_PASSWORD` and
  **overrides** whatever is in `.env` — so you only need to set
  `POSTGRES_PASSWORD` under Compose. Also documented when/why a stale Postgres
  volume needs `docker compose down -v` (with an explicit local-data-loss
  warning). Selftest example output now matches the real, current chain of
  scenarios instead of an outdated summary.
* **Enrichment error handling**: an external source failure (e.g. URLhaus
  returning HTTP 403) no longer surfaces a raw exception class
  (`HTTPStatusError`) to the user. The IOC is kept — never removed or
  corrupted — and, on a first enrichment attempt with no source data at all,
  its verdict is `unknown` rather than a fabricated `no_known_threat`. The
  technical failure (source, HTTP status, exception type) is recorded via the
  audit trail for troubleshooting; the UI only ever sees a friendly,
  source-specific message.
* **Exposure Findings UI**: fixed `risk_breakdown` rendering as
  `[object Object]` in the findings list. The dedicated risk-breakdown panel
  is unchanged; the generic detail renderer now skips it (already rendered
  richly elsewhere) and safely formats any other object/array/empty/null
  value it might encounter.
* **Open investigation context inheritance**: a case opened from an Exposure
  finding now inherits `brand_id` automatically when the finding correlates
  to exactly one brand (never guesses among multiple candidates), assigns the
  authenticated user as `assignee_user_id` when available, and carries a
  structured description (finding type, affected email/asset, source, risk
  score, import id) instead of a one-line generic note. Manual case creation
  is unaffected.
* **Exposure Dashboard — Top Exposed Assets**: now also counts findings linked
  to a monitored asset via correlation (shared e-mail/domain), not only a
  direct `asset_id` foreign key, matching what the Correlate graph already
  shows for the same finding. Other dashboard metrics are unchanged.
* **Tests**: new pytest coverage for the URLhaus 403 scenario and for the
  `brand_id` inheritance in Open investigation. Frontend-only fixes (Etapa 3
  `[object Object]` and Etapa 5 Top Exposed Assets) are covered by a manual
  validation checklist below because there is no JS test harness in the
  Community repo yet.

## Validation

**Sandbox (executed here):**

```text
python3 -m py_compile <all changed .py files>   → OK
node --check app/static/app.js                  → OK
```

**Local validation completed before publishing `v0.9.1`:**

```bash
docker compose up -d --build                                      # OK
curl http://localhost:8000/health                                 # OK, version 0.9.1
docker compose exec api python -m app.selftest_isolation           # OK
docker compose cp tests api:/tmp/tests                             # OK
docker compose exec api python -m pytest /tmp/tests/test_observables_enrich.py /tmp/tests/test_exposure_open_case.py -q  # OK, 7 passed
docker compose exec api python -m pytest /tmp/tests -q             # OK, 15 passed
```

Expected selftest output (unchanged chain, now correctly documented in the README):

```text
TENANT ISOLATION + INVITES + OPERATOR ROLES + BRAND EDIT + ARCHIVE/DELETE + CASES + NOTES + EVIDENCE + EXPORT + INTEGRATIONS + EXPOSURE + TIMELINE + RISK + CORRELATION + SURFACE + PROMOTE + CREDINTEL + CREDID + REUSE + VIPALERT + CREDTL + CREDREPORT + LICENSE: ALL TESTS PASSED ✅
```

## Manual validation completed before tag

The following flows were exercised by real UI interaction with synthetic data before publishing this release:

1. **Etapa 1 — installation**
   - Fresh `git clone` (or fresh zip extract).
   - `cp .env.example .env` and set `POSTGRES_PASSWORD`, `API_KEY`,
     `JWT_SECRET` to `openssl rand -hex 32`.
   - `docker compose up -d --build`.
   - `curl http://localhost:8000/health` returns
     `{"status":"ok","service":"threatforge","version":"0.9.1"}`.
   - `docker compose exec api python -m app.selftest_isolation` finishes with
     the full `… + LICENSE: ALL TESTS PASSED ✅` line.

2. **Etapa 2 — enrichment error (also has automated test)**
   - Create observable, click Enrich against an IOC that will hit URLhaus
     with 403 (e.g. `ABUSECH_API_KEY` invalid).
   - Toast shows the friendly `"Não foi possível consultar a fonte URLhaus…"`
     message; never `HTTPStatusError`.
   - Observable list still shows the IOC, verdict `unknown`.
   - `/audit` (as tenant admin) shows entry `enrichment.source_failed`
     with `source=urlhaus`, `status_code=403`.

3. **Etapa 3 — Exposure Findings risk_breakdown**
   - Trigger an Exposure import that produces at least one finding with
     `risk_breakdown` in `detail`.
   - In Exposure > Findings, confirm **no card** displays `[object Object]`.
   - Confirm the dedicated Risk breakdown panel (click on the risk badge)
     still shows `+points  factor (reason)` rows.
   - Sanity check that a finding with empty or absent breakdown shows
     `No risk factors available.` in the panel and never `[object Object]`
     in the detail row.

4. **Etapa 4 — Open investigation context inheritance (also has automated test)**
   - Create a brand with an official domain (e.g. `cbgsecurity.com.br`).
   - Import an exposure finding whose `detail.email` uses that domain.
   - Confirm the Correlate graph on that finding shows exactly one brand.
   - Click **Open investigation** on that finding.
   - Navigate to Cases → open the new case → confirm:
     * `brand_id` is set to the correlated brand;
     * `assignee_user_id` is the currently logged-in user;
     * description contains finding type, affected email, source, risk score
       and — if the finding came from an import — the ingest id.
   - Repeat with a finding that correlates to **two** brands and confirm
     `brand_id` stays NULL (no random pick).

5. **Etapa 5 — Top Exposed Assets**
   - Add a monitored asset (e.g. `CBG Security Website` with value
     `cbgsecurity.com.br`).
   - Import an exposure batch that creates findings whose `detail.email`
     domain matches that asset **but** the finding rows do not have
     `asset_id` set.
   - Confirm the Exposure dashboard `Top Exposed Assets` now lists
     `CBG Security Website` with the correct count and max risk, not
     `No asset-linked findings yet.`.
   - Confirm all other dashboard cards (Total Findings, Credential Leaks,
     bands histogram) still show the same numbers as before.

6. **Regression — Enterprise gates unchanged**
   - `GET /license/status` still shows `edition=community`.
   - `GET /cases/{id}/export.pdf` still returns HTTP 402 with the
     `enterprise_feature_required` payload.
   - `GET /integrations` still shows premium integrations as `enabled:false`
     with an `upgrade` block.
   - `GET /cases/{id}/export.stix.json` still returns a STIX bundle (free
     in Community).

## Recommended installation

```bash
cp .env.example .env

openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32

vi .env
docker compose up -d --build
curl http://localhost:8000/health
docker compose exec api python -m app.selftest_isolation
```

Required minimum `.env` values:

```env
API_KEY=<generated_value>
POSTGRES_PASSWORD=<generated_value>
JWT_SECRET=<generated_value>
COOKIE_SECURE=false
APP_BASE_URL=http://localhost:8000
```

## Scope confirmation

* No changes to the Enterprise repository or package.
* No Enterprise contract/licensing logic changed
  (`app/routers/license_routes.py`, `app/enterprise_adapter.py`,
  `app/features.py` untouched).
* No premium feature implemented in Community.
* Historical `[0.7.0]` entry in `CHANGELOG.md` (Investigation Cases, Evidence
  & Export milestone) is **not** rewritten — v0.9.1 is a new entry above
  `[0.9.0] — Community Preview`.
* No real/sensitive data used anywhere in code or tests — synthetic values
  only (`203.0.113.0/24` TEST-NET-3 range for the enrichment tests, existing
  synthetic-credential helpers for the selftest).

## Notes

This version is intended for local testing, development, research and
defensive CTI/DRP workflows. Before production usage, review secrets
management, HTTPS, cookie security, CORS, SMTP, logging policy, dependency
audit and infrastructure hardening.
