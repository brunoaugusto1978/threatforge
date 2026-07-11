# Neo4j Graph Integration — POC Assessment (Issue #20)

> **Stage:** assessment / documentation only. No application code, dependency,
> or deployment file has been changed in this pass. Nothing in this document
> should be implemented before the design is approved (see [Decision](#decision)).

## Decision

**Postpone real implementation. Ship this document only for now.**

If/when the design below is approved, the *first* code change should be a
disabled-by-default, mocked-tested adapter seam in Community (no Neo4j
dependency, no docker-compose change) — mirroring `app/enterprise_adapter.py`.
Anything beyond the seam (real Bolt driver calls, sync scheduling, graph
analytics/UI) belongs in the private `threatforge-enterprise` overlay,
consistent with `PRODUCT_STRATEGY.md` and `ROADMAP.md`.

Rationale is in [§7 Product Decision](#7-product-decision).

---

## 1. Purpose & Scope

Issue #20 asks whether ThreatForge should back its correlation graph with
Neo4j. This document:

1. Maps the current, internal correlation/timeline graph (§2).
2. States why a graph database is even being considered, and where the
   current model runs out of headroom (§3).
3. Proposes an **optional** architecture that cannot regress Community (§4).
4. Defines a minimal technical contract — entities, relationships, upsert and
   redaction rules — for a *future* implementation (§5).
5. Defines the operational model — sync, fallback, failure isolation,
   health (§6).
6. Makes the product/licensing/support call on what stays in Community vs.
   Enterprise (§7).

Out of scope for this pass: any real Cypher/Bolt code, docker-compose
changes, new dependencies, or UI work.

---

## 2. Current State — the Internal Correlation Graph

ThreatForge Community already has a working, tenant-scoped correlation graph.
It is computed **on demand**, in Python, from existing tables — there is no
graph table and no persisted graph store today.

### 2.1 `app/correlation.py`

- No new table: the module docstring (lines 1–7) is explicit that
  correlation is "computed on demand by matching normalized identifiers
  across the existing tenant-scoped tables."
- `_LIMIT = 1000` (line 17) bounds every per-table scan — each call to
  `correlate()` does one bounded `SELECT` per entity table
  (`ExposureFinding`, `MonitoredAsset`, `Observable`, `Brand`,
  `BrandFinding`, `SurfaceAsset`, `InvestigationCase`), tenant-scoped.
- Identifiers are normalized emails/domains/hashes/IPs extracted per entity
  by `_ids_from_exposure`, `_ids_from_surface`, `_ids_from_asset`,
  `_ids_from_observable` (lines 42–105). `_overlap()` (lines 113–119) returns
  the first shared identifier between the seed and a candidate.
- `correlate(db, tid, kind, ref)` (lines 155–232) resolves a seed
  (finding/asset/observable/surface/identifier), then does **one pass**
  over each table and links anything that shares an identifier with the
  seed — this is a **single-hop star graph**: seed → direct matches. It does
  not do BFS/multi-hop expansion (e.g., A↔B↔C where A and C never share an
  identifier directly is not surfaced).
- Output contract: `{seed, nodes, edges, identifiers}` (line 231–232), with
  `edges` carrying `{source, target, via}` where `via` is the identifier
  type/value that justified the link.

### 2.2 `app/routers/correlation_routes.py`

- `GET /correlation?entity=finding:{id}|asset:{id}|observable:{id}|surface:{id}|email:{v}|domain:{v}|hash:{v}|ip:{v}`
  (lines 1–5, 17, 20–34).
- Read-only; `require_viewer` dependency gate (line 15); tenant resolved via
  `current_tenant_id` (line 22); cross-tenant or unknown entity → 404;
  malformed selector → 422 (lines 24–33).
- Thin: the router does no graph logic itself, it only validates the
  selector and delegates to `correlation.correlate()`.

### 2.3 `app/timeline.py` and `app/routers/timeline_routes.py`

- Timeline is a second, adjacent read model: a **pluggable aggregator**, not
  a graph. `TimelineSource` is a `Protocol` (lines 48–52); Community
  registers `ExposureTimelineSource`, `CaseTimelineSource`,
  `AuditTimelineSource`, `CredentialTimelineSource` (lines 211–214).
- `collect()` (lines 148–156) iterates all registered sources and **swallows
  any single source's exception** ("uma fonte não pode derrubar a timeline
  inteira", line 153) — this is the exact fail-isolation pattern any Neo4j
  source must copy.
- `GET /timeline?scope=tenant|case:{id}|finding:{id}|identity:{hash}` (router
  lines 1–6, 20–47, 50–59); `GET /timeline/sources` lists registered source
  names (lines 62–64). Docstring guarantees: "Secrets never appear (upstream
  redaction)" (line 5).
- `CredentialTimelineSource` (lines 160–208) is the most sensitive source: it
  only ever emits `identity_hash`-scoped events, never raw email/password —
  see redaction discussion in §5.5.

### 2.4 UI — `app/static/app.js` (correlation/timeline area)

- Correlation: lines 2653–2820. `toggleCorrelate()` calls
  `GET /correlation?entity=finding:{id}` (line 2696) and caches the response
  client-side (`COR_CACHE`). Two views: `renderCorList()` (grouped list) and
  `renderCorGraph()` (a **single-hop radial layout**: the seed is the center
  node, one ring of neighbors around it — lines 2738–2793). Kinds with more
  than `_COR_CAP = 3` (line 2678) nodes collapse into an expandable "+N"
  aggregate node.
- Node click routes back into the relevant module (`corNodeClick`, lines
  2812–2819) rather than deep-linking into a graph explorer — there is no
  multi-hop pan/zoom canvas today.
- Timeline: lines 2336–2378 (`renderTimeline`, `toggleFindingTimeline`,
  `loadTenantTimeline`), plus the identity dossier view (lines 2879, 2910)
  that overlays `GET /timeline?scope=identity:{hash}`.

### 2.5 Tests / selftest coverage

- `tests/test_exposure_open_case.py` covers correlation indirectly through
  case-opening (`test_open_case_inherits_brand_when_correlation_is_unique`,
  `test_open_case_leaves_brand_null_when_no_correlation`, lines 35, 77) — no
  dedicated `test_correlation.py`/`test_timeline.py` unit file exists today;
  the deep functional coverage lives in `app/selftest_isolation.py`:
  - Timeline: lines 743–770 (sources registered, tenant timeline sorted
    desc, finding/case-scoped timeline, cross-tenant → 404, invalid scope →
    422) and 1230–1271 (credential timeline: `leak_ingested` + `vip_hit` +
    `reused_password`, explicit assertion that no plaintext appears in the
    response body, line 1260).
  - Correlation: lines 826–844 (finding→domain correlation, cross-tenant →
    404, invalid entity → 422) and 990–997 (surface-asset correlation).
- Any Neo4j-backed path must not require new selftest infrastructure to pass
  — `python -m pytest -q` and `python -m app.selftest_isolation` must keep
  passing unmodified, because Neo4j stays absent in that environment (see
  §6.2 and the [Acceptance Criteria Checklist](#9-acceptance-criteria-checklist)).

### 2.6 What this buys today, and where it runs out

The current design is simple, has zero extra infra, and is already
tenant-safe and redaction-safe. Its ceiling:

- **Single-hop only.** No transitive "friend of a friend" traversal, no
  shortest-path, no community/cluster detection across the whole tenant
  graph.
- **Recomputed per request.** Every `GET /correlation` re-scans every table
  (bounded at 1000 rows each) instead of querying a precomputed graph index.
  At small-to-medium tenant scale (which is what Community targets) this is
  fine; it stops being fine as row counts approach and exceed `_LIMIT`.
- **No graph-native analytics.** Centrality, path-finding, temporal graph
  queries, and cross-entity pattern mining are impractical to bolt onto
  Python set-intersection.
- **No persisted graph for external tooling.** Nothing exportable to a SOC's
  own graph exploration/BI tooling.

None of this is a defect in Community — it's the correct trade-off for an
open-source, single-Postgres deployment. It is, however, exactly the set of
gaps a graph database is good at closing, which is why #20 is worth
evaluating for **larger, Enterprise/advanced deployments** — not as a
Community requirement.

---

## 3. Why (and Why Not) Neo4j

**Arguments for:** multi-hop traversal, graph algorithms (shortest path,
centrality, community detection) for larger tenants, and a query surface
(Cypher) suited to "show me everything connected to X within N hops" — the
natural evolution of the correlation graph for advanced/analyst-heavy
deployments.

**Arguments against, right now:** the current model has not hit its ceiling
for Community's target deployments (single tenant, single Postgres, small
teams); adding a second stateful service raises operational cost
(backup, upgrade, monitoring, memory) for every Community user, even those
who never need multi-hop analysis; and it introduces a second source of
truth that must never be allowed to diverge from Postgres or to become a
required dependency.

This tension is resolved by making the integration **strictly optional and
additive** (§4), never a replacement for `app/correlation.py`.

---

## 4. Proposed Optional Architecture

### 4.1 Design principles (non-negotiable)

1. **Disabled by default.** A new env var, e.g. `GRAPH_BACKEND` (default
   `"internal"`; the only other value in Community's contract is
   `"neo4j"`), controls whether the adapter is even consulted. Default
   behavior is byte-for-byte what Community does today.
2. **Community works 100% without Neo4j.** No import of a Neo4j driver at
   module load time outside the adapter itself; the adapter lazy-imports
   exactly like `app/enterprise_adapter.py` (`_load_enterprise_integration`,
   lines 53–57) so `ModuleNotFoundError` degrades to "unavailable", never a
   crash.
3. **No default docker-compose change.** `docker-compose.yml` keeps its two
   services (`db`, `api`) untouched. A Neo4j service is offered only via a
   separate, opt-in compose overlay (§4.4).
4. **No mandatory dependency.** `neo4j` (the current official Python driver
   package name — `neo4j-driver` is deprecated) is **not** added to
   `requirements.txt`. It ships as an extra
   (`pip install threatforge[graph]` or a documented
   `pip install neo4j>=5,<6`) that Community can ignore entirely.
5. **No private code in the public repo.** Only the thin adapter interface,
   the Cypher contract, and a mocked test live in Community — exactly the
   boundary already drawn for `app/enterprise_adapter.py` and
   `docs/ENTERPRISE_ADAPTER.md`.
6. **Never break `/correlation` or `/timeline`.** Both endpoints keep
   working against `app/correlation.py`/`app/timeline.py` regardless of
   Neo4j's state. Neo4j is a *complementary* read/write path, never a
   dependency of these two request paths, in the same way `timeline.collect()`
   already isolates per-source failures (line 152–154).

### 4.2 Proposed module layout (future stage, not this one)

```
app/
  graph/
    __init__.py
    adapter.py        # thin, lazy-import seam (mirrors enterprise_adapter.py)
    contract.py        # entity/relationship dataclasses + Cypher templates
    sync.py            # optional on-demand/async upsert orchestration
  routers/
    graph_routes.py    # optional GET /graph/status (mirrors /license/status)
tests/
  test_graph_adapter.py  # mocked driver, no real Neo4j required
docs/
  NEO4J_GRAPH_POC.md      # this document
  NEO4J_GRAPH_INSTALL.md  # future — mirrors ENTERPRISE_INSTALL.md, written only
                          # once/if implementation is approved
```

`app/graph/adapter.py` would follow the exact shape of
`app/enterprise_adapter.py`: a `graph_available()` boolean check, a
`get_graph_status()` dict with no secrets, and upsert entry points that
convert *any* driver/network failure into a no-op plus a logged warning —
never a 500 on the caller's request path.

### 4.3 Feature-gate wiring

Two independent knobs, not one, because "is Neo4j configured" and "is this
Enterprise-licensed" are different questions:

- `GRAPH_BACKEND` (`app/config.py`, alongside `EDITION`) — whether Community
  even attempts to talk to Neo4j. Default `"internal"`.
- A new `Feature.GRAPH_NEO4J` entry in `app/features.py`'s `PREMIUM` set —
  whether the *value-add* capabilities (scheduled/async sync, multi-hop
  query endpoints, graph analytics, a graph-explorer UI) are unlocked.
  Community may still expose the raw adapter/status seam unlicensed (mirrors
  how the integrations catalog is visible in Community per
  `app/routers/integrations_routes.py`'s docstring), but the sync worker and
  any new query surface stay behind `ensure_enabled(Feature.GRAPH_NEO4J)`
  and return **402**, same as every other premium seam.

This mirrors the existing separation in `app/features.py` between
`config.EDITION` and the license (`entitlements()`, lines 123–126): a
customer can point `GRAPH_BACKEND=neo4j` at their own Neo4j instance, but
the advanced surface stays gated until Enterprise unlocks it.

### 4.4 Deployment: opt-in overlay, not a default service

- Add (in a later stage) `docker-compose.neo4j.yml` as an **additive**
  compose file (`docker compose -f docker-compose.yml -f docker-compose.neo4j.yml up`),
  following the existing precedent of `docker-compose.mailhog.yml` and
  `docker-compose.podman.yml` already being separate, opt-in files in this
  repo. `docker-compose.yml` itself is never touched.
- Neo4j Community Edition, run as its own container and reached over Bolt
  (`bolt://neo4j:7687`), is architecturally identical to how Postgres is
  already run today — a separate networked service, not a linked library.
  See §7.3 — licensing implications should still be reviewed before
  production use.

### 4.5 Dependency: extra, not core

- `requirements.txt` stays untouched. Document a
  `requirements-graph.txt` (or a `graph` extra in packaging metadata) that
  installs the `neo4j` driver package only for operators who set
  `GRAPH_BACKEND=neo4j`.
- The adapter must tolerate `ModuleNotFoundError` for `neo4j` exactly like
  `app/enterprise_adapter.py` tolerates a missing `threatforge_enterprise`
  package.

---

## 5. Technical Contract (for a future implementation)

This is the **minimum viable graph schema** — deliberately small, and
deliberately a mirror of what `app/correlation.py` already computes, not a
new data model.

### 5.1 Node labels (entities)

| Label | Source (Community) | Key properties (redacted) |
|---|---|---|
| `Tenant` | `tenants` table | `tenant_id` (unique) |
| `Brand` | `Brand` (`app/models.py`) | `tenant_id`, `brand_id`, `name` |
| `Observable` | `Observable` | `tenant_id`, `observable_id`, `type`, `value` (already a non-secret IOC — email/domain/hash/ip, same values `app/correlation.py`'s `_ids_from_observable` extracts) |
| `ExposureFinding` | `ExposureFinding` | `tenant_id`, `finding_id`, `title`, `exposure_type`, `severity`, `risk_score`, `created_at` — **never** the raw `detail` JSON blob |
| `SurfaceAsset` | `SurfaceAsset` | `tenant_id`, `asset_id`, `asset_type`, `value` (domain/IP), `brand_id` |
| `CredentialIdentity` | `CredentialIdentity` | `tenant_id`, `identity_hash` (the sha256 reference already used by `GET /timeline?scope=identity:{hash}` — **never** the `email`/`password_hashes` columns), `domain`, `leak_count`, `max_risk`, `status` |
| `InvestigationCase` | `InvestigationCase` | `tenant_id`, `case_id`, `title`, `status`, `severity`, `created_at` |

Every node carries `tenant_id` as a first-class property (see §5.4) — there
is no entity type in this contract that is not already tenant-scoped in
Postgres.

### 5.2 Relationship types (minimum set, per the request)

| Relationship | Direction | Meaning | Community precedent |
|---|---|---|---|
| `RELATED_TO` | any ↔ any correlated entity | Generic identifier overlap edge — the graph equivalent of `correlation.py`'s `edges[].via` | `correlate()` lines 163–168 (`add()`), edge shape `{source, target, via}` |
| `OBSERVED_IN` | `Observable`/`SurfaceAsset` → `ExposureFinding` | The observable/asset was seen inside a specific finding | `_ids_from_exposure` matching |
| `BELONGS_TO` | `Brand`/`SurfaceAsset`/`Observable` → `Tenant` | Tenant ownership/scoping edge, redundant with the `tenant_id` property but useful for `MATCH (t:Tenant)-[:BELONGS_TO]-()` scoping queries | tenant filter already applied per query in every `correlate()` table scan |
| `OPENED_FROM` | `InvestigationCase` → `ExposureFinding` (or seed entity) | Mirrors "Case opened from finding" (`case.finding_snapshot`, `correlate()` lines 216–229, "case-of-finding" `via`) | `InvestigationCase.finding_snapshot` |
| `SHARES_IDENTIFIER` | entity ↔ entity | Explicit typed edge for `via="email:…"` / `"domain:…"` / `"hash:…"` / `"ip:…"` overlaps, so Cypher queries can filter by identifier type instead of parsing the `via` string | `_overlap()` (lines 113–119) |

Every relationship property set should carry `{via_type, via_value_hash?}` —
whether the actual identifier value (e.g., an email) is stored as an edge
property or only its type is a redaction-policy call (§5.5), not an
architecture call.

### 5.3 Idempotent upsert strategy

- Every node upsert is a `MERGE` keyed by the **stable composite key** the
  entity already has in Postgres — `(tenant_id, <entity>_id)` — never an
  autogenerated Neo4j-internal id:

  ```cypher
  MERGE (f:ExposureFinding {tenant_id: $tenant_id, finding_id: $finding_id})
  ON CREATE SET f.title = $title, f.created_at = $created_at, f.first_synced_at = datetime()
  ON MATCH  SET f.title = $title, f.severity = $severity, f.risk_score = $risk_score,
                f.last_synced_at = datetime()
  ```

- Relationship upserts are likewise `MERGE`d on `(source_key, target_key,
  type, via_type)` so re-running a sync never creates duplicate edges — this
  is the standard Neo4j idempotency guidance (transaction functions must be
  safely retryable; `MERGE ... ON CREATE ... ON MATCH ...` is the documented
  pattern for exactly this).
- A per-tenant uniqueness constraint should exist per label, e.g.
  `CREATE CONSTRAINT IF NOT EXISTS FOR (f:ExposureFinding) REQUIRE (f.tenant_id, f.finding_id) IS UNIQUE`,
  so a bug in the sync path fails loudly (constraint violation) instead of
  silently duplicating nodes.
- Sync is a **projection**, not a migration: Postgres remains the system of
  record for every entity; Neo4j can be dropped and rebuilt from Postgres at
  any time with no data loss.

### 5.4 Tenant scoping

- **Property-based scoping** (`tenant_id` on every node/edge + constraints),
  not one Neo4j database per tenant. Community/Enterprise deployments are
  expected to be small-to-mid tenant counts; per-tenant databases only make
  sense at a scale this POC does not target, and Neo4j multi-database
  ("Fabric"/multi-db) is an Enterprise Neo4j feature — pulling it in would
  couple ThreatForge's tenant model to Neo4j's own commercial tier, which is
  a licensing/complexity trade Community should not force on anyone.
- Every Cypher query issued by the adapter must include `tenant_id = $tid`
  in its `WHERE`/`MERGE` pattern — no query is allowed to span tenants,
  mirroring every existing tenant-scoped query in `app/correlation.py` and
  `app/timeline.py`.

### 5.5 Redaction policy

**Rule: allowlist, not denylist.** The adapter only ever serializes an
explicit, reviewed set of properties per label (§5.1 tables) — it does not
walk a model's `__dict__`/`detail` JSON and strip "known-bad" keys. This
avoids the classic mistake of a denylist missing a new sensitive field added
to a model later.

Explicitly, the following must **never** cross into Neo4j, matching
guarantees Community already makes elsewhere in the codebase:

- Raw secrets/tokens/passwords/API keys (`app/integrations/schemas.py`'s
  `SECRETS_SPEC` pattern: only *names/presence*, never values).
- `CredentialIdentity.email` and `.password_hashes` — export only
  `identity_hash`, exactly as `GET /timeline?scope=identity:{hash}` already
  does, and exactly what `selftest_isolation.py` asserts at line 1260 ("no
  plaintext/password in timeline — leak!").
- Evidence storage keys/paths (`app/evidence_store.py` territory) — out of
  scope for the graph entirely.
- `ExposureFinding.detail` raw JSON — only the normalized identifiers
  `app/correlation.py` already computes (`_ids_from_exposure`, etc.) and the
  safe summary fields in §5.1's table.

---

## 6. Operational Model

### 6.1 Sync trigger

Two options, not mutually exclusive:

- **On-demand (Community-visible seam):** the adapter can be called
  opportunistically the same moment `app/correlation.py` computes a graph
  for a request — "upsert what I just looked up" — cheap, no scheduler,
  same request/response lifecycle Community already has.
- **Async/batch (Enterprise):** a background job (Celery/RQ/cron — the
  scheduling technology is an Enterprise concern, same bucket as "automated
  feeds"/"real-time collection" in `ROADMAP.md`) periodically walks tenants
  and upserts the full entity set. This is the only way to get graph
  freshness independent of API traffic, and it is squarely an
  "advanced deployment" operational concern, not a Community requirement.

### 6.2 Fallback

`/correlation` and `/timeline` **must** keep calling
`app.correlation.correlate()` / `app.timeline.collect()` exactly as today.
Neo4j, if enabled, is an **additional, best-effort** write path (sync) and,
only once Enterprise unlocks it, an *additional* read surface
(`GET /graph/query` or similar, not a replacement for `GET /correlation`).
If `GRAPH_BACKEND=internal` (the default) the adapter module should not even
attempt a connection — `graph_available()` short-circuits to `False` before
any driver code runs, identical in spirit to
`enterprise_adapter.enterprise_available()`.

### 6.3 Failure handling

- Every adapter call is wrapped so that connection errors, timeouts, and
  auth failures degrade to a logged warning and a no-op — never an
  exception that propagates into a FastAPI request handler. This is the
  same isolation `timeline.collect()` already applies per-source (lines
  152–154: "uma fonte não pode derrubar a timeline inteira").
- A short client-side timeout (e.g., 2–3s) and a simple failure counter that
  temporarily disables sync after N consecutive failures (a basic circuit
  breaker) prevent a degraded/unreachable Neo4j from adding latency to
  every request that happens to trigger an on-demand sync.

### 6.4 Health/status (optional)

Mirror `/license/status`: an optional `GET /graph/status` (admin/platform
role, same RBAC precedent as license status) reporting `{backend: "internal"|"neo4j",
available: bool, last_sync_at, last_error}` — never connection strings,
credentials, or raw driver errors that might leak internal hostnames.

---

## 7. Product Decision

### 7.1 Stays in Community (if/when implemented)

- The adapter *interface* (`app/graph/adapter.py`): lazy import, status
  introspection, no-op-on-failure upserts — same boundary as
  `app/enterprise_adapter.py`.
- The `GRAPH_BACKEND` config flag and the Cypher contract/constraints as
  documentation (this file, and a future `NEO4J_GRAPH_INSTALL.md`).
  documentation only.
- A mocked test (`monkeypatch` on the driver import, exactly like
  `tests/test_enterprise_adapter.py` does for
  `threatforge_enterprise` — no real Neo4j required in CI).
- The optional `docker-compose.neo4j.yml` overlay and `requirements-graph.txt`
  (both additive, never touched/required by default).

### 7.2 Stays in Enterprise / overlay

- The real sync scheduler/worker.
- Any new query endpoint beyond the existing `/correlation` and
  `/timeline` (multi-hop traversal, graph algorithms, path-finding).
- A graph-explorer UI beyond the existing single-hop radial view in
  `app/static/app.js`.
- Anything that talks to a **Neo4j Enterprise Edition** (clustering,
  advanced security, multi-database) instead of Community Edition — that is
  a second, independent commercial-license decision (Neo4j's own Enterprise
  license), separate from ThreatForge's Enterprise license, and should not
  be assumed as a requirement.

### 7.3 Licensing risk

**Licensing implications must be reviewed before production use.** The
proposed architecture treats Neo4j as an optional external service reached
only over the network (Bolt protocol) — the same relationship ThreatForge
already has with Postgres — rather than as a linked library. Final
licensing and deployment implications should be validated (with counsel, if
needed) before enabling this in production, given:

- Neo4j **Community Edition** is distributed under GPLv3. Community Edition
  and Enterprise Edition carry different license terms, and Neo4j's own
  licensing model has changed over time (most recently around the Neo4j 3.5
  era, when Enterprise-only source stopped being published on GitHub) — the
  terms in effect at implementation time should be re-checked against
  Neo4j's current legal documentation rather than assumed from this
  document.
- Neo4j **Enterprise Edition** (clustering, advanced security,
  multi-database) requires a separate commercial license from Neo4j, Inc.
  If a future ThreatForge Enterprise offering ever wants those capabilities,
  that would be a **second, independent vendor relationship** to budget and
  negotiate — it should not be assumed as "just an upgrade" without its own
  review.
- This document does not constitute legal advice. Before any production
  rollout, the specific Neo4j edition, version, and deployment topology in
  use should be checked against Neo4j's current license terms and, if there
  is any doubt about interaction with ThreatForge's own AGPL-3.0-or-later
  licensing, reviewed with legal counsel.

### 7.4 Operational/support risk

- A second stateful service means: its own backup/restore story, its own
  upgrade cadence, its own memory footprint (Neo4j is JVM-based and
  noticeably heavier than the current single-Postgres footprint), its own
  failure modes to document and support.
- Community's current promise — "works with just Postgres, one container" —
  should not be diluted. This is the strongest argument for keeping Neo4j
  fully opt-in and out of the default compose/requirements files.
- Support burden: every "why is my graph out of sync" or "why is Neo4j using
  4GB of RAM" ticket is now a support surface. That cost belongs with
  whoever is running the optional/Enterprise deployment, not with Community
  maintainers by default.

### 7.5 Benefit vs. complexity

| | Current (`app/correlation.py`) | Neo4j (proposed, optional) |
|---|---|---|
| Infra | None beyond Postgres | +1 stateful service (JVM) |
| Query power | Single-hop, in-process set overlap | Multi-hop, graph algorithms, Cypher |
| Freshness | Always current (computed per request) | Depends on sync cadence |
| Community impact if unused | None | None, if truly opt-in (§4) |
| Right-sized for | Single-tenant/small-team Community deployments | Larger, analyst-heavy, Enterprise/advanced deployments |

The benefit is real, but it is a **large-tenant / advanced-analysis**
benefit, not a Community-core benefit — which is exactly why #20 should
land as an optional Enterprise-facing capability with a thin, safe seam in
Community, not as a Community dependency.

---

## 8. Recommendation & Next Steps

1. **Implement now:** nothing beyond this document.
2. **Postpone:** the actual adapter code, `docker-compose.neo4j.yml`, the
   `neo4j` driver dependency, and any new endpoint — until this design is
   reviewed and approved.
3. **Keep in Enterprise only, permanently:** sync scheduling/workers,
   multi-hop query endpoints, graph algorithms, and any graph-explorer UI.
4. When approved, the first implementation PR should be scoped to exactly
   §4.2's module layout plus one mocked test — no real Neo4j connection code
   beyond the lazy-import seam — so it can land in Community without adding
   any runtime dependency, exactly like `app/enterprise_adapter.py` did for
   the Enterprise bridge.

---

## 9. Acceptance Criteria Checklist

- [x] `docs/NEO4J_GRAPH_POC.md` created.
- [x] Clear decision recorded: **postpone implementation now; keep the
      value-add surface Enterprise-only when it does land** (§Decision, §8).
- [x] No functional change to Community in this pass — only this markdown
      file was added; `app/`, `requirements.txt`, and `docker-compose.yml`
      are untouched.
- [x] No mandatory Neo4j dependency — none proposed to be added anywhere in
      this stage, and the future design keeps it an opt-in extra (§4.5).
- [x] No code included in this pass (per "código de integração real só
      depois da aprovação do desenho"); when code does land, it must be an
      optional adapter, disabled by default, with a mocked test (§7.1),
      matching the existing `app/enterprise_adapter.py` /
      `tests/test_enterprise_adapter.py` precedent.
- [ ] `python -m pytest -q` / `python -m app.selftest_isolation` — not
      re-run against a modified tree in this pass, because no application
      code changed (documentation-only diff). They should be run as part of
      normal CI on this branch to confirm; nothing in this document alters
      any code path they exercise.

---

## References

- Neo4j Community Edition vs. Enterprise Edition licensing:
  [neo4j.com/open-core-and-neo4j](https://neo4j.com/open-core-and-neo4j/),
  [Neo4j Legal Center](https://legal.neo4j.com/).
- Neo4j Python driver: optional future dependency to be evaluated before implementation.
