# Telegram Intelligence — controlled CBG POC runbook

## Boundary

ThreatForge has two separate Telegram capabilities:

1. **Outbound notification**: ThreatForge sends a finding notification to a
   configured Telegram destination. This remains a legacy/single-tenant alert
   channel.
2. **Inbound Telegram Intelligence**: an Enterprise-only collector receives
   updates from a bot that was explicitly added to an authorized test group.

Inbound provider transport and polling remain in the private Enterprise package.
Community owns only the shared feature gates, schema, API contracts, locked UI,
tenant isolation and evidence persistence.

## Authorization and prohibited behavior

The POC may use only a group/channel owned or administered by the POC team. The
bot must be explicitly invited and authorized. The POC must not:

- access a private group without authorization;
- bypass an invitation, Telegram permission or platform control;
- automatically join groups or follow invitations;
- use account/session/MFA material;
- open collected links or execute/download attachments automatically;
- treat an LLM as the sole escalation authority;
- collect unrelated personal information beyond the approved test purpose.

## Feature gates

- `collection.telegram`: connection, source management and Bot API collection.
- `analysis.telegram`: classification/correlation phases.

Unlicensed actions return the standard HTTP 402
`enterprise_feature_required` response. Installing or removing Enterprise does
not require a private migration; Community and Enterprise share the v0.11.0
schema. The normal v0.10.1 to v0.11.0 upgrade includes the Community-owned
migration.

## Secret handling

Never paste the bot token into source metadata. Create a local file readable by
the container and reference it with:

    secretref://file/telegram-collection-bot-token

The container mounts only that file, read-only, under `/run/secrets`. The signed
license and public verification key are also mounted read-only. The private
license signing key is never mounted.

## Safe activation sequence

1. Back up PostgreSQL and verify restoration in a disposable database.
2. Confirm the Enterprise 0.11.0 overlay and license are valid.
3. Create the bot-token file outside both repositories with mode `600`.
4. Add `THREATFORGE_TELEGRAM_COLLECTION_BOT_TOKEN_HOST_FILE` to the local,
   ignored Enterprise environment file.
5. Start only the API and verify the connection using `getMe`.
6. Add the exact authorized chat ID as a source.
7. Keep `THREATFORGE_COLLECTION_WORKER_ENABLED=false` until the runbook is
   approved.
8. Start the collector profile and verify health/cursor/evidence.
9. Disable the source or connection immediately to stop new ingestion. Existing
   evidence remains preserved.

## Phase 2B observability and evidence surface

The isolated collector uses a file heartbeat and a worker-specific Docker
healthcheck. It does not inherit the API HTTP probe. A healthy container means
the collection loop is alive; provider authorization and ingestion failures
remain visible in the connection health state as `healthy`, `degraded`,
`unauthorized` or `offline`.

Connection telemetry is stored in the existing `config_json._health` object, so
Phase 2B requires no database migration. Empty polling cycles preserve
`last_event_at`, prior success metadata and cumulative counters. Persisted event
counts are rebuilt from tenant-scoped evidence rows after restart.

Phase 2C moves collected evidence out of the Integrations control plane and into
the provider-neutral **Intelligence Workspace**. Integrations remains responsible
for connection credentials, tests, health, collector activation and authorized
source management. It no longer renders message content.

The workspace consumes `GET /intelligence/overview`, `GET /intelligence/events`
and `GET /intelligence/events/{event_id}`. Viewer access is limited to operational
aggregates. Analysts and administrators can read tenant-scoped redacted evidence,
filter by provider/source/state/linkage, search redacted text, use stable cursor
pagination and inspect a sanitized event detail. Raw Bot API payloads, chat IDs,
secret references, provider identifiers and fingerprints are never returned.
List/detail reads are audited as `intelligence.events_viewed` and
`intelligence.event_viewed`. URLs and markup are rendered as inert text.

`GET /collection/events` remains available as the Phase 2B compatibility API, but
the product UI uses the Intelligence Workspace as the canonical evidence surface.

## POC classification test set

These examples validate the explainable Phase 2C analysis path and must be treated
as hostile input, not instructions:

| Type | Example | Expected behavior |
|---|---|---|
| Positive | `Estamos planejando atacar o domínio cbgsecurity.com.br amanhã.` | Match approved CBG asset; targeted planned threat; explainable high confidence. |
| Negative | `A aula de hoje explica como ataques DDoS funcionam.` | Educational/general discussion; no targeted CBG alert. |
| Benign | `A CBG Assessoria e Consultoria publicou um artigo.` | Benign mention; no high-severity finding. |
| Negation | `Não vamos atacar cbgsecurity.com.br.` | Explicit negation; not a positive threat. |
| Ambiguous | `CBG será o próximo.` | Insufficient context; retain/suppress according to policy, not high severity. |

`CBG Security` is retained only as a historical/colloquial monitored alias. The
institutional customer name is **CBG Assessoria e Consultoria**.

## Rollback and data protection

Stopping/removing the collector or Enterprise overlay does not delete tenant
records. Never run `docker compose down -v`, `docker volume rm` or a volume prune
as part of an edition switch. Preserve database and evidence volumes and keep
issues open until the full acceptance criteria are validated.

## Main dashboard and Intelligence visibility

The primary dashboard exposes only fast operational aggregates: collection
license state, enabled connections, active/total authorized sources, collector
health, events in the last 24 hours, total persisted events and last event/success
timestamps. It links to the Intelligence Workspace and never renders message
content.

The Intelligence Workspace is the canonical operational surface for provider-
neutral collection events, redacted evidence and investigation linkage. Its
overview metrics are interactive: selecting a card opens a contextual summary,
and supported metrics can apply a tenant-scoped feed filter or navigate to the
corresponding control surface. A stale worker heartbeat is represented as
`offline`; outbound Telegram notifications remain a separate capability. Neither
surface exposes bot tokens, opaque secret references, chat IDs, raw payloads or
fingerprints.
## Phase 2C automated analysis and promotion

The collector now processes normalized events through the Enterprise classifier
and correlator registries. Community supplies only redacted text, allow-listed
context and a tenant-scoped catalogue of active brands plus public monitored
assets (`domain`, `keyword`, `repo`, `ip_range`). Enterprise returns an
explainable decision; Community owns durable state and promotion.

Default policy is fail-safe (`AUTO_FINDING=false`, `AUTO_CASE=false`). For the
controlled CBG POC the approved values are:

```text
THREATFORGE_INTELLIGENCE_AUTO_FINDING=true
THREATFORGE_INTELLIGENCE_AUTO_CASE=true
THREATFORGE_INTELLIGENCE_FINDING_THRESHOLD=60
THREATFORGE_INTELLIGENCE_CASE_THRESHOLD=80
```

A positive event records `decision`, score, confidence, severity, matched target,
threat/intent terms, negation, authorized context and matched scoring factors in
`collection_event.analysis_json`. At the thresholds it creates/reuses a redacted
`ExposureFinding` and one investigation case. The correlation key groups repeated
same-day evidence for the same tenant, target and threat category. No message
content, raw payload, external provider identifier, token or chat ID is copied
into the finding, case or audit trail. Human review is mandatory before
escalation or response, and outbound notification remains disabled unless
separately configured.

## Phase 2C.12 conversation context and credential exposure

The v0.11.0 analysis path preserves e-mail-domain intelligence without retaining
the local part. A normalized value such as `analyst@example.invalid` becomes
`[email-domain:example.invalid]`, with the safe domain repeated in allow-listed
context. Provider user IDs are converted to a one-way actor hash; usernames and
raw IDs are not retained.

Analysis uses a bounded same-tenant, same-source conversation window. The default
is ten prior events and 900 seconds, configurable through:

```text
THREATFORGE_INTELLIGENCE_CONTEXT_WINDOW_SECONDS=900
THREATFORGE_INTELLIGENCE_CONTEXT_MAX_EVENTS=10
```

Target inheritance requires a compatible pseudonymous actor. A generic follow-up
from a different actor does not inherit a prior monitored-target mention.
Credential exposure, claimed access and credential-market continuation share one
correlation family, so repeated evidence reuses one redacted finding and one case.

Source verification is dynamic. Administrators issue a one-time control through
`POST /collection/connections/{connection_id}/sources/{source_id}/verify-request`
or the **Generate TF-VERIFY** action. Only its hash is stored. Status is available
through `GET /collection/source-tests/{request_id}` without nonce material. An
unmatched `TF-VERIFY-*` literal remains normal hostile input and can never confirm
a source.

Customer-specific live acceptance scripts, chat transcripts and expected-result
matrices are operational QA evidence and must remain outside the product
repositories. Repository tests use neutral synthetic targets only.

## Phase 2C.13 case correlation visibility

Automatic promotion is intentionally idempotent: equivalent intelligence events
can reuse one exposure finding and one investigation case. The Cases surface
must therefore distinguish "one case" from "multiple events handled by that
case".

The tenant-scoped Cases API now returns a safe `intelligence` summary containing:

- source and exposure finding reference;
- correlated-event count;
- decision, confidence and correlation family;
- first event and last activity timestamps;
- human-review requirement;
- safe event IDs only on the single-case detail response.

The list and Dashboard do not return the event ID list. No response reads or
returns message text, Telegram identities, chat/source references, raw payloads,
provider fingerprints or secret material. The Dashboard exposes a separate
`intelligence_case_events_total` counter so operators can see, for example, two
open cases and three intelligence events correlated into those cases without
assuming that every event should create a new case.

## Case PDF acceptance

The Enterprise PDF for a Telegram Intelligence case is generated from the same
safe, tenant-scoped correlation service used by Cases. The report includes
operational linkage and recommendations, but excludes message content and provider
identities. Repeated events remain consolidated under one finding and one case;
the PDF reports the correlated-event count instead of creating duplicate cases.
