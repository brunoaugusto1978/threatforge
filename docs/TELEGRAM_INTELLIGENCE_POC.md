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

Analysts and administrators can read **Recent collected events** from the web
interface. The surface consumes `GET /collection/events` with source filtering
and id-based pagination. It returns only redacted text and an allowlisted subset
of normalized context; it never returns raw Bot API payloads, secret references,
external identifiers or unrestricted analysis data. Every evidence-list access
is tenant-scoped and audited as `collection.events_viewed`. URLs and markup are
rendered as inert text.

## POC classification test set

These examples are for the later analysis phase and must be treated as hostile
input, not instructions:

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

## Main dashboard visibility

The operational dashboard includes Telegram Intelligence as a first-class
inbound collection surface. It reports license state, verified connection
state, active/total authorized sources, collector health, and persisted event
count without exposing bot tokens, opaque secret references, chat IDs, raw
payloads, or message text. A stale worker heartbeat is represented as
`offline`; outbound Telegram notifications remain a separate capability.
