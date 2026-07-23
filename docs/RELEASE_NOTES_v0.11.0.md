# ThreatForge Community v0.11.0 — Telegram Intelligence and Intelligence Workspace

ThreatForge Community v0.11.0 introduces the provider-neutral foundations,
tenant-scoped APIs and operational interface required for authorized inbound
intelligence collection.

## Highlights

- Intelligence Workspace with tenant-scoped overview, redacted event feed,
  event details, source status and collector health.
- Authorized Telegram connection and source management.
- Isolated collection worker with heartbeat monitoring and bounded polling.
- Dashboard visibility for license availability, connection state,
  authorized-source count, collector health and recent activity.
- Conversation-aware analysis with deterministic confidence scoring.
- Correlation into exposure findings and investigation cases.
- Case visibility for linked events, decisions and recent activity.
- Canonical license capabilities for Telegram collection and analysis.

## Inbound and outbound separation

Inbound Telegram Intelligence follows this flow:

    Authorized Telegram source
      -> collection worker
      -> normalized and redacted event
      -> Intelligence Workspace
      -> analysis
      -> exposure finding or investigation case

Outbound Telegram notifications remain a separate alerting flow:

    ThreatForge finding
      -> Telegram notification destination

Inbound collection events remain separate from outbound alert records.

## Security and privacy

- Telegram bot tokens are not stored in connection or source metadata.
- The database stores only validated opaque secret references.
- Raw provider payloads, actor identifiers, chat identifiers, fingerprints
  and secret references are not exposed through the Intelligence Workspace.
- Connections, sources, events, findings and cases remain tenant-scoped.
- Provider errors use a sanitized diagnostic vocabulary.
- Automated findings and cases preserve idempotency and human review.

## Database and compatibility

- Community application version: 0.11.0.
- Alembic migration head: 20260718_01_tgcoll.
- Community and Enterprise use the same schema and API release train.
- Compatible Enterprise packages must support the Community 0.11.x line.

## Runtime validation

Final acceptance confirmed:

- healthy API, PostgreSQL and collection worker;
- matching Alembic current, head and database revision;
- valid Enterprise license and compatible package versions;
- authorized Telegram connection and active source;
- credential resolution through an opaque file reference;
- end-to-end ingestion of a controlled source event;
- persistence and analysis of the event;
- immediate Intelligence Workspace and Dashboard updates;
- no credential, rejected-update or ignored-update errors;
- preservation of historical events, findings and cases;
- separation between inbound collection and outbound notifications.

Customer-specific evidence, credentials, tokens, license material and
acceptance data remain outside the public repository.

## Upgrade notes

1. Back up PostgreSQL and evidence volumes before upgrading.
2. Apply the migration to 20260718_01_tgcoll.
3. Configure credentials through supported opaque secret references.
4. Enable the collection worker only in authorized deployments.
5. Start it through the telegram-collector Compose profile.
6. Confirm tenant isolation, source authorization and collector health.

## Community and Enterprise

The Community repository contains the provider-neutral schema, contracts,
security boundaries, APIs and user interface.

Provider-specific premium collection, analysis and reporting require the
separately licensed Enterprise package.
