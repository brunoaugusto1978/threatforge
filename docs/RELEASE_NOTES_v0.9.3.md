# ThreatForge Community v0.9.3 — Real Integration Configuration UI

Small UX release on top of `0.9.2`. Focus: replace the misleading
"Integration configured" toast that fired after posting an empty body with a
real modal-driven form, and enforce the required-fields contract on the
server so `/test` and `/sync` only report `ready`/`queued` for connections
that could actually be used.

## Why

v0.9.2 unblocked the three `POST` endpoints — they no longer return 501 when
the Enterprise licence unlocks the feature — but the UI still submitted
`{}` on click and the server persisted it. Two problems fell out:

1. The operator saw *Integration configured* even though no fields had been
   entered. That claim was false.
2. `POST /integrations/misp/test` then returned `configured=true, status=ready`
   for a row that had no `base_url` and no `api_key`. Any subsequent sync
   attempt in Enterprise would have failed because the row was structurally
   incomplete.

v0.9.3 fixes both by (a) building a real form per connector and (b) making
the server refuse incomplete payloads.

## What changed

### UI — `app/static/app.js`

- **Modal form.** Clicking **Configure** on an unlocked card opens a modal
  built from `GET /integrations/{name}`:
  - `config_schema.properties` → typed inputs (text / password / number /
    checkbox / select / comma-separated array). Required fields marked with
    `*` and ordered first.
  - `secrets_schema.required` + `secrets_schema.optional` → password inputs.
    Any field whose name matches the server-side secret list is also rendered
    as `type="password"` regardless of what the JSON schema says.
- **Prefill.** Non-secret fields are seeded from `GET
  /integrations/{name}/connections`. Secret inputs are always blank; a
  "•••••••• (on file)" placeholder tells the operator whether a credential
  is stored server-side without ever showing the value.
- **Save.** `POST /integrations/{name}/connections` with the collected
  payload. Response handling:
  - **200** → toast *Integration configuration saved*, close modal, wipe the
    secret input DOM values, refresh the Integrations catalogue view.
  - **422** → toast *Configuration required: base_url, api_key* (list from
    `detail.missing_fields`) and highlight the error under the form.
  - **402** → the existing upgrade CTA (`enterpriseUpgradeMessage`).
- **Test connection.** In-modal button; calls `POST /test` and toasts the
  server's message (`ready` vs `not_configured`) without leaking credential
  state.
- **Locked cards short-circuit.** *Configure (Enterprise)* buttons on locked
  cards go straight to the 402 upgrade CTA — the form isn't rendered at all,
  so an unlicensed operator can't be tricked into typing a credential into a
  UI that would immediately reject it.
- **CSP-safe.** No inline `onclick=`/`onsubmit=` (the app CSP is
  `script-src 'self'`). The click dispatcher already in the app.js handles
  every button via `data-action`; the modal registers a JS `submit` listener
  after insertion so Enter-to-save works without inline handlers.

### Backend — `app/routers/integrations_routes.py`

- **Required-fields validation.** `POST /connections`:
  - Reads required non-secret fields from the descriptor's pydantic JSON
    schema `required` list, and required secret names from
    `SECRETS_SPEC[name].required`.
  - Missing keys yield **422** with:

    ```json
    {"detail": {
      "message": "Configuration required.",
      "missing_fields": ["base_url", "api_key"],
      "missing_config_fields": ["base_url"],
      "missing_required_secrets": ["api_key"]
    }}
    ```

    and audit `integration.config_rejected`. Nothing is persisted on this
    path.
  - Field matching is case-insensitive so `Base_Url` / `API_KEY` still count.
- **`_is_ready(row, descriptor, name)`** predicate replaces the old
  "row exists → ready" heuristic. `/test` and `/sync` gate on this — a row
  with `base_url` but no `api_key` marker reports `not_configured`.
- **`GET /integrations/{name}/connections`** — returns the tenant's stored
  row (masked; `null` if unsaved). Viewer+ can read; response never carries
  secret values. Missing licence → **402** + audit `integration.read_denied`.
- **`GET /integrations/{name}`** now includes `secrets_schema:
  {required: [...], optional: [...]}` alongside `config_schema` so the UI
  can build the credential section from a single request.
- **`ready` flag** on both the POST response and the GET row — mirrors what
  `/test` would say for that row.
- **Merge-safe secret markers.** The router loads the existing row *before*
  running required-secret validation, so a re-save with a blank credential
  input is treated as satisfied by the ``present=True`` marker on file.
  Editing only non-secret fields keeps the *secret on file* marker and
  ``/test`` keeps reporting *Ready* instead of regressing to
  *not_configured*. First-configuration payloads without the required secret
  still 422 (there is no marker to inherit from).

### Contract — `app/integrations/schemas.py`

- **`SecretSpec`** dataclass with `required` and `optional` tuples of secret
  *names* (never values).
- **`SECRETS_SPEC`** mapping:
  - `misp`: required `api_key`
  - `opencti`: required `api_token`
  - `generic`: optional `token`, `secret`
- **`secrets_spec_for(name)`** helper — returns an empty `SecretSpec` for
  unknown names so the router degrades safely.

## Explicit non-goals for v0.9.3

- **No real connector I/O.** Push/pull, scheduled sync, TLS pinning and
  anti-SSRF validation still live in `threatforge-enterprise`.
- **No secret storage in Community.** The DB row never contains secret
  values; the router still strips them before persistence and the response
  never echoes them.
- **No new database migration.** v0.9.3 reuses `integration_connections`
  from v0.9.2 unchanged — the required-fields contract is a runtime concern
  driven by the descriptors, not a schema change.

## Security notes

- CSP unchanged (`script-src 'self'`). The modal contains no inline event
  handlers; all interactivity flows through the existing delegated
  `data-action` dispatcher.
- Secret DOM inputs are cleared programmatically after a successful save so a
  malicious extension reading the DOM later can't recover the typed value.
- The `ready` flag on the response is computed from the row's structure
  only — it is never an "I successfully talked to the remote server" signal;
  that remains an Enterprise concern.
- Audit trail on the licensed path: `integration.config_saved` /
  `integration.config_rejected` / `integration.test_requested` /
  `integration.sync_requested`. Rejected attempts never carry secret values
  — the router logs *missing* field *names*, never *received* field values.

## Migration & rollback

No schema change. Just `git checkout v0.9.3` and restart:

```bash
# no alembic upgrade needed for v0.9.3
```

## Validation

```bash
git diff --stat
git diff
python -m pytest -q
python -m pytest tests/test_integrations* -q
```

Expected: the reworked `tests/test_integrations_config.py` (36 cases)
including the descriptor `secrets_schema` matrix, 422 breakdowns, the
`config_rejected` audit action, the new `GET /connections` endpoint, the
`ready` flag, secret masking (now via `generic` so no unrelated required
credential is needed), upsert-preserves-marker, RBAC, and cross-tenant
isolation — all pass. Legacy suites keep passing (no schema change).

## What to look at manually after deployment

1. Open the Integrations screen as a tenant admin on a Community host
   *without* an Enterprise licence.
   - Cards show `Enterprise 🔒` and the button reads `Configure
     (Enterprise)`. Clicking it toasts the upgrade CTA — no modal opens.
2. On a host with an Enterprise licence granting `integration.misp`:
   - Card shows `Available` and the button reads `Configure`. Clicking it
     opens the modal.
   - Submitting an empty form toasts *Configuration required: base_url,
     api_key* and stays open.
   - Filling both and clicking Save toasts *Integration configuration
     saved* and closes the modal. Reopening prefills `base_url` and the
     credential input shows *•••••••• (on file)*.
   - Clicking *Test connection* toasts the *ready* message.
3. `/audit` shows `integration.config_saved` for the successful save,
   `integration.config_rejected` for the empty-form attempt, and neither
   entry contains the secret value.
