"""Premium integrations — catalog (free) + gated configure/test/sync.

Community exposes the *catalog* (200, viewer+) so the UI can show MISP/OpenCTI/
Generic as Enterprise-locked features with capabilities and an upgrade CTA.
Configure/test/sync go through the single feature-gate layer:

- Without a valid Enterprise license, the endpoints return **402** and log the
  corresponding ``integration.*_denied`` audit action — Community behaviour is
  unchanged for unlicensed hosts.
- With the Enterprise license unlocking the descriptor's feature
  (``integration.misp`` / ``integration.opencti`` / ``integration.generic``), the
  endpoints persist a **minimal, non-secret** connection row and return
  controlled status payloads:

  * ``POST /integrations/{name}/connections`` — enforces the descriptor's
    required config fields (from the pydantic schema's ``required`` list) and
    the required secret names (from :data:`app.integrations.schemas.SECRETS_SPEC`).
    Missing keys yield **422** + ``missing_fields`` and audit
    ``integration.config_rejected`` — nothing is persisted. When all required
    fields are present, secret values are stripped and only their names are
    recorded in ``secrets_metadata``; audit ``integration.config_saved``.
  * ``GET /integrations/{name}/connections`` — returns the tenant's stored row
    (masked; ``null`` when nothing is saved) so the UI can prefill non-secret
    fields on subsequent opens without ever seeing secret values.
  * ``POST /integrations/{name}/test`` — returns ``{configured, status,
    message}`` reflecting :func:`_is_ready`; audit
    ``integration.test_requested``.
  * ``POST /integrations/{name}/sync`` — returns ``{accepted, status, message}``
    on the same predicate; audit ``integration.sync_requested``.

No real MISP/OpenCTI I/O is performed in Community — the transport, encrypted
secret storage and anti-SSRF validation still live in ``threatforge-enterprise``
and register via :func:`app.integrations.register_connector`.

RBAC: viewer reads the catalog and the (masked) stored row; configuring/
testing/syncing requires admin effective role — which excludes support_operator
(analyst) and support_viewer (viewer), so platform/tenant operators in support
mode cannot manage external connector credentials. Cross-tenant/unknown -> 404.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, features, integrations
from app.auth import Principal, current_tenant_id, require_admin, require_viewer
from app.database import get_db
from app.integrations.schemas import SecretSpec, secrets_spec_for
from app.models import IntegrationConnection, utcnow

router = APIRouter(prefix="/integrations", tags=["integrations"],
                   dependencies=[Depends(require_viewer)])


# Keys we never persist and never echo back in cleartext. Kept in lowercase.
# Matches app.audit._REDACT so the same discipline is applied everywhere.
# Union of every documented secret name across connectors, so an unexpected
# secret key from any caller is still stripped defensively.
_SECRET_KEYS: frozenset[str] = frozenset({
    "api_key", "api_token", "token", "secret", "password",
    "client_secret", "auth_key", "private_key",
})


def _audit(db, principal, tid, request, action, name, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="integration", target_id=None, request=request,
                 detail={**detail, "integration": name})


def _secrets_schema_view(spec: SecretSpec) -> dict:
    """UI-facing representation of a :class:`SecretSpec`.

    Returns lists (not tuples) so it JSON-serialises directly and is stable
    across the wire.
    """
    return {"required": list(spec.required), "optional": list(spec.optional)}


def _catalog_item(d) -> dict:
    enabled = features.is_enabled(d.feature)
    item = {
        "name": d.name,
        "title": d.title,
        "feature": d.feature.value,
        "capabilities": list(d.capabilities),
        "premium": d.premium,
        "enabled": enabled,
        "description": d.description,
    }
    if not enabled:
        item["upgrade"] = features.upgrade_block()
    return item


@router.get("")
def list_integrations():
    """Public catalog (viewer+). Always 200 — shows premium features as locked."""
    return [_catalog_item(d) for d in integrations.list_descriptors()]


@router.get("/{name}")
def get_integration(name: str):
    """Descriptor detail: capabilities, config JSON schema and secrets schema.

    The UI uses ``config_schema`` to render non-secret inputs and
    ``secrets_schema`` to render the password-style inputs. Both are needed to
    build a real form.
    """
    d = integrations.get_descriptor(name)
    if d is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    item = _catalog_item(d)
    item["config_schema"] = d.config_schema.model_json_schema()
    item["secrets_schema"] = _secrets_schema_view(secrets_spec_for(name))
    return item


def _gate(db, principal, tid, request, name: str, denied_action: str):
    """Resolve descriptor (404 unknown) and enforce the license gate (402)."""
    d = integrations.get_descriptor(name)
    if d is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    if not features.is_enabled(d.feature):
        _audit(db, principal, tid, request, denied_action, name,
               {"edition": config.EDITION, "feature": d.feature.value})
        features.ensure_enabled(d.feature)  # -> 402 (global handler)
    return d


def _split_secrets(payload: dict | None) -> tuple[dict, dict]:
    """Return (sanitized_config, secrets_metadata).

    * ``sanitized_config`` is the input dict minus every top-level key whose
      lowercase name appears in :data:`_SECRET_KEYS`. Nothing about a secret's
      value is retained.
    * ``secrets_metadata`` records, for each stripped key, only that a secret
      was received (never the value or a partial hash).

    Community never persists real credentials, so masking here is defense in
    depth: even if a client sends ``api_key=<value>``, only ``{"present":
    true, "masked": "***"}`` reaches the database and the response.
    """
    if not isinstance(payload, dict):
        return {}, {}
    sanitized: dict = {}
    secrets: dict = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            # Non-string keys can't be schema fields; drop them defensively.
            continue
        if key.lower() in _SECRET_KEYS:
            secrets[key] = {"present": bool(value), "masked": "***"}
        else:
            sanitized[key] = value
    return sanitized, secrets


def _required_config_fields(descriptor) -> tuple[str, ...]:
    """Extract required non-secret field names from the pydantic JSON schema."""
    schema = descriptor.config_schema.model_json_schema()
    required = schema.get("required") or []
    return tuple(str(x) for x in required)


def _missing_required(descriptor, name: str, payload: dict,
                      existing: IntegrationConnection | None = None,
                      ) -> tuple[list[str], list[str]]:
    """Return (missing_config_fields, missing_required_secret_names).

    A config field is missing when either the key is absent from the payload
    or its value is an empty string / None / empty list. Booleans and zero
    are considered *present* (legitimate values), matching pydantic's
    ``Field(...)``-style contract.

    A required *secret* is missing only when both:

      1. The payload does not carry a non-empty value for that secret name, and
      2. The existing row (if any) does not already record a ``present=True``
         marker for that same name.

    This lets the modal UI post a re-save with the credential input blank —
    which is the correct behaviour when the operator only wants to change
    non-secret fields — without regressing an already-configured row to
    ``not_configured``. On the *first* configuration ``existing`` is ``None``
    and the caller must supply every required secret; the empty-payload path
    still returns 422.

    Config fields do *not* inherit from the existing row: the modal always
    prefills and resends non-secret fields, so an omission in a re-save is a
    genuine attempt to clear a required field and should be rejected.
    """
    def _empty(v) -> bool:
        return v is None or v == "" or v == []

    def _marker_present(meta: dict, key: str) -> bool:
        # Case-insensitive lookup on the stored metadata keys, matching how
        # the split pass writes them (whatever case the caller sent).
        for stored_key, marker in (meta or {}).items():
            if isinstance(stored_key, str) and stored_key.lower() == key.lower():
                return isinstance(marker, dict) and marker.get("present") is True
        return False

    payload = payload if isinstance(payload, dict) else {}

    # Case-insensitive lookup keyed by lowercased key name — this mirrors the
    # secret-masking pass (which is also case-insensitive) so a user typing
    # ``Base_Url`` isn't rejected for a required field they actually sent.
    lowered = {k.lower(): v for k, v in payload.items() if isinstance(k, str)}

    missing_cfg = [f for f in _required_config_fields(descriptor)
                   if _empty(lowered.get(f.lower()))]

    stored_secrets = dict(existing.secrets_metadata or {}) if existing is not None else {}
    spec = secrets_spec_for(name)
    missing_sec = [
        s for s in spec.required
        if _empty(lowered.get(s.lower())) and not _marker_present(stored_secrets, s)
    ]
    return missing_cfg, missing_sec


def _is_ready(row: IntegrationConnection | None, descriptor, name: str) -> bool:
    """True when the stored row has every required config + secret marker.

    Called by ``/test`` and ``/sync`` — the row alone isn't enough anymore: a
    row that only has ``{"base_url": ...}`` for MISP is *persisted* but not
    *ready* until the ``api_key`` presence marker is on file too.
    """
    if row is None:
        return False

    stored_cfg = dict(row.config_json or {})
    stored_secrets = dict(row.secrets_metadata or {})

    # Case-insensitive keys on both sides.
    cfg_lc = {str(k).lower(): v for k, v in stored_cfg.items()}
    sec_lc = {str(k).lower(): v for k, v in stored_secrets.items()}

    for field in _required_config_fields(descriptor):
        v = cfg_lc.get(field.lower())
        if v is None or v == "" or v == []:
            return False

    spec = secrets_spec_for(name)
    for secret_name in spec.required:
        marker = sec_lc.get(secret_name.lower())
        if not (isinstance(marker, dict) and marker.get("present")):
            return False
    return True


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _serialize(row: IntegrationConnection, descriptor=None) -> dict:
    """Row -> JSON response. Never echoes secret values.

    When ``descriptor`` is supplied we also report ``ready`` (mirrors what
    ``/test`` would say for this row) so the UI can render a "Ready ✓" badge
    without an extra request.
    """
    out = {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "enabled": bool(row.enabled),
        "config": dict(row.config_json or {}),
        "secrets_metadata": dict(row.secrets_metadata or {}),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }
    if descriptor is not None:
        out["ready"] = _is_ready(row, descriptor, row.name)
    return out


def _get_connection(db: Session, tid: int, name: str) -> IntegrationConnection | None:
    return db.scalar(select(IntegrationConnection).where(
        IntegrationConnection.tenant_id == tid,
        IntegrationConnection.name == name,
    ))


@router.get("/{name}/connections")
def get_connection(name: str, request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_viewer),
                   tid: int = Depends(current_tenant_id)):
    """Return the tenant's stored connection for ``name`` (masked) or ``null``.

    Used by the UI to prefill non-secret fields when the operator reopens the
    configuration modal. Viewer+ can read this — it contains no secret values
    (only ``secrets_metadata`` presence markers) and no other tenant's data.

    404 for unknown integration names. 402 for premium integrations without a
    licence — behaviour mirrors ``POST /connections`` so unlicensed hosts see
    the same gate for every method.
    """
    d = _gate(db, principal, tid, request, name, "integration.read_denied")
    row = _get_connection(db, tid, name)
    if row is None:
        return None
    return _serialize(row, descriptor=d)


@router.post("/{name}/connections")
def configure_integration(name: str, request: Request, payload: dict = Body(default={}),
                          db: Session = Depends(get_db),
                          principal: Principal = Depends(require_admin),
                          tid: int = Depends(current_tenant_id)):
    """Persist a minimal, non-secret connection for the requested integration.

    Enterprise/licensed path (Community without license -> 402 via ``_gate``):
      1. Load the existing row (if any) so the required-secret validator can
         honour markers already on file (:func:`_missing_required` — this is
         what lets the modal post a re-save with a blank credential input).
      2. Validate required config + required secret names against the payload
         merged with the existing markers. Missing keys yield **422** with a
         ``missing_fields`` breakdown and audit ``integration.config_rejected``
         — nothing is persisted.
      3. Strip secret keys from the payload (``_split_secrets``).
      4. Upsert one row per (tenant, name). Secret markers are merged rather
         than overwritten, so a re-save without a credential input keeps the
         previous ``present=True`` marker.
      5. Audit ``integration.config_saved``.
      6. Return the row with secrets masked (``ready`` reflects
         :func:`_is_ready`, which is guaranteed True on the success path
         because validation just passed).

    Real credential storage / encrypted vault / anti-SSRF validation are still
    Enterprise concerns — this endpoint intentionally does not touch any
    external service.
    """
    d = _gate(db, principal, tid, request, name, "integration.config_denied")

    # IMPORTANT: load existing row BEFORE validation. The required-secret
    # check must know whether a marker is already on file so a partial
    # re-save (non-secret fields only) succeeds. On first configuration the
    # row is ``None`` and every required secret must come from the payload.
    existing = _get_connection(db, tid, name)

    missing_cfg, missing_sec = _missing_required(d, name, payload or {}, existing)
    if missing_cfg or missing_sec:
        _audit(db, principal, tid, request, "integration.config_rejected", name, {
            "missing_config_fields": missing_cfg,
            "missing_required_secrets": missing_sec,
        })
        # 422 mirrors FastAPI's validation semantics. We embed the split so
        # the UI can show a targeted "Configuration required: <field>" toast
        # instead of a generic error.
        raise HTTPException(status_code=422, detail={
            "message": "Configuration required.",
            "missing_fields": missing_cfg + missing_sec,
            "missing_config_fields": missing_cfg,
            "missing_required_secrets": missing_sec,
        })

    sanitized, secrets_meta = _split_secrets(payload)

    if existing is None:
        row = IntegrationConnection(
            tenant_id=tid,
            name=name,
            enabled=True,
            config_json=sanitized,
            secrets_metadata=secrets_meta,
        )
        db.add(row)
    else:
        row = existing
        row.config_json = sanitized
        # Merge secret presence markers rather than overwriting them: on a
        # re-save the UI leaves the secret input blank when the operator only
        # wants to update non-secret fields, and we shouldn't wipe the
        # "already configured" marker in that case. When the payload does
        # carry a secret this turn (present=True), it replaces the marker
        # for that key.
        merged = dict(row.secrets_metadata or {})
        for k, v in secrets_meta.items():
            if v.get("present"):
                merged[k] = v
            elif k not in merged:
                merged[k] = v
        row.secrets_metadata = merged
        row.enabled = True
        row.updated_at = utcnow()
    db.commit()
    db.refresh(row)

    _audit(db, principal, tid, request, "integration.config_saved", name, {
        "connection_id": row.id,
        "config_keys": sorted(sanitized.keys()),
        "secrets_present": sorted(k for k, v in secrets_meta.items() if v.get("present")),
    })
    return _serialize(row, descriptor=d)


@router.post("/{name}/test")
def test_integration(name: str, request: Request, payload: dict = Body(default={}),
                     db: Session = Depends(get_db),
                     principal: Principal = Depends(require_admin),
                     tid: int = Depends(current_tenant_id)):
    """Report whether the stored connection *could* be tested.

    Community does not perform the actual handshake — the real
    ``test_connection`` is Enterprise. We report ``ready`` only when the
    stored row satisfies :func:`_is_ready`; a row that has been *saved* but is
    missing a required secret marker still reports ``not_configured``.
    """
    d = _gate(db, principal, tid, request, name, "integration.test_denied")

    row = _get_connection(db, tid, name)
    ready = _is_ready(row, d, name)

    _audit(db, principal, tid, request, "integration.test_requested", name, {
        "configured": ready,
    })

    if not ready:
        return {
            "name": name,
            "configured": False,
            "status": "not_configured",
            "message": "Configuration required. Save the connector's required fields first.",
        }
    return {
        "name": name,
        "configured": True,
        "status": "ready",
        "message": (
            "Configuration is complete. Live connection testing is provided by "
            "the ThreatForge Enterprise connector."
        ),
    }


@router.post("/{name}/sync")
def sync_integration(name: str, request: Request, payload: dict = Body(default={}),
                     db: Session = Depends(get_db),
                     principal: Principal = Depends(require_admin),
                     tid: int = Depends(current_tenant_id)):
    """Report whether a sync request *could* be accepted.

    Community does not run a real sync job — scheduled pull/push is Enterprise.
    ``accepted=true, status="queued"`` requires the same completeness predicate
    as ``/test`` (:func:`_is_ready`); otherwise ``not_configured``.
    """
    d = _gate(db, principal, tid, request, name, "integration.sync_denied")

    row = _get_connection(db, tid, name)
    ready = _is_ready(row, d, name)

    _audit(db, principal, tid, request, "integration.sync_requested", name, {
        "accepted": ready,
    })

    if not ready:
        return {
            "name": name,
            "accepted": False,
            "status": "not_configured",
            "message": "Configuration required. Save the connector's required fields first.",
        }
    return {
        "name": name,
        "accepted": True,
        "status": "queued",
        "message": (
            "Sync intent recorded. Real pull/push execution is provided by "
            "the ThreatForge Enterprise connector."
        ),
    }
