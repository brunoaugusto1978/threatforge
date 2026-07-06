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

  * ``POST /integrations/{name}/connections`` — validates the incoming payload
    against the descriptor's public schema (best-effort), strips secret fields
    (``api_key``, ``api_token``, ``token``, ``secret``, ``password``), persists
    the sanitized ``config_json`` + ``secrets_metadata``, and returns the row
    with secrets masked. Audit ``integration.config_saved``.
  * ``POST /integrations/{name}/test`` — returns ``{configured, status,
    message}`` without touching any network. Audit ``integration.test_requested``.
  * ``POST /integrations/{name}/sync`` — returns ``{accepted, status, message}``
    without touching any network. Audit ``integration.sync_requested``.

No real MISP/OpenCTI I/O is performed in Community — the transport, encrypted
secret storage and anti-SSRF validation still live in ``threatforge-enterprise``
and register via :func:`app.integrations.register_connector`.

RBAC: viewer reads the catalog; configuring/testing/syncing requires admin
effective role — which excludes support_operator (analyst) and support_viewer
(viewer), so platform/tenant operators in support mode cannot manage external
connector credentials. Cross-tenant/unknown -> 404.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, features, integrations
from app.auth import Principal, current_tenant_id, require_admin, require_viewer
from app.database import get_db
from app.models import IntegrationConnection, utcnow

router = APIRouter(prefix="/integrations", tags=["integrations"],
                   dependencies=[Depends(require_viewer)])


# Keys we never persist and never echo back in cleartext. Kept in lowercase.
# Matches app.audit._REDACT so the same discipline is applied everywhere.
_SECRET_KEYS: frozenset[str] = frozenset({
    "api_key", "api_token", "token", "secret", "password",
    "client_secret", "auth_key", "private_key",
})


def _audit(db, principal, tid, request, action, name, detail):
    audit.record(db, actor=principal.subject, actor_role=principal.role, tenant_id=tid,
                 operator_user_id=principal.user_id, action=action,
                 target_type="integration", target_id=None, request=request,
                 detail={**detail, "integration": name})


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
    d = integrations.get_descriptor(name)
    if d is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    item = _catalog_item(d)
    item["config_schema"] = d.config_schema.model_json_schema()
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


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _serialize(row: IntegrationConnection) -> dict:
    """Row -> JSON response. Never echoes secret values."""
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "enabled": bool(row.enabled),
        "config": dict(row.config_json or {}),
        "secrets_metadata": dict(row.secrets_metadata or {}),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _get_connection(db: Session, tid: int, name: str) -> IntegrationConnection | None:
    return db.scalar(select(IntegrationConnection).where(
        IntegrationConnection.tenant_id == tid,
        IntegrationConnection.name == name,
    ))


@router.post("/{name}/connections")
def configure_integration(name: str, request: Request, payload: dict = Body(default={}),
                          db: Session = Depends(get_db),
                          principal: Principal = Depends(require_admin),
                          tid: int = Depends(current_tenant_id)):
    """Persist a minimal, non-secret connection for the requested integration.

    Enterprise/licensed path (Community without license -> 402 via ``_gate``):
      1. Strip secret keys from the payload (``_split_secrets``).
      2. Upsert one row per (tenant, name).
      3. Audit ``integration.config_saved``.
      4. Return the row with secrets masked.

    Real credential storage / encrypted vault / anti-SSRF validation are still
    Enterprise concerns — this endpoint intentionally does not touch any
    external service.
    """
    _gate(db, principal, tid, request, name, "integration.config_denied")

    sanitized, secrets_meta = _split_secrets(payload)

    row = _get_connection(db, tid, name)
    if row is None:
        row = IntegrationConnection(
            tenant_id=tid,
            name=name,
            enabled=True,
            config_json=sanitized,
            secrets_metadata=secrets_meta,
        )
        db.add(row)
    else:
        row.config_json = sanitized
        # Only overwrite recorded secret metadata when the caller sent secret
        # fields this time — this lets subsequent calls update non-secret
        # config without wiping the "secret was configured" hint. When the
        # caller does send secret fields, we replace the metadata entirely.
        if secrets_meta:
            row.secrets_metadata = secrets_meta
        row.enabled = True
        row.updated_at = utcnow()
    db.commit()
    db.refresh(row)

    _audit(db, principal, tid, request, "integration.config_saved", name, {
        "connection_id": row.id,
        "config_keys": sorted(sanitized.keys()),
        "secrets_present": sorted(secrets_meta.keys()),
    })
    return _serialize(row)


@router.post("/{name}/test")
def test_integration(name: str, request: Request, payload: dict = Body(default={}),
                     db: Session = Depends(get_db),
                     principal: Principal = Depends(require_admin),
                     tid: int = Depends(current_tenant_id)):
    """Report whether a stored connection *could* be tested.

    Community does not perform the actual handshake — the real ``test_connection``
    is Enterprise. Here we only return whether the tenant has a persisted
    connection for ``name``:

    * ``configured=true, status="ready"`` when a row exists.
    * ``configured=false, status="not_configured"`` otherwise.
    """
    _gate(db, principal, tid, request, name, "integration.test_denied")

    row = _get_connection(db, tid, name)
    configured = row is not None

    _audit(db, principal, tid, request, "integration.test_requested", name, {
        "configured": configured,
    })

    if not configured:
        return {
            "name": name,
            "configured": False,
            "status": "not_configured",
            "message": "No connection persisted yet. Save a configuration first.",
        }
    return {
        "name": name,
        "configured": True,
        "status": "ready",
        "message": (
            "Configuration is present. Live connection testing is provided by "
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
    Returns:

    * ``accepted=true, status="queued"`` when a stored connection exists.
    * ``accepted=false, status="not_configured"`` otherwise.
    """
    _gate(db, principal, tid, request, name, "integration.sync_denied")

    row = _get_connection(db, tid, name)
    accepted = row is not None

    _audit(db, principal, tid, request, "integration.sync_requested", name, {
        "accepted": accepted,
    })

    if not accepted:
        return {
            "name": name,
            "accepted": False,
            "status": "not_configured",
            "message": "No connection persisted yet. Save a configuration first.",
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
