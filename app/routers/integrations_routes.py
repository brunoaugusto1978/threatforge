"""Premium integrations — catalog (free) + gated configure/test/sync.

Community exposes the *catalog* (200, viewer+) so the UI can show MISP/OpenCTI/
Generic as Enterprise-locked features with capabilities and an upgrade CTA.
Configure/test/sync go through the single feature-gate layer and return 402
without a license. No real connector and no secrets exist in Community.

RBAC: viewer reads the catalog; configuring/testing/syncing requires admin
effective role — which excludes support_operator (analyst) and support_viewer
(viewer), so platform/tenant operators in support mode cannot manage external
connector credentials. Cross-tenant/unknown -> 404.
"""
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app import audit, config, features, integrations
from app.auth import Principal, current_tenant_id, require_admin, require_viewer
from app.database import get_db

router = APIRouter(prefix="/integrations", tags=["integrations"],
                   dependencies=[Depends(require_viewer)])


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


@router.post("/{name}/connections")
def configure_integration(name: str, request: Request, payload: dict = Body(default={}),
                          db: Session = Depends(get_db),
                          principal: Principal = Depends(require_admin),
                          tid: int = Depends(current_tenant_id)):
    _gate(db, principal, tid, request, name, "integration.config_denied")
    # Enterprise: validate (anti-SSRF), persist connection + encrypted secret, audit
    # "integration.configured". Not present in Community.
    raise HTTPException(status_code=501, detail="Not implemented in this edition.")


@router.post("/{name}/test")
def test_integration(name: str, request: Request, payload: dict = Body(default={}),
                     db: Session = Depends(get_db),
                     principal: Principal = Depends(require_admin),
                     tid: int = Depends(current_tenant_id)):
    _gate(db, principal, tid, request, name, "integration.test_denied")
    raise HTTPException(status_code=501, detail="Not implemented in this edition.")


@router.post("/{name}/sync")
def sync_integration(name: str, request: Request, payload: dict = Body(default={}),
                     db: Session = Depends(get_db),
                     principal: Principal = Depends(require_admin),
                     tid: int = Depends(current_tenant_id)):
    _gate(db, principal, tid, request, name, "integration.sync_denied")
    raise HTTPException(status_code=501, detail="Not implemented in this edition.")
