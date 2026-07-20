"""Enterprise license status — admin introspection endpoint.

``GET /license/status`` reports the current edition and, when Enterprise is
installed, whether the license is valid and which **canonical** premium features
are unlocked. It returns only non-sensitive metadata — never the raw license,
signature, keys, or file paths.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import audit, config, enterprise_adapter, features
from app.auth import Principal, require_admin, require_viewer
from app.database import get_db

router = APIRouter(prefix="/license", tags=["license"])


def _normalized_reason(available: bool, valid: bool, raw: str | None) -> str:
    """Map internal states to the public reason vocabulary.

    valid | missing | expired | invalid_signature | invalid | package_missing
    (feature-level ``feature_not_allowed`` is answered by the 402 path, not here).
    """
    if not available:
        return "package_missing"
    if valid:
        return "valid"
    if raw == "expired":
        return "expired"
    if raw == "invalid_signature":
        return "invalid_signature"
    if raw == "incompatible_core":
        return "incompatible_core"
    if raw in (None, "", "malformed_license"):
        return "missing"
    return "invalid"


def license_status_view() -> dict:
    """Build the public license-status payload (no secrets)."""
    status = enterprise_adapter.get_enterprise_status()
    available = bool(status.get("available"))
    valid = bool(status.get("valid"))
    reason = _normalized_reason(available, valid, status.get("reason"))
    return {
        "edition": config.EDITION,
        "enterprise_package_available": available,
        "license_valid": valid,
        "reason": reason,
        "license_id": status.get("license_id") or "",
        "customer": status.get("customer") or "",
        "plan": status.get("plan") or "",
        "license_type": status.get("license_type") or "",
        "trial": bool(status.get("trial")),
        "issued_at": status.get("issued_at") or None,
        "expires_at": status.get("expires_at") or None,
        "core_version": config.APP_VERSION,
        "enterprise_version": status.get("enterprise_version") or "",
        "core_compatibility": status.get("core_compatibility") or "",
        "core_compatible": bool(status.get("core_compatible")),
        "allowed_features": features.allowed_features(),
        "blocked_features": features.blocked_features(),
        "upgrade_contact": config.THREATFORGE_ENTERPRISE_CONTACT_EMAIL,
    }


def license_capabilities_view() -> dict:
    """Viewer-safe canonical feature flags used only for UI presentation.

    This payload deliberately excludes license identifiers, customer metadata,
    signatures, paths and keys. Backend feature gates remain authoritative.
    """
    allowed = set(features.allowed_features())
    return {
        "edition": config.EDITION,
        "features": {
            feature.value: feature.value in allowed
            for feature in sorted(features.PREMIUM, key=lambda item: item.value)
        },
    }


@router.get("/capabilities", dependencies=[Depends(require_viewer)])
def license_capabilities(_principal: Principal = Depends(require_viewer)):
    return license_capabilities_view()


@router.get("/status", dependencies=[Depends(require_admin)])
def license_status(request: Request,
                   db: Session = Depends(get_db),
                   principal: Principal = Depends(require_admin)):
    view = license_status_view()
    audit.record(
        db,
        actor=principal.subject,
        actor_role=principal.role,
        tenant_id=principal.tenant_id,
        operator_user_id=principal.user_id,
        action="license.status_checked",
        target_type="license",
        target_id=view.get("license_id") or None,
        request=request,
        detail={
            "edition": view["edition"],
            "enterprise_package_available": view["enterprise_package_available"],
            "license_valid": view["license_valid"],
            "reason": view["reason"],
        },
    )
    return view
