"""Runtime bootstrap and sanitized provider diagnostics."""
from __future__ import annotations

from typing import Any

from app import enterprise_adapter
from app.collection import registry, secrets

_ALLOWED_ERROR_CODES = {
    "credential_unavailable",
    "invalid_credential_format",
    "unauthorized",
    "rate_limited",
    "collector_conflict",
    "provider_rejected",
    "provider_unavailable",
    "timeout",
    "invalid_provider_response",
    "invalid_cursor",
    "unsafe_api_base",
}
_ALLOWED_STATES = {"healthy", "degraded", "unauthorized", "offline", "pending"}


def bootstrap_enterprise_extensions(*, replace: bool = True) -> dict[str, str]:
    """Populate host registries when the private package is installed.

    Safe to call repeatedly.  Missing/incompatible packages return an empty
    manifest; Community remains operational and gated.
    """
    return enterprise_adapter.register_collection_extensions(
        registry.providers,
        registry.classifiers,
        registry.correlators,
        secret_loader=secrets.resolve_opaque_ref,
        replace=replace,
    )


def provider_diagnostic(exc: BaseException) -> dict[str, Any]:
    """Convert any provider exception into a small non-secret diagnostic."""
    raw_code = str(getattr(exc, "code", "provider_error"))
    code = raw_code if raw_code in _ALLOWED_ERROR_CODES else "provider_error"
    raw_state = str(getattr(exc, "state", "degraded"))
    state = raw_state if raw_state in _ALLOWED_STATES else "degraded"
    retry = getattr(exc, "retry_after_seconds", None)
    status = getattr(exc, "http_status", None)
    return {
        "code": code,
        "state": state,
        "retry_after_seconds": int(retry) if isinstance(retry, int) and retry >= 0 else None,
        "http_status": int(status) if isinstance(status, int) else None,
    }
