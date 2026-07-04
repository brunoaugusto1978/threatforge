"""Bridge to the private ThreatForge Enterprise package.

The Community repository never imports the Enterprise package directly and never
contains premium code. This adapter loads ``threatforge_enterprise.integration``
lazily *if it is installed*, and exposes a small, stable surface:

- :func:`enterprise_available` / :func:`get_enterprise_status` — introspection for
  ``/license/status`` and the feature gate (no secrets ever returned).
- :func:`is_enterprise_feature_enabled` — single feature check.
- :func:`generate_case_pdf` / :func:`generate_credential_pdf` — formal premium PDF
  path used by :mod:`app.exporters`. Any Enterprise licensing/enforcement failure
  is converted to :class:`app.features.EnterpriseFeatureRequired` (HTTP 402) — the
  seam never raises a 500 and never leaks Enterprise internals.

Community keeps working when the Enterprise package is absent: every entry point
degrades to "unavailable" / 402.
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import asdict, dataclass
from importlib import import_module
from pathlib import Path
from typing import Any


ENTERPRISE_INTEGRATION_MODULE = "threatforge_enterprise.integration"


class EnterpriseUnavailableError(RuntimeError):
    """Raised when Enterprise features are requested but Enterprise is unavailable."""


@dataclass(frozen=True)
class EnterpriseAdapterStatus:
    available: bool
    valid: bool = False
    reason: str | None = None
    plan: str = ""
    license_type: str = ""
    license_id: str = ""
    customer: str = ""
    trial: bool = False
    issued_at: str = ""
    expires_at: str = ""
    features: list[str] | None = None
    limits: dict[str, Any] | None = None
    entitlements: dict[str, Any] | None = None
    message: str = ""


def _load_enterprise_integration():
    try:
        return import_module(ENTERPRISE_INTEGRATION_MODULE)
    except ModuleNotFoundError:
        return None


def enterprise_available() -> bool:
    return _load_enterprise_integration() is not None


def _safe_date(summary, *names: str) -> str:
    """Best-effort read of a non-secret date field from the license summary.

    Forward-compatible: works whether the Enterprise summary exposes the date as
    an attribute now or only in a later contract version. Never returns secrets.
    """
    for name in names:
        value = getattr(summary, name, None)
        if value:
            return str(value)
    payload = getattr(summary, "payload", None)
    if isinstance(payload, dict):
        for name in names:
            if payload.get(name):
                return str(payload[name])
    return ""


def get_enterprise_status() -> dict[str, Any]:
    """Introspective status for the license admin endpoint and the feature gate.

    Returns only non-sensitive metadata: never the raw license, signature, keys
    or file paths.
    """
    integration = _load_enterprise_integration()

    if integration is None:
        return asdict(
            EnterpriseAdapterStatus(
                available=False,
                reason="package_missing",
                message="ThreatForge Enterprise package is not installed.",
            )
        )

    try:
        summary = integration.get_enterprise_license_summary()
    except Exception as exc:  # noqa: BLE001 — never propagate Enterprise internals
        return asdict(
            EnterpriseAdapterStatus(
                available=True,
                valid=False,
                reason="enterprise_integration_error",
                message=f"Enterprise integration failed: {exc}",
            )
        )

    return asdict(
        EnterpriseAdapterStatus(
            available=True,
            valid=bool(summary.valid),
            reason=summary.reason,
            plan=summary.plan,
            license_type=summary.license_type,
            license_id=summary.license_id,
            customer=summary.customer,
            trial=bool(summary.trial),
            issued_at=_safe_date(summary, "issued_at", "valid_from", "not_before"),
            expires_at=_safe_date(summary, "expires_at", "valid_until", "not_after"),
            features=list(summary.features or []),
            limits=dict(summary.limits or {}),
            entitlements=dict(summary.entitlements or {}),
            message="ThreatForge Enterprise package is available.",
        )
    )


def is_enterprise_feature_enabled(feature: str) -> bool:
    integration = _load_enterprise_integration()

    if integration is None:
        return False

    try:
        return bool(integration.is_enterprise_feature_enabled(feature))
    except Exception:  # noqa: BLE001
        return False


def generate_enterprise_pdf_report(
    report: dict[str, Any],
    output_path: str | Path,
) -> str:
    integration = _load_enterprise_integration()

    if integration is None:
        raise EnterpriseUnavailableError(
            "ThreatForge Enterprise package is not installed."
        )

    enterprise_report = integration.EnterpriseReportInput(**report)
    result = integration.generate_enterprise_pdf(enterprise_report, output_path)

    return str(result.output_path)


def _render_pdf_bytes(report: dict[str, Any]) -> bytes:
    """Formal premium PDF path. Converts *any* Enterprise failure into a 402.

    The primary gate is :func:`app.features.ensure_enabled` (called by the
    exporter before we get here); this is defense in depth so an
    enforcement/expiry error from the Enterprise package never becomes a 500.
    """
    from app.features import EnterpriseFeatureRequired, Feature

    integration = _load_enterprise_integration()
    if integration is None:
        raise EnterpriseFeatureRequired(Feature.EXPORT_PDF)

    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "report.pdf")
            path = generate_enterprise_pdf_report(report, out)
            with open(path, "rb") as fh:
                return fh.read()
    except EnterpriseFeatureRequired:
        raise
    except Exception:  # noqa: BLE001 — enterprise enforcement/expiry/etc -> 402
        raise EnterpriseFeatureRequired(Feature.EXPORT_PDF)


def generate_case_pdf(report: dict[str, Any]) -> bytes:
    """Premium case PDF (bytes). 402 when unlicensed/unavailable."""
    return _render_pdf_bytes(report)


def generate_credential_pdf(report: dict[str, Any]) -> bytes:
    """Premium credential-dossier PDF (bytes). 402 when unlicensed/unavailable."""
    return _render_pdf_bytes(report)
