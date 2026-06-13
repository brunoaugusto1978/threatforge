from __future__ import annotations

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


def get_enterprise_status() -> dict[str, Any]:
    integration = _load_enterprise_integration()

    if integration is None:
        return asdict(
            EnterpriseAdapterStatus(
                available=False,
                message="ThreatForge Enterprise package is not installed.",
            )
        )

    try:
        summary = integration.get_enterprise_license_summary()
    except Exception as exc:
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
    except Exception:
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
