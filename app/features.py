"""Feature gate — Community/Enterprise entitlements (single source of truth).

ALL paid modules go through this layer (PDF export, premium integrations,
premium enrichment, ...). Never scatter ad-hoc license checks elsewhere — call
``ensure_enabled``/``is_enabled`` and let the central 402 handler answer.

Community resolves no entitlements (everything premium is locked). The real
license resolution lives in the ``threatforge-enterprise`` package, which
overrides :func:`_resolve_license`.
"""
from __future__ import annotations

from enum import Enum

from app import config


class Feature(str, Enum):
    EXPORT_PDF = "export.pdf"
    INTEGRATION_MISP = "integration.misp"
    INTEGRATION_OPENCTI = "integration.opencti"
    INTEGRATION_GENERIC = "integration.generic"
    ENRICHMENT_PREMIUM = "enrichment.premium"


# Features que exigem licença ativa. Tudo aqui é Enterprise; vendável por flag.
PREMIUM: set[Feature] = {
    Feature.EXPORT_PDF,
    Feature.INTEGRATION_MISP,
    Feature.INTEGRATION_OPENCTI,
    Feature.INTEGRATION_GENERIC,
    Feature.ENRICHMENT_PREMIUM,
}

# Rótulos amigáveis usados na mensagem 402 (mantém a string do PDF original).
_FEATURE_LABEL: dict[str, str] = {
    Feature.EXPORT_PDF.value: "Premium PDF export",
    Feature.INTEGRATION_MISP.value: "MISP integration",
    Feature.INTEGRATION_OPENCTI.value: "OpenCTI integration",
    Feature.INTEGRATION_GENERIC.value: "Generic threat-intel integration",
    Feature.ENRICHMENT_PREMIUM.value: "Premium enrichment",
}


class EnterpriseFeatureRequired(Exception):
    """Raised by Community seams for features gated to Enterprise.

    Converted to HTTP 402 by the global handler (see app/main.py).
    """

    http_status = 402

    def __init__(self, feature):
        self.feature = feature.value if isinstance(feature, Feature) else str(feature)
        super().__init__(f"{self.feature} requires a ThreatForge Enterprise license.")


def _resolve_license() -> set[Feature]:
    """Enterprise override point. Community grants nothing."""
    return set()


def entitlements() -> set[Feature]:
    if (config.EDITION or "community").lower() != "enterprise":
        return set()
    return _resolve_license()


def is_enabled(feature: Feature) -> bool:
    return (feature not in PREMIUM) or (feature in entitlements())


def ensure_enabled(feature: Feature) -> None:
    if not is_enabled(feature):
        raise EnterpriseFeatureRequired(feature)


def upgrade_block() -> dict:
    """Contatos comerciais para o CTA de upgrade (configuráveis por env)."""
    return {
        "message": config.THREATFORGE_ENTERPRISE_CONTACT_MESSAGE,
        "email": config.THREATFORGE_ENTERPRISE_CONTACT_EMAIL,
        "whatsapp": config.THREATFORGE_ENTERPRISE_CONTACT_WHATSAPP,
        "url": config.THREATFORGE_ENTERPRISE_CONTACT_URL,
    }


def payment_required_detail(feature) -> dict:
    """Corpo padronizado da resposta 402 (mesmo formato p/ PDF e integrações)."""
    f = feature.value if isinstance(feature, Feature) else str(feature)
    label = _FEATURE_LABEL.get(f, "This premium feature")
    return {
        "detail": f"{label} requires a ThreatForge Enterprise license.",
        "feature": f,
        "edition": config.EDITION,
        "upgrade": upgrade_block(),
    }
