"""Feature gate — Community/Enterprise entitlements (single source of truth).

ALL paid modules go through this layer (PDF export, premium integrations,
premium enrichment, feeds, ...). Never scatter ad-hoc license checks elsewhere —
call ``ensure_enabled``/``is_enabled`` and let the central 402 handler answer.

Community resolves no entitlements on its own. When ``THREATFORGE_EDITION`` is
``enterprise`` this module consults :mod:`app.enterprise_adapter`, which loads the
private ``threatforge-enterprise`` package (if installed) and its signed license.
If the package is missing, the license is absent/invalid/expired, or the feature
is not granted, entitlements stay empty and premium seams return HTTP 402.

The **canonical, public feature keys** below are the contract. The Enterprise
license payload must answer for these keys. For backward/loose compatibility with
Enterprise builds that still use internal names, a small alias table maps each
canonical key to the internal keys that also satisfy it.
"""
from __future__ import annotations

from enum import Enum

from app import config


class Feature(str, Enum):
    # Exports / integrations / enrichment
    EXPORT_PDF = "export.pdf"
    INTEGRATION_MISP = "integration.misp"
    INTEGRATION_OPENCTI = "integration.opencti"
    INTEGRATION_GENERIC = "integration.generic"
    ENRICHMENT_PREMIUM = "enrichment.premium"
    # Enterprise collection feeds (gated; connectors live outside this repo)
    FEEDS_DARKWEB = "feeds.darkweb"
    FEEDS_REALTIME = "feeds.realtime"
    FEEDS_ENRICHMENT = "feeds.enrichment"
    # Telegram Intelligence (v0.11.0). Provider-neutral collection/analysis seams
    # live in Community; the real Bot API provider + intent classifier live in the
    # private threatforge-enterprise package. Two narrow, explicit keys — no broad
    # commercial alias may satisfy them (see _ENTERPRISE_ALIASES below).
    COLLECTION_TELEGRAM = "collection.telegram"
    ANALYSIS_TELEGRAM = "analysis.telegram"


# Features que exigem licença ativa. Tudo aqui é Enterprise; vendável por flag.
PREMIUM: set[Feature] = {
    Feature.EXPORT_PDF,
    Feature.INTEGRATION_MISP,
    Feature.INTEGRATION_OPENCTI,
    Feature.INTEGRATION_GENERIC,
    Feature.ENRICHMENT_PREMIUM,
    Feature.FEEDS_DARKWEB,
    Feature.FEEDS_REALTIME,
    Feature.FEEDS_ENRICHMENT,
    Feature.COLLECTION_TELEGRAM,
    Feature.ANALYSIS_TELEGRAM,
}

# Rótulos amigáveis usados na mensagem 402 (mantém a string do PDF original).
_FEATURE_LABEL: dict[str, str] = {
    Feature.EXPORT_PDF.value: "Premium PDF export",
    Feature.INTEGRATION_MISP.value: "MISP integration",
    Feature.INTEGRATION_OPENCTI.value: "OpenCTI integration",
    Feature.INTEGRATION_GENERIC.value: "Generic threat-intel integration",
    Feature.ENRICHMENT_PREMIUM.value: "Premium enrichment",
    Feature.FEEDS_DARKWEB.value: "Dark/deep web feeds",
    Feature.FEEDS_REALTIME.value: "Real-time collection",
    Feature.FEEDS_ENRICHMENT.value: "Feed enrichment",
    Feature.COLLECTION_TELEGRAM.value: "Telegram intelligence collection",
    Feature.ANALYSIS_TELEGRAM.value: "Telegram intelligence analysis",
}

# Canonical public key -> set of license keys that also satisfy it. The canonical
# key itself is always accepted; internal Enterprise names are a compatibility
# bridge so activation works even before the Enterprise repo adopts canonical keys.
_ENTERPRISE_ALIASES: dict[str, set[str]] = {
    Feature.EXPORT_PDF.value: {Feature.EXPORT_PDF.value, "premium_pdf_reports"},
    Feature.INTEGRATION_MISP.value: {Feature.INTEGRATION_MISP.value, "enterprise_integrations"},
    Feature.INTEGRATION_OPENCTI.value: {Feature.INTEGRATION_OPENCTI.value, "enterprise_integrations"},
    Feature.INTEGRATION_GENERIC.value: {Feature.INTEGRATION_GENERIC.value, "enterprise_integrations", "advanced_connectors"},
    Feature.ENRICHMENT_PREMIUM.value: {Feature.ENRICHMENT_PREMIUM.value, "advanced_connectors"},
    Feature.FEEDS_DARKWEB.value: {Feature.FEEDS_DARKWEB.value, "advanced_connectors"},
    Feature.FEEDS_REALTIME.value: {Feature.FEEDS_REALTIME.value, "advanced_connectors", "scheduled_reports"},
    Feature.FEEDS_ENRICHMENT.value: {Feature.FEEDS_ENRICHMENT.value, "advanced_connectors"},
    # Telegram keys deliberately map ONLY to themselves. A broad commercial bundle
    # such as ``advanced_connectors``/``enterprise_integrations`` must NOT unlock
    # Telegram collection/analysis — the Enterprise license has to grant the exact
    # canonical key. This keeps the v0.11.0 feature contract auditable.
    Feature.COLLECTION_TELEGRAM.value: {Feature.COLLECTION_TELEGRAM.value},
    Feature.ANALYSIS_TELEGRAM.value: {Feature.ANALYSIS_TELEGRAM.value},
}


class EnterpriseFeatureRequired(Exception):
    """Raised by Community seams for features gated to Enterprise.

    Converted to HTTP 402 by the global handler (see app/main.py).
    """

    http_status = 402

    def __init__(self, feature):
        self.feature = feature.value if isinstance(feature, Feature) else str(feature)
        super().__init__(f"{self.feature} requires a ThreatForge Enterprise license.")


def _enterprise_feature_set() -> set[str]:
    """Feature keys granted by the active Enterprise license (empty if none).

    Delegates to the adapter. Never raises: any failure (missing package,
    invalid/expired license, integration error) yields an empty set so premium
    stays locked and Community keeps working.
    """
    try:
        from app import enterprise_adapter
        status = enterprise_adapter.get_enterprise_status()
    except Exception:
        return set()
    if not status.get("available") or not status.get("valid"):
        return set()
    return {str(f) for f in (status.get("features") or [])}


def _resolve_license() -> set[Feature]:
    """Resolve premium entitlements from the Enterprise license (canonical keys).

    A canonical premium Feature is granted when the license carries the canonical
    key itself or any of its accepted internal aliases.
    """
    granted = _enterprise_feature_set()
    if not granted:
        return set()
    enabled: set[Feature] = set()
    for feat in PREMIUM:
        if _ENTERPRISE_ALIASES.get(feat.value, {feat.value}) & granted:
            enabled.add(feat)
    return enabled


def entitlements() -> set[Feature]:
    if (config.EDITION or "community").lower() != "enterprise":
        return set()
    return _resolve_license()


def is_enabled(feature: Feature) -> bool:
    return (feature not in PREMIUM) or (feature in entitlements())


def ensure_enabled(feature: Feature) -> None:
    if not is_enabled(feature):
        raise EnterpriseFeatureRequired(feature)


def allowed_features() -> list[str]:
    """Canonical premium keys currently unlocked by the license (sorted)."""
    ent = entitlements()
    return sorted(f.value for f in PREMIUM if f in ent)


def blocked_features() -> list[str]:
    """Canonical premium keys still locked (sorted)."""
    ent = entitlements()
    return sorted(f.value for f in PREMIUM if f not in ent)


def upgrade_block() -> dict:
    """Contatos comerciais para o CTA de upgrade (configuráveis por env)."""
    email = config.THREATFORGE_ENTERPRISE_CONTACT_EMAIL
    return {
        "message": config.THREATFORGE_ENTERPRISE_CONTACT_MESSAGE,
        "contact": email,
        "email": email,
        "url": config.THREATFORGE_ENTERPRISE_CONTACT_URL,
    }


def payment_required_detail(feature) -> dict:
    """Corpo padronizado da resposta 402 (mesmo formato p/ PDF, integrações, feeds)."""
    f = feature.value if isinstance(feature, Feature) else str(feature)
    label = _FEATURE_LABEL.get(f, "This premium feature")
    return {
        "error": "enterprise_feature_required",
        "detail": f"{label} requires a ThreatForge Enterprise license.",
        "feature": f,
        "edition": config.EDITION,
        "upgrade": upgrade_block(),
    }
