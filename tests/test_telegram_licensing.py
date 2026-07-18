from __future__ import annotations

from app import features
from app.features import Feature


def test_telegram_keys_are_premium():
    assert Feature.COLLECTION_TELEGRAM in features.PREMIUM
    assert Feature.ANALYSIS_TELEGRAM in features.PREMIUM


def test_locked_in_community_edition():
    # Community edition resolves no entitlements → telegram stays locked (402 seam).
    assert features.is_enabled(Feature.COLLECTION_TELEGRAM) is False
    assert features.is_enabled(Feature.ANALYSIS_TELEGRAM) is False


def test_no_broad_alias_bridges_telegram():
    aliases = features._ENTERPRISE_ALIASES
    assert aliases[Feature.COLLECTION_TELEGRAM.value] == {"collection.telegram"}
    assert aliases[Feature.ANALYSIS_TELEGRAM.value] == {"analysis.telegram"}
    # a broad internal bundle must not appear in the telegram alias sets
    for broad in ("advanced_connectors", "enterprise_integrations"):
        assert broad not in aliases[Feature.COLLECTION_TELEGRAM.value]
        assert broad not in aliases[Feature.ANALYSIS_TELEGRAM.value]


def test_payment_required_detail_shape():
    body = features.payment_required_detail(Feature.COLLECTION_TELEGRAM)
    assert body["feature"] == "collection.telegram"
    assert body["error"] == "enterprise_feature_required"
