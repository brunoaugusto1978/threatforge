from __future__ import annotations

from app.routers import license_routes


def test_license_status_reports_overlay_metadata_without_secrets(monkeypatch):
    monkeypatch.setattr(
        license_routes.enterprise_adapter,
        "get_enterprise_status",
        lambda: {
            "available": True,
            "valid": True,
            "reason": None,
            "license_id": "lic_cbg_poc_2026",
            "customer": "CBG Assessoria e Consultoria",
            "plan": "enterprise",
            "license_type": "trial_90_days",
            "trial": True,
            "issued_at": "2026-07-18T16:18:39Z",
            "expires_at": "2026-10-16T16:18:39Z",
            "enterprise_version": "0.11.0",
            "core_compatibility": ">=0.11.0,<0.12.0",
            "core_compatible": True,
        },
    )
    monkeypatch.setattr(license_routes.features, "allowed_features", lambda: ["collection.telegram"])
    monkeypatch.setattr(license_routes.features, "blocked_features", lambda: ["analysis.telegram"])

    view = license_routes.license_status_view()
    assert view["reason"] == "valid"
    assert view["core_version"] == "0.11.0"
    assert view["enterprise_version"] == "0.11.0"
    assert view["expires_at"] == "2026-10-16T16:18:39Z"
    assert view["core_compatible"] is True
    serialized = repr(view).lower()
    assert "signature" not in serialized
    assert "private_key" not in serialized
    assert "license_file" not in serialized


def test_incompatible_core_reason_is_public_and_fail_closed(monkeypatch):
    monkeypatch.setattr(
        license_routes.enterprise_adapter,
        "get_enterprise_status",
        lambda: {
            "available": True,
            "valid": False,
            "reason": "incompatible_core",
            "core_compatible": False,
        },
    )
    monkeypatch.setattr(license_routes.features, "allowed_features", lambda: [])
    monkeypatch.setattr(license_routes.features, "blocked_features", lambda: ["collection.telegram"])
    view = license_routes.license_status_view()
    assert view["reason"] == "incompatible_core"
    assert view["core_compatible"] is False
    assert view["allowed_features"] == []
