from __future__ import annotations

from types import SimpleNamespace

import pytest

import app.enterprise_adapter as adapter
from app.enterprise_adapter import EnterpriseUnavailableError


def test_enterprise_available_returns_false_when_package_is_missing(monkeypatch):
    def fake_import_module(_name: str):
        raise ModuleNotFoundError("threatforge_enterprise")

    monkeypatch.setattr(adapter, "import_module", fake_import_module)

    assert adapter.enterprise_available() is False


def test_get_enterprise_status_returns_unavailable_when_package_is_missing(monkeypatch):
    def fake_import_module(_name: str):
        raise ModuleNotFoundError("threatforge_enterprise")

    monkeypatch.setattr(adapter, "import_module", fake_import_module)

    status = adapter.get_enterprise_status()

    assert status["available"] is False
    assert status["valid"] is False
    assert status["message"] == "ThreatForge Enterprise package is not installed."


def test_get_enterprise_status_returns_summary_when_package_is_available(monkeypatch):
    fake_summary = SimpleNamespace(
        valid=True,
        reason=None,
        plan="enterprise",
        license_type="annual",
        license_id="lic_test",
        customer="Example Customer",
        trial=False,
        features=["premium_pdf_reports"],
        limits={"max_tenants": 25},
        entitlements={"valid": True},
    )

    fake_integration = SimpleNamespace(
        get_enterprise_license_summary=lambda: fake_summary,
    )

    monkeypatch.setattr(adapter, "import_module", lambda _name: fake_integration)

    status = adapter.get_enterprise_status()

    assert status["available"] is True
    assert status["valid"] is True
    assert status["plan"] == "enterprise"
    assert status["license_type"] == "annual"
    assert status["license_id"] == "lic_test"
    assert status["customer"] == "Example Customer"
    assert status["trial"] is False
    assert status["features"] == ["premium_pdf_reports"]
    assert status["limits"] == {"max_tenants": 25}
    assert status["entitlements"] == {"valid": True}


def test_get_enterprise_status_handles_integration_error(monkeypatch):
    fake_integration = SimpleNamespace(
        get_enterprise_license_summary=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    monkeypatch.setattr(adapter, "import_module", lambda _name: fake_integration)

    status = adapter.get_enterprise_status()

    assert status["available"] is True
    assert status["valid"] is False
    assert status["reason"] == "enterprise_integration_error"
    assert status["message"] == "Enterprise integration failed."
    assert "boom" not in status["message"]


def test_is_enterprise_feature_enabled_returns_false_when_package_is_missing(monkeypatch):
    def fake_import_module(_name: str):
        raise ModuleNotFoundError("threatforge_enterprise")

    monkeypatch.setattr(adapter, "import_module", fake_import_module)

    assert adapter.is_enterprise_feature_enabled("premium_pdf_reports") is False


def test_is_enterprise_feature_enabled_uses_enterprise_integration(monkeypatch):
    fake_integration = SimpleNamespace(
        is_enterprise_feature_enabled=lambda feature: feature == "premium_pdf_reports",
    )

    monkeypatch.setattr(adapter, "import_module", lambda _name: fake_integration)

    assert adapter.is_enterprise_feature_enabled("premium_pdf_reports") is True
    assert adapter.is_enterprise_feature_enabled("executive_dashboard") is False


def test_generate_enterprise_pdf_report_raises_when_package_is_missing(monkeypatch, tmp_path):
    def fake_import_module(_name: str):
        raise ModuleNotFoundError("threatforge_enterprise")

    monkeypatch.setattr(adapter, "import_module", fake_import_module)

    with pytest.raises(EnterpriseUnavailableError):
        adapter.generate_enterprise_pdf_report(
            {
                "tenant_name": "Tenant",
                "report_title": "Report",
                "executive_summary": "Summary",
                "risk_score": 50,
                "findings": [],
            },
            tmp_path / "report.pdf",
        )


def test_generate_enterprise_pdf_report_calls_enterprise_integration(monkeypatch, tmp_path):
    class FakeEnterpriseReportInput:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    def fake_generate_enterprise_pdf(_report, output_path):
        return SimpleNamespace(output_path=str(output_path))

    fake_integration = SimpleNamespace(
        EnterpriseReportInput=FakeEnterpriseReportInput,
        generate_enterprise_pdf=fake_generate_enterprise_pdf,
    )

    monkeypatch.setattr(adapter, "import_module", lambda _name: fake_integration)

    output = adapter.generate_enterprise_pdf_report(
        {
            "tenant_name": "Tenant",
            "report_title": "Report",
            "executive_summary": "Summary",
            "risk_score": 50,
            "findings": [],
        },
        tmp_path / "report.pdf",
    )

    assert output == str(tmp_path / "report.pdf")


def test_status_propagates_dates_versions_and_core_compatibility(monkeypatch):
    seen = {}

    def summary(*, core_version):
        seen["core_version"] = core_version
        return SimpleNamespace(
            valid=True,
            reason=None,
            plan="enterprise",
            license_type="trial_90_days",
            license_id="lic_cbg_poc_2026",
            customer="CBG Assessoria e Consultoria",
            trial=True,
            issued_at="2026-07-18T16:18:39Z",
            expires_at="2026-10-16T16:18:39Z",
            features=["collection.telegram"],
            limits={"max_tenants": 5},
            entitlements={"valid": True},
            enterprise_version="0.11.0",
            core_compatibility=">=0.11.0,<0.12.0",
            compatible=True,
        )

    monkeypatch.setattr(
        adapter,
        "import_module",
        lambda _name: SimpleNamespace(get_enterprise_license_summary=summary),
    )
    status = adapter.get_enterprise_status()
    assert seen["core_version"] == "0.11.0"
    assert status["issued_at"] == "2026-07-18T16:18:39Z"
    assert status["expires_at"] == "2026-10-16T16:18:39Z"
    assert status["enterprise_version"] == "0.11.0"
    assert status["core_compatibility"] == ">=0.11.0,<0.12.0"
    assert status["core_compatible"] is True
