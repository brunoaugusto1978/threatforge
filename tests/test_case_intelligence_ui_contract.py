"""Static UI contract for safe case/intelligence correlation visibility."""
from pathlib import Path


def test_cases_and_dashboard_render_correlation_metadata():
    app_js = Path("app/static/app.js").read_text(encoding="utf-8")
    for marker in (
        "function caseIntelligenceCell(summary)",
        "function caseIntelligencePanel(summary)",
        "Correlated events",
        "Last activity",
        "Safe event references",
        "Case-linked intelligence events",
        "intelligence_case_events_total",
    ):
        assert marker in app_js


def test_case_api_uses_tenant_scoped_safe_summary_service():
    service = Path("app/case_intelligence.py").read_text(encoding="utf-8")
    cases = Path("app/routers/cases_routes.py").read_text(encoding="utf-8")
    dashboard = Path("app/routers/dashboard_routes.py").read_text(encoding="utf-8")

    assert "CollectionEvent.tenant_id == tenant_id" in service
    assert "ExposureFinding.tenant_id == tenant_id" in service
    assert "include_event_ids=False" in cases
    assert "include_event_ids=True" in cases
    assert "case_intelligence_summaries" in dashboard

    # The summary query is column-scoped; sensitive provider content is not
    # selected into the Cases or Dashboard response path.
    event_select = service.split("event_rows = db.execute(", 1)[1].split(").all()", 1)[0]
    assert "CollectionEvent.redacted_text" not in event_select
    assert "CollectionEvent.context_json" not in event_select
    assert "CollectionEvent.raw_fingerprint" not in event_select


def test_pdf_action_is_license_aware_and_not_hardcoded_locked():
    app_js = Path("app/static/app.js").read_text(encoding="utf-8")
    license_routes = Path("app/routers/license_routes.py").read_text(encoding="utf-8")

    assert 'api("GET", "/license/capabilities")' in app_js
    assert 'capabilityEnabled(capabilities, "export.pdf")' in app_js
    assert 'const pdfLabel = pdfEnabled ? "Export PDF" : "Export PDF 🔒";' in app_js
    assert '${esc(pdfLabel)}' in app_js
    assert '>Export PDF 🔒</button>' not in app_js
    assert '"features": {' in license_routes
