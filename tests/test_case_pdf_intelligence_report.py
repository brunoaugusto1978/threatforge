"""Intelligence-aware case PDF report contract."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _seed_case(tenant_id: int = 1) -> int:
    from app.database import SessionLocal
    from app.models import (
        CollectionConnection,
        CollectionEvent,
        CollectionSource,
        ExposureFinding,
        InvestigationCase,
    )

    first = datetime(2026, 7, 19, 15, 55, 29, tzinfo=timezone.utc)
    last = first + timedelta(hours=2, minutes=59, seconds=9)
    with SessionLocal() as db:
        finding = ExposureFinding(
            tenant_id=tenant_id,
            exposure_type="brand_exposure",
            title="Potential targeted threat against Example Corp",
            source="telegram_intelligence",
            source_reliability="B",
            info_credibility="2",
            severity="high",
            status="new",
            observed_at=first,
            first_seen=first,
            last_seen=last,
            dedup_key="f" * 64,
            detail={
                "decision": "targeted_threat",
                "confidence_score": 95,
                "correlation_family": "attack",
                "target_label": "Example Corp",
                "event_count": 2,
                "human_review_required": True,
            },
            redacted=True,
            risk_score=95,
        )
        db.add(finding)
        db.flush()

        case = InvestigationCase(
            tenant_id=tenant_id,
            finding_snapshot={
                "exposure_finding_id": finding.id,
                "exposure_type": finding.exposure_type,
                "source": finding.source,
                "intelligence": {
                    "decision": "targeted_threat",
                    "latest_decision": "targeted_threat",
                    "confidence_score": 95,
                    "correlation_family": "attack",
                    "target_label": "Example Corp",
                },
            },
            title="Potential targeted threat against Example Corp",
            description="Safe generated case description.",
            severity="alto",
            status="open",
        )
        db.add(case)
        db.flush()

        connection = CollectionConnection(
            tenant_id=tenant_id,
            provider="telegram",
            name="Example connection",
            enabled=True,
            status="active",
        )
        db.add(connection)
        db.flush()
        source = CollectionSource(
            tenant_id=tenant_id,
            connection_id=connection.id,
            provider="telegram",
            source_ref="example-source",
            kind="group",
            name="Example source",
            enabled=True,
            status="active",
        )
        db.add(source)
        db.flush()

        for index, when in enumerate((first, last), start=1):
            db.add(CollectionEvent(
                tenant_id=tenant_id,
                source_id=source.id,
                provider="telegram",
                external_id_hash=(str(index) * 64)[:64],
                processing_state="analyzed",
                redacted_text=f"DO-NOT-EXPORT-MESSAGE-{index}",
                context_json={
                    "actor_ref": "DO-NOT-EXPORT-ACTOR",
                    "thread_ref": "DO-NOT-EXPORT-CHAT",
                },
                occurred_at=when,
                finding_id=finding.id,
                case_id=case.id,
                analysis_json={"decision": "targeted_threat", "score": 95},
            ))
        db.commit()
        return case.id


def test_case_pdf_route_builds_safe_intelligence_report(tenant_admin_client, monkeypatch):
    from app import exporters
    from app.routers import cases_routes

    case_id = _seed_case()
    captured: dict = {}

    def _render(case, **kwargs):
        captured.update(exporters._case_report(case, **kwargs))
        return b"%PDF-1.4\nsynthetic"

    monkeypatch.setattr(cases_routes.exporters, "render_case_pdf", _render)

    response = tenant_admin_client.get(f"/cases/{case_id}/export.pdf")
    assert response.status_code == 200, response.text
    assert response.content.startswith(b"%PDF-")

    assert captured["tenant_name"] == "Tenant Test"
    assert captured["risk_score"] == 95
    assert captured["overall_severity"] == "high"
    assert captured["report_id"] == f"case-{case_id}"
    assert captured["case_context"]["source"] == "Telegram Intelligence"
    assert captured["case_context"]["decision"] == "targeted_threat"
    assert captured["case_context"]["confidence_score"] == 95
    assert captured["case_context"]["correlated_event_count"] == 2
    assert captured["case_context"]["human_review_required"] is True
    assert captured["case_context"]["event_references"]

    finding = captured["findings"][0]
    assert finding["severity"] == "high"
    assert finding["title"] == "Potential targeted threat against Example Corp"
    assert finding["evidence"][0]["source"] == "Telegram Intelligence"
    assert finding["evidence"][0]["confidence"] == "95/100"
    assert len(captured["recommendations"]) >= 4
    assert len(captured["next_steps"]) >= 3

    serialized = repr(captured)
    for forbidden in (
        "DO-NOT-EXPORT-MESSAGE",
        "DO-NOT-EXPORT-ACTOR",
        "DO-NOT-EXPORT-CHAT",
        "redacted_text",
        "context_json",
        "raw_fingerprint",
        "storage_key",
        "license_id",
    ):
        assert forbidden not in serialized


def test_case_pdf_report_normalizes_portuguese_severity():
    from types import SimpleNamespace
    from app import exporters

    case = SimpleNamespace(
        id=7,
        tenant_id=1,
        title="Example case",
        description="Example description",
        severity="alto",
        status="open",
        finding_snapshot=None,
    )
    report = exporters._case_report(case, tenant_name="Example Tenant")
    assert report["overall_severity"] == "high"
    assert report["findings"][0]["severity"] == "high"
    assert report["tenant_name"] == "Example Tenant"
