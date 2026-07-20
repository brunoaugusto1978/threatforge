"""Case correlation visibility for provider-neutral intelligence events."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _pw(label: str) -> str:
    return f"{label}Aa12345!"


def _seed_intelligence_case(*, tenant_id: int, suffix: str = "a") -> tuple[int, int, list[int]]:
    from app.database import SessionLocal
    from app.models import (
        CollectionConnection,
        CollectionEvent,
        CollectionSource,
        ExposureFinding,
        InvestigationCase,
    )

    first = datetime(2026, 7, 19, 18, 0, tzinfo=timezone.utc)
    with SessionLocal() as db:
        finding = ExposureFinding(
            tenant_id=tenant_id,
            exposure_type="brand_exposure",
            title=f"Potential targeted threat {suffix}",
            source="telegram_intelligence",
            source_reliability="B",
            info_credibility="2",
            severity="high",
            status="new",
            observed_at=first,
            first_seen=first,
            last_seen=first + timedelta(minutes=4),
            dedup_key=(suffix * 64)[:64],
            detail={
                "decision": "targeted_threat",
                "confidence_score": 95,
                "correlation_family": "targeted_threat",
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
                    "correlation_family": "targeted_threat",
                },
            },
            title=f"Threat case {suffix}",
            description="Safe case description",
            severity="alto",
            status="open",
        )
        db.add(case)
        db.flush()

        connection = CollectionConnection(
            tenant_id=tenant_id,
            provider="telegram",
            name=f"Connection {suffix}",
            enabled=True,
            status="active",
        )
        db.add(connection)
        db.flush()
        source = CollectionSource(
            tenant_id=tenant_id,
            connection_id=connection.id,
            provider="telegram",
            source_ref=f"source-{suffix}",
            kind="group",
            name=f"Source {suffix}",
            enabled=True,
            status="active",
        )
        db.add(source)
        db.flush()

        events = []
        for index, when in enumerate((first, first + timedelta(minutes=4)), start=1):
            event = CollectionEvent(
                tenant_id=tenant_id,
                source_id=source.id,
                provider="telegram",
                external_id_hash=(f"{suffix}{index}" * 64)[:64],
                processing_state="analyzed",
                redacted_text=f"DO-NOT-EXPOSE-RAW-{suffix}-{index}",
                context_json={
                    "actor_ref": f"actor-secret-{suffix}",
                    "thread_ref": f"chat-secret-{suffix}",
                },
                occurred_at=when,
                finding_id=finding.id,
                case_id=case.id,
                analysis_json={
                    "decision": "targeted_threat",
                    "score": 95,
                },
            )
            db.add(event)
            db.flush()
            events.append(event.id)

        db.commit()
        return case.id, finding.id, events


def test_case_list_and_detail_expose_safe_correlation_metadata(tenant_admin_client):
    client = tenant_admin_client
    case_id, finding_id, event_ids = _seed_intelligence_case(tenant_id=1, suffix="a")

    listing = client.get("/cases")
    assert listing.status_code == 200, listing.text
    row = next(item for item in listing.json() if item["id"] == case_id)
    summary = row["intelligence"]
    assert summary["source"] == "telegram_intelligence"
    assert summary["finding_id"] == finding_id
    assert summary["correlated_event_count"] == 2
    assert summary["decision"] == "targeted_threat"
    assert summary["confidence_score"] == 95
    assert summary["human_review_required"] is True
    assert summary["first_event_at"].startswith("2026-07-19T18:00:00")
    assert summary["last_activity_at"].startswith("2026-07-19T18:04:00")
    assert "event_ids" not in summary

    detail = client.get(f"/cases/{case_id}")
    assert detail.status_code == 200, detail.text
    detail_summary = detail.json()["intelligence"]
    assert detail_summary["event_ids"] == event_ids
    assert detail_summary["correlated_event_count"] == len(event_ids)

    serialized = detail.text
    assert "DO-NOT-EXPOSE-RAW" not in serialized
    assert "actor-secret" not in serialized
    assert "chat-secret" not in serialized
    assert "redacted_text" not in serialized
    assert "context_json" not in serialized


def test_manual_case_has_no_fabricated_intelligence_summary(tenant_admin_client):
    response = tenant_admin_client.post(
        "/cases", json={"title": "Manual investigation", "severity": "medio"}
    )
    assert response.status_code == 201, response.text
    case_id = response.json()["id"]

    detail = tenant_admin_client.get(f"/cases/{case_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["intelligence"] is None


def test_dashboard_distinguishes_cases_from_correlated_events(tenant_admin_client):
    case_id, finding_id, _ = _seed_intelligence_case(tenant_id=1, suffix="b")

    response = tenant_admin_client.get("/dashboard/overview")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["summary"]["cases_total"] == 1
    assert body["summary"]["cases_open"] == 1
    assert body["summary"]["intelligence_case_events_total"] == 2

    case = next(item for item in body["recent_cases"] if item["id"] == case_id)
    assert case["intelligence"]["finding_id"] == finding_id
    assert case["intelligence"]["correlated_event_count"] == 2
    assert "event_ids" not in case["intelligence"]


def test_case_correlation_summary_is_tenant_scoped(fresh_app):
    from fastapi.testclient import TestClient
    from app.main import app

    op = fresh_app
    assert op.post(
        "/setup/operator",
        json={"email": "op@plat.com", "password": _pw("Operator")},
    ).status_code == 201

    tenant_clients = []
    tenant_ids = []
    for index in (1, 2):
        created = op.post(
            "/tenants",
            json={
                "name": f"Tenant {index}",
                "admin_email": f"admin{index}@test.com",
                "admin_password": _pw(f"TenantAdmin{index}"),
            },
        )
        assert created.status_code == 201, created.text
        tenant_ids.append(created.json()["id"])
        client = TestClient(app)
        login = client.post(
            "/auth/login",
            json={
                "email": f"admin{index}@test.com",
                "password": _pw(f"TenantAdmin{index}"),
            },
        )
        assert login.status_code == 200, login.text
        tenant_clients.append(client)

    case_1, finding_1, events_1 = _seed_intelligence_case(
        tenant_id=tenant_ids[0], suffix="c"
    )
    case_2, finding_2, events_2 = _seed_intelligence_case(
        tenant_id=tenant_ids[1], suffix="d"
    )

    body_1 = tenant_clients[0].get("/cases").json()
    body_2 = tenant_clients[1].get("/cases").json()
    assert [item["id"] for item in body_1] == [case_1]
    assert [item["id"] for item in body_2] == [case_2]
    assert body_1[0]["intelligence"]["finding_id"] == finding_1
    assert body_2[0]["intelligence"]["finding_id"] == finding_2
    assert tenant_clients[0].get(f"/cases/{case_2}").status_code == 404
    assert tenant_clients[1].get(f"/cases/{case_1}").status_code == 404
    assert tenant_clients[0].get(f"/cases/{case_1}").json()["intelligence"]["event_ids"] == events_1
    assert tenant_clients[1].get(f"/cases/{case_2}").json()["intelligence"]["event_ids"] == events_2
