"""Phase 2C Intelligence Workspace API and static UI contract tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path


def _enable(monkeypatch, *feature_names: str) -> None:
    from app import features as feats
    from app.features import Feature

    wanted = {Feature(name) for name in feature_names}
    monkeypatch.setattr(feats, "entitlements", lambda: wanted)


def _seed_collection() -> tuple[int, int]:
    from app.database import SessionLocal
    from app.models import (
        CollectionConnection,
        CollectionEvent,
        CollectionSource,
        ExposureFinding,
        InvestigationCase,
        Tenant,
        utcnow,
    )

    now = utcnow()
    checked_at = now.isoformat()
    with SessionLocal() as db:
        connection = CollectionConnection(
            tenant_id=1,
            provider="telegram",
            name="CBG Telegram POC",
            enabled=True,
            status="active",
            provider_account_ref="8770625350",
            secret_refs={"bot_token": "secretref://file/telegram-token"},
            config_json={
                "bot_username": "threatforge_qa_bot",
                "_health": {
                    "state": "healthy",
                    "checked_at": checked_at,
                    "last_success_at": checked_at,
                    "last_event_at": checked_at,
                    "persisted_events": 3,
                    "deduplicated_updates": 1,
                    "ignored_updates": 2,
                },
            },
        )
        db.add(connection)
        db.flush()
        source = CollectionSource(
            tenant_id=1,
            connection_id=connection.id,
            provider="telegram",
            source_ref="-1001234567890",
            kind="group",
            name="Grupo QA Autorizado",
            enabled=True,
            status="active",
        )
        db.add(source)
        db.flush()
        source_id = source.id

        finding = ExposureFinding(
            tenant_id=1,
            exposure_type="brand_exposure",
            title="Telegram brand mention",
            source="manual_intake",
            source_reliability="B",
            info_credibility="2",
            severity="medium",
            status="new",
            dedup_key="intelligence-workspace-finding",
            detail={"source": "telegram"},
        )
        case = InvestigationCase(
            tenant_id=1,
            title="Telegram intelligence review",
            severity="medio",
            status="open",
        )
        db.add_all([finding, case])
        db.flush()

        events = [
            CollectionEvent(
                tenant_id=1,
                source_id=source_id,
                provider="telegram",
                external_id_hash=f"{index:064x}",
                processing_state=state,
                redacted_text=text,
                context_json={
                    "chat_type": "group",
                    "update_kind": "message",
                    "forwarded": False,
                    "has_attachment": index == 3,
                    "entity_count": index,
                    "raw_payload": {"token": "must-not-leak"},
                    "secret": "must-not-leak",
                },
                occurred_at=now - timedelta(minutes=index),
                finding_id=finding.id if index == 2 else None,
                case_id=case.id if index == 3 else None,
                analysis_version="telegram-targeted-threat-v1" if index == 2 else None,
                analysis_json={
                    "decision": "targeted_threat",
                    "score": 95,
                    "confidence": "high",
                    "severity": "high",
                    "threat_category": "attack",
                    "matched_target": {
                        "ref": "brand:1",
                        "kind": "brand",
                        "label": "CBG Security",
                        "brand_id": 1,
                        "criticality": "high",
                    },
                    "matched_target_terms": ["CBG"],
                    "matched_threat_terms": ["atacar"],
                    "matched_intent_terms": ["vamos"],
                    "negation": False,
                    "authorized_context": False,
                    "informational_context": False,
                    "factors": [
                        {
                            "code": "protected_target_match",
                            "weight": 35,
                            "matched": True,
                            "detail": "CBG Security",
                        },
                        {
                            "code": "unapproved_internal_factor",
                            "weight": 999,
                            "matched": True,
                            "detail": "must-not-leak",
                        },
                    ],
                    "promotion": {
                        "finding_id": finding.id,
                        "case_id": None,
                        "finding_created": True,
                        "case_created": False,
                    },
                    "raw_payload": {"secret": "must-not-leak"},
                } if index == 2 else {},
            )
            for index, state, text in (
                (1, "normalized", "CBG controlled validation message"),
                (2, "analyzed", "Potential brand mention"),
                (3, "failed", "<script>alert(1)</script> inert evidence"),
            )
        ]
        db.add_all(events)

        db.add(Tenant(id=2, name="Other tenant", slug="other-tenant"))
        db.flush()
        other_connection = CollectionConnection(
            tenant_id=2,
            provider="telegram",
            name="Other tenant collector",
            enabled=True,
            status="active",
        )
        db.add(other_connection)
        db.flush()
        other_source = CollectionSource(
            tenant_id=2,
            connection_id=other_connection.id,
            provider="telegram",
            source_ref="-999",
            kind="group",
            name="Other tenant source",
            enabled=True,
            status="active",
        )
        db.add(other_source)
        db.flush()
        db.add(
            CollectionEvent(
                tenant_id=2,
                source_id=other_source.id,
                provider="telegram",
                external_id_hash="f" * 64,
                processing_state="normalized",
                redacted_text="must-not-cross-tenant",
                occurred_at=now,
            )
        )
        db.commit()
        return source_id, other_source.id


def test_intelligence_catalog_visible_but_events_locked(tenant_admin_client):
    overview = tenant_admin_client.get("/intelligence/overview")
    assert overview.status_code == 200, overview.text
    body = overview.json()
    assert body["license_enabled"] is False
    assert body["summary"]["events_total"] == 0
    assert body["summary"]["collector_state"] == "not_configured"
    assert body["upgrade"]["email"]

    events = tenant_admin_client.get("/intelligence/events")
    assert events.status_code == 402
    assert events.json()["feature"] == "collection.telegram"


def test_intelligence_overview_feed_detail_isolated_redacted_and_audited(
    tenant_admin_client, monkeypatch
):
    _enable(monkeypatch, "collection.telegram", "analysis.telegram")
    source_id, other_source_id = _seed_collection()

    overview = tenant_admin_client.get("/intelligence/overview")
    assert overview.status_code == 200, overview.text
    body = overview.json()
    summary = body["summary"]
    assert body["license_enabled"] is True
    assert body["analysis_enabled"] is True
    assert summary["events_total"] == 3
    assert summary["events_24h"] == 3
    assert summary["sources_total"] == 1
    assert summary["sources_active"] == 1
    assert summary["connections_enabled"] == 1
    assert summary["collector_state"] == "healthy"
    assert summary["linked_findings"] == 1
    assert summary["linked_cases"] == 1
    assert body["providers"] == {"telegram": 3}
    assert body["states"]["normalized"] == 1
    assert body["states"]["analyzed"] == 1
    assert body["states"]["failed"] == 1
    assert body["sources"][0]["name"] == "Grupo QA Autorizado"
    assert body["sources"][0]["event_count"] == 3
    assert body["collectors"][0]["state"] == "healthy"

    # Operational views never expose chat IDs, bot identity or secret refs.
    assert "-1001234567890" not in overview.text
    assert "8770625350" not in overview.text
    assert "secretref://" not in overview.text
    assert "must-not-cross-tenant" not in overview.text

    page = tenant_admin_client.get("/intelligence/events?limit=2")
    assert page.status_code == 200, page.text
    payload = page.json()
    assert len(payload["items"]) == 2
    assert payload["has_more"] is True
    assert payload["next_before_id"] == payload["items"][-1]["id"]
    assert all(row["source_name"] == "Grupo QA Autorizado" for row in payload["items"])
    assert "must-not-leak" not in page.text
    assert "external_id_hash" not in page.text
    assert "raw_payload" not in page.text

    older = tenant_admin_client.get(
        f"/intelligence/events?limit=2&before_id={payload['next_before_id']}"
    )
    assert older.status_code == 200
    assert len(older.json()["items"]) == 1
    assert older.json()["has_more"] is False

    pending = tenant_admin_client.get(
        "/intelligence/events?pending_analysis=true"
    )
    assert pending.status_code == 200, pending.text
    assert {row["state"] for row in pending.json()["items"]} == {"normalized", "failed"}

    filtered = tenant_admin_client.get(
        f"/intelligence/events?source_id={source_id}&state=analyzed&query=brand&has_finding=true"
    )
    assert filtered.status_code == 200, filtered.text
    assert len(filtered.json()["items"]) == 1
    event = filtered.json()["items"][0]
    assert event["has_finding"] is True
    assert event["finding_id"] is not None
    assert event["analysis"]["decision"] == "targeted_threat"
    assert event["analysis"]["score"] == 95
    assert event["analysis"]["matched_target"] == {
        "kind": "brand",
        "label": "CBG Security",
        "criticality": "high",
    }
    assert event["analysis"]["matched_target_terms"] == ["CBG"]
    assert "ref" not in event["analysis"]["matched_target"]
    assert "unapproved_internal_factor" not in filtered.text

    detail = tenant_admin_client.get(f"/intelligence/events/{event['id']}")
    assert detail.status_code == 200, detail.text
    detail_body = detail.json()
    assert detail_body["redaction_profile"] == "default"
    assert detail_body["content_version"] == 1
    assert detail_body["context"] == {
        "chat_type": "group",
        "update_kind": "message",
        "forwarded": False,
        "has_attachment": False,
        "entity_count": 2,
    }
    assert "external_id_hash" not in detail.text
    assert "raw_fingerprint" not in detail.text
    assert "normalized_fingerprint" not in detail.text
    assert "source_ref" not in detail.text
    assert "raw_payload" not in detail.text
    assert "brand:1" not in detail.text
    assert detail_body["analysis"]["promotion"]["finding_id"] == event["finding_id"]

    cross_tenant_source = tenant_admin_client.get(
        f"/intelligence/events?source_id={other_source_id}"
    )
    assert cross_tenant_source.status_code == 404

    from app.database import SessionLocal
    from app.models import AuditLog

    with SessionLocal() as db:
        actions = [
            row.action
            for row in db.query(AuditLog)
            .filter(AuditLog.tenant_id == 1)
            .order_by(AuditLog.id)
            .all()
        ]
    assert "intelligence.events_viewed" in actions
    assert "intelligence.event_viewed" in actions


def test_intelligence_static_ui_separates_feed_from_integrations():
    html = Path("app/static/index.html").read_text(encoding="utf-8")
    source = Path("app/static/app.js").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    assert 'data-view="intelligence"' in html
    assert "Intelligence Workspace" in source
    assert 'api("GET", "/intelligence/overview")' in source
    assert 'api("GET", `/intelligence/events?${params.toString()}`)' in source
    assert "${esc(event.redacted_text)}" in source
    assert "Open Intelligence workspace" in source
    assert 'data-action="intelligenceMetric"' in source
    assert 'id="intelligenceMetricSummary"' in source
    assert "renderIntelligenceMetricSummary" in source
    assert 'data-action="intelligenceMetricFilter"' in source
    assert 'params.set("pending_analysis", "true")' in source
    assert "intel-metric-card" in html
    assert "intel-metric-summary" in html
    assert 'id="telegramEvents"' not in source
    assert "telegramLoadEvents" not in source
    assert "Recent collected events" not in source
    assert "Control plane for authorized Bot API connections and sources" in source
    assert "Automated analysis" in source
    assert "Why this was detected" in source
    assert 'data-action="intelligenceOpenFinding"' in source
    assert 'data-action="intelligenceOpenCase"' in source
    assert "Current release: v0.10.1" in readme
    assert "Upcoming v0.11.0" in readme
    assert "Inbound collection flow" in readme
