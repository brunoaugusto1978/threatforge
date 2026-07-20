from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select

from app.collection import intelligence_analysis, registry, service
from app.models import Brand, CollectionEvent, ExposureFinding, InvestigationCase, utcnow
from tests._tg import make_session, make_tenant


class _ConversationClassifier:
    name = "telegram"

    def classify(self, envelope):
        text = str(envelope.get("redacted_text") or "")
        if "[email-domain:example.invalid]" in text:
            decision = "credential_exposure"
            score = 100
            category = "credential_exposure"
            target = _target()
        elif "Example Corp" in text or "example.invalid" in text:
            decision = "monitored_target_mention"
            score = 45
            category = "none"
            target = _target()
        else:
            decision = "informational"
            score = 5
            category = "none"
            target = None
        return {
            "decision": decision,
            "score": score,
            "confidence": "high" if score >= 80 else "low",
            "severity": "high" if score >= 80 else "low",
            "threat_category": category,
            "correlation_family": category,
            "matched_target": target,
            "matched_target_terms": ["Example Corp"] if target else [],
            "matched_threat_terms": ["email-domain"] if score >= 80 else [],
            "matched_intent_terms": [],
            "matched_email_domains": ["example.invalid"] if score >= 80 else [],
            "contextual_match": False,
            "conversation_followup": False,
            "context_event_count": len(envelope.get("conversation") or []),
            "negation": False,
            "authorized_context": False,
            "informational_context": False,
            "factors": [],
        }


class _ConversationCorrelator:
    name = "telegram"

    def correlate(self, envelope):
        result = dict(envelope["analysis"])
        policy = envelope["policy"]
        eligible = result["decision"] == "credential_exposure"
        result["promotion"] = {
            "create_finding": bool(
                eligible
                and policy["auto_finding"]
                and result["score"] >= policy["finding_threshold"]
            ),
            "create_case": bool(
                eligible
                and policy["auto_case"]
                and result["score"] >= policy["case_threshold"]
            ),
            "finding_threshold": policy["finding_threshold"],
            "case_threshold": policy["case_threshold"],
        }
        return result


def _target():
    return {
        "ref": "brand:1",
        "kind": "brand",
        "label": "Example Corp",
        "brand_id": 1,
        "asset_id": None,
        "asset_type": "brand",
        "criticality": "high",
    }


def _setup(db):
    make_tenant(db, 1)
    db.add(
        Brand(
            id=1,
            tenant_id=1,
            name="Example Corp",
            official_domains="example.invalid",
            aliases=["Example"],
            status="active",
        )
    )
    conn = service.create_connection(
        db, tenant_id=1, provider="telegram", name="Example Telegram"
    )
    source = service.create_source(
        db,
        tenant_id=1,
        connection_id=conn.id,
        source_ref="-1001",
        kind="group",
        name="Authorized test source",
    )
    conn.enabled = True
    conn.status = "active"
    service.enable_source(db, tenant_id=1, source_id=source.id)
    db.commit()
    registry.classifiers.register("telegram", _ConversationClassifier(), replace=True)
    registry.correlators.register("telegram", _ConversationCorrelator(), replace=True)
    return source


def _event(db, source_id, text, when, actor):
    row = CollectionEvent(
        tenant_id=1,
        source_id=source_id,
        provider="telegram",
        processing_state="normalized",
        normalized_fingerprint=(str(actor) * 64)[:64],
        redacted_text=text,
        occurred_at=when,
        context_json={
            "chat_type": "group",
            "update_kind": "message",
            "actor_ref": (str(actor) * 64)[:64],
        },
    )
    db.add(row)
    db.commit()
    return row


def _policy():
    return intelligence_analysis.AnalysisPolicy(
        auto_finding=True,
        auto_case=True,
        finding_threshold=60,
        case_threshold=80,
        batch_size=25,
        context_window_seconds=900,
        context_max_events=10,
    )


def test_prior_target_mentions_are_linked_when_credential_exposure_promotes(monkeypatch):
    db = make_session()
    source = _setup(db)
    now = utcnow()
    first = _event(db, source.id, "target example.invalid", now, "a")
    second = _event(db, source.id, "is this Example Corp?", now + timedelta(minutes=2), "b")
    trigger = _event(
        db,
        source.id,
        "sample [email-domain:example.invalid] available privately",
        now + timedelta(minutes=4),
        "a",
    )
    monkeypatch.setattr(intelligence_analysis.features, "is_enabled", lambda _f: True)

    outcomes = intelligence_analysis.run_analysis_once(db, policy=_policy())

    assert len(outcomes) == 3
    db.refresh(first)
    db.refresh(second)
    db.refresh(trigger)
    assert trigger.analysis_json["decision"] == "credential_exposure"
    assert trigger.finding_id is not None and trigger.case_id is not None
    assert first.finding_id == trigger.finding_id
    assert second.finding_id == trigger.finding_id
    assert first.case_id == trigger.case_id
    assert second.case_id == trigger.case_id
    finding = db.get(ExposureFinding, trigger.finding_id)
    case = db.get(InvestigationCase, trigger.case_id)
    assert finding.exposure_type == "credential_exposure"
    assert finding.detail["event_count"] == 3
    assert finding.detail["matched_email_domains"] == ["example.invalid"]
    assert case.finding_snapshot["intelligence"]["event_count"] == 3
    assert db.scalar(select(func.count()).select_from(ExposureFinding)) == 1
    assert db.scalar(select(func.count()).select_from(InvestigationCase)) == 1


def test_context_window_excludes_old_or_other_source_events():
    db = make_session()
    source = _setup(db)
    other_conn = service.create_connection(
        db, tenant_id=1, provider="telegram", name="Other"
    )
    other = service.create_source(
        db,
        tenant_id=1,
        connection_id=other_conn.id,
        source_ref="-2002",
        kind="group",
        name="Other source",
    )
    other_conn.enabled = True
    other_conn.status = "active"
    service.enable_source(db, tenant_id=1, source_id=other.id)
    db.commit()
    now = utcnow()
    _event(db, source.id, "old Example Corp", now - timedelta(minutes=30), "a")
    recent = _event(db, source.id, "recent Example Corp", now - timedelta(minutes=2), "a")
    _event(db, other.id, "other Example Corp", now - timedelta(minutes=1), "a")
    current = _event(db, source.id, "current", now, "a")

    rows = intelligence_analysis.recent_context_events(
        db, event=current, policy=_policy()
    )

    assert [row.id for row in rows] == [recent.id]
