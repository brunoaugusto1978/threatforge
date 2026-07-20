from __future__ import annotations

from sqlalchemy import func, select

from app.collection import intelligence_analysis, registry, service
from app.models import (
    AuditLog,
    Brand,
    CollectionEvent,
    ExposureFinding,
    InvestigationCase,
)
from tests._tg import make_session, make_tenant


class _Classifier:
    name = "telegram"

    def classify(self, envelope):
        text = str(envelope.get("redacted_text") or "")
        targeted = "atacar" in text.lower() and "cbg" in text.lower()
        return {
            "decision": "targeted_threat" if targeted else "informational",
            "score": 95 if targeted else 0,
            "confidence": "high" if targeted else "low",
            "severity": "high" if targeted else "low",
            "threat_category": "attack" if targeted else "none",
            "matched_target": {
                "ref": "brand:1",
                "kind": "brand",
                "label": "CBG Security",
                "brand_id": 1,
                "asset_id": None,
                "asset_type": "brand",
                "criticality": "high",
            } if targeted else None,
            "matched_target_terms": ["CBG"] if targeted else [],
            "matched_threat_terms": ["atacar"] if targeted else [],
            "matched_intent_terms": ["vamos"] if targeted else [],
            "negation": False,
            "authorized_context": False,
            "informational_context": False,
            "factors": [
                {
                    "code": "protected_target_match",
                    "weight": 35,
                    "matched": targeted,
                    "detail": "CBG Security" if targeted else "",
                },
                {
                    "code": "threat_term_match",
                    "weight": 30,
                    "matched": targeted,
                    "detail": "atacar" if targeted else "",
                },
            ],
        }


class _Correlator:
    name = "telegram"

    def correlate(self, envelope):
        result = dict(envelope["analysis"])
        policy = envelope["policy"]
        score = result["score"]
        result["promotion"] = {
            "create_finding": bool(policy["auto_finding"] and score >= policy["finding_threshold"]),
            "create_case": bool(policy["auto_case"] and score >= policy["case_threshold"]),
            "finding_threshold": policy["finding_threshold"],
            "case_threshold": policy["case_threshold"],
        }
        return result


def _setup(db):
    registry.classifiers.register("telegram", _Classifier(), replace=True)
    registry.correlators.register("telegram", _Correlator(), replace=True)
    make_tenant(db, 1)
    db.add(
        Brand(
            id=1,
            tenant_id=1,
            name="CBG Security",
            official_domains="cbgsecurity.com.br",
            aliases=["CBG"],
            status="active",
        )
    )
    conn = service.create_connection(
        db,
        tenant_id=1,
        provider="telegram",
        name="CBG Telegram POC",
    )
    src = service.create_source(
        db,
        tenant_id=1,
        connection_id=conn.id,
        source_ref="-1001",
        kind="group",
        name="Grupo QA Autorizado",
    )
    service.enable_source(db, tenant_id=1, source_id=src.id)
    db.commit()
    return src


def _event(db, source_id, text, fingerprint):
    event = CollectionEvent(
        tenant_id=1,
        source_id=source_id,
        provider="telegram",
        processing_state="normalized",
        normalized_fingerprint=fingerprint,
        redacted_text=text,
        context_json={"chat_type": "group", "update_kind": "message"},
    )
    db.add(event)
    db.commit()
    return event


def _policy():
    return intelligence_analysis.AnalysisPolicy(
        auto_finding=True,
        auto_case=True,
        finding_threshold=60,
        case_threshold=80,
        batch_size=25,
    )


def test_targeted_threat_is_analyzed_and_promoted_atomically(monkeypatch):
    db = make_session()
    source = _setup(db)
    event = _event(db, source.id, "Vamos atacar a CBG", "a" * 64)
    monkeypatch.setattr(
        intelligence_analysis.features,
        "is_enabled",
        lambda _feature: True,
    )

    outcomes = intelligence_analysis.run_analysis_once(db, policy=_policy())

    assert len(outcomes) == 1
    db.refresh(event)
    assert event.processing_state == "analyzed"
    assert event.analysis_version == intelligence_analysis.ANALYSIS_VERSION
    assert event.analysis_json["decision"] == "targeted_threat"
    assert event.analysis_json["score"] == 95
    assert event.finding_id is not None
    assert event.case_id is not None

    finding = db.get(ExposureFinding, event.finding_id)
    case = db.get(InvestigationCase, event.case_id)
    assert finding is not None and finding.source == "telegram_intelligence"
    assert finding.severity == "high" and finding.risk_score == 95
    assert finding.detail["event_ids"] == [event.id]
    assert finding.detail["case_id"] == case.id
    assert case is not None and case.brand_id == 1
    assert case.finding_id is None
    assert case.finding_snapshot["exposure_finding_id"] == finding.id
    assert "Vamos atacar" not in (case.description or "")
    assert db.scalar(select(func.count()).select_from(AuditLog)) >= 3


def test_repeated_same_day_evidence_reuses_finding_and_case(monkeypatch):
    db = make_session()
    source = _setup(db)
    first = _event(db, source.id, "Vamos atacar a CBG", "a" * 64)
    second = _event(db, source.id, "Iremos atacar a CBG", "b" * 64)
    monkeypatch.setattr(
        intelligence_analysis.features,
        "is_enabled",
        lambda _feature: True,
    )

    outcomes = intelligence_analysis.run_analysis_once(db, policy=_policy())

    assert len(outcomes) == 2
    db.refresh(first)
    db.refresh(second)
    assert first.finding_id == second.finding_id
    assert first.case_id == second.case_id
    assert db.scalar(select(func.count()).select_from(ExposureFinding)) == 1
    assert db.scalar(select(func.count()).select_from(InvestigationCase)) == 1
    finding = db.get(ExposureFinding, first.finding_id)
    assert finding.detail["event_count"] == 2
    assert set(finding.detail["event_ids"]) == {first.id, second.id}


def test_informational_event_is_analyzed_without_promotion(monkeypatch):
    db = make_session()
    source = _setup(db)
    event = _event(db, source.id, "A CBG publicou um artigo", "c" * 64)
    monkeypatch.setattr(
        intelligence_analysis.features,
        "is_enabled",
        lambda _feature: True,
    )

    intelligence_analysis.run_analysis_once(db, policy=_policy())

    db.refresh(event)
    assert event.processing_state == "analyzed"
    assert event.analysis_json["decision"] == "informational"
    assert event.finding_id is None
    assert event.case_id is None
    assert db.scalar(select(func.count()).select_from(ExposureFinding)) == 0
    assert db.scalar(select(func.count()).select_from(InvestigationCase)) == 0


def test_policy_defaults_are_fail_safe(monkeypatch):
    for name in (
        "THREATFORGE_INTELLIGENCE_AUTO_FINDING",
        "THREATFORGE_INTELLIGENCE_AUTO_CASE",
    ):
        monkeypatch.delenv(name, raising=False)
    policy = intelligence_analysis.policy_from_env()
    assert policy.auto_finding is False
    assert policy.auto_case is False
    assert policy.finding_threshold == 60
    assert policy.case_threshold == 80


def test_classifier_cannot_inject_unapproved_target_ids(monkeypatch):
    class _ForgedClassifier(_Classifier):
        def classify(self, envelope):
            result = super().classify(envelope)
            result["matched_target"] = {
                "ref": "brand:999",
                "kind": "brand",
                "label": "Other tenant",
                "brand_id": 999,
                "asset_id": None,
                "asset_type": "brand",
                "criticality": "critical",
            }
            return result

    db = make_session()
    source = _setup(db)
    event = _event(db, source.id, "Vamos atacar a CBG", "d" * 64)
    registry.classifiers.register("telegram", _ForgedClassifier(), replace=True)
    monkeypatch.setattr(
        intelligence_analysis.features,
        "is_enabled",
        lambda _feature: True,
    )

    intelligence_analysis.run_analysis_once(db, policy=_policy())

    db.refresh(event)
    assert event.processing_state == "analyzed"
    assert event.analysis_json["matched_target"] is None
    assert event.analysis_json["promotion"]["finding_id"] is None
    assert event.finding_id is None
    assert event.case_id is None
    assert db.scalar(select(func.count()).select_from(ExposureFinding)) == 0
    assert db.scalar(select(func.count()).select_from(InvestigationCase)) == 0
