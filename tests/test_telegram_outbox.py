from __future__ import annotations

import pytest

from app.collection import outbox, service
from app.models import AlertOutbox
from tests._tg import make_finding, make_session, make_tenant


def _channel(db, tenant_id, name="ch"):
    ch = service.create_alert_channel(
        db, tenant_id=tenant_id, name=name, channel_type="telegram",
        payload={"chat_id": "synthetic-chat", "bot_token": "synthetic-token"})
    service.enable_alert_channel(db, tenant_id=tenant_id, channel_id=ch.id)
    db.commit()
    return ch


def test_dedup_key_deterministic_and_versioned():
    k1 = outbox.compute_dedup_key(1, 10, 5, "tpl", "1")
    k2 = outbox.compute_dedup_key(1, 10, 5, "tpl", "1")
    k3 = outbox.compute_dedup_key(1, 10, 5, "tpl", "2")
    assert k1 == k2 and k1 != k3 and len(k1) == 64


def test_enqueue_is_idempotent_req5():
    db = make_session(); make_tenant(db, 1)
    ch = _channel(db, 1)
    finding = make_finding(db, 1, "f1")
    db.commit()
    o1 = service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                               finding_id=finding.id,
                               template="finding.alert", template_version="1")
    db.commit()
    o2 = service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                               finding_id=finding.id,
                               template="finding.alert", template_version="1")
    db.commit()
    assert o1.created is True and o2.created is False
    assert o1.outbox_id == o2.outbox_id
    assert db.query(AlertOutbox).count() == 1


def test_enqueue_rejects_cross_tenant_channel_req2():
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    ch1 = _channel(db, 1, "c1")
    finding_t2 = make_finding(db, 2, "f2")
    db.commit()
    with pytest.raises(service.TenantMismatch):
        service.enqueue_alert(db, tenant_id=2, alert_channel_id=ch1.id,
                              finding_id=finding_t2.id,
                              template="t", template_version="1")


def test_enqueue_rejects_cross_tenant_finding_c6():
    """Mandatory test #7: tenant 1 + canal tenant 1 + finding tenant 2 → rejeitado."""
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    ch1 = _channel(db, 1, "c1")
    finding_t2 = make_finding(db, 2, "other-tenant")
    db.commit()
    with pytest.raises(service.TenantMismatch):
        service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch1.id,
                              finding_id=finding_t2.id,
                              template="t", template_version="1")


def test_enqueue_rejects_missing_finding_c6():
    db = make_session(); make_tenant(db, 1)
    ch = _channel(db, 1)
    with pytest.raises(service.NotFound):
        service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                              finding_id=424242, template="t", template_version="1")


def test_payload_must_not_carry_delivery_state_req4():
    db = make_session(); make_tenant(db, 1)
    ch = _channel(db, 1)
    finding = make_finding(db, 1, "f3")
    db.commit()
    with pytest.raises(ValueError):
        service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                              finding_id=finding.id,
                              template="t", template_version="1",
                              payload={"status": "delivered"})
    with pytest.raises(ValueError):
        outbox.assert_payload_clean({"delivery_state": "sent"})


def test_external_ref_is_additive_not_a_replacement_req2():
    db = make_session(); make_tenant(db, 1)
    ch = _channel(db, 1)
    finding = make_finding(db, 1, "f4")
    db.commit()
    o = service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                              finding_id=finding.id,
                              template="t", template_version="1",
                              external_channel_ref="ext-ref-abc")
    db.commit()
    row = db.get(AlertOutbox, o.outbox_id)
    assert row.alert_channel_id == ch.id
    assert row.external_channel_ref == "ext-ref-abc"


def test_outbox_rejects_arbitrary_or_sensitive_payload():
    with pytest.raises(ValueError):
        outbox.assert_payload_clean({"conversation": "SECRET RAW TEXT"})
    with pytest.raises(ValueError):
        outbox.assert_payload_clean({"token": "abc"})
    outbox.assert_payload_clean({
        "severity": "high", "redacted_title": "Threat detected",
        "redacted_summary": "Redacted operational summary", "confidence": 0.9,
    })


def test_enqueue_rejects_disabled_or_incomplete_channel():
    db = make_session(); make_tenant(db, 1)
    ch = service.create_alert_channel(db, tenant_id=1, name="disabled",
                                      channel_type="telegram",
                                      payload={"chat_id": "x", "bot_token": "synthetic"})
    finding = make_finding(db, 1, "disabled")
    db.commit()
    with pytest.raises(service.ChannelNotReady):
        service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                              finding_id=finding.id, template="t")


def test_enqueue_integrity_race_returns_existing(monkeypatch):
    """Simulate another worker winning UNIQUE(dedup_key) after our first lookup."""
    from contextlib import contextmanager
    from sqlalchemy import insert
    db = make_session(); make_tenant(db, 1)
    ch = _channel(db, 1, "race")
    finding = make_finding(db, 1, "race")
    db.commit()
    dedup = outbox.compute_dedup_key(1, finding.id, ch.id, "t", "1")
    original_begin_nested = db.begin_nested
    injected = {"done": False}

    @contextmanager
    def _begin_nested_with_winner():
        if not injected["done"]:
            db.connection().execute(insert(AlertOutbox).values(
                tenant_id=1, alert_channel_id=ch.id, finding_id=finding.id,
                template="t", template_version="1", dedup_key=dedup,
                status="pending", attempts=0, payload_json={}))
            injected["done"] = True
        with original_begin_nested():
            yield

    monkeypatch.setattr(db, "begin_nested", _begin_nested_with_winner)
    result = service.enqueue_alert(db, tenant_id=1, alert_channel_id=ch.id,
                                   finding_id=finding.id, template="t")
    assert result.created is False
    assert db.query(AlertOutbox).filter_by(dedup_key=dedup).count() == 1
