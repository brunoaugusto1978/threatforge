from __future__ import annotations

import pytest

from app.collection import registry, secrets, service
from app.collection.envelope import EvidenceEnvelope, fingerprint_normalized
from tests._tg import make_session, make_tenant


def test_envelope_fingerprint_stable_and_no_original_custody():
    n = {"a": 1, "b": [2, 3]}
    e = EvidenceEnvelope.from_normalized(
        provider="telegram", tenant_id=1, source_ref="s", normalized=n,
        redacted_text="hi", content_version=2)
    assert e.original_custody is False
    assert e.normalized_fingerprint == fingerprint_normalized(n, 2)
    assert fingerprint_normalized(n, 2) != fingerprint_normalized(n, 3)


def test_custody_statement_wording():
    s = EvidenceEnvelope.custody_statement()
    assert "impressão digital" in s and "não mantém custódia do payload original" in s


def test_registry_register_get_duplicate_reset():
    reg = registry._Registry("x")
    reg.register("a", object())
    assert "a" in reg and reg.get("a") is not None
    with pytest.raises(ValueError):
        reg.register("a", object())
    reg.register("a", object(), replace=True)
    assert reg.names() == ["a"]


def test_secret_classification_fail_closed_c3():
    payload = {
        "chat_id": "123",                      # allowed for telegram channel
        "bot_token": "111:AAA",                # secret by name
        "smtp_password": "p@ss",               # secret by name
        # secret by VALUE analysis, regardless of unknown field name (C3):
        "some_random_field": "https://hooks.slack.com/services/T/B/XXXXXXXXXXXXXXXXXXXX",
        # unknown non-URL field for a known channel type → fail closed (C3):
        "mystery_setting": "whatever",
    }
    split = secrets.classify_payload(payload, channel_type="telegram")
    assert split.config_json == {"chat_id": "123"}
    names = {r.name for r in split.secret_refs}
    assert {"bot_token", "smtp_password", "some_random_field", "mystery_setting"} <= names
    kinds = {r.name: r.kind for r in split.secret_refs}
    assert kinds["some_random_field"] == "webhook_url_with_token"
    assert kinds["mystery_setting"] == "unclassified_fail_closed"


def test_tokened_url_never_stays_in_config_even_without_channel_type_c3():
    tokened = "https://api.telegram.org/bot123456:AAHfakeToken/sendMessage"
    split = secrets.classify_payload({"anything": tokened})
    assert "anything" not in split.config_json
    plain = "https://example.com/webhook"
    assert secrets.webhook_url_is_secret(plain) is False


def test_secret_refs_persisted_and_recoverable_c3():
    """Mandatory test #8: refs are stored and resolvable by the authorised path."""
    resolver = secrets.InMemorySecretResolver()
    secrets.set_resolver(resolver)
    try:
        db = make_session(); make_tenant(db, 1)
        conn = service.create_connection(
            db, tenant_id=1, provider="telegram", name="c",
            payload={"bot_token": "111:AAA-synthetic", "chat_id": "42"})
        ch = service.create_alert_channel(
            db, tenant_id=1, name="ch", channel_type="smtp",
            payload={"smtp_host": "mail.local", "smtp_password": "synthetic-pass"})
        db.commit()
        # refs persisted (not values)
        assert "bot_token" in conn.secret_refs
        assert "111:AAA-synthetic" not in str(conn.secret_refs)
        assert "111:AAA-synthetic" not in str(conn.config_json)
        assert "smtp_password" in ch.secret_refs
        # authorised recovery through the resolver
        assert service.resolve_connection_secret(conn, "bot_token") == "111:AAA-synthetic"
        assert service.resolve_channel_secret(ch, "smtp_password") == "synthetic-pass"
        assert service.resolve_connection_secret(conn, "nonexistent") is None
    finally:
        secrets.set_resolver(secrets.NullSecretResolver())


def test_null_resolver_never_returns_value():
    r = secrets.NullSecretResolver()
    ref = r.put(1, "channel:x", "bot_token", "111:AAA")
    assert ref.startswith("secretref://null/")
    assert r.get(ref) is None


def test_connection_payload_is_fail_closed_by_provider_schema():
    resolver = secrets.InMemorySecretResolver()
    secrets.set_resolver(resolver)
    try:
        db = make_session(); make_tenant(db, 1)
        conn = service.create_connection(
            db, tenant_id=1, provider="telegram", name="strict",
            payload={"poll_timeout_seconds": 30,
                     "mystery_secret_value": "not-obviously-named"})
        db.commit()
        assert conn.config_json == {"poll_timeout_seconds": 30}
        assert "mystery_secret_value" in conn.secret_refs
        assert service.resolve_connection_secret(conn, "mystery_secret_value") == "not-obviously-named"
    finally:
        secrets.set_resolver(secrets.NullSecretResolver())


def test_alert_channel_types_are_registry_validated_not_db_check():
    from app.models import TenantAlertChannel
    db = make_session(); make_tenant(db, 1)
    registry.alert_channels.register("teams", "teams")
    try:
        ch = service.create_alert_channel(db, tenant_id=1, name="teams",
                                          channel_type="teams", payload={})
        db.commit()
        assert db.get(TenantAlertChannel, ch.id).channel_type == "teams"
    finally:
        registry.alert_channels.unregister("teams")
