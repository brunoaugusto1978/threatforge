"""Etapa 2 — URLhaus / enrichment error handling.

Covers the POC finding: when an external enrichment source (URLhaus) fails
with an HTTP error, the API must not leak the raw exception class (e.g.
"HTTPStatusError") to the client, must keep the observable as UNKNOWN instead
of registering it as clean, and must record the technical failure in the
audit trail.

Isolation: uses the shared `tenant_admin_client` fixture from `conftest.py`,
which purges cached `app.*` modules and rebuilds a fresh FastAPI app + fresh
SQLite DB per test. Previously each test file rolled its own fixture with
`os.environ` mutation, which left `app.database.engine` bound to the first
test's DB and produced `POST /setup/operator -> 409 Conflict` on every
follow-up test.
"""
from __future__ import annotations


def _make_urlhaus_403(monkeypatch):
    """Force the URLhaus connector on the freshly-imported app to fail
    exactly like the POC log:
    ``POST https://urlhaus-api.abuse.ch/v1/host/ -> 403 Forbidden``.
    """
    import app.routers.observables as obs_router

    class _FakeResponse:
        status_code = 403

    class _FakeHTTPStatusError(Exception):
        def __init__(self):
            super().__init__("403 Forbidden")
            self.response = _FakeResponse()

    def _raise(self, observable_type, value, db):
        raise _FakeHTTPStatusError()

    for connector in obs_router.CONNECTORS:
        if connector.name == "urlhaus":
            monkeypatch.setattr(connector, "enrich", _raise.__get__(connector))


def test_enrich_urlhaus_403_returns_friendly_message_not_raw_exception(
    tenant_admin_client, monkeypatch
):
    client = tenant_admin_client
    _make_urlhaus_403(monkeypatch)

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.10"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    r = client.post(f"/observables/{obs_id}/enrich")

    # Controlled response: 200, not a 502 that reads as an internal platform
    # error.
    assert r.status_code == 200, r.text
    body = r.json()

    # Never leak the technical exception class or raw HTTP error text.
    raw_text = r.text.lower()
    for leaked in ("httpstatuserror", "403 forbidden", "traceback"):
        assert leaked not in raw_text, f"leaked technical detail: {leaked}"

    # Friendly, source-specific message instead.
    assert body["enrichment_warnings"], body
    assert any("urlhaus" in w.lower() for w in body["enrichment_warnings"])


def test_enrich_urlhaus_403_keeps_ioc_as_unknown(tenant_admin_client, monkeypatch):
    client = tenant_admin_client
    _make_urlhaus_403(monkeypatch)

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.11"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    r = client.post(f"/observables/{obs_id}/enrich")
    assert r.status_code == 200, r.text
    body = r.json()

    # IOC is neither removed nor corrupted; it stays registered as UNKNOWN
    # rather than being scored as "no known threat" (a check that never ran).
    assert body["verdict"] == "unknown", body
    assert body["score"] == 0, body

    still_there = client.get(f"/observables/{obs_id}")
    assert still_there.status_code == 200
    assert still_there.json()["verdict"] == "unknown"


def test_enrich_urlhaus_403_is_logged_to_audit(tenant_admin_client, monkeypatch):
    client = tenant_admin_client
    _make_urlhaus_403(monkeypatch)

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.12"})
    obs_id = created.json()["id"]
    client.post(f"/observables/{obs_id}/enrich")

    audit_entries = client.get("/audit").json()
    matches = [a for a in audit_entries if a.get("action") == "enrichment.source_failed"]
    assert matches, audit_entries
    detail = matches[0].get("detail") or {}
    assert detail.get("source") == "urlhaus"
    assert detail.get("status_code") == 403
    assert detail.get("error_type")
