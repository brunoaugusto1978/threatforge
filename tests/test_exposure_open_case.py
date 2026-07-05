"""Etapa 4 — Open investigation context inheritance.

Covers the POC finding: a case opened from an Exposure finding that
correlates to exactly one brand must inherit that brand's id; multiple
candidate brands must NOT be guessed; the description must carry structured
finding context (type, affected email, source, risk score, ingest id when
available); the authenticated user must be set as assignee.

Isolation: uses the shared `tenant_admin_client` fixture from `conftest.py`
(sys.modules purge + tmp_path SQLite). See conftest for the rationale.
"""
from __future__ import annotations


def _create_brand(client, name, domains):
    r = client.post("/brands", json={"name": name, "official_domains": domains})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _create_finding(client, email):
    r = client.post(
        "/exposure/findings/intake",
        json={
            "exposure_type": "identity_exposure",
            "title": f"Test finding {email}",
            "source": "manual_intake",
            "detail": {"email": email},
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def test_open_case_inherits_brand_when_correlation_is_unique(tenant_admin_client):
    client = tenant_admin_client
    brand_id = _create_brand(client, "Example Brand", ["example.com"])
    finding_id = _create_finding(client, "alice@example.com")

    # Sanity: correlate graph should contain exactly this brand.
    graph = client.get(f"/correlation?entity=finding:{finding_id}").json()
    brand_nodes = [n for n in graph.get("nodes", []) if n.get("kind") == "brand"]
    assert len(brand_nodes) == 1, graph
    assert brand_nodes[0]["ref"]["id"] == brand_id

    r = client.post(f"/exposure/findings/{finding_id}/case")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["brand_id"] == brand_id, body
    # Authenticated user is the tenant admin created in the fixture — must
    # be set as assignee, not left NULL.
    assert body["assignee_user_id"], body

    case = client.get(f"/cases/{body['case_id']}").json()
    assert case["brand_id"] == brand_id, case
    desc = case.get("description") or ""
    assert "identity_exposure" in desc, desc
    assert "alice@example.com" in desc, desc
    assert "manual_intake" in desc, desc
    assert "Risk score" in desc, desc


def test_open_case_does_not_guess_brand_when_multiple_candidates(tenant_admin_client):
    client = tenant_admin_client
    _create_brand(client, "Brand One", ["shared.example"])
    _create_brand(client, "Brand Two", ["shared.example"])
    # Both brands share the same official domain — deliberate ambiguity.
    finding_id = _create_finding(client, "someone@shared.example")

    r = client.post(f"/exposure/findings/{finding_id}/case")
    assert r.status_code == 201, r.text
    body = r.json()
    # Multiple candidate brands → do NOT pick randomly.
    assert body["brand_id"] is None, body


def test_open_case_leaves_brand_null_when_no_correlation(tenant_admin_client):
    client = tenant_admin_client
    finding_id = _create_finding(client, "orphan@no-brand-match.example")

    r = client.post(f"/exposure/findings/{finding_id}/case")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["brand_id"] is None, body
    # Manual case flow is unaffected: description still contains context.
    case = client.get(f"/cases/{body['case_id']}").json()
    assert "orphan@no-brand-match.example" in (case.get("description") or "")


def test_manual_case_creation_still_works(tenant_admin_client):
    """Regression: creating a case manually (no finding) still succeeds and
    does not require the inherited-context path.
    """
    client = tenant_admin_client
    brand_id = _create_brand(client, "Manual Brand", ["manual.example"])
    r = client.post(
        "/cases",
        json={"title": "Manual case", "severity": "medio", "brand_id": brand_id},
    )
    assert r.status_code == 201, r.text
    case = r.json()
    assert case["brand_id"] == brand_id
