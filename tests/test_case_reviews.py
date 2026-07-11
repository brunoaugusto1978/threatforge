"""Issue #18 — operational review workflow for investigation cases.

Covers the first backend slice:
* analyst/admin can append operational review entries;
* viewer can read review history;
* viewer cannot create reviews;
* cross-tenant access returns 404;
* review creation is audited.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _pw(label: str) -> str:
    return f"{label}Aa12345!"


def _create_case(client, title="Review workflow case"):
    r = client.post("/cases", json={"title": title, "severity": "alto"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _create_user(client, email: str, role: str):
    r = client.post("/users", json={
        "email": email,
        "password": _pw(email.split("@")[0].replace(".", "")),
        "role": role,
    })
    assert r.status_code == 201, r.text
    return r.json()


def _login(email: str):
    from app.main import app

    client = TestClient(app)
    password = _pw(email.split("@")[0].replace(".", ""))
    r = client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return client


def _platform_operator_client(setup_client):
    from app.main import app

    email = "op-case-review@example.com"
    password = _pw("Operator")
    r = setup_client.post("/setup/operator", json={
        "email": email,
        "password": password,
    })
    assert r.status_code in (200, 201), r.text

    op = TestClient(app)
    rl = op.post("/auth/login", json={
        "email": email,
        "password": password,
    })
    assert rl.status_code == 200, rl.text
    return op


def _create_tenant_admin(op_client, tenant_name: str, admin_email: str):
    from app.main import app

    r = op_client.post("/tenants", json={
        "name": tenant_name,
        "admin_email": admin_email,
        "admin_password": _pw("TenantAdmin"),
    })
    assert r.status_code == 201, r.text

    admin = TestClient(app)
    rl = admin.post("/auth/login", json={
        "email": admin_email,
        "password": _pw("TenantAdmin"),
    })
    assert rl.status_code == 200, rl.text
    return admin


def test_case_review_append_and_read_history(tenant_admin_client):
    client = tenant_admin_client
    case_id = _create_case(client)

    r = client.post(f"/cases/{case_id}/reviews", json={
        "review_status": "approved",
        "notes": "Reviewed and approved by operations.",
    })
    assert r.status_code == 201, r.text
    review = r.json()
    assert review["case_id"] == case_id
    assert review["review_status"] == "approved"
    assert review["notes"] == "Reviewed and approved by operations."
    assert review["reviewer_user_id"]
    assert review["created_by_user_id"] == review["reviewer_user_id"]
    assert review["reviewed_at"] is not None

    r2 = client.get(f"/cases/{case_id}/reviews")
    assert r2.status_code == 200, r2.text
    rows = r2.json()
    assert len(rows) == 1
    assert rows[0]["id"] == review["id"]
    assert rows[0]["review_status"] == "approved"

    audit = client.get("/audit").json()
    matching = [a for a in audit if a.get("action") == "case.review_added"]
    assert matching, audit
    assert any(str(a.get("target_id")) == str(case_id) for a in matching), matching


def test_viewer_can_read_but_cannot_create_review(tenant_admin_client):
    admin = tenant_admin_client
    case_id = _create_case(admin, "Viewer review permissions")
    _create_user(admin, "case.viewer@example.com", "viewer")
    viewer = _login("case.viewer@example.com")

    created = admin.post(f"/cases/{case_id}/reviews", json={
        "review_status": "in_review",
        "notes": "Initial operational review.",
    })
    assert created.status_code == 201, created.text

    read = viewer.get(f"/cases/{case_id}/reviews")
    assert read.status_code == 200, read.text
    assert len(read.json()) == 1

    denied = viewer.post(f"/cases/{case_id}/reviews", json={
        "review_status": "approved",
        "notes": "Viewer must not be able to approve.",
    })
    assert denied.status_code == 403, denied.text


def test_case_reviews_are_tenant_scoped(fresh_app):
    op = _platform_operator_client(fresh_app)

    admin_a = _create_tenant_admin(op, "Tenant A", "admin-a@example.com")
    admin_b = _create_tenant_admin(op, "Tenant B", "admin-b@example.com")

    case_a = _create_case(admin_a, "Tenant A review case")

    rb_get = admin_b.get(f"/cases/{case_a}/reviews")
    assert rb_get.status_code == 404, rb_get.text

    rb_post = admin_b.post(f"/cases/{case_a}/reviews", json={
        "review_status": "approved",
        "notes": "Cross-tenant review must not be allowed.",
    })
    assert rb_post.status_code == 404, rb_post.text
