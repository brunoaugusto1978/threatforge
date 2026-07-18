from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.collection import service
from app.collection.contracts import ProviderIdentity
from app.models import CollectionConnection, CollectionEvent, CollectionSource
from tests._tg import make_session, make_tenant


def test_connection_starts_disabled_req1():
    db = make_session(); make_tenant(db, 1)
    conn = service.create_connection(db, tenant_id=1, provider="telegram", name="c1")
    db.commit()
    assert conn.enabled is False and conn.status == "pending"


def test_source_starts_disabled_c2():
    db = make_session(); make_tenant(db, 1)
    conn = service.create_connection(db, tenant_id=1, provider="telegram", name="c1")
    src = service.create_source(db, tenant_id=1, connection_id=conn.id, source_ref="s1")
    db.commit()
    assert src.enabled is False and src.status == "pending"


def test_unregistered_provider_rejected_c10():
    db = make_session(); make_tenant(db, 1)
    with pytest.raises(service.UnknownProvider):
        service.create_connection(db, tenant_id=1, provider="carrierpigeon", name="x")


def test_soft_delete_allows_name_reuse_req9():
    db = make_session(); make_tenant(db, 1)
    c1 = service.create_connection(db, tenant_id=1, provider="telegram", name="dup")
    db.commit()
    db.add(CollectionConnection(tenant_id=1, provider="telegram", name="dup"))
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    service.soft_delete_connection(db, tenant_id=1, connection_id=c1.id)
    db.commit()
    c2 = service.create_connection(db, tenant_id=1, provider="telegram", name="dup")
    db.commit()
    assert c2.id != c1.id


def test_bot_identity_exclusive_across_tenants_req7():
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    c1 = service.create_connection(db, tenant_id=1, provider="telegram", name="a")
    c2 = service.create_connection(db, tenant_id=2, provider="telegram", name="b")
    db.commit()
    ident = ProviderIdentity(provider="telegram", account_ref="9001")
    service.bind_bot_identity(db, tenant_id=1, connection_id=c1.id, identity=ident)
    db.commit()
    with pytest.raises(service.IdentityConflict):
        service.bind_bot_identity(db, tenant_id=2, connection_id=c2.id, identity=ident)


def test_identity_provider_must_match_connection_c10():
    db = make_session(); make_tenant(db, 1)
    c1 = service.create_connection(db, tenant_id=1, provider="telegram", name="a")
    db.commit()
    with pytest.raises(service.ProviderMismatch):
        service.bind_bot_identity(
            db, tenant_id=1, connection_id=c1.id,
            identity=ProviderIdentity(provider="discord", account_ref="1"))


def test_tenant_isolation_on_read():
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    service.create_connection(db, tenant_id=1, provider="telegram", name="only-t1")
    db.commit()
    rows_t2 = db.execute(
        select(CollectionConnection).where(CollectionConnection.tenant_id == 2)
    ).scalars().all()
    assert rows_t2 == []


def test_source_must_share_connection_tenant():
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    c1 = service.create_connection(db, tenant_id=1, provider="telegram", name="a")
    db.commit()
    db.add(CollectionSource(tenant_id=2, connection_id=c1.id, provider="telegram",
                            source_ref="x"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_physical_delete_of_connection_and_source_blocked_c2():
    """Mandatory test #2: physical deletes are RESTRICTed; events survive."""
    db = make_session(); make_tenant(db, 1)
    conn = service.create_connection(db, tenant_id=1, provider="telegram", name="c")
    src = service.create_source(db, tenant_id=1, connection_id=conn.id, source_ref="s")
    db.add(CollectionEvent(tenant_id=1, source_id=src.id, provider="telegram",
                           external_id_hash="h1", processing_state="normalized"))
    db.commit()
    # deleting the source with events must fail
    db.delete(src)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    # deleting the connection with sources must fail
    conn = db.get(CollectionConnection, conn.id)
    db.delete(conn)
    with pytest.raises(IntegrityError):
        db.flush()
    db.rollback()
    # events are intact
    assert db.execute(select(CollectionEvent)).scalars().all() != []


def test_collection_event_rejects_cross_tenant_source_fk():
    """DB-level tenant isolation: event tenant must match source tenant."""
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    c2 = service.create_connection(db, tenant_id=2, provider="telegram", name="c2")
    s2 = service.create_source(db, tenant_id=2, connection_id=c2.id, source_ref="s2")
    db.commit()
    db.add(CollectionEvent(tenant_id=1, source_id=s2.id, provider="telegram",
                           processing_state="normalized"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_source_test_request_rejects_cross_tenant_and_cross_connection():
    from app.models import CollectionSourceTestRequest
    db = make_session(); make_tenant(db, 1); make_tenant(db, 2)
    c1 = service.create_connection(db, tenant_id=1, provider="telegram", name="c1")
    c1b = service.create_connection(db, tenant_id=1, provider="telegram", name="c1b")
    c2 = service.create_connection(db, tenant_id=2, provider="telegram", name="c2")
    s1b = service.create_source(db, tenant_id=1, connection_id=c1b.id, source_ref="s1b")
    s2 = service.create_source(db, tenant_id=2, connection_id=c2.id, source_ref="s2")
    db.commit()
    with pytest.raises(service.NotFound):
        service.request_source_test(db, tenant_id=1, connection_id=c1.id, source_id=s2.id)
    with pytest.raises(service.TenantMismatch):
        service.request_source_test(db, tenant_id=1, connection_id=c1.id, source_id=s1b.id)
    db.add(CollectionSourceTestRequest(
        tenant_id=1, connection_id=c1.id, source_id=s2.id, provider="telegram",
        nonce_hash="f" * 64, status="awaiting"))
    with pytest.raises(IntegrityError):
        db.flush()


def test_soft_delete_sets_revoked_status():
    db = make_session(); make_tenant(db, 1)
    conn = service.create_connection(db, tenant_id=1, provider="telegram", name="c")
    src = service.create_source(db, tenant_id=1, connection_id=conn.id, source_ref="s")
    conn.enabled = True; conn.status = "active"
    src.enabled = True; src.status = "active"
    db.commit()
    service.soft_delete_source(db, tenant_id=1, source_id=src.id, actor="admin")
    service.soft_delete_connection(db, tenant_id=1, connection_id=conn.id, actor="admin")
    db.commit()
    assert src.enabled is False and src.status == "revoked" and src.deleted_at is not None
    assert conn.enabled is False and conn.status == "revoked" and conn.deleted_at is not None
