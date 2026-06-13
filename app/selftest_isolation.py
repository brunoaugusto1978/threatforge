"""End-to-end multi-tenant isolation selftest.

Uses its own temporary SQLite database, does not touch the production database, and uses TestClient
FastAPI to prove that Tenant A cannot access Tenant B data.

Run inside the container:
    docker compose -f docker-compose.yml -f docker-compose.podman.yml exec api python -m app.selftest_isolation
"""
import os
import tempfile

def _pw(label: str) -> str:
    """Generate deterministic synthetic test credentials.

    This avoids static password literals in the selftest while keeping
    repeatable values across create/login flows.
    """
    return f'{label}Aa12345!'

_DB = os.path.join(tempfile.gettempdir(), 'tf_isolation_test.db')
if os.path.exists(_DB):
    os.remove(_DB)
os.environ['DATABASE_URL'] = f'sqlite:///{_DB}'
os.environ['JWT_SECRET'] = _pw('JwtSecret')
os.environ['API_KEY'] = ''
os.environ['BOOTSTRAP_OPERATOR_EMAIL'] = ''
os.environ['BOOTSTRAP_OPERATOR_PASSWORD'] = str()
from fastapi.testclient import TestClient
from app.main import app

def _ok(msg):
    print(f'  ✓ {msg}')

def run():
    op = TestClient(app)
    r = op.post('/setup/operator', json={'email': 'op@plat.com', 'password': _pw('Operator')})
    if not r.status_code == 201:
        raise RuntimeError(r.text)
    _ok('platform operator created')
    ra = op.post('/tenants', json={'name': 'Tenant A', 'admin_email': 'admin@a.com', 'admin_password': _pw('TenantAdminA')})
    rb = op.post('/tenants', json={'name': 'Tenant B', 'admin_email': 'admin@b.com', 'admin_password': _pw('TenantAdminB')})
    if not (ra.status_code == 201 and rb.status_code == 201):
        raise RuntimeError((ra.text, rb.text))
    ta, tb = (ra.json()['id'], rb.json()['id'])
    _ok(f'tenants created (A={ta}, B={tb})')
    ca, cb = (TestClient(app), TestClient(app))
    if not ca.post('/auth/login', json={'email': 'admin@a.com', 'password': _pw('TenantAdminA')}).status_code == 200:
        raise RuntimeError('selftest check failed: ca.post("/auth/login", json={"email": "admin@a.com", "password": _pw("TenantAdminA")}).status_code == 200')
    if not cb.post('/auth/login', json={'email': 'admin@b.com', 'password': _pw('TenantAdminB')}).status_code == 200:
        raise RuntimeError('selftest check failed: cb.post("/auth/login", json={"email": "admin@b.com", "password": _pw("TenantAdminB")}).status_code == 200')
    _ok('admins from A and B authenticated')
    ba = ca.post('/brands', json={'name': 'BrandA', 'official_domains': ['a-corp.com.br']})
    bb = cb.post('/brands', json={'name': 'BrandB', 'official_domains': ['b-corp.com.br']})
    if not (ba.status_code == 201 and bb.status_code == 201):
        raise RuntimeError((ba.text, bb.text))
    ba_id = ba.json()['id']
    if not ca.post('/observables', json={'type': 'ip', 'value': '1.1.1.1'}).status_code == 201:
        raise RuntimeError('selftest check failed: ca.post("/observables", json={"type": "ip", "value": "1.1.1.1"}).status_code == 201')
    if not cb.post('/observables', json={'type': 'ip', 'value': '2.2.2.2'}).status_code == 201:
        raise RuntimeError('selftest check failed: cb.post("/observables", json={"type": "ip", "value": "2.2.2.2"}).status_code == 201')
    _ok('data created in each tenant')
    a_brands = [x['name'] for x in ca.get('/brands').json()]
    b_brands = [x['name'] for x in cb.get('/brands').json()]
    if not a_brands == ['BrandA']:
        raise RuntimeError(a_brands)
    if not b_brands == ['BrandB']:
        raise RuntimeError(b_brands)
    _ok('brand listing isolated (A only sees A; B only sees B)')
    a_obs = [x['value'] for x in ca.get('/observables').json()]
    b_obs = [x['value'] for x in cb.get('/observables').json()]
    if not (a_obs == ['1.1.1.1'] and b_obs == ['2.2.2.2']):
        raise RuntimeError((a_obs, b_obs))
    _ok('observable listing isolated')
    if not cb.get(f'/brands/{ba_id}').status_code == 404:
        raise RuntimeError('selftest check failed: cb.get(f"/brands/{ba_id}").status_code == 404')
    if not cb.delete(f'/brands/{ba_id}').status_code == 404:
        raise RuntimeError('selftest check failed: cb.delete(f"/brands/{ba_id}").status_code == 404')
    _ok('cross-tenant access by ID blocked (404 without leaking existence)')
    a_users = [u['email'] for u in ca.get('/users').json()]
    if not a_users == ['admin@a.com']:
        raise RuntimeError(a_users)
    _ok('users isolated by tenant')
    if not op.get('/brands').status_code == 400:
        raise RuntimeError('selftest check failed: op.get("/brands").status_code == 400')
    op_a = op.get('/brands', headers={'X-Tenant-Id': str(ta)}).json()
    if not [x['name'] for x in op_a] == ['BrandA']:
        raise RuntimeError('selftest check failed: [x["name"] for x in op_a] == ["BrandA"]')
    _ok('operator requires X-Tenant-Id and sees the selected tenant')
    k = op.post(f'/tenants/{ta}/api-keys', json={'label': 'ci', 'role': 'viewer'}).json()
    key_client = TestClient(app)
    via_key = key_client.get('/brands', headers={'X-API-Key': k['api_key']}).json()
    if not [x['name'] for x in via_key] == ['BrandA']:
        raise RuntimeError(via_key)
    _ok('tenant API key is bound to its own tenant')
    rc = op.post('/tenants', json={'name': 'Tenant C', 'admin_email': 'admin@c.com'})
    if not rc.status_code == 201:
        raise RuntimeError(rc.text)
    link = rc.json().get('invite_link')
    if not (link and 'token=' in link):
        raise RuntimeError(rc.json())
    token = link.split('token=', 1)[1]
    _ok('tenant created through invite without password; link generated')
    v = op.get(f'/invites/validate?token={token}').json()
    if not (v['valid'] and v['email'] == 'admin@c.com'):
        raise RuntimeError(v)
    if not TestClient(app).post('/auth/login', json={'email': 'admin@c.com', 'password': _pw('InactiveUser')}).status_code == 401:
        raise RuntimeError('selftest check failed: TestClient(app).post("/auth/login",\n                                json={"email": "admin@c.com", "password": _pw("InactiveUser")}).status_code == 401')
    _ok('valid invite; inactive user cannot log in before acceptance')
    cc = TestClient(app)
    ac = cc.post('/invites/accept', json={'token': token, 'password': _pw('Client')})
    if not ac.status_code == 200:
        raise RuntimeError(ac.text)
    if not ac.json()['tenant_id'] == rc.json()['id']:
        raise RuntimeError('selftest check failed: ac.json()["tenant_id"] == rc.json()["id"]')
    _ok('acceptance activates the user bound to the invite tenant')
    if not cc.post('/invites/accept', json={'token': token, 'password': _pw('Other')}).status_code == 400:
        raise RuntimeError('selftest check failed: cc.post("/invites/accept", json={"token": token, "password": _pw("Other")}).status_code == 400')
    if not op.get(f'/invites/validate?token={token}').json()['valid'] is False:
        raise RuntimeError('selftest check failed: op.get(f"/invites/validate?token={token}").json()["valid"] is False')
    _ok('single-use token invalidated after acceptance')
    cc2 = TestClient(app)
    if not cc2.post('/auth/login', json={'email': 'admin@c.com', 'password': _pw('Client')}).status_code == 200:
        raise RuntimeError('selftest check failed: cc2.post("/auth/login", json={"email": "admin@c.com", "password": _pw("Client")}).status_code == 200')
    if not cc2.get('/brands').json() == []:
        raise RuntimeError('selftest check failed: cc2.get("/brands").json() == []')
    _ok('invited client isolated in its own tenant')
    rso = op.post('/operators', json={'email': 'support@plat.com', 'password': _pw('Support'), 'operator_role': 'support_operator'})
    if not rso.status_code == 201:
        raise RuntimeError(rso.text)
    sop_id = rso.json()['id']
    _ok('platform admin creates support operator')
    sc = TestClient(app)
    if not sc.post('/auth/login', json={'email': 'support@plat.com', 'password': _pw('Support')}).status_code == 200:
        raise RuntimeError('selftest check failed: sc.post("/auth/login", json={"email": "support@plat.com", "password": _pw("Support")}).status_code == 200')
    if not sc.get('/tenants').json() == []:
        raise RuntimeError('selftest check failed: sc.get("/tenants").json() == []')
    if not sc.get('/brands', headers={'X-Tenant-Id': str(ta)}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.get("/brands", headers={"X-Tenant-Id": str(ta)}).status_code == 403')
    _ok('support without assignment cannot access any tenant (403)')
    if not op.post(f'/operators/{sop_id}/tenant-access', json={'tenant_id': ta, 'access_role': 'support_operator'}).status_code == 201:
        raise RuntimeError('selftest check failed: op.post(f"/operators/{sop_id}/tenant-access",\n                   json={"tenant_id": ta, "access_role": "support_operator"}).status_code == 201')
    if not [t['id'] for t in sc.get('/tenants').json()] == [ta]:
        raise RuntimeError('selftest check failed: [t["id"] for t in sc.get("/tenants").json()] == [ta]')
    if not sc.get('/brands', headers={'X-Tenant-Id': str(ta)}).status_code == 200:
        raise RuntimeError('selftest check failed: sc.get("/brands", headers={"X-Tenant-Id": str(ta)}).status_code == 200')
    if not sc.get('/brands', headers={'X-Tenant-Id': str(tb)}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.get("/brands", headers={"X-Tenant-Id": str(tb)}).status_code == 403')
    _ok('support accesses only the assigned tenant (A yes, B no)')
    if not sc.post('/tenants', json={'name': 'X', 'admin_email': 'x@x.com', 'admin_password': _pw('Denied')}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.post("/tenants", json={"name": "X", "admin_email": "x@x.com",\n                                     "admin_password": _pw("Denied")}).status_code == 403')
    if not sc.patch(f'/tenants/{ta}?status=suspended').status_code == 403:
        raise RuntimeError('selftest check failed: sc.patch(f"/tenants/{ta}?status=suspended").status_code == 403')
    if not sc.post('/operators', json={'email': 'n@n.com', 'operator_role': 'support_operator'}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.post("/operators", json={"email": "n@n.com", "operator_role": "support_operator"}).status_code == 403')
    if not sc.post(f'/tenants/{ta}/api-keys', json={'label': 'x', 'role': 'viewer'}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.post(f"/tenants/{ta}/api-keys", json={"label": "x", "role": "viewer"}).status_code == 403')
    if not sc.delete(f'/brands/{ba_id}', headers={'X-Tenant-Id': str(ta)}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.delete(f"/brands/{ba_id}", headers={"X-Tenant-Id": str(ta)}).status_code == 403')
    _ok('support is blocked from destructive and administrative actions')
    if not op.patch(f'/tenants/{tb}?status=suspended').status_code == 200:
        raise RuntimeError('selftest check failed: op.patch(f"/tenants/{tb}?status=suspended").status_code == 200')
    _ok('platform admin suspends/reactivates tenant')
    sc.get('/brands', headers={'X-Tenant-Id': str(ta)})
    audit_rows = op.get('/audit', headers={'X-Tenant-Id': str(ta)}).json()
    if not (any((a.get('action') == 'operator.grant_access' for a in audit_rows)) or any((a.get('operator_user_id') for a in audit_rows))):
        raise RuntimeError('selftest check failed: any(a.get("action") == "operator.grant_access" for a in audit_rows) or \\\n           any(a.get("operator_user_id") for a in audit_rows)')
    _ok('actions generate audit logs with operator/tenant context')
    if not op.delete(f'/operators/{sop_id}/tenant-access/{ta}').status_code == 204:
        raise RuntimeError('selftest check failed: op.delete(f"/operators/{sop_id}/tenant-access/{ta}").status_code == 204')
    if not sc.get('/brands', headers={'X-Tenant-Id': str(ta)}).status_code == 403:
        raise RuntimeError('selftest check failed: sc.get("/brands", headers={"X-Tenant-Id": str(ta)}).status_code == 403')
    _ok('access revocation blocks support immediately')
    print('\nTENANT ISOLATION + INVITES + OPERATOR ROLES: ALL TESTS PASSED ✅')
if __name__ == '__main__':
    try:
        run()
    finally:
        if os.path.exists(_DB):
            os.remove(_DB)
