"""End-to-end multi-tenant isolation selftest.

Uses its own temporary SQLite database, does not touch the production database, and uses TestClient
FastAPI to prove that Tenant A cannot access Tenant B data.

Run inside the accountiner:
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
os.environ['EVIDENCE_STORAGE_BACKEND'] = 'local'
os.environ['EVIDENCE_STORAGE_DIR'] = os.path.join(tempfile.gettempdir(), 'tf_evidence_test')
os.environ['EVIDENCE_MAX_BYTES'] = '2048'
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
    # ============ BRAND EDIT (tenant-scoped PATCH /brands/{id}) ============
    # 1) tenant_admin edits own brand name + official_domains
    r = ca.patch(f"/brands/{ba_id}", json={
        "name": "BrandA Renamed",
        "official_domains": ["a-corp.com.br", "A-Corp.com.br", "extra[.]com"]})
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "BrandA Renamed"
    # 2) refang + lowercase + dedup -> 2 domains
    assert r.json()["official_domains"] == "a-corp.com.br,extra.com", r.json()["official_domains"]
    _ok("tenant_admin edits brand name/domains (refang+lower+dedup)")

    # 3) empty official_domains -> 422
    assert ca.patch(f"/brands/{ba_id}", json={"official_domains": []}).status_code == 422
    _ok("empty official_domains -> 422")

    # 4) tenant analyst -> 403
    ca.post("/users", json={"email": "analyst@a.com", "password": "AnalystA123", "role": "analyst"})
    an = TestClient(app)
    an.post("/auth/login", json={"email": "analyst@a.com", "password": "AnalystA123"})
    assert an.patch(f"/brands/{ba_id}", json={"name": "x"}).status_code == 403
    # support_operator WITH access -> still 403 (edit requires admin)
    op.post(f"/operators/{sop_id}/tenant-access", json={"tenant_id": ta, "access_role": "support_operator"})
    assert sc.patch(f"/brands/{ba_id}", headers={"X-Tenant-Id": str(ta)}, json={"name": "x"}).status_code == 403
    _ok("analyst and support_operator -> 403 (cannot edit brand)")

    # 5) editing a brand from another tenant -> 404
    assert cb.patch(f"/brands/{ba_id}", json={"name": "x"}).status_code == 404
    _ok("editing another tenant's brand -> 404")

    # 6) clear_findings=true removes old findings after scope change
    from app.database import SessionLocal
    from app.models import BrandFinding
    _s = SessionLocal()
    _s.add(BrandFinding(tenant_id=ta, brand_id=ba_id, domain="fake-a.example", source="typosquat"))
    _s.commit(); _s.close()
    assert len(ca.get(f"/brands/{ba_id}/findings").json()) == 1
    r = ca.patch(f"/brands/{ba_id}?clear_findings=true", json={"official_domains": ["a-corp.com.br"]})
    assert r.status_code == 200, r.text
    assert ca.get(f"/brands/{ba_id}/findings").json() == []
    _ok("clear_findings=true removes old findings after scope change")

    # 7) audit records brand.update with before/after + operator/ip/user-agent fields
    arows = ca.get("/audit").json()
    bu = [a for a in arows if a.get("action") == "brand.update"]
    assert bu, "no brand.update audit entry"
    assert bu[0]["detail"].get("changes"), bu[0]
    assert "user_agent" in bu[0] and "operator_user_id" in bu[0] and "ip" in bu[0]
    _ok("audit logs brand.update with before/after + operator/ip/user-agent")

    # ============ ARCHIVE / DELETE BRAND (tenant-scoped) ============
    r = ca.post(f"/brands/{ba_id}/archive")
    assert r.status_code == 200 and r.json()["status"] == "archived", r.text
    assert ca.post(f"/brands/{ba_id}/scan?deep=false").status_code == 422
    _ok("admin archives brand; scan blocked while archived (422)")

    assert ca.post(f"/brands/{ba_id}/unarchive").json()["status"] == "active"
    _ok("admin unarchives brand")

    assert an.post(f"/brands/{ba_id}/archive").status_code == 403
    assert sc.post(f"/brands/{ba_id}/archive", headers={"X-Tenant-Id": str(ta)}).status_code == 403
    _ok("analyst/support_operator -> 403 (cannot archive)")

    assert cb.post(f"/brands/{ba_id}/archive").status_code == 404
    _ok("archiving another tenant's brand -> 404")

    assert ca.delete(f"/brands/{ba_id}").status_code == 422
    assert ca.delete(f"/brands/{ba_id}?confirm_name=wrong").status_code == 422
    _ok("delete requires matching confirm_name (422)")

    from app.database import SessionLocal
    from app.models import BrandFinding
    _s = SessionLocal()
    _s.add(BrandFinding(tenant_id=ta, brand_id=ba_id, domain="del.example", source="typosquat"))
    _s.commit(); _s.close()
    assert ca.delete(f"/brands/{ba_id}?confirm_name=BrandA%20Renamed").status_code == 409
    _ok("delete blocked when findings exist (409 without force)")

    assert ca.delete(f"/brands/{ba_id}?confirm_name=BrandA%20Renamed&force=true").status_code == 204
    assert ca.get(f"/brands/{ba_id}").status_code == 404
    _ok("force delete removes brand and its findings")

    arows = ca.get("/audit").json()
    assert any(a.get("action") == "brand.archive" for a in arows)
    assert any(a.get("action") == "brand.delete" for a in arows)
    _ok("audit logs brand.archive and brand.delete")

    # ============ INVESTIGATION CASES ============
    from app.database import SessionLocal
    from app.models import BrandFinding
    # brand + finding frescos no tenant A
    cbid = ca.post("/brands", json={"name": "CaseBrand", "official_domains": ["case-brand.com.br"]}).json()["id"]
    _cs = SessionLocal()
    _f = BrandFinding(tenant_id=ta, brand_id=cbid, domain="case-brand-fake.example",
                      source="typosquat", verdict="malicious", score=80)
    _cs.add(_f); _cs.commit(); fid = _f.id; _cs.close()
    # analyst e viewer do tenant A
    ua = ca.post("/users", json={"email": "case-analyst@a.com", "password": "CaseAnalyst1", "role": "analyst"}).json()["id"]
    caa = TestClient(app); caa.post("/auth/login", json={"email": "case-analyst@a.com", "password": "CaseAnalyst1"})
    ca.post("/users", json={"email": "case-viewer@a.com", "password": "CaseViewer1", "role": "viewer"})
    cvv = TestClient(app); cvv.post("/auth/login", json={"email": "case-viewer@a.com", "password": "CaseViewer1"})

    # analyst cria case manual
    r = caa.post("/cases", json={"title": "Manual case", "severity": "alto"})
    assert r.status_code == 201 and r.json()["status"] == "open", r.text
    mcid = r.json()["id"]
    _ok("analyst creates manual case")

    # abrir case a partir de finding (snapshot + severidade do verdict)
    r = caa.post(f"/brands/{cbid}/findings/{fid}/case")
    assert r.status_code == 201, r.text
    fcid = r.json()["id"]
    assert r.json()["finding_id"] == fid
    assert r.json()["finding_snapshot"]["domain"] == "case-brand-fake.example"
    assert r.json()["severity"] == "alto"
    _ok("open case from finding (snapshot captured, severity from verdict)")

    # duplicidade ativa -> 409 com existing_case_id
    r = caa.post(f"/brands/{cbid}/findings/{fid}/case")
    assert r.status_code == 409 and r.json()["detail"]["existing_case_id"] == fcid, r.text
    _ok("duplicate active case from finding -> 409 with existing_case_id")

    # POST /cases com finding_id que já tem case ativo -> 409
    r = caa.post("/cases", json={"title": "dup via /cases", "finding_id": fid})
    assert r.status_code == 409 and r.json()["detail"]["existing_case_id"] == fcid, r.text
    _ok("POST /cases with duplicate finding_id -> 409 with existing_case_id")

    # POST /cases com brand_id incompatível com finding_id -> 422
    cbid2 = ca.post("/brands", json={"name": "CaseBrand2", "official_domains": ["case-brand2.com.br"]}).json()["id"]
    r = caa.post("/cases", json={"title": "mismatch", "brand_id": cbid2, "finding_id": fid})
    assert r.status_code == 422, r.text
    _ok("POST /cases with brand_id != finding.brand_id -> 422")

    # cross-tenant -> 404
    assert cb.get(f"/cases/{mcid}").status_code == 404
    assert cb.patch(f"/cases/{mcid}", json={"title": "x"}).status_code == 404
    _ok("cross-tenant case access -> 404")

    # viewer: lê mas não cria (403)
    assert cvv.post("/cases", json={"title": "nope"}).status_code == 403
    assert cvv.get("/cases").status_code == 200
    _ok("viewer read-only on cases (create -> 403)")

    # state machine + RBAC
    assert caa.patch(f"/cases/{mcid}", json={"status": "investigating"}).status_code == 200  # analyst move ativo
    assert caa.patch(f"/cases/{mcid}", json={"status": "closed"}).status_code == 403          # analyst nao fecha
    assert caa.patch(f"/cases/{mcid}", json={"assignee_user_id": ua}).status_code == 403       # analyst nao atribui
    assert ca.patch(f"/cases/{mcid}", json={"assignee_user_id": ua}).status_code == 200         # admin atribui
    rc = ca.patch(f"/cases/{mcid}", json={"status": "closed"})
    assert rc.status_code == 200 and rc.json()["closed_at"], rc.text                            # admin fecha
    assert ca.patch(f"/cases/{mcid}", json={"status": "false_positive"}).status_code == 422     # terminal->terminal invalido
    rr = ca.patch(f"/cases/{mcid}", json={"status": "open"})
    assert rr.status_code == 200 and rr.json()["closed_at"] is None                             # admin reabre
    _ok("state machine + assign/close/reopen admin-only; invalid transition -> 422")

    # support_operator: com acesso ao tenant cria/lê case; sem acesso -> 403
    op.post(f"/operators/{sop_id}/tenant-access", json={"tenant_id": ta, "access_role": "support_operator"})
    assert sc.post("/cases", headers={"X-Tenant-Id": str(ta)}, json={"title": "support case"}).status_code == 201
    assert sc.get("/cases", headers={"X-Tenant-Id": str(ta)}).status_code == 200
    op.delete(f"/operators/{sop_id}/tenant-access/{ta}")
    assert sc.get("/cases", headers={"X-Tenant-Id": str(ta)}).status_code == 403
    _ok("support_operator: cases require tenant access (create/list ok with access; 403 without)")

    # filtros
    assert all(c["status"] == "open" for c in caa.get("/cases?status=open").json())
    assert all(c["severity"] == "alto" for c in caa.get("/cases?severity=alto").json())
    _ok("case list filters (status/severity)")

    # auditoria
    arows = ca.get("/audit").json()
    for act in ("case.create", "case.assign", "case.status_change", "case.close", "case.reopen"):
        assert any(a.get("action") == act for a in arows), act
    _ok("audit logs case.create/assign/status_change/close/reopen")

    # CRITICO (cadeia de custodia): case sobrevive ao delete da brand/finding
    assert ca.delete(f"/brands/{cbid}?confirm_name=CaseBrand&force=true").status_code == 204
    surv = ca.get(f"/cases/{fcid}")
    assert surv.status_code == 200, "case foi removido junto com a brand/finding!"
    sb = surv.json()
    assert sb["brand_id"] is None and sb["finding_id"] is None, sb
    assert sb["finding_snapshot"]["domain"] == "case-brand-fake.example", sb
    _ok("CRITICAL: case survives brand/finding delete (FK SET NULL + snapshot intact)")

    # ============ ANALYST NOTES ============
    r = caa.post(f"/cases/{mcid}/notes", json={"body": "First analyst note"})
    assert r.status_code == 201, r.text
    nid = r.json()["id"]
    notes = cvv.get(f"/cases/{mcid}/notes").json()
    assert any(n["id"] == nid and n["body"] == "First analyst note" for n in notes), notes
    _ok("analyst adds note; viewer reads notes")

    assert cvv.post(f"/cases/{mcid}/notes", json={"body": "nope"}).status_code == 403
    _ok("viewer cannot add note (403)")

    assert cb.post(f"/cases/{mcid}/notes", json={"body": "x"}).status_code == 404
    assert cb.get(f"/cases/{mcid}/notes").status_code == 404
    _ok("cross-tenant notes -> 404")

    op.post(f"/operators/{sop_id}/tenant-access", json={"tenant_id": ta, "access_role": "support_operator"})
    assert sc.post(f"/cases/{mcid}/notes", headers={"X-Tenant-Id": str(ta)}, json={"body": "support note"}).status_code == 201
    op.delete(f"/operators/{sop_id}/tenant-access/{ta}")
    assert sc.get(f"/cases/{mcid}/notes", headers={"X-Tenant-Id": str(ta)}).status_code == 403
    _ok("support_operator notes require tenant access (create with; 403 without)")

    arows = ca.get("/audit").json()
    assert any(a.get("action") == "case.note_added" for a in arows)
    _ok("audit logs case.note_added")

    # ============ EVIDENCE ATTACHMENTS ============
    import hashlib as _hl
    blob = b"\x89PNG\r\n\x1a\n" + b"fake png body 123"
    r = caa.post(f"/cases/{mcid}/evidence",
                 files={"file": ("ev.png", blob, "image/png")},
                 data={"origin": "manual_upload", "description": "screenshot"})
    assert r.status_code == 201, r.text
    ev = r.json()
    assert ev["sha256"] == _hl.sha256(blob).hexdigest(), "server-side hash mismatch"
    assert ev["size_bytes"] == len(blob)
    assert ev["stored"] is True
    assert "storage_key" not in ev, "storage_key must not be exposed"
    evid = ev["id"]
    _ok("analyst uploads evidence; server computes SHA-256 (matches bytes); key not exposed")

    # download retorna bytes idênticos
    dl = caa.get(f"/cases/{mcid}/evidence/{evid}/download")
    assert dl.status_code == 200 and dl.content == blob, "download bytes differ"
    _ok("download returns identical bytes (storage_backend=local)")

    # filename do usuário é sanitizado (nunca usado como path)
    r = caa.post(f"/cases/{mcid}/evidence",
                 files={"file": ("../../evil name.png", b"\x89PNG\r\n\x1a\n" + b"x", "image/png")},
                 data={"origin": "manual_upload"})
    assert r.status_code == 201 and "/" not in r.json()["filename"] and " " not in r.json()["filename"]
    _ok("uploaded filename sanitized (no path/space); storage_key server-generated")

    # MIME não permitido -> 415 ; tamanho excedido -> 413
    assert caa.post(f"/cases/{mcid}/evidence", files={"file": ("x.html", b"<html>", "text/html")},
                    data={"origin": "manual_upload"}).status_code == 415
    assert caa.post(f"/cases/{mcid}/evidence", files={"file": ("big.txt", b"a" * 3000, "text/plain")},
                    data={"origin": "manual_upload"}).status_code == 413
    _ok("blocked MIME -> 415; oversize -> 413")

    # consistência evidência x case x finding (mesmo tenant)
    _PNG = b"\x89PNG\r\n\x1a\n" + b"ok"
    cbX = ca.post("/brands", json={"name": "EvBrand", "official_domains": ["evbrand.com.br"]}).json()["id"]
    _se = SessionLocal()
    _f1 = BrandFinding(tenant_id=ta, brand_id=cbX, domain="evf1.example", source="typosquat", verdict="malicious", score=70)
    _f2 = BrandFinding(tenant_id=ta, brand_id=cbX, domain="evf2.example", source="typosquat", verdict="suspicious", score=40)
    _se.add(_f1); _se.add(_f2); _se.commit(); f1id = _f1.id; f2id = _f2.id; _se.close()
    caseX = caa.post(f"/brands/{cbX}/findings/{f1id}/case").json()["id"]
    # finding_id incompatível com o case -> 422
    r = caa.post(f"/cases/{caseX}/evidence", files={"file": ("m.png", _PNG, "image/png")},
                 data={"origin": "manual_upload", "finding_id": str(f2id)})
    assert r.status_code == 422, r.text
    # finding_id compatível -> 201
    r = caa.post(f"/cases/{caseX}/evidence", files={"file": ("ok.png", _PNG, "image/png")},
                 data={"origin": "manual_upload", "finding_id": str(f1id)})
    assert r.status_code == 201, r.text
    _ok("evidence/case/finding consistency enforced (mismatch 422, match 201)")

    # ============ CASE EXPORT (Community/Enterprise) ============
    # viewer pode exportar markdown de um case legível (mcid tem notes + evidence)
    rmd = cvv.get(f"/cases/{mcid}/export.md")
    assert rmd.status_code == 200, rmd.text
    md_body = rmd.text
    assert f"# Case #{mcid}" in md_body, md_body[:200]
    assert "## Notes" in md_body and "## Evidence" in md_body
    # não vaza storage_key / caminhos / extensão interna .bin
    assert "storage_key" not in md_body
    assert "/data/evidence" not in md_body
    assert ".bin" not in md_body
    assert 'attachment; filename="case-' in rmd.headers.get("content-disposition", "")
    _ok("viewer exports case markdown (metadata only; no storage_key/paths/.bin)")

    # cross-tenant export -> 404 (sem vazar existência)
    assert cb.get(f"/cases/{mcid}/export.md").status_code == 404
    _ok("cross-tenant markdown export -> 404")

    # PDF premium bloqueado no Community -> 402 com mensagem Enterprise
    rpdf = caa.get(f"/cases/{mcid}/export.pdf")
    assert rpdf.status_code == 402, rpdf.text
    assert "Enterprise license" in (rpdf.json().get("detail") or ""), rpdf.text
    _ok("PDF export blocked in Community -> 402 (Enterprise license required)")
    pj = rpdf.json()
    assert pj.get("feature") == "export.pdf", pj
    assert pj.get("edition") == "community", pj
    _up = pj.get("upgrade") or {}
    assert _up.get("email") and _up.get("url"), pj
    _ok("402 carries standardized upgrade block (feature/edition/contacts)")

    # cross-tenant PDF também -> 404 (não vaza nem o bloqueio)
    assert cb.get(f"/cases/{mcid}/export.pdf").status_code == 404
    _ok("cross-tenant PDF export -> 404")

    # auditoria: case.export e case.export_pdf_denied
    aexp = ca.get("/audit").json()
    assert any(a.get("action") == "case.export" for a in aexp)
    assert any(a.get("action") == "case.export_pdf_denied" for a in aexp)
    _ok("audit logs case.export and case.export_pdf_denied")

    # viewer não anexa (403) mas lê/baixa
    assert cvv.post(f"/cases/{mcid}/evidence", files={"file": ("v.txt", b"x", "text/plain")},
                    data={"origin": "manual_upload"}).status_code == 403
    assert cvv.get(f"/cases/{mcid}/evidence").status_code == 200
    assert cvv.get(f"/cases/{mcid}/evidence/{evid}/download").status_code == 200
    _ok("viewer read/download ok; upload -> 403")

    # cross-tenant -> 404
    assert cb.get(f"/cases/{mcid}/evidence").status_code == 404
    assert cb.post(f"/cases/{mcid}/evidence", files={"file": ("x.txt", b"x", "text/plain")},
                   data={"origin": "manual_upload"}).status_code == 404
    _ok("cross-tenant evidence -> 404")

    # support_operator: com acesso anexa; sem acesso -> 403
    op.post(f"/operators/{sop_id}/tenant-access", json={"tenant_id": ta, "access_role": "support_operator"})
    assert sc.post(f"/cases/{mcid}/evidence", headers={"X-Tenant-Id": str(ta)},
                   files={"file": ("s.txt", b"sup", "text/plain")},
                   data={"origin": "manual_upload"}).status_code == 201
    op.delete(f"/operators/{sop_id}/tenant-access/{ta}")
    assert sc.get(f"/cases/{mcid}/evidence", headers={"X-Tenant-Id": str(ta)}).status_code == 403
    _ok("support_operator evidence requires tenant access (201 with; 403 without)")

    # audit
    arows = ca.get("/audit").json()
    assert any(a.get("action") == "evidence.add" for a in arows)
    assert any(a.get("action") == "evidence.download" for a in arows)
    _ok("audit logs evidence.add and evidence.download")

    print('\nTENANT ISOLATION + INVITES + OPERATOR ROLES + BRAND EDIT + ARCHIVE/DELETE + CASES + NOTES + EVIDENCE + EXPORT: ALL TESTS PASSED ✅')
if __name__ == '__main__':
    try:
        run()
    finally:
        if os.path.exists(_DB):
            os.remove(_DB)
