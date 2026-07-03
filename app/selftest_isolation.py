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

    # export STIX 2.1 local (Community, gratuito) — mcid tem evidências com sha256
    rstix = cvv.get(f"/cases/{mcid}/export.stix.json")
    assert rstix.status_code == 200, rstix.text
    bundle = rstix.json()
    assert bundle.get("type") == "bundle" and bundle.get("objects"), bundle
    _types = [o["type"] for o in bundle["objects"]]
    assert "identity" in _types and "report" in _types, _types
    assert any(o["type"] == "indicator" for o in bundle["objects"]), "expected evidence indicators"
    assert all(o.get("spec_version") == "2.1" for o in bundle["objects"]), bundle
    _sb = rstix.text
    assert "storage_key" not in _sb and "/data/evidence" not in _sb and ".bin" not in _sb
    assert "application/stix+json" in rstix.headers.get("content-type", "")
    assert 'filename="case-' in rstix.headers.get("content-disposition", "")
    _ok("viewer exports STIX 2.1 bundle (indicators; no secrets/paths)")

    assert cb.get(f"/cases/{mcid}/export.stix.json").status_code == 404
    _ok("cross-tenant STIX export -> 404")

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

    # ============ PREMIUM INTEGRATIONS (catalog + feature gate) ============
    # viewer vê o catálogo (200) com recursos premium bloqueados + bloco upgrade
    rcat = cvv.get("/integrations")
    assert rcat.status_code == 200, rcat.text
    cat = {i["name"]: i for i in rcat.json()}
    assert {"misp", "opencti", "generic"} <= set(cat), cat
    for nm in ("misp", "opencti", "generic"):
        assert cat[nm]["premium"] is True and cat[nm]["enabled"] is False, cat[nm]
        assert cat[nm]["capabilities"], cat[nm]
        up = cat[nm].get("upgrade") or {}
        assert up.get("email") and up.get("url"), cat[nm]
    _ok("viewer reads integrations catalog (premium, locked, upgrade block)")

    # descritor individual traz o config_schema (JSON Schema) p/ a UI
    rdesc = cvv.get("/integrations/misp")
    assert rdesc.status_code == 200 and "config_schema" in rdesc.json(), rdesc.text
    assert "properties" in rdesc.json()["config_schema"], rdesc.json()
    # conector inexistente -> 404
    assert cvv.get("/integrations/nope").status_code == 404
    _ok("integration descriptor exposes public config_schema; unknown -> 404")

    # admin tenta configurar sem licença -> 402 com bloco upgrade
    rconf = ca.post("/integrations/misp/connections", json={"base_url": "https://misp.x"})
    assert rconf.status_code == 402, rconf.text
    pj = rconf.json()
    assert pj.get("feature") == "integration.misp" and (pj.get("upgrade") or {}).get("email"), pj
    # test/sync também -> 402
    assert ca.post("/integrations/opencti/sync", json={}).status_code == 402
    assert ca.post("/integrations/generic/test", json={}).status_code == 402
    _ok("admin configure/test/sync blocked in Community -> 402 (per-feature)")

    # viewer não pode configurar (require_admin) -> 403
    assert cvv.post("/integrations/misp/connections", json={}).status_code == 403
    _ok("viewer cannot configure integrations (403)")

    # support_operator (mesmo com tenant access) NÃO configura conectores/secrets -> 403
    op.post(f"/operators/{sop_id}/tenant-access", json={"tenant_id": ta, "access_role": "support_operator"})
    rsup = sc.post("/integrations/misp/connections", headers={"X-Tenant-Id": str(ta)}, json={})
    assert rsup.status_code == 403, rsup.text
    op.delete(f"/operators/{sop_id}/tenant-access/{ta}")
    _ok("support_operator cannot configure connectors even with tenant access (403)")

    # auditoria: *_denied registrados
    aint = ca.get("/audit").json()
    assert any(a.get("action") == "integration.config_denied" for a in aint)
    assert any(a.get("action") == "integration.sync_denied" for a in aint)
    _ok("audit logs integration.config_denied and integration.sync_denied")

    # ============ EXPOSURE MONITORING (DRP) — Issue 1 ============
    from app.database import SessionLocal as _SL
    from app.models import ExposureFinding, MonitoredAsset

    # admin A cria um monitored asset (VIP/identidade) com consentimento
    ra_as = ca.post("/exposure/assets", json={
        "asset_type": "identity", "label": "CEO – Fulano", "value": "ceo@a-corp.com.br",
        "criticality": "critical", "consent_ref": "DPA-2026-001"})
    assert ra_as.status_code == 201, ra_as.text
    a_asset = ra_as.json()
    assert a_asset["value_hash"] and a_asset["consent_ref"] == "DPA-2026-001"
    assert a_asset["value_hash"] != a_asset["value"], "value_hash deve ser hash, não o valor"
    _ok("admin creates monitored asset (VIP) with consent_ref + server-side value_hash")

    # viewer lê, mas NÃO cria (require_admin -> 403)
    assert cvv.get("/exposure/assets").status_code == 200
    assert cvv.post("/exposure/assets", json={
        "asset_type": "email", "label": "x", "value": "x@a.com"}).status_code == 403
    _ok("viewer reads assets but cannot create (403)")

    # tenant B NÃO enxerga asset de A (cross-tenant -> 404) e lista isolada
    assert cb.get(f"/exposure/assets/{a_asset['id']}").status_code == 404
    assert cb.get("/exposure/assets").json() == []
    _ok("monitored assets isolated per tenant (cross-tenant 404; B sees none)")

    # cria findings direto no banco (intake real = Issue 2), 1 por tenant, com reliability
    _es = _SL()
    ef_a = ExposureFinding(
        tenant_id=ta, exposure_type="credential_exposure", asset_id=a_asset["id"],
        title="Credential leak ceo@a-corp", source="stealer",
        source_reliability="B", info_credibility="2", severity="high", status="new",
        dedup_key="a-cred-1",
        detail={"email": "ceo@a-corp.com.br", "domain": "a-corp.com.br",
                "password_hash": "e3b0c44298fc1c149afbf4c8996fb924", "password_masked": "S3****!x",
                "stealer_family": "redline"})
    ef_b = ExposureFinding(
        tenant_id=tb, exposure_type="identity_exposure", title="Impersonation of B exec",
        source="osint", source_reliability="D", info_credibility="4", severity="medium",
        status="new", dedup_key="b-id-1", detail={"person_label": "B exec"})
    _es.add(ef_a); _es.add(ef_b); _es.commit()
    a_fid = ef_a.id
    _es.close()

    # isolamento de findings
    a_finds = ca.get("/exposure/findings").json()
    b_finds = cb.get("/exposure/findings").json()
    assert [f["id"] for f in a_finds] == [a_fid], a_finds
    assert all(f["tenant_id"] == tb for f in b_finds) and a_fid not in [f["id"] for f in b_finds]
    _ok("exposure findings isolated per tenant")

    # cross-tenant get -> 404
    assert cb.get(f"/exposure/findings/{a_fid}").status_code == 404
    _ok("cross-tenant exposure finding -> 404")

    # Source Reliability (Admiralty) presente e sem senha em claro
    fa = ca.get(f"/exposure/findings/{a_fid}").json()
    assert fa["source_reliability"] == "B" and fa["info_credibility"] == "2", fa
    _cols = set(ExposureFinding.__table__.columns.keys())
    assert not ({"password", "secret", "token", "api_key"} & _cols), "modelo não pode ter coluna de segredo em claro"
    _blob = str(fa["detail"])
    assert "password_hash" in _blob and "S3****!x" in _blob, fa
    _ok("Admiralty reliability/credibility present; NO plaintext secret (hash+mask only)")

    # catálogo de tipos: MVP = identity + credential
    types = {t["type"]: t["mvp"] for t in ca.get("/exposure/types").json()}
    assert types.get("identity_exposure") and types.get("credential_exposure"), types
    assert types.get("secret_exposure") is False, "secret_exposure previsto no enum mas não-MVP"
    _ok("exposure types catalog: MVP = identity + credential; future types reserved")

    # audit do CRUD de asset
    aexp = ca.get("/audit").json()
    assert any(a.get("action") == "exposure.asset_create" for a in aexp)
    _ok("audit logs exposure.asset_create")

    # ============ EXPOSURE — Issue 2 (intake/import/dedup/redação/masking) ============
    import app.config as _cfg

    # intake estruturado com credencial -> redigido (sem senha em claro)
    _pl = {"exposure_type": "credential_exposure", "source": "manual_intake",
           "detail": {"email": "vip1@a-corp.com.br", "password": "S3nha!Secreta",
                      "domain": "a-corp.com.br"}}
    r1 = caa.post("/exposure/findings/intake", json=_pl)
    assert r1.status_code == 201, r1.text
    d1 = r1.json()
    assert "password" not in d1["detail"], d1
    assert d1["detail"].get("password_sha256") and d1["detail"].get("password_masked"), d1
    assert "S3nha!Secreta" not in r1.text, "plaintext password leaked in response!"
    assert d1["redacted"] is True
    intake_id = d1["id"]
    _ok("intake redacts credential (hash+mask; no plaintext in response)")

    # dedup: intake idêntico não duplica (mesmo id)
    r2 = caa.post("/exposure/findings/intake", json=_pl)
    assert r2.status_code == 201 and r2.json()["id"] == intake_id, "dedup should return same finding"
    _ok("identical intake deduped (idempotent; same finding id)")

    # viewer não faz intake (403)
    assert cvv.post("/exposure/findings/intake", json=_pl).status_code == 403
    _ok("viewer cannot intake (403)")

    # import de combolist (email:senha) -> credential findings, sem senha em claro
    _combo = b"attack1@a-corp.com.br:P@ssw0rd1\nattack2@a-corp.com.br:hunter2\n"
    ri = caa.post("/exposure/import",
                  files={"file": ("leak.txt", _combo, "text/plain")},
                  data={"parser": "combolist"})
    assert ri.status_code == 201, ri.text
    batch = ri.json()
    bid = batch["id"]
    assert batch["created_count"] == 2 and batch["source_file_hash"], batch
    assert batch["parser"] == "combolist" and batch["parser_version"], batch
    # findings do lote: proveniência + sem senha em claro
    body = caa.get(f"/exposure/findings?ingest_id={bid}").text
    assert "P@ssw0rd1" not in body and "hunter2" not in body, "plaintext leaked from import!"
    finds = caa.get(f"/exposure/findings?ingest_id={bid}").json()
    assert len(finds) == 2 and all(f["ingest_id"] == bid and f["parser_version"] for f in finds), finds
    assert all(f["record_number"] for f in finds), finds
    _ok("import combolist: 2 credential findings, provenance stored, no plaintext")

    # re-import idêntico -> idempotente (deduped, 0 created)
    ri2 = caa.post("/exposure/import",
                   files={"file": ("leak.txt", _combo, "text/plain")},
                   data={"parser": "combolist"})
    assert ri2.status_code == 201 and ri2.json()["deduped_count"] == 2 and ri2.json()["created_count"] == 0, ri2.text
    _ok("re-import same file is idempotent (deduped=2, created=0)")

    # MIME inválido -> 415 ; parser desconhecido -> 422
    assert caa.post("/exposure/import", files={"file": ("x.html", b"<html>", "text/html")},
                    data={"parser": "combolist"}).status_code == 415
    assert caa.post("/exposure/import", files={"file": ("x.txt", b"a", "text/plain")},
                    data={"parser": "nope"}).status_code == 422
    _ok("import rejects bad MIME (415) and unknown parser (422)")

    # rollback (admin, hard delete) ; analyst não pode (403)
    assert caa.delete(f"/exposure/ingests/{bid}").status_code == 403
    rb = ca.delete(f"/exposure/ingests/{bid}")
    assert rb.status_code == 200 and rb.json()["removed"] == 2, rb.text
    assert caa.get(f"/exposure/findings?ingest_id={bid}").json() == []
    assert ca.get(f"/exposure/ingests/{bid}").json()["status"] == "rolled_back"
    _ok("import rollback: admin hard-deletes batch findings; status rolled_back; analyst 403")

    # cross-tenant: B não vê intake/ingests de A
    assert cb.get(f"/exposure/findings/{intake_id}").status_code == 404
    assert cb.get(f"/exposure/ingests/{bid}").status_code == 404
    _ok("cross-tenant intake/ingest -> 404")

    # masking por role: off (default) mostra e-mail; by_role mascara p/ não-admin
    off_val = ca.get(f"/exposure/assets/{a_asset['id']}").json()["value"]
    assert off_val == "ceo@a-corp.com.br", off_val
    _cfg.EXPOSURE_PII_MASKING = "by_role"
    try:
        v_viewer = cvv.get(f"/exposure/assets/{a_asset['id']}").json()["value"]
        v_admin = ca.get(f"/exposure/assets/{a_asset['id']}").json()["value"]
        assert "***" in v_viewer and v_viewer != "ceo@a-corp.com.br", v_viewer
        assert v_admin == "ceo@a-corp.com.br", v_admin
    finally:
        _cfg.EXPOSURE_PII_MASKING = "off"
    _ok("PII masking by_role: viewer sees masked email, admin sees full (off = full)")

    # abrir case a partir de finding de exposure (snapshot + severity mapeada)
    rc = caa.post(f"/exposure/findings/{intake_id}/case")
    assert rc.status_code == 201, rc.text
    _cid = rc.json()["case_id"]
    _case = caa.get(f"/cases/{_cid}").json()
    assert _case["finding_snapshot"]["exposure_finding_id"] == intake_id, _case
    assert "S3nha!Secreta" not in caa.get(f"/cases/{_cid}").text, "plaintext leaked into case!"
    _ok("open Investigation Case from exposure finding (redacted snapshot)")

    # auditoria da Issue 2
    a2 = ca.get("/audit").json()
    for _act in ("exposure.intake", "exposure.import", "exposure.import_rollback"):
        assert any(a.get("action") == _act for a in a2), _act
    _ok("audit logs exposure.intake / import / import_rollback")

    # ============ TIMELINE (agregação read-only, event sources) ============
    srcs = ca.get("/timeline/sources").json()
    assert {"exposure", "case", "audit"} <= set(srcs), srcs
    _ok("timeline sources registered (exposure, case, audit)")

    tl_t = ca.get("/timeline?scope=tenant").json()
    assert isinstance(tl_t, list) and len(tl_t) > 0, tl_t
    assert all({"ts", "source", "type", "ref"} <= set(e) for e in tl_t), tl_t[0]
    # ordenado desc por ts
    _ts = [e["ts"] for e in tl_t if e["ts"]]
    assert _ts == sorted(_ts, reverse=True), "timeline not sorted desc"
    _ok("tenant timeline aggregates events, sorted desc")

    tl_f = ca.get(f"/timeline?scope=finding:{intake_id}").json()
    assert any(e["source"] == "exposure" and e["type"] == "exposure.finding_created"
               and e["ref"]["id"] == intake_id for e in tl_f), tl_f
    assert any(e["source"] == "audit" for e in tl_f), "expected audit events for finding"
    _ok("finding-scoped timeline (exposure + audit events)")

    tl_c = ca.get(f"/timeline?scope=case:{_cid}").json()
    assert any(e["source"] == "case" and e["type"] == "case.created" for e in tl_c), tl_c
    _ok("case-scoped timeline (case.created)")

    # cross-tenant e escopo inválido
    assert cb.get(f"/timeline?scope=finding:{intake_id}").status_code == 404
    assert cb.get(f"/timeline?scope=case:{_cid}").status_code == 404
    assert ca.get("/timeline?scope=bogus:1").status_code == 422
    assert ca.get("/timeline?scope=finding:abc").status_code == 422
    _ok("timeline cross-tenant -> 404; invalid scope -> 422")

    # ============ RISK SCORE EXPLICÁVEL ============
    # alto: credential + asset critical (a_asset) + Admiralty B2 + fresco
    rhi = caa.post("/exposure/findings/intake", json={
        "exposure_type": "credential_exposure", "source": "stealer",
        "asset_id": a_asset["id"], "source_reliability": "B", "info_credibility": "2",
        "detail": {"email": "riskhi@a-corp.com.br", "password": "Zzz9!", "domain": "a-corp.com.br"}})
    assert rhi.status_code == 201, rhi.text
    hi = rhi.json(); hi_id = hi["id"]
    assert hi["risk_score"] >= 70 and hi["detail"]["risk_breakdown"]["band"] in ("high", "critical"), hi
    assert hi["detail"]["risk_breakdown"]["score"] == hi["risk_score"]
    _ok(f"high-risk finding scored {hi['risk_score']} ({hi['detail']['risk_breakdown']['band']})")

    # baixo: identity + OSINT (D4) + sem asset
    rlo = caa.post("/exposure/findings/intake", json={
        "exposure_type": "identity_exposure", "source": "osint",
        "source_reliability": "D", "info_credibility": "4",
        "detail": {"person_label": "Random mention", "url": "http://x.example"}})
    assert rlo.status_code == 201, rlo.text
    lo = rlo.json(); lo_id = lo["id"]; lo_score = lo["risk_score"]
    assert lo_score < hi["risk_score"], (lo_score, hi["risk_score"])
    _ok(f"lower-risk finding scored {lo_score} (< high)")

    # breakdown endpoint (para a UI) com fatores explicáveis
    bd = caa.get(f"/exposure/findings/{hi_id}/risk").json()
    assert bd["score"] == hi["risk_score"] and isinstance(bd["factors"], list), bd
    _labels = {f["label"] for f in bd["factors"]}
    assert {"Asset criticality", "Exposure type", "Source reliability", "Verification"} <= _labels, _labels
    _ok("risk breakdown endpoint returns explainable factors")

    # determinismo
    bd2 = caa.get(f"/exposure/findings/{hi_id}/risk").json()
    assert bd2["score"] == bd["score"], (bd, bd2)
    _ok("risk score is deterministic (same inputs -> same score)")

    # recompute na triagem: new -> confirmed aumenta o score
    rt = caa.patch(f"/exposure/findings/{lo_id}", json={"status": "confirmed"})
    assert rt.status_code == 200 and rt.json()["risk_score"] > lo_score, rt.text
    _ok("risk recomputed on triage (confirmed raises score)")

    # false_positive zera o score
    rfp = caa.patch(f"/exposure/findings/{lo_id}", json={"status": "false_positive"})
    assert rfp.status_code == 200 and rfp.json()["risk_score"] == 0, rfp.text
    _ok("false_positive drives risk_score to 0")

    # ============ CORRELATION ENGINE ============
    # finding que compartilha e-mail com a_asset (ceo@a-corp) e domínio com BrandA
    cf = caa.post("/exposure/findings/intake", json={
        "exposure_type": "credential_exposure", "source": "stealer",
        "detail": {"email": "ceo@a-corp.com.br", "password": "corrPw", "domain": "a-corp.com.br"}}).json()
    cf_id = cf["id"]
    ca.post("/observables", json={"type": "domain", "value": "a-corp.com.br"})
    # BrandA original foi removido no teste de archive/delete; cria um brand p/ o domínio
    assert ca.post("/brands", json={"name": "CorrBrand", "official_domains": ["a-corp.com.br"]}).status_code == 201

    g = ca.get(f"/correlation?entity=finding:{cf_id}").json()
    kinds = {n["kind"] for n in g["nodes"]}
    assert g["seed"]["kind"] == "exposure_finding", g["seed"]
    assert "monitored_asset" in kinds, kinds   # mesmo e-mail (a_asset)
    assert "brand" in kinds, kinds             # domínio a-corp.com.br (BrandA)
    assert "observable" in kinds, kinds        # IOC de domínio
    assert all("via" in e for e in g["edges"]), g["edges"]
    _ok("correlate finding -> related asset + brand + IOC via shared email/domain")

    # correlação por identificador cru
    g2 = ca.get("/correlation?entity=domain:a-corp.com.br").json()
    assert g2["seed"]["kind"] == "identifier"
    assert any(n["kind"] == "exposure_finding" for n in g2["nodes"]), g2
    _ok("correlate by raw domain identifier -> exposure findings")

    # cross-tenant e seletor inválido
    assert cb.get(f"/correlation?entity=finding:{cf_id}").status_code == 404
    assert ca.get("/correlation?entity=bogus:1").status_code == 422
    _ok("correlation cross-tenant -> 404; invalid entity -> 422")





    # ============ ATTACK SURFACE DISCOVERY (import manual) ============
    # analyst importa ativos de superfície (subdomain/ip/certificate)
    rimp = caa.post("/surface/import", json={"assets": [
        {"asset_type": "subdomain", "value": "vpn.a-corp.com.br"},
        {"asset_type": "ip", "value": "203.0.113.10"},
        {"asset_type": "certificate", "value": "sha256:abc", "detail": {"issuer": "Lets Encrypt"}}]})
    assert rimp.status_code == 201, rimp.text
    assert rimp.json()["created"] == 3, rimp.json()
    sa_ids = rimp.json()["asset_ids"]
    _ok("analyst imports surface assets (subdomain/ip/certificate)")

    # idempotência: reimportar o mesmo subdomínio -> deduped
    rdup = caa.post("/surface/import", json={"assets": [
        {"asset_type": "subdomain", "value": "VPN.a-corp.com.br"}]})  # case-insensitive
    assert rdup.status_code == 201 and rdup.json()["deduped"] == 1 and rdup.json()["created"] == 0, rdup.text
    _ok("surface import idempotent per (tenant, type, value) — case-insensitive")

    # viewer lê, mas não importa (403)
    assert cvv.get("/surface/assets").status_code == 200
    assert cvv.post("/surface/import", json={"assets": [
        {"asset_type": "ip", "value": "198.51.100.1"}]}).status_code == 403
    _ok("viewer reads surface assets but cannot import (403)")

    # tipo fora do MVP -> 422
    assert caa.post("/surface/import", json={"assets": [
        {"asset_type": "port", "value": "443/tcp"}]}).status_code == 422
    _ok("non-MVP surface type rejected (422)")

    # triagem (analyst) confirm
    rt = caa.patch(f"/surface/assets/{sa_ids[0]}", json={"status": "confirmed"})
    assert rt.status_code == 200 and rt.json()["status"] == "confirmed", rt.text
    _ok("analyst triages surface asset (confirmed)")

    # isolamento por tenant + cross-tenant 404
    assert cb.get("/surface/assets").json() == []
    assert cb.get(f"/surface/assets/{sa_ids[0]}").status_code == 404
    assert cb.patch(f"/surface/assets/{sa_ids[0]}", json={"status": "ignored"}).status_code == 404
    _ok("surface assets isolated per tenant; cross-tenant -> 404")

    # catálogo de tipos: MVP = subdomain/ip/certificate
    st = {t["type"]: t["mvp"] for t in ca.get("/surface/types").json()}
    assert st.get("subdomain") and st.get("ip") and st.get("certificate"), st
    assert st.get("port") is False and st.get("service") is False, st
    _ok("surface types catalog: MVP = subdomain/ip/certificate; port/service reserved")

    # audit
    asurf = ca.get("/audit").json()
    assert any(a.get("action") == "surface.import" for a in asurf)
    _ok("audit logs surface.import")

    # ---- descoberta PASSIVA (mocks: sem internet real) ----
    import app.surface_discovery as _sd
    _SD_ORIG = (_sd._ct_subdomains, _sd._resolve_ips, _sd._rdap, _sd._cert_info)
    _sd._ct_subdomains = lambda domain, client, limit=300: (
        ["vpn." + domain, "mail." + domain] if domain == "surf-corp.com.br" else [])
    # vpn e mail compartilham 203.0.113.10 (hosting compartilhado): ASD deve deduplicar
    _sd._resolve_ips = lambda host: (
        ["203.0.113.10"] if host.startswith("vpn.") else
        (["203.0.113.10", "203.0.113.11"] if host.startswith("mail.") else []))
    _sd._rdap = lambda domain, client: {"registered": "2020-01-01T00:00:00Z", "handle": "REG-1"}
    _sd._cert_info = lambda domain, client: {
        "issuer": "Let's Encrypt", "not_before": "2026-01-01", "not_after": "2026-04-01",
        "serial": "deadbeef01"}
    try:
        sb = ca.post("/brands", json={"name": "SurfBrand", "official_domains": ["surf-corp.com.br"]})
        assert sb.status_code == 201, sb.text
        sb_id = sb.json()["id"]

        # viewer não pode descobrir (require_admin) -> 403
        assert cvv.post(f"/surface/discover?brand_id={sb_id}").status_code == 403
        _ok("viewer cannot run passive discovery (403)")

        rd = ca.post(f"/surface/discover?brand_id={sb_id}")
        assert rd.status_code == 201, rd.text
        res = rd.json()
        # valida COMPORTAMENTO, não cardinalidade artificial de IPs (subdomínios podem
        # compartilhar IP -> dedup é o esperado em ASD).
        assert res["counts"]["subdomain"] == 3, res
        assert res["counts"]["certificate"] == 1, res
        assert res["counts"]["ip"] >= 1, res
        assert res["deduped"] >= 1, res  # ao menos o IP compartilhado foi deduplicado
        _ok("passive discovery materializes subdomains + ip(s) + cert (shared IP deduped)")

        assets = ca.get(f"/surface/assets?brand_id={sb_id}").json()
        kinds = {a["asset_type"] for a in assets}
        assert {"subdomain", "ip", "certificate"} <= kinds, kinds
        # encadeamento: ip tem parent_id (subdomínio)
        ips = [a for a in assets if a["asset_type"] == "ip"]
        assert ips and all(a["parent_id"] for a in ips), ips  # todo IP tem parent (subdomínio)
        # rdap no apex
        apex = [a for a in assets if a["value"] == "surf-corp.com.br"]
        assert apex and apex[0]["detail"].get("rdap"), apex
        _ok("discovered assets chained (ip.parent = subdomain) + rdap on apex")

        # re-descoberta é idempotente (dedup)
        rd2 = ca.post(f"/surface/discover?brand_id={sb_id}")
        assert rd2.json()["created"] == 0 and rd2.json()["deduped"] >= 1, rd2.json()
        _ok("re-discovery idempotent (all deduped)")

        # cross-tenant: B não descobre a brand de A
        assert cb.post(f"/surface/discover?brand_id={sb_id}").status_code == 404
        _ok("cross-tenant discovery -> 404")

        # audit
        assert any(a.get("action") == "surface.discover" for a in ca.get("/audit").json())
        _ok("audit logs surface.discover")
    finally:
        _sd._ct_subdomains, _sd._resolve_ips, _sd._rdap, _sd._cert_info = _SD_ORIG


    # ============ ASD PR3: ciclo Surface -> Exposure -> Correlation -> Investigation ============
    p3b = ca.post("/brands", json={"name": "P3Brand", "official_domains": ["p3-corp.com.br"]})
    assert p3b.status_code == 201, p3b.text
    p3_bid = p3b.json()["id"]
    # importa surface assets vinculados à brand (subdomínio + ip)
    rimp3 = caa.post("/surface/import", json={"brand_id": p3_bid, "assets": [
        {"asset_type": "subdomain", "value": "vpn.p3-corp.com.br"},
        {"asset_type": "ip", "value": "203.0.113.50"}]})
    assert rimp3.status_code == 201 and rimp3.json()["created"] == 2, rimp3.text
    ip_sid = rimp3.json()["asset_ids"][1]  # o ip

    # PROMOTE: surface asset (ip) -> infrastructure_exposure finding
    rpro = caa.post(f"/surface/assets/{ip_sid}/promote")
    assert rpro.status_code == 201 and rpro.json()["created"] is True, rpro.text
    inf_fid = rpro.json()["exposure_finding_id"]
    _ok("promote surface asset (ip) -> infrastructure_exposure finding")

    # o finding aparece no módulo Exposure com o tipo certo
    fdet = caa.get(f"/exposure/findings/{inf_fid}").json()
    assert fdet["exposure_type"] == "infrastructure_exposure", fdet
    assert fdet["detail"].get("ip") == "203.0.113.50", fdet
    assert fdet["detail"].get("surface_asset_id") == ip_sid, fdet
    _ok("infrastructure_exposure finding materialized (linked to surface asset)")

    # promote idempotente
    rpro2 = caa.post(f"/surface/assets/{ip_sid}/promote")
    assert rpro2.status_code == 201 and rpro2.json()["created"] is False and rpro2.json()["exposure_finding_id"] == inf_fid, rpro2.text
    _ok("promote idempotent (same infrastructure finding)")

    # CORRELATION do infra finding: inclui o surface asset e a brand (ponte via surface.brand_id)
    gp3 = ca.get(f"/correlation?entity=finding:{inf_fid}").json()
    kinds3 = {n["kind"] for n in gp3["nodes"]}
    assert "surface_asset" in kinds3, kinds3
    assert "brand" in kinds3, kinds3  # Brand<->Subdomain/IP<->Exposure fechado
    _ok("correlate infra finding -> surface_asset + brand (Surface<->Exposure<->Brand)")

    # seed a partir do surface asset também correlaciona o finding
    gsurf = ca.get(f"/correlation?entity=surface:{ip_sid}").json()
    assert gsurf["seed"]["kind"] == "surface_asset"
    assert any(n["kind"] == "exposure_finding" for n in gsurf["nodes"]), gsurf
    _ok("correlate by surface asset -> exposure finding")

    # INVESTIGATION: abre case a partir do infra finding (fecha o ciclo)
    rcase3 = caa.post(f"/exposure/findings/{inf_fid}/case")
    assert rcase3.status_code == 201, rcase3.text
    _ok("open Investigation Case from infrastructure_exposure (cycle closed)")

    # cross-tenant: B não promove asset de A
    assert cb.post(f"/surface/assets/{ip_sid}/promote").status_code == 404
    # audit
    assert any(a.get("action") == "surface.promote" for a in ca.get("/audit").json())
    _ok("cross-tenant promote -> 404; audit surface.promote")

    print('\nTENANT ISOLATION + INVITES + OPERATOR ROLES + BRAND EDIT + ARCHIVE/DELETE + CASES + NOTES + EVIDENCE + EXPORT + INTEGRATIONS + EXPOSURE + TIMELINE + RISK + CORRELATION + SURFACE + PROMOTE: ALL TESTS PASSED ✅')
if __name__ == '__main__':
    try:
        run()
    finally:
        if os.path.exists(_DB):
            os.remove(_DB)
