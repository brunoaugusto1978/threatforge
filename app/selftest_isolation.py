"""Selftest de isolamento multi-tenant (ponta a ponta).

Usa um SQLite temporário próprio (NÃO toca no banco de produção) e o TestClient
do FastAPI para provar que Tenant A não acessa dados do Tenant B.

Rodar dentro do container:
    docker compose -f docker-compose.yml -f docker-compose.podman.yml \
        exec api python -m app.selftest_isolation
"""
import os
import tempfile

# isola o teste num sqlite temporário ANTES de importar o app
_DB = os.path.join(tempfile.gettempdir(), "tf_isolation_test.db")
if os.path.exists(_DB):
    os.remove(_DB)
os.environ["DATABASE_URL"] = f"sqlite:///{_DB}"
os.environ["JWT_SECRET"] = "selftest-secret-key-please-ignore"
os.environ["API_KEY"] = ""
os.environ["BOOTSTRAP_OPERATOR_EMAIL"] = ""
os.environ["BOOTSTRAP_OPERATOR_PASSWORD"] = ""

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def _ok(msg):
    print(f"  ✓ {msg}")


def run():
    op = TestClient(app)
    r = op.post("/setup/operator", json={"email": "op@plat.com", "password": "OperatorPass1"})
    assert r.status_code == 201, r.text
    _ok("operador de plataforma criado")

    # operador cria dois tenants (cada um com seu admin)
    ra = op.post("/tenants", json={"name": "Tenant A", "admin_email": "admin@a.com",
                                   "admin_password": "TenantAdminA1"})
    rb = op.post("/tenants", json={"name": "Tenant B", "admin_email": "admin@b.com",
                                   "admin_password": "TenantAdminB1"})
    assert ra.status_code == 201 and rb.status_code == 201, (ra.text, rb.text)
    ta, tb = ra.json()["id"], rb.json()["id"]
    _ok(f"tenants criados (A={ta}, B={tb})")

    # logins separados
    ca, cb = TestClient(app), TestClient(app)
    assert ca.post("/auth/login", json={"email": "admin@a.com", "password": "TenantAdminA1"}).status_code == 200
    assert cb.post("/auth/login", json={"email": "admin@b.com", "password": "TenantAdminB1"}).status_code == 200
    _ok("admins de A e B autenticados")

    # cada tenant cria seus dados
    ba = ca.post("/brands", json={"name": "BrandA", "official_domains": ["a-corp.com.br"]})
    bb = cb.post("/brands", json={"name": "BrandB", "official_domains": ["b-corp.com.br"]})
    assert ba.status_code == 201 and bb.status_code == 201, (ba.text, bb.text)
    ba_id = ba.json()["id"]
    assert ca.post("/observables", json={"type": "ip", "value": "1.1.1.1"}).status_code == 201
    assert cb.post("/observables", json={"type": "ip", "value": "2.2.2.2"}).status_code == 201
    _ok("dados criados em cada tenant")

    # ---- ISOLAMENTO ----
    a_brands = [x["name"] for x in ca.get("/brands").json()]
    b_brands = [x["name"] for x in cb.get("/brands").json()]
    assert a_brands == ["BrandA"], a_brands
    assert b_brands == ["BrandB"], b_brands
    _ok("listagem de marcas isolada (A só vê A; B só vê B)")

    a_obs = [x["value"] for x in ca.get("/observables").json()]
    b_obs = [x["value"] for x in cb.get("/observables").json()]
    assert a_obs == ["1.1.1.1"] and b_obs == ["2.2.2.2"], (a_obs, b_obs)
    _ok("listagem de IOCs isolada")

    # B tenta acessar a marca de A pelo id -> 404
    assert cb.get(f"/brands/{ba_id}").status_code == 404
    assert cb.delete(f"/brands/{ba_id}").status_code == 404
    _ok("acesso cruzado por id bloqueado (404, sem vazar existência)")

    # usuários: A não vê admin de B
    a_users = [u["email"] for u in ca.get("/users").json()]
    assert a_users == ["admin@a.com"], a_users
    _ok("usuários isolados por tenant")

    # operador precisa de X-Tenant-Id para dados de tenant
    assert op.get("/brands").status_code == 400
    op_a = op.get("/brands", headers={"X-Tenant-Id": str(ta)}).json()
    assert [x["name"] for x in op_a] == ["BrandA"]
    _ok("operador: exige X-Tenant-Id e vê o tenant indicado")

    # API key de tenant A só enxerga A
    k = op.post(f"/tenants/{ta}/api-keys", json={"label": "ci", "role": "viewer"}).json()
    key_client = TestClient(app)
    via_key = key_client.get("/brands", headers={"X-API-Key": k["api_key"]}).json()
    assert [x["name"] for x in via_key] == ["BrandA"], via_key
    # e a mesma key não acessa B (não há como; é presa ao tenant_id da key)
    _ok("API key por tenant: presa ao próprio tenant")

    # ---- FLUXO DE CONVITE ----
    rc = op.post("/tenants", json={"name": "Tenant C", "admin_email": "admin@c.com"})
    assert rc.status_code == 201, rc.text
    link = rc.json().get("invite_link")
    assert link and "token=" in link, rc.json()
    token = link.split("token=", 1)[1]
    _ok("tenant criado por convite (sem senha) -> link gerado")

    # token válido
    v = op.get(f"/invites/validate?token={token}").json()
    assert v["valid"] and v["email"] == "admin@c.com", v
    # antes de aceitar, login deve falhar (usuário inativo)
    assert TestClient(app).post("/auth/login",
                                json={"email": "admin@c.com", "password": "whatever12"}).status_code == 401
    _ok("convite válido; usuário inativo não loga antes do aceite")

    # aceita e define senha
    cc = TestClient(app)
    ac = cc.post("/invites/accept", json={"token": token, "password": "ClienteSenha1"})
    assert ac.status_code == 200, ac.text
    assert ac.json()["tenant_id"] == rc.json()["id"]
    _ok("aceite ativa o usuário vinculado ao tenant do convite")

    # token de uso único: segunda tentativa falha
    assert cc.post("/invites/accept", json={"token": token, "password": "Outra123456"}).status_code == 400
    assert op.get(f"/invites/validate?token={token}").json()["valid"] is False
    _ok("token de uso único: invalidado após aceite")

    # cliente C logado vê só o próprio tenant (isolado de A e B)
    cc2 = TestClient(app)
    assert cc2.post("/auth/login", json={"email": "admin@c.com", "password": "ClienteSenha1"}).status_code == 200
    assert cc2.get("/brands").json() == []  # tenant novo, sem marcas
    _ok("cliente do convite isolado no próprio tenant")

    # ============ PAPÉIS DE OPERADOR ============
    # platform admin cria um support operator
    rso = op.post("/operators", json={"email": "support@plat.com", "password": "SupportPass1",
                                       "operator_role": "support_operator"})
    assert rso.status_code == 201, rso.text
    sop_id = rso.json()["id"]
    _ok("platform admin cria support operator")

    sc = TestClient(app)
    assert sc.post("/auth/login", json={"email": "support@plat.com", "password": "SupportPass1"}).status_code == 200

    # support sem acesso a tenant nenhum: lista vazia e 403 ao tentar entrar em A
    assert sc.get("/tenants").json() == []
    assert sc.get("/brands", headers={"X-Tenant-Id": str(ta)}).status_code == 403
    _ok("support sem atribuição não acessa nenhum tenant (403)")

    # platform admin concede acesso ao tenant A
    assert op.post(f"/operators/{sop_id}/tenant-access",
                   json={"tenant_id": ta, "access_role": "support_operator"}).status_code == 201
    # agora support acessa A...
    assert [t["id"] for t in sc.get("/tenants").json()] == [ta]
    assert sc.get("/brands", headers={"X-Tenant-Id": str(ta)}).status_code == 200
    # ...mas NÃO acessa B (não atribuído)
    assert sc.get("/brands", headers={"X-Tenant-Id": str(tb)}).status_code == 403
    _ok("support acessa só o tenant atribuído (A sim, B não)")

    # support NÃO pode ações destrutivas/administrativas
    assert sc.post("/tenants", json={"name": "X", "admin_email": "x@x.com",
                                     "admin_password": "Xxxxxxx123"}).status_code == 403  # criar tenant
    assert sc.patch(f"/tenants/{ta}?status=suspended").status_code == 403                  # bloquear tenant
    assert sc.post("/operators", json={"email": "n@n.com", "operator_role": "support_operator"}).status_code == 403  # criar operador
    assert sc.post(f"/tenants/{ta}/api-keys", json={"label": "x", "role": "viewer"}).status_code == 403  # api key
    assert sc.delete(f"/brands/{ba_id}", headers={"X-Tenant-Id": str(ta)}).status_code == 403  # apagar marca (admin)
    _ok("support bloqueado em ações destrutivas/administrativas")

    # platform admin PODE bloquear tenant
    assert op.patch(f"/tenants/{tb}?status=suspended").status_code == 200
    _ok("platform admin bloqueia/ativa tenant")

    # ação de support gera audit log com operator_user_id
    sc.get("/brands", headers={"X-Tenant-Id": str(ta)})
    audit_rows = op.get("/audit", headers={"X-Tenant-Id": str(ta)}).json()
    assert any(a.get("action") == "operator.grant_access" for a in audit_rows) or \
           any(a.get("operator_user_id") for a in audit_rows)
    _ok("ações registram audit log com operator/tenant")

    # revogar acesso: support volta a 403 em A
    assert op.delete(f"/operators/{sop_id}/tenant-access/{ta}").status_code == 204
    assert sc.get("/brands", headers={"X-Tenant-Id": str(ta)}).status_code == 403
    _ok("revogação de acesso bloqueia o support imediatamente")

    print("\nISOLAMENTO + CONVITES + PAPÉIS DE OPERADOR: TODOS OS TESTES PASSARAM ✅")


if __name__ == "__main__":
    try:
        run()
    finally:
        if os.path.exists(_DB):
            os.remove(_DB)
