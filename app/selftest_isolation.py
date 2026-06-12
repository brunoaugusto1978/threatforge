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

    print("\nISOLAMENTO MULTI-TENANT: TODOS OS TESTES PASSARAM ✅")


if __name__ == "__main__":
    try:
        run()
    finally:
        if os.path.exists(_DB):
            os.remove(_DB)
