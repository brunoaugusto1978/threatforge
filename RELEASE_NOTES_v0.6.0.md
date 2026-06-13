# ThreatForge v0.6.0

First stable multi-tenant release of ThreatForge.

## Highlights

* Multi-tenant architecture with strong tenant isolation.
* Platform operator onboarding.
* Tenant-scoped users with `admin`, `analyst` and `viewer` roles.
* Platform roles: `platform_admin`, `support_operator` and `support_viewer`.
* Support access restricted by tenant assignment.
* Invite flow by e-mail with hashed token, expiration and single use.
* Tenant-scoped API keys.
* Audit logs with user, operator, tenant, IP and user-agent context.
* Automated isolation selftest covering admin, support and client flows.
* Updated README with installation, `.env` configuration and validation steps.

## Validation

The following checks were validated before release:

```text
Healthcheck: OK
ThreatForge version: 0.6.0
Multi-tenant selftest: OK
Client A login: OK
Client B login: OK
Support restricted to Client A: OK
Tenant isolation: OK
```

Expected selftest output:

```text
ISOLAMENTO + CONVITES + PAPÉIS DE OPERADOR: TODOS OS TESTES PASSARAM ✅
```

## Recommended installation

```bash
cp .env.example .env

openssl rand -hex 32
openssl rand -hex 32
openssl rand -hex 32

vi .env
docker compose up -d --build
curl http://localhost:8000/health
docker compose exec api python -m app.selftest_isolation
```

Required minimum `.env` values:

```env
API_KEY=<generated_value>
POSTGRES_PASSWORD=<generated_value>
JWT_SECRET=<generated_value>
COOKIE_SECURE=false
APP_BASE_URL=http://localhost:8000
```

## Notes

This version is intended for local testing, development, research and defensive CTI/DRP workflows.

Before production usage, review secrets management, HTTPS, cookie security, CORS, SMTP, logging policy, dependency audit and infrastructure hardening.

