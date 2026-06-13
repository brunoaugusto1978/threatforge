# Contributing to ThreatForge

Thank you for considering contributing to ThreatForge.

ThreatForge is an open source Cyber Threat Intelligence and Digital Risk Protection platform focused on defensive security, investigation workflows and actionable intelligence.

## Project Scope

Contributions should support defensive and authorized use cases, such as:

- threat intelligence enrichment;
- indicator normalization;
- brand abuse monitoring;
- tenant isolation;
- secure authentication and authorization;
- reporting;
- case management;
- auditability;
- integrations with defensive tools;
- documentation and testing.

Do not contribute features intended for unauthorized access, credential theft, malware deployment, evasion, exploitation of third-party systems or offensive abuse.

## Development Setup

Clone the repository:

    git clone https://github.com/brunoaugusto1978/threatforge.git
    cd threatforge

Create the environment file:

    cp .env.example .env

Generate strong local values:

    openssl rand -hex 32
    openssl rand -hex 32
    openssl rand -hex 32

Edit .env and configure at least:

    API_KEY=<generated_value>
    POSTGRES_PASSWORD=<generated_value>
    JWT_SECRET=<generated_value>
    COOKIE_SECURE=false
    APP_BASE_URL=http://localhost:8000

Start the stack:

    docker compose up -d --build

Validate:

    curl http://localhost:8000/health
    docker compose exec api python -m app.selftest_isolation

Expected result:

    ISOLAMENTO + CONVITES + PAPÉIS DE OPERADOR: TODOS OS TESTES PASSARAM ✅

## Branching

Use short-lived branches from main.

Examples:

- feature/pdf-reports
- fix/invite-token-redaction
- docs/security-model
- ci/selftest-workflow

## Commit Style

Use clear commit messages.

Examples:

- docs: add security policy
- ci: add selftest workflow
- fix: restrict support tenant access
- feature: add connector registry
- security: redact invite tokens from production logs

## Pull Request Requirements

Before opening a pull request:

- run the application locally;
- run the selftest;
- confirm no .env or secret file is included;
- describe what changed;
- describe how it was tested;
- include screenshots for UI changes when relevant.

## Security Requirements

Do not commit:

- .env;
- API keys;
- passwords;
- tokens;
- private keys;
- customer data;
- real leaked credentials;
- production logs containing secrets.

Security-sensitive changes must include tests or clear validation steps.

## Multi-tenant Rules

All data access must preserve tenant isolation.

Any new model containing tenant-owned data must include tenant_id.

Any new query reading tenant-owned data must be scoped by tenant.

Cross-tenant access must be explicitly blocked unless performed by an authorized platform operator with the correct context.

## Enterprise Features

ThreatForge follows an Open Core strategy.

The public repository contains the Community Edition.

Commercial or Enterprise-only modules must not be committed to this public repository.

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 license used by this repository.
