# ThreatForge Enterprise — CBG POC Local Runtime

## Purpose

This document describes the local Enterprise overlay used by the controlled
CBG Assessoria e Consultoria POC.

The ThreatForge Community core and the Enterprise overlay use the same
PostgreSQL database and the same shared schema.

Installing or removing the Enterprise Python package does not delete tenant
data and does not require recreating the PostgreSQL volume.

## Runtime architecture

The Enterprise runtime is built from:

- ThreatForge Community core version 0.11.0;
- threatforge-enterprise package version 0.11.0;
- a signed Enterprise license;
- the public verification key;
- local environment configuration.

The private signing key is never required by the application runtime.

## Security requirements

The private signing key must never be:

- copied into the Community repository;
- copied into the Enterprise wheel;
- included in a Docker image;
- mounted into the application container;
- committed to Git;
- printed in logs;
- copied into the runtime license directory.

Only these files are mounted into the application container:

- the signed license file;
- the public verification key.

Both files are mounted read-only.

## Local non-versioned files

The following paths must remain outside Git:

- `.env.enterprise.local`
- `.enterprise-build/`
- `~/threatforge-enterprise/.local/runtime-cbg-poc/`
- `~/threatforge-enterprise/.local/cbg-poc-2026/`
- `~/threatforge-enterprise/.local/licenses/`

## Build the Enterprise overlay

Run:

    cd ~/threatforge

    ./scripts/build_enterprise_overlay.sh \
      ~/threatforge \
      ~/threatforge-enterprise

Expected result:

    ENTERPRISE_OVERLAY_BUILD=PASS

## Validate the overlay without database access

Run:

    cd ~/threatforge

    ./scripts/validate_enterprise_overlay.sh \
      ~/threatforge

Expected result:

    ENTERPRISE_OVERLAY_VALIDATION=PASS
    core_version: 0.11.0
    enterprise_version: 0.11.0
    edition: enterprise
    customer: CBG Assessoria e Consultoria

## Start the Enterprise runtime

The Enterprise Compose overlay must always be combined with the Community
Compose file.

Run:

    cd ~/threatforge

    COMPOSE_PROJECT_NAME=community docker compose \
      --env-file .env \
      --env-file .env.enterprise.local \
      -f docker-compose.yml \
      -f docker-compose.enterprise.yml \
      up -d --build api

This command recreates only the API container. It does not recreate or remove
the PostgreSQL volume.

## Runtime verification

Check the containers:

    cd ~/threatforge

    COMPOSE_PROJECT_NAME=community docker compose \
      --env-file .env \
      --env-file .env.enterprise.local \
      -f docker-compose.yml \
      -f docker-compose.enterprise.yml \
      ps

Check application health:

    curl -sS http://localhost:8000/health \
      | python3 -m json.tool

Check the Enterprise package and license:

    cd ~/threatforge

    COMPOSE_PROJECT_NAME=community docker compose \
      --env-file .env \
      --env-file .env.enterprise.local \
      -f docker-compose.yml \
      -f docker-compose.enterprise.yml \
      exec -T api python - <<'PY'
    import importlib.metadata
    import importlib.util

    from app import config, enterprise_adapter

    status = enterprise_adapter.get_enterprise_status()

    print("core_version:", config.APP_VERSION)
    print("edition:", config.EDITION)
    print(
        "enterprise_package:",
        importlib.util.find_spec("threatforge_enterprise") is not None,
    )
    print(
        "enterprise_version:",
        importlib.metadata.version("threatforge-enterprise"),
    )
    print("license_valid:", status.get("valid"))
    print("customer:", status.get("customer"))
    print("license_id:", status.get("license_id"))
    print("expires_at:", status.get("expires_at"))
    print("features:", sorted(status.get("features") or []))
    PY

Expected minimum state:

    core_version: 0.11.0
    edition: enterprise
    enterprise_package: True
    enterprise_version: 0.11.0
    license_valid: True
    customer: CBG Assessoria e Consultoria

## Data protection

The CBG POC database and evidence volumes must never be removed during an
edition switch.

Do not execute:

    docker compose down -v
    docker volume rm
    docker volume prune
    docker system prune --volumes

Before any migration, rollback or runtime change:

1. create a PostgreSQL dump;
2. verify the dump catalog;
3. copy the backup outside WSL;
4. preserve the current source code in Git;
5. validate the candidate using a disposable database.

## Return to Community runtime

Returning to the Community runtime does not require changing or restoring the
database.

Run:

    cd ~/threatforge

    COMPOSE_PROJECT_NAME=community docker compose \
      -f docker-compose.yml \
      up -d --build api

The Enterprise features will become locked again, but tenant data remains
unchanged.

## Git-tracked runtime files

The following operational files are versioned:

- `Dockerfile.enterprise`
- `docker-compose.enterprise.yml`
- `scripts/build_enterprise_overlay.sh`
- `scripts/validate_enterprise_overlay.sh`
- `docs/ENTERPRISE_LOCAL_POC.md`

License files, public keys, private keys and local environment files are not
committed.

## Telegram collector profile

The inbound collector is disabled by default and is not part of the API
process. Configure a read-only bot-token host file and add this ignored local
setting:

    THREATFORGE_TELEGRAM_COLLECTION_BOT_TOKEN_HOST_FILE=/secure/path/token
    THREATFORGE_COLLECTION_WORKER_ENABLED=true

Then start the isolated profile only after POC authorization:

    COMPOSE_PROJECT_NAME=community docker compose \
      --env-file .env \
      --env-file .env.enterprise.local \
      -f docker-compose.yml \
      -f docker-compose.enterprise.yml \
      --profile telegram-collector \
      up -d --no-build collector

The source metadata stores only
`secretref://file/telegram-collection-bot-token`.
