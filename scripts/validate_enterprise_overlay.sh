#!/usr/bin/env bash
set -Eeuo pipefail

COMMUNITY_DIR="${1:-$HOME/threatforge}"
IMAGE="threatforge-enterprise-api:0.11.0-local"

cd "$COMMUNITY_DIR"

set -a
# shellcheck disable=SC1091
source .env.enterprise.local
set +a

for file in \
  "$THREATFORGE_ENTERPRISE_LICENSE_HOST_FILE" \
  "$THREATFORGE_ENTERPRISE_PUBLIC_KEY_HOST_FILE"
do
  if [[ ! -r "$file" ]]; then
    echo "ERRO: arquivo não legível: $file" >&2
    exit 1
  fi
done

docker run --rm -i \
  --network none \
  --entrypoint python \
  -e THREATFORGE_EDITION=enterprise \
  -e THREATFORGE_ENTERPRISE_LICENSE_FILE=/run/secrets/threatforge-license.json \
  -e THREATFORGE_ENTERPRISE_PUBLIC_KEY_FILE=/run/secrets/threatforge-license-public.pem \
  -e THREATFORGE_ENTERPRISE_LICENSE_KEY_ID="$THREATFORGE_ENTERPRISE_LICENSE_KEY_ID" \
  -e THREATFORGE_ENTERPRISE_INSTALLATION_ID="$THREATFORGE_ENTERPRISE_INSTALLATION_ID" \
  -v "$THREATFORGE_ENTERPRISE_LICENSE_HOST_FILE:/run/secrets/threatforge-license.json:ro" \
  -v "$THREATFORGE_ENTERPRISE_PUBLIC_KEY_HOST_FILE:/run/secrets/threatforge-license-public.pem:ro" \
  "$IMAGE" - <<'PY'
import importlib.metadata
import importlib.util

from app import config, enterprise_adapter

expected = {
    "export.pdf",
    "integration.misp",
    "integration.opencti",
    "integration.generic",
    "enrichment.premium",
    "feeds.darkweb",
    "feeds.realtime",
    "feeds.enrichment",
    "collection.telegram",
    "analysis.telegram",
}

status = enterprise_adapter.get_enterprise_status()
features = set(status.get("features") or [])

assert config.APP_VERSION == "0.11.0", config.APP_VERSION
assert config.EDITION == "enterprise", config.EDITION
assert importlib.util.find_spec("threatforge_enterprise") is not None
assert importlib.metadata.version("threatforge-enterprise") == "0.11.0"
assert status.get("available") is True, status
assert status.get("valid") is True, status
assert expected <= features, sorted(features)

print("ENTERPRISE_OVERLAY_VALIDATION=PASS")
print("core_version:", config.APP_VERSION)
print("enterprise_version:", importlib.metadata.version("threatforge-enterprise"))
print("edition:", config.EDITION)
print("customer:", status.get("customer"))
print("license_id:", status.get("license_id"))
print("expires_at:", status.get("expires_at"))
print("features:")
for feature in sorted(features):
    print(" -", feature)
PY
