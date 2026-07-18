#!/usr/bin/env bash
set -Eeuo pipefail

COMMUNITY_DIR="${1:-$HOME/threatforge}"
ENTERPRISE_DIR="${2:-$HOME/threatforge-enterprise}"
BUILD_DIR="$COMMUNITY_DIR/.enterprise-build"
IMAGE="threatforge-enterprise-api:0.11.0-local"

cd "$COMMUNITY_DIR"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

echo "[1/4] Construindo wheel Enterprise..."
"$COMMUNITY_DIR/.venv/bin/python" -m pip wheel \
  --no-deps \
  --wheel-dir "$BUILD_DIR" \
  "$ENTERPRISE_DIR"

mapfile -t WHEELS < <(find "$BUILD_DIR" -maxdepth 1 -type f -name '*.whl')

if [[ "${#WHEELS[@]}" -ne 1 ]]; then
  echo "ERRO: esperado exatamente um wheel; encontrados ${#WHEELS[@]}." >&2
  exit 1
fi

WHEEL="${WHEELS[0]}"

echo "[2/4] Validando conteúdo do wheel..."
if "$COMMUNITY_DIR/.venv/bin/python" -m zipfile -l "$WHEEL" \
    | grep -Eiq '(^|/)\.local/|private-key|\.license\.json'; then
  echo "ERRO: o wheel contém artefato local, licença ou chave privada." >&2
  exit 1
fi

echo "[3/4] Atualizando imagem Community base sem recriar containers..."
COMPOSE_PROJECT_NAME=community docker compose build api

echo "[4/4] Construindo overlay Enterprise..."
docker build \
  --build-arg BASE_IMAGE=community-api:latest \
  --file Dockerfile.enterprise \
  --tag "$IMAGE" \
  .

echo "ENTERPRISE_OVERLAY_BUILD=PASS"
docker image inspect "$IMAGE" \
  --format 'Image={{.RepoTags}} ID={{.Id}} Size={{.Size}}'
