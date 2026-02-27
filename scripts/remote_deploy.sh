#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  echo "missing .env in $ROOT_DIR" >&2
  exit 1
fi

DEPLOY_CADDY="${DEPLOY_CADDY:-0}"
BUILD_BACKEND="${BUILD_BACKEND:-1}"

COMPOSE=(docker compose)
if ! docker compose version >/dev/null 2>&1; then
  if command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    echo "neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
  fi
fi

"${COMPOSE[@]}" --env-file .env config >/dev/null

# Legacy compose v1 workaround for Docker 28 metadata incompatibility.
if [[ "${COMPOSE[*]}" == "docker-compose" ]]; then
  "${COMPOSE[@]}" --env-file .env rm -sf backend caddy >/dev/null 2>&1 || true
fi

BACKEND_UP_ARGS=(-d --no-deps backend)
if [[ "$BUILD_BACKEND" == "1" ]]; then
  BACKEND_UP_ARGS=(-d --build --no-deps backend)
fi

"${COMPOSE[@]}" --env-file .env up "${BACKEND_UP_ARGS[@]}"

if [[ "$DEPLOY_CADDY" == "1" ]]; then
  "${COMPOSE[@]}" --env-file .env up -d --no-deps caddy
fi

ready=0
for _ in $(seq 1 60); do
  if curl -skf https://ahoj420.eu/robots.txt >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 2
done

if [[ "$ready" != "1" ]]; then
  echo "backend readiness check failed (https://ahoj420.eu/robots.txt)" >&2
  exit 1
fi

"${COMPOSE[@]}" --env-file .env ps
