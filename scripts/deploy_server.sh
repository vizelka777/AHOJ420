#!/usr/bin/env bash
set -euo pipefail

REMOTE="${1:-sss@46.36.37.243}"
REMOTE_DIR="${2:-/home/sss/AHOJ420}"
DEPLOY_CADDY="${DEPLOY_CADDY:-0}"
BUILD_BACKEND="${BUILD_BACKEND:-1}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tar -czf - \
  --exclude=.git \
  --exclude=.env \
  --exclude=.env.* \
  --exclude=tmp \
  --exclude='cookies*.txt' \
  -C "$ROOT_DIR" . \
| ssh "$REMOTE" "mkdir -p '$REMOTE_DIR' && tar -xzf - -C '$REMOTE_DIR'"

ssh "$REMOTE" "cd '$REMOTE_DIR' && chmod +x scripts/remote_deploy.sh && DEPLOY_CADDY='$DEPLOY_CADDY' BUILD_BACKEND='$BUILD_BACKEND' ./scripts/remote_deploy.sh"
