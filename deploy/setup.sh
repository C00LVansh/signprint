#!/usr/bin/env bash
# One-time setup for the demo: builds the image and generates the keyring
# and secrets. Safe to re-run; existing keys are kept.
set -euo pipefail
cd "$(dirname "$0")"

docker compose build proxy

if [ ! -f config/keyring.json ] || [ ! -f .env ]; then
  keys=$(docker run --rm --entrypoint signprint-proxy signprint:latest keygen 1)
  umask 077
  printf '%s\n' "$keys" | sed -n '/^{/,/^}/p' > config/keyring.json
  {
    printf '%s\n' "$keys" | grep '^SIGNPRINT_'
    printf 'SIGNPRINT_CALIBRATE=%s\n' "$(head -c 24 /dev/urandom | base64 | tr -d '/+=')"
  } > .env
  # the container runs as uid 10001 and only needs to read these
  chmod 644 config/keyring.json
  echo "keys written to config/keyring.json and .env (keep both private)"
else
  echo "keys already exist, leaving them alone"
fi

if [ -z "${TUNNEL_NETWORK:-}" ]; then
  docker network inspect signprint-tunnel >/dev/null 2>&1 || docker network create signprint-tunnel >/dev/null
  echo "using a standalone network; set TUNNEL_NETWORK to join an existing tunnel's network"
fi

echo "now: docker compose up -d"
