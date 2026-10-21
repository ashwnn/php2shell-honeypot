#!/bin/sh
# Manual verification only. No GitHub Actions or external test target.
set -eu
cd "$(dirname "$0")/.."
if ! command -v cargo >/dev/null 2>&1; then
  exec sh scripts/check-docker.sh
fi
if ! command -v python3 >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
  echo 'BLOCKED: Python 3 and openssl are required for synthetic TLS verification' >&2
  exit 1
fi
# Initial migration only: review/commit the resolved lockfile before release.
if [ ! -f Cargo.lock ]; then cargo generate-lockfile; fi
cargo fmt --all
cargo test --locked
cargo clippy --locked --all-targets
python3 scripts/smoke-tls.py target/debug/php2shell
# Compose config can be checked without a running daemon.
docker compose config --quiet
docker compose --env-file .env.vps.example -f compose.yaml -f compose.public.yaml config --quiet
docker compose --env-file .env.vps.example -f compose.yaml -f compose.public.yaml -f compose.https.yaml config --quiet
if ! docker info >/dev/null 2>&1; then
  echo 'BLOCKED: Rust checks completed; start local Docker Engine for the stack check' >&2
  exit 1
fi
if ! command -v sshpass >/dev/null 2>&1; then
  echo 'BLOCKED: install sshpass for the local SSH smoke check' >&2
  exit 1
fi
# Use a separate project and only loopback ports; never target deployed volumes.
export COMPOSE_PROJECT_NAME="php2shell-check-$$"
export BIND_ADDRESS=127.0.0.1 HTTP_PORT=18080 SSH_PORT=12222 TELNET_PORT=12323
trap 'docker compose --profile test down -v' EXIT
trap 'exit 130' INT TERM
docker compose --profile test up -d --build
python3 scripts/smoke-compose.py
