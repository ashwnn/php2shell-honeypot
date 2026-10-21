#!/bin/sh
# Manual local checks with Rust and SSH dependencies provided by containers.
set -eu
cd "$(dirname "$0")/.."
command -v docker >/dev/null 2>&1 || { echo 'Docker is required' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo 'Host Python 3 is required for stack orchestration' >&2; exit 1; }
docker info >/dev/null
# Unit/process/TLS checks execute during this dedicated image build.
docker build -f Dockerfile.test -t php2shell-tests:local .
# Preserve the tested resolution for subsequent application image builds.
if [ ! -f Cargo.lock ]; then
  lock_container=$(docker create php2shell-tests:local)
  trap 'docker rm "$lock_container" >/dev/null' EXIT
  docker cp "$lock_container:/tests/Cargo.lock" Cargo.lock
  docker rm "$lock_container" >/dev/null
  trap - EXIT
fi
export COMPOSE_PROJECT_NAME="php2shell-check-$$"
export BIND_ADDRESS=127.0.0.1 HTTP_PORT=18080 SSH_PORT=12222 TELNET_PORT=12323
trap 'docker compose --profile test down -v' EXIT
trap 'exit 130' INT TERM
docker compose config --quiet
docker compose --profile test up -d --build
docker compose --profile test stop ssh-client
python3 scripts/smoke-compose.py
