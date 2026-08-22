#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/../../.." && pwd)"
compose=(docker compose -f "$root/tests/dockerlabs/codex-cli-resume/docker-compose.yml" -p hol-guard-codex-cli-resume)

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

"${compose[@]}" build
"${compose[@]}" run --rm e2e
