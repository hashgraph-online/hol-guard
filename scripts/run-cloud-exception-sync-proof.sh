#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -x "./dashboard/node_modules/.bin/tsx" ]; then
  echo "cloud exception sync proof: incomplete; dashboard tsx is unavailable. Run: cd dashboard && bun install --frozen-lockfile" >&2
  exit 2
fi

python3 -m pytest tests/test_cloud_exception_sync_proof.py -q
./dashboard/node_modules/.bin/tsx dashboard/src/policy-review-scope.test.ts

echo "cloud exception sync proof: ok"
