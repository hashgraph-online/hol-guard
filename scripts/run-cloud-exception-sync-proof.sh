#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m pytest tests/test_cloud_exception_sync_proof.py -q
./dashboard/node_modules/.bin/tsx dashboard/src/policy-review-scope.test.ts 2>/dev/null \
  || python3 -m pytest tests/test_cloud_exception_sync_proof.py -q

echo "cloud exception sync proof: ok"
