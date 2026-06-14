#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m pytest tests/test_cloud_exception_sync_proof.py -q
if [ -f "./dashboard/node_modules/.bin/tsx" ]; then
  ./dashboard/node_modules/.bin/tsx dashboard/src/policy-review-scope.test.ts
else
  echo "Warning: tsx not found, skipping policy-review-scope test"
fi

echo "cloud exception sync proof: ok"
