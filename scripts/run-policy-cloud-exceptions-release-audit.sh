#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ ! -x "./dashboard/node_modules/.bin/tsx" ]; then
  echo "policy cloud exceptions release audit: incomplete; dashboard tsx is unavailable. Run: cd dashboard && bun install --frozen-lockfile" >&2
  exit 2
fi

git diff --check

python3 -m pytest tests/test_cloud_exception_sync_proof.py tests/test_cloud_exception_sync_proof_no_skip.py tests/test_guard_cloud_exceptions.py -q

cd dashboard
./node_modules/.bin/tsx src/policy-final-release-guard.test.ts
./node_modules/.bin/tsx src/policy-cloud-exceptions-ia.test.tsx
./node_modules/.bin/tsx src/policy-data-truth.test.ts
./node_modules/.bin/tsx src/policy-ui-hardening.test.ts
./node_modules/.bin/tsx src/policy-review-scope.test.ts

echo "policy cloud exceptions release audit: ok"
