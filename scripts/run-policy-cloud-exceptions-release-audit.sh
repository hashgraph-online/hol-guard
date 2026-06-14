#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

git diff --check

python3 -m pytest tests/test_cloud_exception_sync_proof.py tests/test_guard_cloud_exceptions.py -q

cd dashboard
npx tsx src/policy-final-release-guard.test.ts
npx tsx src/policy-cloud-exceptions-ia.test.tsx
npx tsx src/policy-data-truth.test.ts
npx tsx src/policy-ui-hardening.test.ts
npx tsx src/policy-review-scope.test.ts

echo "policy cloud exceptions release audit: ok"
