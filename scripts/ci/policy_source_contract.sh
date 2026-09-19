#!/usr/bin/env bash
set -euo pipefail
if [[ "$#" -ne 2 ]]; then
  echo "usage: policy_source_contract.sh <3.10|3.12> <policy|maintenance>" >&2
  exit 2
fi
exec uv run --no-sync python scripts/ci/policy_source_contract.py "$1" "$2"
