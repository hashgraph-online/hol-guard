#!/usr/bin/env bash
# Install the locked dependency set for the selected installed proof.
set -eo pipefail

extras=()
# Preserve the existing proof-specific boundary; only extensions select test tooling.
if [[ "$NATIVE_PROOF" == "extensions" ]]; then
  extras=(--group ci-test)
fi
uv sync --frozen --no-dev --no-install-project --python 3.12 "${extras[@]}"
