#!/usr/bin/env bash
# Install the locked dependency set for the selected installed proof.
set -eo pipefail

extras=()
if [[ "$NATIVE_PROOF" == "extensions" ]]; then
  extras=(--extra dev)
fi
uv sync --frozen --no-dev --no-install-project --python 3.12 "${extras[@]}"
