#!/usr/bin/env bash
# Prepare both language analyzers before Sonar receives its authentication token.
set -euo pipefail

shopt -s nullglob
reports=(coverage-data/*/.coverage)
echo "Combining ${#reports[@]} shard coverage files"
test "${#reports[@]}" -eq 96
uv run --no-sync coverage combine "${reports[@]}"
uv run --no-sync python scripts/ci/parallel_coverage_xml.py --workers 4

cargo clippy --manifest-path rust/Cargo.toml --locked --workspace
