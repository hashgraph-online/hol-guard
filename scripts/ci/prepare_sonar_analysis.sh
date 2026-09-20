#!/usr/bin/env bash
# Combine every pytest shard before Sonar receives its authentication token.
set -euo pipefail

shopt -s nullglob
reports=(coverage-data/*/.coverage)
echo "Combining ${#reports[@]} shard coverage files"
test "${#reports[@]}" -eq 192
uv run --no-sync python scripts/ci/parallel_coverage_combine.py --workers 4 "${reports[@]}"
uv run --no-sync python scripts/ci/parallel_coverage_xml.py --workers 4
