#!/bin/bash
set -euo pipefail

mode=${1:-dry}
case "$mode" in
  dry|delete) ;;
  *) exit 64 ;;
esac

report="$HOME/maintenance-report.tsv"
: > "$report"
for repository in alpha beta; do
  fixture-registry list "$repository" | sort | head -n 2 >> "$report"
  case "$mode" in
    dry) fixture-registry inspect "$repository" >> "$report" ;;
    delete) fixture-registry delete "$repository" obsolete ;;
  esac
done
