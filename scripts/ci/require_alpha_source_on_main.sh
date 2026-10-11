#!/usr/bin/env bash
# Main keeps moving while an alpha publishes, so a main alpha only needs its
# source commit to still be part of main's history, not to be its head.
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${SOURCE_SHA:?}"

if ! [[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Alpha publication source is not a full commit SHA" >&2
  exit 1
fi

status=$(gh api "repos/${GITHUB_REPOSITORY}/compare/${SOURCE_SHA}...main" --jq .status)
case "$status" in
  ahead | identical) ;;
  *)
    echo "Alpha publication source is no longer on main (compare status: ${status})" >&2
    exit 1
    ;;
esac
