#!/usr/bin/env bash
# Select the stable Core release a desktop feed builds; prints step outputs.
# A named version reads that one release instead of paginating every release.
set -euo pipefail

PLATFORM="${1:?platform wheel pattern}"
: "${GITHUB_REPOSITORY:?}"
: "${RUNNER_TEMP:?}"
REQUESTED_CORE_VERSION="${REQUESTED_CORE_VERSION:-}"

INVENTORY="$RUNNER_TEMP/release-inventory.jsonl"
TAGS="$RUNNER_TEMP/release-tags.txt"
RELEASE_FILTER='select(.draft == false and .prerelease == false) | {tag: .tag_name, assets: [.assets[] | select(.state == "uploaded") | .name]}'

if [[ -n "$REQUESTED_CORE_VERSION" ]]; then
  if [[ ! "$REQUESTED_CORE_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "Requested Core version is not a stable version: $REQUESTED_CORE_VERSION" >&2
    exit 1
  fi
  gh api "repos/${GITHUB_REPOSITORY}/releases/tags/v${REQUESTED_CORE_VERSION}" \
    --jq "$RELEASE_FILTER" > "$INVENTORY"
else
  gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
    --jq ".[] | $RELEASE_FILTER" > "$INVENTORY"
fi
python3 -I scripts/release/ready_core_releases.py --inventory "$INVENTORY" --platform "$PLATFORM" > "$TAGS"
ARGS=(--tags "$TAGS")
if [[ -n "$REQUESTED_CORE_VERSION" ]]; then
  ARGS+=(--version "$REQUESTED_CORE_VERSION")
fi
python3 -I scripts/release/desktop_core_alpha_feed.py discover-release "${ARGS[@]}"
