#!/usr/bin/env bash
# Select the Core release a desktop feed builds; prints step outputs.
# A named version reads that one release instead of paginating every release.
# CORE_RELEASE_CHANNEL=alpha reads exactly one alpha prerelease and never scans.
set -euo pipefail

PLATFORM="${1:?platform wheel pattern}"
: "${GITHUB_REPOSITORY:?}"
: "${RUNNER_TEMP:?}"
REQUESTED_CORE_VERSION="${REQUESTED_CORE_VERSION:-}"
CORE_RELEASE_CHANNEL="${CORE_RELEASE_CHANNEL:-stable}"

INVENTORY="$RUNNER_TEMP/release-inventory.jsonl"
TAGS="$RUNNER_TEMP/release-tags.txt"
RELEASE_FILTER='select(.draft == false and .prerelease == false) | {tag: .tag_name, assets: [.assets[] | select(.state == "uploaded") | .name]}'

if [[ "$CORE_RELEASE_CHANNEL" == "alpha" ]]; then
  # Alpha builds are explicit: one exact version, one prerelease, no discovery scan.
  if [[ ! "$REQUESTED_CORE_VERSION" =~ ^3\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)a[1-9][0-9]*$ ]]; then
    echo "Requested Core version is not an alpha version: $REQUESTED_CORE_VERSION" >&2
    exit 1
  fi
  ALPHA_FILTER='select(.draft == false and .prerelease == true) | {tag: .tag_name, assets: [.assets[] | select(.state == "uploaded") | .name]}'
  if ! gh api "repos/${GITHUB_REPOSITORY}/releases/tags/alpha/v${REQUESTED_CORE_VERSION}" \
    --jq "$ALPHA_FILTER" > "$INVENTORY" 2> "$RUNNER_TEMP/release-tag.err"; then
    cat "$RUNNER_TEMP/release-tag.err" >&2
    echo "Alpha prerelease alpha/v${REQUESTED_CORE_VERSION} is not published; it may have been retracted. Nothing was created." >&2
    exit 1
  fi
elif [[ "$CORE_RELEASE_CHANNEL" != "stable" ]]; then
  echo "Unsupported Core release channel: $CORE_RELEASE_CHANNEL" >&2
  exit 1
elif [[ -n "$REQUESTED_CORE_VERSION" ]]; then
  if [[ ! "$REQUESTED_CORE_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "Requested Core version is not a stable version: $REQUESTED_CORE_VERSION" >&2
    exit 1
  fi
  gh api "repos/${GITHUB_REPOSITORY}/releases/tags/v${REQUESTED_CORE_VERSION}" \
    --jq "$RELEASE_FILTER" > "$INVENTORY"
else
  # Stable tags come from the git protocol, which costs no REST quota. Read
  # releases newest version first and stop at the first ready one: that is the
  # same release the full scan would select. Paginate only as a fallback.
  : > "$INVENTORY"
  STABLE_TAGS=$(
    git ls-remote --tags --refs "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY}.git" 'v*' |
      sed -n 's#^[0-9a-f]*[[:space:]]*refs/tags/##p' |
      grep -E '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' |
      sort -t. -k1.2,1nr -k2,2nr -k3,3nr |
      head -n 20 || true
  )
  found=false
  for tag in $STABLE_TAGS; do
    if ! release=$(gh api "repos/${GITHUB_REPOSITORY}/releases/tags/${tag}" --jq "$RELEASE_FILTER" 2>"$RUNNER_TEMP/release-tag.err"); then
      grep -q "Not Found" "$RUNNER_TEMP/release-tag.err" || { cat "$RUNNER_TEMP/release-tag.err" >&2; exit 1; }
      continue
    fi
    [[ -n "$release" ]] || continue
    printf '%s\n' "$release" > "$INVENTORY"
    ready=$(python3 -I scripts/release/ready_core_releases.py --inventory "$INVENTORY" --platform "$PLATFORM") || exit 1
    if [[ -n "$ready" ]]; then
      found=true
      break
    fi
  done
  if [[ "$found" != true ]]; then
    gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
      --jq ".[] | $RELEASE_FILTER" > "$INVENTORY"
  fi
fi
python3 -I scripts/release/ready_core_releases.py --inventory "$INVENTORY" --platform "$PLATFORM" \
  --channel "$CORE_RELEASE_CHANNEL" > "$TAGS"
ARGS=(--tags "$TAGS" --channel "$CORE_RELEASE_CHANNEL")
if [[ -n "$REQUESTED_CORE_VERSION" ]]; then
  ARGS+=(--version "$REQUESTED_CORE_VERSION")
fi
python3 -I scripts/release/desktop_core_alpha_feed.py discover-release "${ARGS[@]}"
