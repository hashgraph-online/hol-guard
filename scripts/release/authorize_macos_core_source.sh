#!/usr/bin/env bash
# Authorize the exact tagged Core source before a Desktop sidecar is reused or built.
set -euo pipefail

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0

: "${CORE_TAG:?}"
: "${CORE_VERSION:?}"
: "${RELEASE_BRANCH:?}"
: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_OUTPUT:?}"
: "${RUNNER_TEMP:?}"

TRUST_REPO="$RUNNER_TEMP/core-trust.git"
TRUST_ASSETS="$RUNNER_TEMP/core-trust-assets"
mkdir -p "$TRUST_ASSETS"
git init --bare "$TRUST_REPO"
git -C "$TRUST_REPO" remote add origin "https://github.com/${GITHUB_REPOSITORY}.git"
git -C "$TRUST_REPO" fetch --force --no-recurse-submodules origin \
  "+refs/tags/${CORE_TAG}:refs/tags/${CORE_TAG}" \
  "+refs/heads/${RELEASE_BRANCH}:refs/remotes/origin/${RELEASE_BRANCH}"
SOURCE_SHA=$(git -C "$TRUST_REPO" rev-parse "refs/tags/${CORE_TAG}^{commit}")
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]
git -C "$TRUST_REPO" merge-base --is-ancestor \
  "$SOURCE_SHA" "refs/remotes/origin/${RELEASE_BRANCH}"
gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" \
  --pattern "hol_guard-${CORE_VERSION}-*-macosx_*_arm64.whl" \
  --dir "$TRUST_ASSETS"
gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" \
  --pattern "hol-guard-v${CORE_VERSION}.intoto.jsonl" --dir "$TRUST_ASSETS"
WHEEL=""
WHEEL_COUNT=0
while IFS= read -r candidate; do
  WHEEL="$candidate"
  WHEEL_COUNT=$((WHEEL_COUNT + 1))
done < <(find "$TRUST_ASSETS" -maxdepth 1 -type f \
  -name "hol_guard-${CORE_VERSION}-*-macosx_*_arm64.whl" -print)
test "$WHEEL_COUNT" -eq 1
test -f "$WHEEL"
BUNDLE="$TRUST_ASSETS/hol-guard-v${CORE_VERSION}.intoto.jsonl"
test -s "$BUNDLE"
verify_published_wheel() {
  local source_ref="$1"
  gh attestation verify "$WHEEL" \
    --repo "$GITHUB_REPOSITORY" \
    --bundle "$BUNDLE" \
    --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish.yml" \
    --signer-digest "$SOURCE_SHA" \
    --source-digest "$SOURCE_SHA" \
    --source-ref "$source_ref" \
    --deny-self-hosted-runners >/dev/null
}
# Release Please attests the tag. A manual stable dispatch attests main.
if ! verify_published_wheel "refs/tags/${CORE_TAG}"; then
  verify_published_wheel "refs/heads/${RELEASE_BRANCH}"
fi
cp "$WHEEL" "$RUNNER_TEMP/attested-macos-arm64.whl"
test -f "$RUNNER_TEMP/attested-macos-arm64.whl"
echo "sha=$SOURCE_SHA" >> "$GITHUB_OUTPUT"
