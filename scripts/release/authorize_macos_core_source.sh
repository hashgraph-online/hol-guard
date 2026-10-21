#!/usr/bin/env bash
# Authorize the exact tagged Core source before a Desktop sidecar is reused or built.
# RELEASE_CHANNEL=alpha additionally binds the alpha tag to the dispatched publication source.
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
RELEASE_CHANNEL="${RELEASE_CHANNEL:-stable}"
case "${RELEASE_TARGET:-aarch64-apple-darwin}" in
  aarch64-apple-darwin)
    WHEEL_PATTERN="hol_guard-${CORE_VERSION}-*-macosx_*_arm64.whl"
    ATTESTED_NAME=attested-macos-arm64.whl
    ;;
  x86_64-unknown-linux-gnu)
    WHEEL_PATTERN="hol_guard-${CORE_VERSION}-*-manylinux_*_x86_64.whl"
    ATTESTED_NAME=attested-linux-x64.whl
    ;;
  *) echo "Unsupported Desktop Core target" >&2; exit 1 ;;
esac

case "$RELEASE_CHANNEL" in
  stable) ;;
  alpha)
    # Explicit exits: errexit does not reliably stop on a failed [[ ]] in older bash.
    [[ "$RELEASE_BRANCH" == "main" ]] || { echo "Alpha Core is authorized from main only" >&2; exit 1; }
    [[ "$CORE_TAG" == "alpha/v${CORE_VERSION}" ]] || { echo "Alpha tag does not match the version" >&2; exit 1; }
    [[ "${PUBLICATION_SOURCE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { echo "Alpha publication source is required" >&2; exit 1; }
    ;;
  *) echo "Unsupported Core release channel: $RELEASE_CHANNEL" >&2; exit 1 ;;
esac

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
if [[ "$RELEASE_CHANNEL" == "alpha" && "$SOURCE_SHA" != "$PUBLICATION_SOURCE_SHA" ]]; then
  echo "Alpha tag does not target the dispatched publication source" >&2
  exit 1
fi
git -C "$TRUST_REPO" merge-base --is-ancestor \
  "$SOURCE_SHA" "refs/remotes/origin/${RELEASE_BRANCH}"
gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" \
  --pattern "$WHEEL_PATTERN" \
  --dir "$TRUST_ASSETS"
gh release download "$CORE_TAG" --repo "$GITHUB_REPOSITORY" \
  --pattern "hol-guard-v${CORE_VERSION}.intoto.jsonl" --dir "$TRUST_ASSETS"
WHEEL=""
WHEEL_COUNT=0
while IFS= read -r candidate; do
  WHEEL="$candidate"
  WHEEL_COUNT=$((WHEEL_COUNT + 1))
done < <(find "$TRUST_ASSETS" -maxdepth 1 -type f \
  -name "$WHEEL_PATTERN" -print)
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
# A repair dispatch attests the later main commit that checked out this tag.
if ! verify_published_wheel "refs/tags/${CORE_TAG}"; then
  if ! verify_published_wheel "refs/heads/${RELEASE_BRANCH}"; then
    attested_commit=$(python3 -I scripts/release/read_publish_attestation_commit.py \
      "$BUNDLE" "refs/heads/${RELEASE_BRANCH}")
    [[ "$attested_commit" =~ ^[0-9a-f]{40}$ ]]
    git -C "$TRUST_REPO" fetch --force --no-recurse-submodules origin \
      "+${attested_commit}:refs/repair-attested"
    git -C "$TRUST_REPO" merge-base --is-ancestor "$SOURCE_SHA" "$attested_commit"
    gh attestation verify "$WHEEL" \
      --repo "$GITHUB_REPOSITORY" \
      --bundle "$BUNDLE" \
      --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/publish.yml" \
      --signer-digest "$attested_commit" \
      --source-digest "$attested_commit" \
      --source-ref "refs/heads/${RELEASE_BRANCH}" \
      --deny-self-hosted-runners >/dev/null
  fi
fi
cp "$WHEEL" "$RUNNER_TEMP/$ATTESTED_NAME"
echo "ATTESTED_WHEEL_FILENAME=$(basename "$WHEEL")" >> "$GITHUB_ENV"
test -f "$RUNNER_TEMP/$ATTESTED_NAME"
echo "sha=$SOURCE_SHA" >> "$GITHUB_OUTPUT"
