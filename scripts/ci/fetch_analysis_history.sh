#!/usr/bin/env bash
# Preserve complete blame and PR ancestry without fetching unrelated branches or tags.
set -euo pipefail

source_sha="${GITHUB_SHA:?GITHUB_SHA is required}"
if [[ ! "$source_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected a full analyzed commit SHA" >&2
  exit 1
fi
test "$(git rev-parse HEAD)" = "$source_sha"

set --
if [[ "$(git rev-parse --is-shallow-repository)" == true ]]; then
  set -- --unshallow
fi
git -c protocol.version=2 fetch --no-tags --no-recurse-submodules "$@" \
  origin "$source_sha" '+refs/heads/main:refs/remotes/origin/main'
test "$(git rev-parse --is-shallow-repository)" = false
test "$(git rev-parse HEAD)" = "$source_sha"
