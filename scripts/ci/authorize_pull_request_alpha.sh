#!/usr/bin/env bash
# Bind a manual pull request alpha to a repository admin and that pull request's head.
# The caller checks this script out from main, never from the pull request.
set -euo pipefail

: "${GITHUB_REPOSITORY:?}"
: "${GITHUB_ACTOR:?}"
: "${GITHUB_ACTOR_ID:?}"
: "${PULL_REQUEST:?}"
: "${EXPECTED_SHA:?}"
: "${GITHUB_OUTPUT:?}"

if [[ "$GITHUB_ACTOR_ID" == "41898282" ]]; then
  echo "The GitHub Actions bot cannot publish a pull request alpha" >&2
  exit 1
fi
if [[ ! "$PULL_REQUEST" =~ ^[1-9][0-9]*$ ]]; then
  echo "Pull request number must be a positive integer" >&2
  exit 1
fi
if [[ ! "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  echo "Expected source SHA must be 40 lowercase hexadecimal characters" >&2
  exit 1
fi
if ! permission=$(gh api "repos/${GITHUB_REPOSITORY}/collaborators/${GITHUB_ACTOR}/permission" --jq .permission); then
  echo "Pull request alphas can only be published by a repository admin" >&2
  exit 1
fi
if [[ "$permission" != "admin" ]]; then
  echo "Pull request alphas can only be published by a repository admin" >&2
  exit 1
fi
if ! head_sha=$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PULL_REQUEST}" --jq .head.sha); then
  echo "Pull request ${PULL_REQUEST} could not be read" >&2
  exit 1
fi
if [[ ! "$head_sha" =~ ^[0-9a-f]{40}$ || "$head_sha" != "$EXPECTED_SHA" ]]; then
  echo "Pull request ${PULL_REQUEST} head does not match the expected source" >&2
  exit 1
fi
printf 'source_sha=%s\n' "$head_sha" >> "$GITHUB_OUTPUT"
