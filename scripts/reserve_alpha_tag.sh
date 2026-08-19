#!/usr/bin/env bash
set -euo pipefail
tag="alpha/v${VERSION}"
for attempt in 1 2 3; do
  remote_tag_sha=$(git ls-remote origin "refs/tags/${tag}" | awk '{print $1}')
  if [[ -n "$remote_tag_sha" ]]; then
    break
  fi
  if gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" \
    -f ref="refs/tags/${tag}" \
    -f sha="$SOURCE_SHA" >/dev/null; then
    remote_tag_sha=$(git ls-remote origin "refs/tags/${tag}" | awk '{print $1}')
    if [[ -n "$remote_tag_sha" ]]; then
      break
    fi
  fi
  if [[ "$attempt" != "3" ]]; then
    sleep $((attempt * 5))
  fi
done
if [[ -z "${remote_tag_sha:-}" ]]; then
  git tag "$tag" "$SOURCE_SHA"
  git push origin "refs/tags/${tag}" || true
  remote_tag_sha=$(git ls-remote origin "refs/tags/${tag}" | awk '{print $1}')
fi
if [[ "$remote_tag_sha" != "$SOURCE_SHA" ]]; then
  echo "Alpha tag reservation does not target the published source" >&2
  exit 1
fi
