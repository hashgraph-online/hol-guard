#!/usr/bin/env bash
set -euo pipefail
tag="alpha/v${VERSION}"
set +e
ref_json=$(gh api --method GET "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" 2>ref.err)
ref_code=$?
set -e
if [[ "$ref_code" -ne 0 ]]; then
  if grep -q 'Not Found' ref.err; then
    echo "No reservation tag to release"
    exit 0
  fi
  cat ref.err >&2
  exit "$ref_code"
fi
remote_tag_sha=$(printf '%s' "$ref_json" | jq -r '.object.sha // empty')
if [[ -z "$remote_tag_sha" ]]; then
  echo "Reservation lookup returned no object sha" >&2
  exit 1
fi
if [[ "$remote_tag_sha" != "$SOURCE_SHA" ]]; then
  echo "Reservation tag no longer points at this source"
  exit 0
fi
keep_reservation=false
for project in hol-guard plugin-scanner; do
  set +e
  http_code=$(curl -sS -o /dev/null -w '%{http_code}' "https://pypi.org/pypi/${project}/${VERSION}/json")
  curl_code=$?
  set -e
  if [[ "$curl_code" -ne 0 ]]; then
    echo "Could not inspect PyPI for ${project} ${VERSION}" >&2
    exit "$curl_code"
  fi
  if [[ "$http_code" == "200" ]]; then
    echo "PyPI already has ${project} ${VERSION}; keeping reservation"
    keep_reservation=true
    continue
  fi
  if [[ "$http_code" != "404" ]]; then
    echo "Unexpected PyPI status ${http_code} for ${project} ${VERSION}" >&2
    exit 1
  fi
done
if [[ "$keep_reservation" == "true" ]]; then
  exit 0
fi
gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/tags/${tag}"
set +e
gh api --method GET "repos/${GITHUB_REPOSITORY}/git/ref/tags/${tag}" 2>deleted.err
deleted_code=$?
set -e
if [[ "$deleted_code" -eq 0 ]]; then
  echo "Reservation tag still exists after delete" >&2
  exit 1
fi
if ! grep -q 'Not Found' deleted.err; then
  cat deleted.err >&2
  exit "$deleted_code"
fi
