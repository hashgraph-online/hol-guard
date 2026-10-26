#!/usr/bin/env bash
# Notarize the Core onefile and onedir archives; both must be accepted.
# Usage: notarize_core_archives.sh ONEFILE_ZIP ONEFILE_RESULT ONEDIR_ZIP ONEDIR_RESULT
# The archives are independent, so Apple reviews both at once.
set -euo pipefail
ONEFILE_ZIP="${1:?onefile archive}"
ONEFILE_RESULT="${2:?onefile result path}"
ONEDIR_ZIP="${3:?onedir archive}"
ONEDIR_RESULT="${4:?onedir result path}"
: "${APPLE_ID:?}"
: "${APPLE_PASSWORD:?}"
: "${APPLE_TEAM_ID:?}"
notarize() {
  xcrun notarytool submit "$1" \
    --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$APPLE_TEAM_ID" \
    --wait --output-format json > "$2"
}
notarize "$ONEFILE_ZIP" "$ONEFILE_RESULT" &
ONEFILE_NOTARY=$!
notarize "$ONEDIR_ZIP" "$ONEDIR_RESULT" &
ONEDIR_NOTARY=$!
ONEFILE_STATUS=0
wait "$ONEFILE_NOTARY" || ONEFILE_STATUS=$?
ONEDIR_STATUS=0
wait "$ONEDIR_NOTARY" || ONEDIR_STATUS=$?
for result in "$ONEFILE_RESULT" "$ONEDIR_RESULT"; do
  jq -e '.status == "Accepted"' "$result" >/dev/null || {
    cat "$result" >&2
    exit 1
  }
done
if [[ "$ONEFILE_STATUS" -ne 0 || "$ONEDIR_STATUS" -ne 0 ]]; then
  echo "notarytool failed: onefile=$ONEFILE_STATUS onedir=$ONEDIR_STATUS" >&2
  exit 1
fi
