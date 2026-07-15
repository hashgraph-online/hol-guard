#!/bin/zsh
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || exit 3
[[ "$#" -eq 2 ]] || exit 2
readonly USER_NAME="$1"
readonly USER_HOME="$2"
readonly USER_UID="$(id -u "${USER_NAME}")"
readonly GUARD="/Library/Application Support/HOL Guard/hol-guard/hol-guard"
readonly AUTH_ROOT="/Library/Application Support/HOL Guard State/removal-authorizations"
readonly AUTH_FILE="${AUTH_ROOT}/${USER_UID}-$(uuidgen).json"
readonly TOKEN_NAME="${AUTH_FILE:t}"

trap 'rm -f "${AUTH_FILE}"' EXIT
"${GUARD}" mdm authorize-deactivation --home "${USER_HOME}" --user "${USER_NAME}" \
  --token-name "${TOKEN_NAME}" --json >/dev/null
launchctl asuser "${USER_UID}" sudo -u "${USER_NAME}" -- \
  "${GUARD}" mdm deactivate --home "${USER_HOME}" --user "${USER_NAME}" \
  --authorization-file "${AUTH_FILE}" --json
