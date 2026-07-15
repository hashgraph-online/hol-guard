#!/bin/zsh
set -euo pipefail

readonly GUARD="/Library/Application Support/HOL Guard/hol-guard/hol-guard"
readonly USER_NAME="$(id -un)"
readonly USER_HOME="$(dscl . -read "/Users/${USER_NAME}" NFSHomeDirectory | awk '{print $2}')"
[[ -n "${USER_HOME}" && -d "${USER_HOME}" ]] || exit 0
exec "${GUARD}" mdm repair --home "${USER_HOME}" --user "${USER_NAME}" --json
