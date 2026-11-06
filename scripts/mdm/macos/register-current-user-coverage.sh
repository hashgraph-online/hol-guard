#!/bin/zsh
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || exit 3
readonly GUARD="/Library/Application Support/HOL Guard/hol-guard/hol-guard"
readonly USER_NAME="$(/usr/bin/stat -f '%Su' /dev/console)"
[[ -n "${USER_NAME}" && "${USER_NAME}" != "root" && "${USER_NAME}" != "loginwindow" ]] || exit 0
readonly USER_HOME="$(dscl . -read "/Users/${USER_NAME}" NFSHomeDirectory | sed -n 's/^NFSHomeDirectory: //p')"
[[ -n "${USER_HOME}" && -d "${USER_HOME}" ]] || exit 2

exec "${GUARD}" mdm harness-coverage-register --home "${USER_HOME}" --user "${USER_NAME}" --json
