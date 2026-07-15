#!/bin/zsh
set -u

readonly GUARD="/Library/Application Support/HOL Guard/hol-guard/hol-guard"
[[ -x "${GUARD}" ]] || exit 1
exec "${GUARD}" mdm status --scope machine --json
