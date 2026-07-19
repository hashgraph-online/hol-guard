#!/bin/zsh
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || exit 3
pkgutil --forget org.hol.guard >/dev/null 2>&1 || true
rm -rf "/Library/Application Support/HOL Guard" "/Library/Application Support/HOL Guard State"
rm -f "/Library/LaunchAgents/org.hol.guard.user-activation.plist"
exit 0
