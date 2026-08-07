#!/bin/zsh
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || exit 3
/bin/launchctl bootout system/org.hol.guard.machine-health >/dev/null 2>&1 || true
pkgutil --forget org.hol.guard >/dev/null 2>&1 || true
rm -rf "/Library/Application Support/HOL Guard" "/Library/Application Support/HOL Guard State"
rm -f "/Library/LaunchAgents/org.hol.guard.user-activation.plist"
rm -f "/Library/LaunchDaemons/org.hol.guard.machine-health.plist"
exit 0
