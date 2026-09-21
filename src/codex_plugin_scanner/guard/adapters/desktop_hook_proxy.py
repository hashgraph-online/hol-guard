"""Signed macOS Desktop proxy launcher for frozen bounded hooks."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

_DESKTOP_PROXY_ENV = "HOL_GUARD_DESKTOP_HOOK_PROXY"


def _codesign_team(path: Path) -> str | None:
    """Return a verified Apple TeamIdentifier without importing the Desktop runtime."""

    verify = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode != 0:
        return None
    display = subprocess.run(
        ["/usr/bin/codesign", "--display", "--verbose=4", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if display.returncode != 0:
        return None
    for line in display.stderr.splitlines():
        team = line.strip().removeprefix("TeamIdentifier=")
        if team != line.strip() and team and team != "not set":
            return team
    return None


_DESKTOP_PROXY_LAUNCH_SCRIPT = r"""
set -u
proxy=$1
expected_team=$2
bundle=$3
config=$4
fallback=$5
fallback_bridge() {
  exec "$fallback" __guard-bounded-hook "$config"
}
verify_team() {
  candidate=$1
  /usr/bin/codesign --verify --strict --verbose=2 "$candidate" >/dev/null 2>&1 || return 1
  actual_team=$(
    /usr/bin/codesign --display --verbose=4 "$candidate" 2>&1 \
      | /usr/bin/sed -n 's/^TeamIdentifier=//p' \
      | /usr/bin/head -n 1
  ) || return 1
  [ -n "$actual_team" ] || return 1
  [ "$actual_team" != "not set" ] || return 1
  [ "$actual_team" = "$expected_team" ]
}
[ -x "$proxy" ] && [ ! -L "$proxy" ] || fallback_bridge
[ -x "$fallback" ] && [ ! -L "$fallback" ] || fallback_bridge
[ -d "$bundle" ] && [ ! -L "$bundle" ] || fallback_bridge
proxy_before=$(/usr/bin/stat -f '%d:%i:%u:%p' "$proxy" 2>/dev/null) || fallback_bridge
fallback_before=$(/usr/bin/stat -f '%d:%i:%u:%p' "$fallback" 2>/dev/null) || fallback_bridge
verify_team "$bundle" || fallback_bridge
verify_team "$proxy" || fallback_bridge
verify_team "$fallback" || fallback_bridge
proxy_after=$(/usr/bin/stat -f '%d:%i:%u:%p' "$proxy" 2>/dev/null) || fallback_bridge
fallback_after=$(/usr/bin/stat -f '%d:%i:%u:%p' "$fallback" 2>/dev/null) || fallback_bridge
[ "$proxy_before" = "$proxy_after" ] || fallback_bridge
[ "$fallback_before" = "$fallback_after" ] || fallback_bridge
"$proxy" __guard-hook-proxy "$config"
status=$?
if [ "$status" -eq 125 ] || [ "$status" -eq 126 ] || [ "$status" -eq 127 ]; then
  fallback_bridge
fi
exit "$status"
""".strip()


def _bundle_for_executable(path: Path) -> Path | None:
    for ancestor in path.parents:
        if ancestor.suffix == ".app":
            return ancestor
    return None


def _trusted_desktop_path(path: Path) -> bool:
    """Require a regular private executable under a non-symlinked app bundle."""

    try:
        raw_metadata = path.lstat()
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return False
    if stat.S_ISLNK(raw_metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if not os.access(resolved, os.X_OK):
        return False
    if metadata.st_uid not in {os.getuid(), 0} or stat.S_IMODE(metadata.st_mode) & 0o022:
        return False
    bundle = _bundle_for_executable(resolved)
    if bundle is None:
        return False
    for directory in (bundle, bundle / "Contents", bundle / "Contents" / "MacOS"):
        try:
            raw = directory.lstat()
            current = directory.stat()
        except OSError:
            return False
        if stat.S_ISLNK(raw.st_mode) or not stat.S_ISDIR(current.st_mode):
            return False
        if current.st_uid not in {os.getuid(), 0} or stat.S_IMODE(current.st_mode) & 0o022:
            return False
    return True


def _trusted_desktop_hook_proxy_command(
    python_executable: str,
    config_json: str,
) -> tuple[str, ...] | None:
    """Return a runtime-verified signed macOS proxy command or retain Core."""

    if (
        sys.platform != "darwin"
        or not bool(getattr(sys, "frozen", False))
        or os.environ.get("HOL_GUARD_DESKTOP") != "1"
    ):
        return None
    raw = os.environ.get(_DESKTOP_PROXY_ENV)
    if not raw:
        return None
    candidate = Path(raw)
    core_candidate = Path(python_executable)
    if not candidate.is_absolute() or not core_candidate.is_absolute():
        return None
    if not _trusted_desktop_path(candidate) or not _trusted_desktop_path(core_candidate):
        return None
    try:
        proxy = candidate.resolve(strict=True)
        core = core_candidate.resolve(strict=True)
    except OSError:
        return None
    proxy_bundle = _bundle_for_executable(proxy)
    core_bundle = _bundle_for_executable(core)
    if proxy_bundle is None or proxy_bundle != core_bundle or proxy.parent != core.parent:
        return None

    proxy_team = _codesign_team(proxy)
    core_team = _codesign_team(core)
    bundle_team = _codesign_team(proxy_bundle)
    if proxy_team is None or proxy_team == "not set" or proxy_team != core_team or proxy_team != bundle_team:
        return None

    return (
        "/bin/sh",
        "-c",
        _DESKTOP_PROXY_LAUNCH_SCRIPT,
        "hol-guard-desktop-proxy",
        str(proxy),
        proxy_team,
        str(proxy_bundle),
        config_json,
        str(core),
    )
