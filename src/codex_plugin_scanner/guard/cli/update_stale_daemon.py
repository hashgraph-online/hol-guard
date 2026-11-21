"""Restart a live Guard daemon that still runs an older package than this CLI.

A failed daemon restart during an earlier update leaves the old daemon running,
and every later update then reports "already current". The already-current
path uses this module to find that daemon and load the installed package.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

from packaging.version import InvalidVersion, Version

from ..native_daemon_manage import _daemon_manage
from ..native_daemon_peer import daemon_refresh_outcome_succeeded

_STALE_DAEMON_PROBE_TIMEOUT_SECONDS = 3.0
# The whole native request, discovery included, so a hung runtime cannot hold an already-current update.
_STALE_DAEMON_REQUEST_SECONDS = 5.0

_RESTART_FAILED_MESSAGE = (
    "HOL Guard is current, but its daemon still runs an older version and could not be restarted safely."
)

RefreshResult = tuple[dict[str, object] | None, str | None]


def _live_daemon_identity(guard_home: Path) -> dict[str, object] | None:
    answer = _daemon_manage(
        "live_identity",
        guard_home,
        deadline=time.monotonic() + _STALE_DAEMON_REQUEST_SECONDS,
        args={"timeout": _STALE_DAEMON_PROBE_TIMEOUT_SECONDS, "verify_dashboard": False},
    )
    if answer is None or "error" in answer or answer.get("reason") != "healthy":
        return None
    identity = answer.get("identity")
    return cast(dict[str, object], identity) if isinstance(identity, dict) else None


def stale_live_daemon_version(guard_home: Path, current_version: str) -> str | None:
    """The live daemon's package version when it is older than ``current_version``."""
    if not (guard_home / "daemon-state.json").is_file():
        return None
    identity = _live_daemon_identity(guard_home)
    if identity is None:
        return None
    daemon_version = identity.get("package_version")
    if not isinstance(daemon_version, str) or not daemon_version.strip():
        return None
    try:
        older = Version(daemon_version) < Version(current_version)
    except InvalidVersion:
        return None
    return daemon_version if older else None


def restart_stale_live_daemon(
    payload: dict[str, object],
    *,
    guard_home: Path,
    current_version: str,
    refresh: Callable[[], RefreshResult],
    note: Callable[[dict[str, object], str | None], None],
) -> bool:
    """Refresh an older live daemon; False (with a failed payload) when that refresh fails."""
    if stale_live_daemon_version(guard_home, current_version) is None:
        return True
    daemon_refresh, daemon_refresh_note = refresh()
    if daemon_refresh is not None:
        payload["daemon_refresh"] = daemon_refresh
    note(payload, daemon_refresh_note)
    if not daemon_refresh_outcome_succeeded(daemon_refresh, allow_not_running=True):
        payload.update(
            {
                "status": "failed",
                "reason_code": "update_daemon_refresh_failed",
                "message": _RESTART_FAILED_MESSAGE,
            }
        )
        return False
    status = daemon_refresh.get("status") if isinstance(daemon_refresh, dict) else None
    if status == "restarted":
        payload["changed"] = True
    elif status == "retained_newer_runtime":
        # A newer runtime came up meanwhile; it owns package shims and harness hooks.
        payload["runtime_artifact_owner"] = "newer_runtime"
    return True


__all__ = ["restart_stale_live_daemon", "stale_live_daemon_version"]
