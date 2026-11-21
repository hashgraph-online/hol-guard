"""Find a live Guard daemon that still runs an older package than this CLI."""

from __future__ import annotations

from pathlib import Path

from packaging.version import InvalidVersion, Version

from ..native_daemon_peer import verified_live_guard_daemon_identity

_STALE_DAEMON_PROBE_TIMEOUT_SECONDS = 3.0


def stale_live_daemon_version(guard_home: Path, current_version: str) -> str | None:
    """The live daemon's package version when it is older than ``current_version``."""
    identity = verified_live_guard_daemon_identity(
        guard_home,
        session_timeout=_STALE_DAEMON_PROBE_TIMEOUT_SECONDS,
    )
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


__all__ = ["stale_live_daemon_version"]
