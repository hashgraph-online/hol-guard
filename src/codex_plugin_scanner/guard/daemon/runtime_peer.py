"""Identity rules for same-release and Desktop-sidecar daemon peers."""

from __future__ import annotations

_DESKTOP_CORE_MARKER = "org.hol.guard.desktop/core/versions/"


def daemon_source_is_desktop_core(source_root: object) -> bool:
    """Return True when daemon state points at a Desktop Core sidecar tree."""

    if not isinstance(source_root, str) or not source_root.strip():
        return False
    return _DESKTOP_CORE_MARKER in source_root.replace("\\", "/").lower()


def daemon_state_matches_current_runtime(payload: dict[str, object]) -> bool:
    """Accept the live daemon when identity, version, or Desktop sidecar matches."""

    from .manager import (
        GUARD_DAEMON_COMPATIBILITY_VERSION,
        __version__,
        _current_guard_daemon_runtime_fingerprint,
    )

    fingerprint = payload.get("runtime_fingerprint")
    if payload.get("compatibility_version") != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        return False
    if fingerprint == _current_guard_daemon_runtime_fingerprint():
        return True
    if payload.get("package_version") == __version__:
        return True
    return daemon_source_is_desktop_core(payload.get("source_root"))
