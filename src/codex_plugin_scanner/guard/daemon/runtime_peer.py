"""Identity rules for same-release and Desktop-sidecar daemon peers."""

from __future__ import annotations

from pathlib import Path

from packaging.version import InvalidVersion, Version

_DESKTOP_CORE_PARTS = ("org.hol.guard.desktop", "core", "versions")


def daemon_source_is_desktop_core(source_root: object) -> bool:
    """Return True when daemon state points at a Desktop Core sidecar tree."""

    if not isinstance(source_root, str) or not source_root.strip():
        return False
    parts = tuple(part.lower() for part in source_root.replace("\\", "/").split("/") if part)
    marker_len = len(_DESKTOP_CORE_PARTS)
    return any(parts[index : index + marker_len] == _DESKTOP_CORE_PARTS for index in range(len(parts) - marker_len))


def daemon_desktop_core_source_available(source_root: object) -> bool:
    """Return True when a Desktop Core sidecar path still exists on disk.

    Relative fixture paths keep matching by shape. Absolute trees that were
    deleted after a Core move are not peers and must be recycled.
    """

    if not daemon_source_is_desktop_core(source_root):
        return False
    path = Path(str(source_root).replace("\\", "/"))
    if not path.is_absolute():
        return True
    return path.exists()


def _package_version_is_current_or_newer(package_version: object, current_version: str) -> bool:
    if not isinstance(package_version, str) or not package_version.strip():
        return False
    try:
        return Version(package_version) >= Version(current_version)
    except InvalidVersion:
        return False


def live_daemon_package_is_newer_than(package_version: object, current_version: str) -> bool:
    """True when a live daemon must not be replaced by an older caller."""

    if not isinstance(package_version, str) or not package_version.strip():
        return False
    try:
        return Version(package_version) > Version(current_version)
    except InvalidVersion:
        return False


def daemon_state_matches_current_runtime(
    payload: dict[str, object],
    *,
    current_version: str | None = None,
) -> bool:
    """Accept the live current-protocol daemon when identity or a current Desktop Core matches."""

    from .manager import (
        GUARD_DAEMON_COMPATIBILITY_VERSION,
        __version__,
        _current_guard_daemon_runtime_fingerprint,
    )

    installed_version = current_version if current_version is not None else __version__
    fingerprint = payload.get("runtime_fingerprint")
    if payload.get("compatibility_version") != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        return False
    if fingerprint == _current_guard_daemon_runtime_fingerprint():
        return True
    if payload.get("package_version") == installed_version:
        return True
    if not daemon_desktop_core_source_available(payload.get("source_root")):
        return False
    return _package_version_is_current_or_newer(payload.get("package_version"), installed_version)


def retain_newer_live_daemon_url(guard_home: Path, current_version: str) -> str | None:
    """Keep a newer live daemon when an older Desktop or CLI caller tries to replace it."""

    from .manager import _live_guard_daemon_url, _load_authenticated_daemon_identity

    identity = _load_authenticated_daemon_identity(guard_home)
    if identity is None:
        return None
    payload, _auth_token = identity
    if not live_daemon_package_is_newer_than(payload.get("package_version"), current_version):
        return None
    return _live_guard_daemon_url(guard_home, require_current_runtime=False)


def live_or_newer_daemon_url(
    guard_home: Path,
    *,
    executable: Path | None,
    preferred_port: int | None,
    current_version: str,
) -> str | None:
    """Reuse a newer live daemon on any port; otherwise only the preferred port."""

    from .manager import _guard_daemon_url_port, load_guard_daemon_url

    if executable is not None:
        return retain_newer_live_daemon_url(guard_home, current_version)
    existing_url = load_guard_daemon_url(guard_home)
    if existing_url is None:
        return None
    if preferred_port is None or _guard_daemon_url_port(existing_url) == preferred_port:
        return existing_url
    return None
