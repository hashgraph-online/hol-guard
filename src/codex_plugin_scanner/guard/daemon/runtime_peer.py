"""Identity rules for same-release and Desktop-sidecar daemon peers."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

from packaging.version import InvalidVersion, Version

_DESKTOP_CORE_PARTS = ("org.hol.guard.desktop", "core", "versions")
_DESKTOP_APP_BUNDLE_PART = "hol guard.app"
_DESKTOP_WINDOWS_INSTALL_PART = "hol guard"
_DESKTOP_WINDOWS_RUNTIME_DIR = "hol-guard"
_DESKTOP_BUNDLED_PART = "bundled"
_DESKTOP_BUNDLED_BIN_PART = "bin"
_DESKTOP_BUNDLED_CORE_PARTS = ("lib", "hol-guard-core")
_DESKTOP_CORE_EXECUTABLES = ("hol-guard", "hol-guard.exe")
_DESKTOP_VERSIONS_PART = "versions"
_DESKTOP_STABLE_LAUNCHER_PARTS = ("current-hol-guard", "current-hol-guard.cmd")


def daemon_source_is_desktop_core(source_root: object) -> bool:
    """Return True when daemon state points at a Desktop Core sidecar tree.

    Desktop daemons record these source shapes: the managed Core versions
    tree, the executable bundled inside the macOS ``HOL Guard.app`` bundle,
    the Windows installer layout ``HOL Guard/hol-guard``, and the frozen
    Desktop Core layouts from stable_guard_cli (``versions/<release>/<exe>``,
    ``bundled/<release>/bin/<exe>``,
    ``bundled/<release>/lib/hol-guard-core/<exe>``, and the
    ``current-hol-guard`` launcher).
    A source tree that is merely a checkout, a pipx venv, or another app's
    bundle never matches.
    """

    if not isinstance(source_root, str) or not source_root.strip():
        return False
    parts = tuple(part.lower() for part in source_root.replace("\\", "/").split("/") if part)
    marker_len = len(_DESKTOP_CORE_PARTS)
    if any(parts[index : index + marker_len] == _DESKTOP_CORE_PARTS for index in range(len(parts) - marker_len + 1)):
        return True
    if any(part == _DESKTOP_APP_BUNDLE_PART for part in parts):
        return True
    if any(
        parts[index] == _DESKTOP_WINDOWS_INSTALL_PART and parts[index + 1] == _DESKTOP_WINDOWS_RUNTIME_DIR
        for index in range(len(parts) - 1)
    ):
        return True
    if parts and parts[-1] in _DESKTOP_STABLE_LAUNCHER_PARTS:
        return True
    if any(
        parts[index] == _DESKTOP_BUNDLED_PART
        and index + 2 < len(parts)
        and parts[index + 2] == _DESKTOP_BUNDLED_BIN_PART
        for index in range(len(parts) - 2)
    ):
        return True
    if any(
        parts[index] == _DESKTOP_BUNDLED_PART
        and len(parts) - index == 5
        and parts[index + 2 : index + 4] == _DESKTOP_BUNDLED_CORE_PARTS
        and parts[index + 4] in _DESKTOP_CORE_EXECUTABLES
        for index in range(len(parts) - 4)
    ):
        return True
    return any(parts[index] == _DESKTOP_VERSIONS_PART and len(parts) - index == 3 for index in range(len(parts) - 2))


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


def live_desktop_owned_daemon(guard_home: Path) -> dict[str, object] | None:
    """Return a verified live daemon identity that Guard Desktop owns.

    The Desktop supervises its daemon and respawns it, so no CLI-side
    retirement can win against it. Callers use this to keep such a daemon
    serving instead of fighting it.
    """

    from .live_identity import verified_live_guard_daemon_identity

    identity = verified_live_guard_daemon_identity(guard_home)
    if identity is None:
        return None
    if not daemon_desktop_core_source_available(identity.get("source_root")):
        return None
    return identity


def load_guard_daemon_endpoint(guard_home: Path) -> tuple[str, str] | None:
    """Resolve a verified daemon endpoint, preferring the current runtime or Desktop owner."""

    from .manager import load_guard_daemon_auth_token, load_guard_daemon_url

    daemon_url = load_guard_daemon_url(guard_home)
    auth_token = load_guard_daemon_auth_token(guard_home)
    if isinstance(daemon_url, str) and daemon_url.strip() and isinstance(auth_token, str) and auth_token.strip():
        return daemon_url, auth_token

    identity = live_desktop_owned_daemon(guard_home)
    if identity is None:
        return None
    identity_guard_home = identity.get("guard_home")
    try:
        if (
            not isinstance(identity_guard_home, str)
            or Path(identity_guard_home).expanduser().resolve() != guard_home.expanduser().resolve()
        ):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    owner_url = identity.get("daemon_url")
    if not isinstance(owner_url, str) or not owner_url.strip():
        return None
    owner_token = load_guard_daemon_auth_token(guard_home)
    if not isinstance(owner_token, str) or not owner_token.strip():
        return None
    auth_token_id = identity.get("auth_token_id")
    if not isinstance(auth_token_id, str) or not auth_token_id.strip():
        return None
    if not secrets.compare_digest(hashlib.sha256(owner_token.encode("utf-8")).hexdigest(), auth_token_id):
        return None
    return owner_url, owner_token


def load_guard_daemon_endpoint_url(guard_home: Path) -> str | None:
    """Return the URL from a verified current-runtime or Desktop-owned endpoint."""

    endpoint = load_guard_daemon_endpoint(guard_home)
    return endpoint[0] if endpoint is not None else None


def retained_newer_runtime_payload(
    guard_home: Path,
    *,
    minimum_version: str | None = None,
) -> dict[str, object] | None:
    """Retain a live newer runtime only after signed-state and loopback health agree."""

    from .live_identity import verified_live_guard_daemon_identity

    identity = verified_live_guard_daemon_identity(guard_home)
    if identity is None:
        return None
    daemon_version_text = identity.get("package_version")
    daemon_url = identity.get("daemon_url")
    if not isinstance(daemon_version_text, str) or not isinstance(daemon_url, str):
        return None
    from ... import version as package_version

    try:
        daemon_version = Version(daemon_version_text)
        required_version_text = minimum_version or package_version.__version__
        required_version = Version(required_version_text)
    except InvalidVersion:
        return None
    if daemon_version <= required_version:
        return None

    return {
        "status": "retained_newer_runtime",
        "daemon_url": daemon_url,
        "daemon_version": daemon_version_text,
        "cli_version": required_version_text,
        "runtime_verified": True,
    }


def daemon_refresh_outcome_succeeded(payload: object, *, allow_not_running: bool = False) -> bool:
    """Accept a refresh that restarted, retained another owner, or found nothing running."""

    if not isinstance(payload, dict):
        return False
    status = payload.get("status")
    if status == "not_running":
        return allow_not_running
    return (
        status in {"restarted", "retained_newer_runtime", "retained_desktop_owner"}
        and payload.get("runtime_verified") is True
    )


def retained_desktop_owner_payload(
    guard_home: Path,
    *,
    minimum_version: str | None = None,
) -> dict[str, object] | None:
    """Build a refresh result that keeps a verified Desktop-owned daemon.

    Callers that just activated a specific runtime pass ``minimum_version`` so
    only a daemon already serving those bytes is retained; the CLI self-update
    path keeps any verified Desktop daemon and lets the Desktop app converge.
    """

    identity = live_desktop_owned_daemon(guard_home)
    if identity is None:
        return None
    daemon_url = identity.get("daemon_url")
    daemon_version_text = identity.get("package_version")
    if not isinstance(daemon_url, str) or not daemon_url:
        return None
    if not isinstance(daemon_version_text, str) or not daemon_version_text:
        return None
    if minimum_version is not None:
        try:
            daemon_at_least_minimum = Version(daemon_version_text) >= Version(minimum_version)
        except InvalidVersion:
            return None
        if not daemon_at_least_minimum:
            return None
    return {
        "status": "retained_desktop_owner",
        "daemon_url": daemon_url,
        "daemon_version": daemon_version_text,
        "runtime_verified": True,
    }


def retained_desktop_owner_note(daemon_version: object) -> str:
    version_text = f" (version {daemon_version})" if isinstance(daemon_version, str) and daemon_version else ""
    return (
        f"Kept the Guard Desktop daemon{version_text} running; "
        "it will load the new package when the Desktop app updates."
    )


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
