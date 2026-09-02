"""User-initiated repair for stale local daemon runtimes."""

from __future__ import annotations

from pathlib import Path

from packaging.version import InvalidVersion, Version

from ...version import __version__
from .live_identity import verified_live_guard_daemon_identity
from .manager import (
    clear_guard_daemon_state,
    ensure_guard_daemon_after_update,
    guard_daemon_retirement_is_complete,
    repair_approval_center_locator,
    retire_all_guard_daemons_for_home,
)
from .runtime_peer import daemon_source_is_desktop_core
from .start_lock import guard_daemon_start_lock as _guard_daemon_start_lock


def _verified_live_runtime(
    identity: dict[str, object],
) -> tuple[Version, str, str] | None:
    version_text = identity.get("package_version")
    runtime_fingerprint = identity.get("runtime_fingerprint")
    if not isinstance(version_text, str) or not isinstance(runtime_fingerprint, str):
        return None
    try:
        version = Version(version_text)
    except InvalidVersion:
        return None
    return version, version_text, runtime_fingerprint


def _retained_runtime_status(daemon_version: Version, current_version: Version) -> str:
    if daemon_version == current_version:
        return "current"
    if daemon_version > current_version:
        return "retained_newer_runtime"
    return "retained_desktop_runtime"


def repair_guard_daemon_runtime(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
) -> dict[str, object]:
    """Repair discovery state and replace an authenticated older runtime."""

    trusted_home = (home_dir or Path.home()).expanduser().resolve(strict=True)
    if not trusted_home.is_dir():
        raise RuntimeError("Guard daemon requires a user home directory.")
    with _guard_daemon_start_lock(guard_home):
        result = repair_approval_center_locator(guard_home)
        identity = verified_live_guard_daemon_identity(guard_home)
        verified_runtime = _verified_live_runtime(identity) if identity is not None else None
        try:
            current_version = Version(__version__)
        except InvalidVersion as error:
            raise RuntimeError("Installed Guard package version is invalid.") from error
        desktop_sidecar = identity is not None and daemon_source_is_desktop_core(identity.get("source_root"))
        if verified_runtime is not None and (verified_runtime[0] >= current_version or desktop_sidecar):
            daemon_version, daemon_version_text, _ = verified_runtime
            return {
                **result,
                "runtime_status": _retained_runtime_status(daemon_version, current_version),
                "daemon_version": daemon_version_text,
                "cli_version": __version__,
            }

        daemon_version_text = identity.get("package_version") if identity is not None else None
        retired = retire_all_guard_daemons_for_home(guard_home)
        if not guard_daemon_retirement_is_complete(guard_home):
            raise RuntimeError("Stale Guard daemon could not be retired safely.")
        clear_guard_daemon_state(guard_home)
        daemon_url = ensure_guard_daemon_after_update(
            guard_home,
            home_dir=trusted_home,
        )
    return {
        **result,
        "runtime_status": "restarted",
        "daemon_version": daemon_version_text if isinstance(daemon_version_text, str) else "unknown",
        "cli_version": __version__,
        "daemon_url": daemon_url,
        "retired": retired,
    }


__all__ = ["repair_guard_daemon_runtime"]
