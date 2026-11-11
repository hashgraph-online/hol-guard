"""PyInstaller-specific Guard daemon runtime adaptations."""

from __future__ import annotations

import hashlib
import os
import secrets
import sys
from pathlib import Path

from . import native_daemon_manage as manager
from .macos_code_signing import verified_macos_signing_team

_frozen_runtime_fingerprint_cache: tuple[Path, str] | None = None
_signing_team_cache: dict[tuple[Path, int, int], str] = {}
_SIGNING_TEAM_CACHE_LIMIT = 8


def _trusted_frozen_executable() -> Path:
    executable = Path(sys.executable).expanduser()
    if not executable.is_absolute() or not executable.is_file():
        raise RuntimeError("Frozen Guard daemon requires the signed Guard executable.")
    try:
        return executable.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("Frozen Guard daemon requires the signed Guard executable.") from error


def _frozen_runtime_source_root() -> str:
    """Use the stable one-file executable path instead of the temporary extraction root."""

    return str(_trusted_frozen_executable())


def _frozen_runtime_fingerprint() -> str:
    """Bind daemon compatibility to the exact frozen executable bytes."""

    global _frozen_runtime_fingerprint_cache
    executable = _trusted_frozen_executable()
    cached = _frozen_runtime_fingerprint_cache
    if cached is not None and cached[0] == executable:
        return cached[1]

    fingerprint = _executable_sha256(executable)
    _frozen_runtime_fingerprint_cache = (executable, fingerprint)
    return fingerprint


def _executable_sha256(executable: Path) -> str:
    digest = hashlib.sha256()
    try:
        with executable.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise RuntimeError("Frozen Guard daemon executable identity could not be read.") from error
    return digest.hexdigest()


def _cached_macos_signing_team(executable: Path) -> str | None:
    try:
        stat_result = executable.stat()
    except OSError:
        return None
    cache_key = (executable, stat_result.st_mtime_ns, stat_result.st_size)
    cached = _signing_team_cache.get(cache_key)
    if cached is not None:
        return cached
    team = verified_macos_signing_team(executable, deep=True)
    if team is None:
        return None
    if len(_signing_team_cache) >= _SIGNING_TEAM_CACHE_LIMIT:
        _signing_team_cache.clear()
    _signing_team_cache[cache_key] = team
    return team


def _trusted_frozen_peer_state(payload: dict[str, object]) -> bool:
    """Accept a same-release macOS peer only when Apple verifies one publisher."""

    if (
        payload.get("compatibility_version") != manager.GUARD_DAEMON_COMPATIBILITY_VERSION
        or payload.get("package_version") != manager.__version__
    ):
        return False
    source_root = payload.get("source_root")
    fingerprint = payload.get("runtime_fingerprint")
    if not isinstance(source_root, str) or not isinstance(fingerprint, str) or not manager._is_sha256_hex(fingerprint):
        return False
    try:
        peer = Path(source_root).expanduser().resolve(strict=True)
        current = _trusted_frozen_executable()
    except (OSError, RuntimeError):
        return False
    if not peer.is_file():
        return False
    try:
        peer_fingerprint = _executable_sha256(peer)
    except RuntimeError:
        return False
    if not secrets.compare_digest(peer_fingerprint, fingerprint):
        return False
    current_team = _cached_macos_signing_team(current)
    return current_team is not None and _cached_macos_signing_team(peer) == current_team


def install_frozen_daemon_runtime() -> None:
    """Drop the one-file relaunch marker; the native manager owns frozen identity checks."""

    if not bool(getattr(sys, "frozen", False)):
        return

    # The detached daemon launcher supplies this only for the independent
    # one-file relaunch. Do not leak it to the daemon's multiprocessing workers.
    os.environ.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
