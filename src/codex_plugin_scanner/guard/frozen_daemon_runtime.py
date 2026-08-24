"""PyInstaller-specific Guard daemon runtime adaptations."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from .daemon import manager

_frozen_runtime_installed = False
_frozen_runtime_fingerprint_cache: tuple[Path, str] | None = None
_frozen_runtime_state_matcher: Callable[[dict[str, object]], bool] | None = None


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

    digest = hashlib.sha256()
    try:
        with executable.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise RuntimeError("Frozen Guard daemon executable identity could not be read.") from error
    fingerprint = digest.hexdigest()
    _frozen_runtime_fingerprint_cache = (executable, fingerprint)
    return fingerprint


def _macos_signing_team(executable: Path) -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        verified = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(executable)],
            check=False,
            capture_output=True,
            timeout=5,
        )
        details = subprocess.run(
            ["/usr/bin/codesign", "--display", "--verbose=4", str(executable)],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if verified.returncode != 0 or details.returncode != 0:
        return None
    for line in details.stderr.splitlines():
        if not line.startswith("TeamIdentifier="):
            continue
        team = line.partition("=")[2].strip()
        return team if team and team != "not set" else None
    return None


def _trusted_frozen_peer_state(payload: dict[str, object]) -> bool:
    """Accept a same-release macOS peer only when Apple verifies one publisher."""

    if (
        payload.get("compatibility_version") != manager.GUARD_DAEMON_COMPATIBILITY_VERSION
        or payload.get("package_version") != manager.__version__
    ):
        return False
    source_root = payload.get("source_root")
    fingerprint = payload.get("runtime_fingerprint")
    if not isinstance(source_root, str) or not manager._is_sha256_hex(fingerprint):
        return False
    try:
        peer = Path(source_root).expanduser().resolve(strict=True)
        current = _trusted_frozen_executable()
    except (OSError, RuntimeError):
        return False
    if not peer.is_file():
        return False
    current_team = _macos_signing_team(current)
    return current_team is not None and _macos_signing_team(peer) == current_team


def _frozen_runtime_state_matches(payload: dict[str, object]) -> bool:
    matcher = _frozen_runtime_state_matcher
    if matcher is None:
        return False
    return matcher(payload) or _trusted_frozen_peer_state(payload)


def _same_guard_home(left: Path, right: Path) -> bool:
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def _split_frozen_parent_command(command: str, executable: Path) -> list[str] | None:
    """Preserve a trusted frozen executable path when POSIX ps drops argv quoting."""

    executable_text = str(executable)
    if os.name != "nt" and command.startswith(executable_text):
        suffix = command[len(executable_text) :]
        if not suffix:
            return [executable_text]
        if suffix[0].isspace():
            tail = manager._split_process_command(suffix.lstrip())
            if tail is None:
                return None
            return [executable_text, *tail]
    return manager._split_process_command(command)


def _trusted_frozen_bootloader_parent_pid(guard_home: Path) -> int | None:
    """Return the proven PyInstaller one-file parent PID for this daemon child."""

    if not bool(getattr(sys, "frozen", False)):
        return None
    current_pid = os.getpid()
    parent_pid = os.getppid()
    if parent_pid <= 1 or parent_pid == current_pid:
        return None

    command = manager._guard_daemon_command_for_pid(parent_pid)
    if command is None:
        return None
    try:
        current_executable = _trusted_frozen_executable()
    except RuntimeError:
        return None
    parts = _split_frozen_parent_command(command, current_executable)
    if not parts or not manager._guard_daemon_command_parts_match(parts):
        return None
    command_guard_home = manager._guard_home_from_command_parts(parts)
    if command_guard_home is None or not _same_guard_home(command_guard_home, guard_home):
        return None

    try:
        parent_executable = Path(parts[0]).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if parent_executable != current_executable:
        return None
    return parent_pid


def _filter_frozen_bootloader_parent(
    guard_home: Path,
    inventory: list[tuple[int, int]] | None,
) -> list[tuple[int, int]] | None:
    if inventory is None:
        return None
    parent_pid = _trusted_frozen_bootloader_parent_pid(guard_home)
    if parent_pid is None:
        return inventory
    return [(pid, port) for pid, port in inventory if pid != parent_pid]


def install_frozen_daemon_runtime() -> None:
    """Install one-file daemon identity and process-inventory adaptations."""

    global _frozen_runtime_installed, _frozen_runtime_state_matcher
    if not bool(getattr(sys, "frozen", False)):
        return

    # The detached daemon launcher supplies this only for the independent
    # one-file relaunch. Do not leak it to the daemon's multiprocessing workers.
    os.environ.pop("PYINSTALLER_RESET_ENVIRONMENT", None)

    if _frozen_runtime_installed:
        return
    current_inventory = manager._guard_daemon_process_inventory_for_guard_home
    _frozen_runtime_state_matcher = manager._guard_daemon_state_matches_current_runtime

    def filtered_inventory(guard_home: Path) -> list[tuple[int, int]] | None:
        return _filter_frozen_bootloader_parent(guard_home, current_inventory(guard_home))

    manager._guard_daemon_process_inventory_for_guard_home = filtered_inventory
    manager._current_guard_daemon_source_root = _frozen_runtime_source_root
    manager._current_guard_daemon_runtime_fingerprint = _frozen_runtime_fingerprint
    manager._guard_daemon_state_matches_current_runtime = _frozen_runtime_state_matches
    _frozen_runtime_installed = True
