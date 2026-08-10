"""PyInstaller-specific Guard daemon runtime adaptations."""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

from .daemon import manager

_frozen_runtime_installed = False
_frozen_runtime_fingerprint_cache: tuple[Path, str] | None = None


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

    global _frozen_runtime_installed
    if not bool(getattr(sys, "frozen", False)):
        return

    # A daemon is an independent invocation of the one-file executable. Force
    # PyInstaller to create a fresh extraction root instead of treating it as a
    # worker process that reuses the parent's private _MEI runtime directory.
    os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"

    if _frozen_runtime_installed:
        return
    current_inventory = manager._guard_daemon_process_inventory_for_guard_home

    def filtered_inventory(guard_home: Path) -> list[tuple[int, int]] | None:
        return _filter_frozen_bootloader_parent(guard_home, current_inventory(guard_home))

    manager._guard_daemon_process_inventory_for_guard_home = filtered_inventory
    manager._current_guard_daemon_source_root = _frozen_runtime_source_root
    manager._current_guard_daemon_runtime_fingerprint = _frozen_runtime_fingerprint
    _frozen_runtime_installed = True
