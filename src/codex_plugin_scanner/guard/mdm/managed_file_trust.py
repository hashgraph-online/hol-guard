"""Cross-platform ownership checks for machine-managed trust files."""

from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

from .acl import (
    _macos_request,
    _native_answer,
    _native_deadline,
    _PathSurface,
)
from .windows_support import windows_directory


def posix_path_is_root_owned_and_restricted(path: Path) -> bool:
    """Walk from path to root requiring regular file at path, directories above,
    no symlinks, root ownership, and no group/world write bits anywhere."""

    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
        if current == path:
            if not stat.S_ISREG(metadata.st_mode):
                return False
        elif not stat.S_ISDIR(metadata.st_mode):
            return False
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return False
        if current.parent == current:
            return True
        current = current.parent


def machine_controlled_file_is_trusted(path: Path, *, system_name: str | None = None) -> bool:
    """Verify a machine-owned regular file and every ancestor without following links."""
    resolved_system = system_name or platform.system()
    if not path.is_absolute():
        return False
    if resolved_system == "Darwin":
        surface = _PathSurface("managed-file", path, False, Path(path.anchor))
        answer = _native_answer(_macos_request((surface,), 0), deadline=_native_deadline())
        return answer is not None and answer.get("status") == "healthy"
    if resolved_system == "Windows":
        try:
            directory = windows_directory()
        except OSError:
            return False
        request: dict[str, object] = {
            "op": "windows-file-probe",
            "managed_file": str(path),
            "windows_directory": directory,
        }
        verdict = _native_answer(request, deadline=_native_deadline())
        return verdict is not None and verdict.get("status") == "healthy"
    if os.name != "posix":
        return False
    return posix_path_is_root_owned_and_restricted(path)
