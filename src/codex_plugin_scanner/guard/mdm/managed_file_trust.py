"""Cross-platform ownership checks for machine-managed trust files."""

from __future__ import annotations

import json
import os
import platform
import stat
import subprocess
from pathlib import Path

from .acl import (
    _PathSurface,
    _run_windows_acl_payload,
    _verify_macos_surface,
    _windows_filesystem_chain,
    _windows_result,
)


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
        return _verify_macos_surface(surface, expected_uid=0, cache={}).healthy
    if resolved_system == "Windows":
        try:
            chain = _windows_filesystem_chain(str(path))
            payload = [
                {
                    "name": f"managed-file-{index:03d}",
                    "path": candidate,
                    "kind": "filesystem",
                    "expectedContainer": index < len(chain) - 1,
                    "leaf": index == len(chain) - 1,
                }
                for index, candidate in enumerate(chain)
            ]
            raw = _run_windows_acl_payload(payload)
            rows = raw if isinstance(raw, list) else [raw]
            results = [_windows_result(row) for row in rows]
            return len(results) == len(payload) and all(result.healthy for result in results)
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            return False
    if os.name != "posix":
        return False
    return posix_path_is_root_owned_and_restricted(path)
