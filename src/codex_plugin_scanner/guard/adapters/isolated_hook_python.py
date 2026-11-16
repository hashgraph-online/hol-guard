"""The system interpreter a stdlib hook client runs under, probed in isolation."""

from __future__ import annotations

import functools
import os
import stat
import subprocess
import sys
from pathlib import Path

_ISOLATED_PYTHON_PROBE = (
    "import hmac, json, sys, urllib.request; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)"
)
_ISOLATED_PYTHON_PROBE_TIMEOUT_SECONDS = 1.5


def _isolated_python_candidates() -> tuple[str, ...]:
    candidates = ["/usr/bin/python3"] if sys.platform == "darwin" or sys.platform.startswith("linux") else []
    return tuple(candidates)


def _isolated_python_is_usable(path: Path) -> bool:
    """Return whether *path* can run the stdlib Cursor hook client in isolation."""

    try:
        metadata = path.stat()
    except OSError:
        return False
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        return False
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) & 0o022:
        return False
    probe_env = {"PATH": "/usr/bin:/bin"}
    system_root = os.environ.get("SYSTEMROOT")
    if isinstance(system_root, str) and system_root:
        probe_env["SYSTEMROOT"] = system_root
    try:
        completed = subprocess.run(
            [str(path), "-I", "-c", _ISOLATED_PYTHON_PROBE],
            check=False,
            capture_output=True,
            timeout=_ISOLATED_PYTHON_PROBE_TIMEOUT_SECONDS,
            env=probe_env,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


@functools.lru_cache(maxsize=1)
def _discover_isolated_cursor_hook_python() -> str | None:
    for candidate in _isolated_python_candidates():
        path = Path(candidate)
        if _isolated_python_is_usable(path):
            return str(path)
    return None


def isolated_cursor_hook_python() -> str | None:
    """Return a probed system interpreter for the stdlib Cursor hook client."""

    return _discover_isolated_cursor_hook_python()


__all__ = ["isolated_cursor_hook_python"]
