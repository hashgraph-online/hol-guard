"""Bounded host-version execution for explicitly enabled evaluation preflight."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path

from .adapters.hook_python_subprocess import run_probe

_VERSION_TIMEOUT_SECONDS = 2.0
_VERSION_OUTPUT_LIMIT_BYTES = 64 * 1024


def _isolated_version_environment(probe_root: Path) -> dict[str, str]:
    """Build a minimal environment with all user-state locations redirected."""

    state_root = probe_root / "state"
    state_root.mkdir(mode=0o700)
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "HOME": str(state_root),
        "USERPROFILE": str(state_root),
        "XDG_CONFIG_HOME": str(state_root / "config"),
        "XDG_DATA_HOME": str(state_root / "data"),
        "XDG_STATE_HOME": str(state_root / "state"),
        "XDG_CACHE_HOME": str(state_root / "cache"),
        "TMPDIR": str(state_root / "tmp"),
        "TMP": str(state_root / "tmp"),
        "TEMP": str(state_root / "tmp"),
        "PYTHONNOUSERSITE": "1",
        "LC_ALL": "C",
        "LANG": "C",
    }
    for directory in ("config", "data", "state", "cache", "tmp"):
        (state_root / directory).mkdir(mode=0o700)
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "PATHEXT"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
    return environment


def _version_matches(output: str, expected_version: str) -> bool:
    core = (
        expected_version[1:]
        if expected_version[:1] in {"v", "V"} and expected_version[1:2].isdigit()
        else expected_version
    )
    prefix = "[vV]?" if core[0].isdigit() else ""
    pattern = rf"(?<![A-Za-z0-9_.-]){prefix}{re.escape(core)}(?![A-Za-z0-9_.-])"
    return re.search(pattern, output) is not None


def check_host_version(
    executable: Path, expected_version: str, *, timeout_seconds: float, output_limit_bytes: int
) -> tuple[bool, str]:
    probe_root = Path(tempfile.mkdtemp(prefix="hol-guard-preflight-"))
    try:
        probe_root.chmod(0o700)
        environment = _isolated_version_environment(probe_root)
        try:
            completed = run_probe(
                [os.fspath(executable), "--version"],
                cwd=probe_root,
                env=environment,
                timeout_seconds=min(_VERSION_TIMEOUT_SECONDS, timeout_seconds),
                output_limit_bytes=min(_VERSION_OUTPUT_LIMIT_BYTES, output_limit_bytes),
            )
        except (OSError, RuntimeError, ValueError):
            return False, "host_version_unavailable"
        if completed.output_overflow:
            return False, "host_version_output_limit"
        if completed.timed_out:
            return False, "host_version_timeout"
        if completed.capture_incomplete or completed.returncode != 0:
            return False, "host_version_unavailable"
        try:
            output = completed.stdout.decode("utf-8") + "\n" + completed.stderr.decode("utf-8")
        except UnicodeError:
            return False, "host_version_unavailable"
        if not _version_matches(output, expected_version):
            return False, "host_version_mismatch"
        return True, ""
    except (OSError, RuntimeError):
        return False, "host_version_unavailable"
    finally:
        shutil.rmtree(probe_root, ignore_errors=True)
