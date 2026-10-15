"""Route Codex contained-test receipts through the PreToolUse ``updatedInput`` rewrite.

Codex applies ``permissionDecision: "allow"`` with ``updatedInput`` from 0.131.0.
macOS routes every contained profile and Linux the workspace sandbox, as for Z Code.
Older releases treat that output as an unsupported hook result and run the
original command, so the bridge rewrites only after it has confirmed the Codex
process that launched it is new enough. Otherwise the denial stands.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import TypeGuard

from .zcode_contained_tests import contained_zcode_response, platform_contains

_MIN_VERSION = (0, 131, 0)
_MAX_ANCESTORS = 6
_PROC_PIDTBSDINFO = 3
_PROC_BSDINFO_SIZE = 136
_PPID_OFFSET = 16
_VERSION = re.compile(r"^codex-cli (\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?\s*$")
UPDATE_HINT = "Update Codex to 0.131 or later so HOL Guard can run this command inside its contained runner."


def route_codex_containment(
    response: dict[str, object],
    *,
    hook_input: str,
    guard_home: Path | None,
    home_dir: Path | None = None,
    deadline: float | None = None,
) -> dict[str, object]:
    """Rewrite a containment receipt into the contained sink, or keep the denial."""

    if (
        not platform_contains(response)
        or guard_home is None
        or not _absolute_hook_home(home_dir)
        or response.get("policy_action") != "sandbox-required"
        or response.get("decision") != "deny"
    ):
        return response
    try:
        payload = json.loads(hook_input)
    except ValueError:
        return response
    if not isinstance(payload, dict) or payload.get("guard_containment_receipt_only") is True:
        return response
    executable = launching_codex_executable()
    if executable is None or not codex_applies_updated_input(executable, deadline=deadline):
        return _with_update_hint(response)
    routed = contained_zcode_response(
        response,
        input_text=json.dumps(payload),
        config={
            "harness": "codex",
            "guard_home": str(guard_home),
            "python_executable": sys.executable,
            "package_root": str(Path(__file__).resolve().parents[3]),
        },
        cli_args=["--home", str(home_dir)],
    )
    return routed if routed is not None else response


def _absolute_hook_home(home_dir: Path | None) -> TypeGuard[Path]:
    """True only for the absolute home bound into the installed Codex hook."""

    if home_dir is None:
        return False
    return home_dir.is_absolute() and "\x00" not in str(home_dir)


def launching_codex_executable() -> Path | None:
    """Path of the nearest ``codex`` ancestor process, read from the kernel."""

    if sys.platform == "linux":
        return _linux_codex_ancestor()
    try:
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    except OSError:
        return None
    pid = os.getppid()
    for _ in range(_MAX_ANCESTORS):
        if pid <= 1:
            return None
        path_buffer = ctypes.create_string_buffer(4096)
        if libproc.proc_pidpath(pid, path_buffer, len(path_buffer)) <= 0:
            return None
        path = Path(os.fsdecode(path_buffer.value))
        if path.name == "codex":
            return path
        info = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
        size = libproc.proc_pidinfo(pid, _PROC_PIDTBSDINFO, ctypes.c_uint64(0), info, _PROC_BSDINFO_SIZE)
        if size != _PROC_BSDINFO_SIZE:
            return None
        pid = int.from_bytes(info.raw[_PPID_OFFSET : _PPID_OFFSET + 4], sys.byteorder)
    return None


def _linux_codex_ancestor() -> Path | None:
    """The same walk through ``/proc``: each process's executable and parent."""

    pid = os.getppid()
    for _ in range(_MAX_ANCESTORS):
        if pid <= 1:
            return None
        try:
            path = Path(os.readlink(f"/proc/{pid}/exe"))
            if path.name == "codex":
                return path
            stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        # The command name can hold spaces and parentheses; the fields after its closing one are fixed.
        fields = stat.rsplit(")", 1)[-1].split()
        try:
            pid = int(fields[1])
        except (IndexError, ValueError):
            return None
    return None


def codex_applies_updated_input(executable: Path, *, deadline: float | None = None) -> bool:
    """True when ``codex --version`` reports a stable release that applies ``updatedInput``."""

    timeout = _version_probe_timeout(deadline)
    if timeout is None:
        return False
    try:
        result = subprocess.run(
            [os.fspath(executable), "--version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
        )
    except (OSError, subprocess.SubprocessError):
        return False
    match = _VERSION.match(result.stdout.strip()) if result.returncode == 0 else None
    if match is None:
        return False
    version = tuple(int(part) for part in match.group(1, 2, 3))
    # Any pre-release can predate the rewrite support, including one newer than 0.131.0.
    return match.group(4) is None and version >= _MIN_VERSION


def _version_probe_timeout(deadline: float | None) -> float | None:
    """Stay inside the hook deadline. A missed probe keeps the denial."""

    if deadline is None:
        return 3.0
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    return min(3.0, remaining)


def _with_update_hint(response: dict[str, object]) -> dict[str, object]:
    hook_output = response.get("hookSpecificOutput")
    if not isinstance(hook_output, dict):
        return response
    reason = hook_output.get("permissionDecisionReason")
    text = f"{reason} {UPDATE_HINT}" if isinstance(reason, str) and reason else UPDATE_HINT
    return {**response, "hookSpecificOutput": {**hook_output, "permissionDecisionReason": text}}


__all__ = [
    "UPDATE_HINT",
    "codex_applies_updated_input",
    "launching_codex_executable",
    "route_codex_containment",
]
