"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_FAILURE_CODE_LENGTH = 128
_FAILURE_CODE_PATTERN = re.compile(r"native_[a-z0-9_]+")
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def _record_failure_code(stderr: str, fallback: str) -> None:
    for line in stderr.splitlines():
        if len(line) <= _MAX_FAILURE_CODE_LENGTH and _FAILURE_CODE_PATTERN.fullmatch(line):
            _LAST_FAILURE_CODE.set(line)
            return
    _LAST_FAILURE_CODE.set(fallback)


def native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float,
    raw_hook_envelope: bool = False,
) -> bytes | None:
    """Invoke the native client without interpreting its protocol."""
    _LAST_FAILURE_CODE.set(None)
    if not payload or timeout_seconds <= 0:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    try:
        input_text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    state_dir = guard_home / "native-runtime"
    command = "hook-client" if raw_hook_envelope else "resident-client"
    try:
        result = run_isolated_hook_process(
            (str(executable), command, "--stdin", str(state_dir)),
            input_text=input_text,
            cwd=executable.parent,
            environment=dict(environment),
            timeout_seconds=timeout_seconds,
            output_limit=_MAX_RESPONSE_BYTES,
            windows_kill_on_job_close=False,
        )
    except (OSError, RuntimeError, ValueError):
        _LAST_FAILURE_CODE.set("native_client_launcher_failed")
        return None
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.containment_failed
        or not result.stdout
    ):
        _record_failure_code(result.stderr, "native_client_process_failed")
        return None
    return result.stdout.encode("utf-8")


__all__ = ["native_resident_client_failure_code", "native_resident_client_request"]
