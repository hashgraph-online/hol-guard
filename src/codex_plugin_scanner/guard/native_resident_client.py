"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


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
    if not payload or timeout_seconds <= 0:
        return None
    try:
        input_text = payload.decode("utf-8")
    except UnicodeDecodeError:
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
        )
    except (OSError, RuntimeError, ValueError):
        return None
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.containment_failed
        or not result.stdout
    ):
        return None
    return result.stdout.encode("utf-8")


__all__ = ["native_resident_client_request"]
