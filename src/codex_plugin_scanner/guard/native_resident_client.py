"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path

from .codex_hook_launch_runtime import BoundedHookProcessResult, run_isolated_hook_process

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_FAILURE_CODE_LENGTH = 128
_FAILURE_CODE_PATTERN = re.compile(r"native_[a-z0-9_]+")
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)
_RESIDENTS_LOCK = threading.Lock()
_RESIDENTS: dict[tuple[Path, Path], Mapping[str, str]] = {}


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def _allowlisted_failure_code(stderr: str) -> str | None:
    for line in stderr.splitlines():
        if len(line) <= _MAX_FAILURE_CODE_LENGTH and _FAILURE_CODE_PATTERN.fullmatch(line):
            return line
    return None


def _classify_failure(result: BoundedHookProcessResult) -> str:
    if result.containment_failed:
        return "native_client_containment_failed"
    if result.timed_out:
        return "native_client_timed_out"
    if result.output_limit_exceeded:
        return "native_client_output_limit_exceeded"
    if result.returncode is None:
        return "native_client_status_missing"
    if result.returncode != 0:
        return "native_client_exit_nonzero"
    if not result.stdout:
        return "native_client_output_missing"
    return "native_client_process_failed"


def _record_failure_code(result: BoundedHookProcessResult) -> None:
    _LAST_FAILURE_CODE.set(_allowlisted_failure_code(result.stderr) or _classify_failure(result))


def _track_resident(executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
    if not state_dir.is_dir():
        return
    with _RESIDENTS_LOCK:
        _RESIDENTS[(executable, state_dir)] = dict(environment)


def stop_native_resident(
    *,
    executable: Path,
    state_dir: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = 3.0,
) -> bool:
    """Stop one Rust-managed resident and wait for its state retirement."""
    result = run_isolated_hook_process(
        (str(executable), "resident-stop", "--state-dir", str(state_dir)),
        input_text="",
        cwd=executable.parent,
        environment=dict(environment),
        timeout_seconds=timeout_seconds,
        output_limit=_MAX_RESPONSE_BYTES,
    )
    return (
        result.returncode == 0
        and not result.timed_out
        and not result.containment_failed
        and not list(state_dir.glob("resident-v3-*/generation-*.json"))
    )


def close_native_residents() -> None:
    """Stop Rust-managed residents created by this Python process."""
    with _RESIDENTS_LOCK:
        residents = list(_RESIDENTS.items())
    remaining: dict[tuple[Path, Path], Mapping[str, str]] = {}
    for (executable, state_dir), environment in residents:
        state_files = list(state_dir.glob("resident-v3-*/generation-*.json"))
        if state_files and not stop_native_resident(
            executable=executable,
            state_dir=state_dir,
            environment=environment,
        ):
            remaining[(executable, state_dir)] = environment
    with _RESIDENTS_LOCK:
        _RESIDENTS.clear()
        _RESIDENTS.update(remaining)


def native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None = None,
    raw_hook_envelope: bool = False,
    deadline_monotonic: float | None = None,
) -> bytes | None:
    """Invoke the native client without interpreting its protocol."""
    _LAST_FAILURE_CODE.set(None)
    if not payload or (deadline_monotonic is None and (timeout_seconds is None or timeout_seconds <= 0)):
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
        if deadline_monotonic is not None:
            result = run_isolated_hook_process(
                (str(executable), command, "--stdin", str(state_dir)),
                input_text=input_text,
                cwd=executable.parent,
                environment=dict(environment),
                timeout_seconds=None,
                deadline_monotonic=deadline_monotonic,
                output_limit=_MAX_RESPONSE_BYTES,
                windows_kill_on_job_close=False,
            )
        else:
            assert timeout_seconds is not None
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
        _record_failure_code(result)
        return None
    _track_resident(executable=executable, state_dir=state_dir, environment=environment)
    return result.stdout.encode("utf-8")


__all__ = [
    "close_native_residents",
    "native_resident_client_failure_code",
    "native_resident_client_request",
    "stop_native_resident",
]
