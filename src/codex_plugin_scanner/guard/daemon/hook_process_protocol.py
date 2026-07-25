"""Content-safe protocol helpers for isolated hook workers."""

from __future__ import annotations

import io
import json
import os
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager, redirect_stdout
from typing import TextIO, TypeGuard, cast

_HOOK_PROCESS_OUTPUT_LIMIT = 1_000_000
HOOK_ENV_ALLOWLIST = frozenset(
    {
        "HOL_GUARD_MANAGED_CURSOR_HOOK",
        "HOL_GUARD_CURSOR_APPROVAL_BINDING",
        "HOL_GUARD_CURSOR_AFTER_SHELL_PROOF",
        "CURSOR_PROJECT_DIR",
        "CURSOR_VERSION",
        "CURSOR_TRACE_ID",
        "CURSOR_SESSION_ID",
        "CURSOR_TRANSCRIPT_PATH",
    }
)


def capture_hook_command(run: Callable[[TextIO], int]) -> dict[str, object]:
    output = io.StringIO()
    with redirect_stdout(output):
        exit_code = run(output)
    raw_response = output.getvalue()
    if len(raw_response.encode("utf-8")) > _HOOK_PROCESS_OUTPUT_LIMIT:
        return {"payload": None, "reason_code": "daemon_hook_process_output_limit"}
    if not raw_response.strip():
        return {
            "payload": {} if exit_code == 0 else None,
            "reason_code": None if exit_code == 0 else "daemon_hook_process_failed",
        }
    try:
        parsed = cast(object, json.loads(raw_response))
    except json.JSONDecodeError:
        return {"payload": None, "reason_code": "daemon_hook_process_invalid_json"}
    typed_payload = as_string_object_dict(parsed)
    if typed_payload is None:
        return {"payload": None, "reason_code": "daemon_hook_process_invalid_json"}
    return {"payload": typed_payload, "reason_code": None}


def as_string_object_dict(value: object) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        return None
    return {key: item for key, item in raw.items() if isinstance(key, str)}


def is_pair(value: object) -> TypeGuard[tuple[object, object]]:
    return isinstance(value, tuple) and len(cast(tuple[object, ...], value)) == 2


@contextmanager
def applied_hook_environment(request: Mapping[str, object]) -> Generator[None, None, None]:
    raw_overlay = request.get("hook_env")
    overlay = as_string_object_dict(raw_overlay) or {}
    applied = {key: value for key, value in overlay.items() if key in HOOK_ENV_ALLOWLIST and isinstance(value, str)}
    original_env = {key: os.environ.get(key) for key in applied}
    try:
        os.environ.update(applied)
        yield
    finally:
        for key, original in original_env.items():
            if original is None:
                _ = os.environ.pop(key, None)
            else:
                os.environ[key] = original


__all__ = [
    "HOOK_ENV_ALLOWLIST",
    "applied_hook_environment",
    "as_string_object_dict",
    "capture_hook_command",
    "is_pair",
]
