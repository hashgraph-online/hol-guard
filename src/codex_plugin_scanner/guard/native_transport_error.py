"""Rust-backed validation for native transport error envelopes."""

from __future__ import annotations

import json
import time

_ERROR_CHECK_TIMEOUT_SECONDS = 0.25
_ERROR_CHECK_OUTPUT_LIMIT = 16 * 1024


def _native_error_code_result(
    payload: object,
    *,
    deadline_monotonic: float | None = None,
) -> tuple[bool, str | None]:
    try:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError):
        return False, None

    from .native_runtime import _run_native_process, _runtime_candidates, _validate_binary

    for candidate in _runtime_candidates():
        if _validate_binary(candidate) is None:
            continue
        timeout_seconds = _ERROR_CHECK_TIMEOUT_SECONDS
        if deadline_monotonic is not None:
            timeout_seconds = min(timeout_seconds, deadline_monotonic - time.monotonic())
            if timeout_seconds <= 0:
                return False, None
        output = _run_native_process(
            candidate,
            ("native-error-code", "--stdin"),
            input_text=encoded,
            timeout_seconds=timeout_seconds,
            output_limit=_ERROR_CHECK_OUTPUT_LIMIT,
        )
        if output is None:
            return False, None
        try:
            value = json.loads(output)
        except json.JSONDecodeError:
            return False, None
        if value is None:
            return True, None
        if isinstance(value, dict) and isinstance(value.get("error"), str):
            return True, value["error"]
        return False, None
    return False, None


def native_error_code(payload: object) -> str | None:
    """Return the Rust-validated code when the runtime is available."""

    _available, code = _native_error_code_result(payload)
    return code


def native_error(payload: object, *, deadline_monotonic: float | None = None) -> str | None:
    """Use Rust for strict error envelopes and retain the no-runtime fallback."""

    from .native_response_decoder import native_error as python_native_error

    local = python_native_error(payload)
    if local is None:
        return None
    available, native = _native_error_code_result(payload, deadline_monotonic=deadline_monotonic)
    return native if available else local
