"""Stable codes for why the native daemon did not start.

The native ``daemon-manage`` answer names the cause of a failure in ``code``.
These helpers carry that code on the raised exception so callers such as the
dashboard launcher can report it instead of an unknown failure.
"""

from __future__ import annotations

NATIVE_RUNTIME_UNAVAILABLE = "native_runtime_unavailable"


def with_failure_code(error: Exception, code: object) -> Exception:
    """Attach a native failure code to ``error`` and return it."""

    if isinstance(code, str) and code:
        error.guard_failure_code = code  # pyright: ignore[reportAttributeAccessIssue]
    return error


def daemon_failure_code(error: BaseException) -> str:
    """The native failure code carried by ``error``, or a code for its type."""

    code = getattr(error, "guard_failure_code", None)
    if isinstance(code, str) and code:
        return code
    if isinstance(error, TimeoutError):
        return "daemon_start_timeout"
    if isinstance(error, ValueError):
        return "daemon_launch_config_invalid"
    return "daemon_unavailable"
