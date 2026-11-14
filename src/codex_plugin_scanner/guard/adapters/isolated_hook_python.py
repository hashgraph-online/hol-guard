"""The system interpreter a stdlib hook client runs under, probed in isolation.

The native ``isolated_hook_python`` kind finds and probes it; see
``harness_adapter/isolated_python.rs``.
"""

from __future__ import annotations

import functools
import os

# The probe itself may take 1.5 seconds.
_TIMEOUT_SECONDS = 5.0


@functools.lru_cache(maxsize=1)
def _discover_isolated_cursor_hook_python() -> str | None:
    # Hook bridges import this module, and must stay off the native runtime
    # until an install actually asks.
    from ..native_runner_authority import NativeRunnerAuthorityError, native_runner_authority

    request = {"system_root": os.environ.get("SYSTEMROOT")}
    try:
        answer = native_runner_authority("isolated_hook_python", request, timeout_seconds=_TIMEOUT_SECONDS)
    except NativeRunnerAuthorityError:
        return None
    interpreter = answer.get("interpreter")
    return interpreter if isinstance(interpreter, str) and set(answer) == {"interpreter"} else None


def isolated_cursor_hook_python() -> str | None:
    """Return a probed system interpreter for the stdlib Cursor hook client."""

    return _discover_isolated_cursor_hook_python()


__all__ = ["isolated_cursor_hook_python"]
