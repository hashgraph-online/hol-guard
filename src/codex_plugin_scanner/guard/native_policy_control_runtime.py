"""Deadline-bound existing runtime selection for off-hook authority control.

The ordinary selector and its capability cache retain their existing behavior.
This path freshly validates the same candidate/manifest/compatibility contract,
without placing deadline-specific results in that cache. Its bounded worker
owns potentially late setup and subprocess cleanup, and never returns it late.
"""

from __future__ import annotations

import json
import threading
import time

from . import native_runtime
from .codex_hook_launch_runtime import run_isolated_hook_process
from .native_policy_control_transport import run_native_control_worker
from .native_runtime import NativeRuntimeIdentity, NativeRuntimeStatus
from .native_runtime_capabilities import NativeRuntimeCapabilities


def native_policy_control_runtime_status(*, deadline_monotonic: float) -> NativeRuntimeStatus | None:
    def select(cancelled: threading.Event) -> NativeRuntimeStatus:
        return _native_policy_control_runtime_status_owned(cancelled=cancelled, deadline_monotonic=deadline_monotonic)

    return run_native_control_worker(select, deadline_monotonic=deadline_monotonic)


def _native_policy_control_runtime_status_owned(
    *, cancelled: threading.Event, deadline_monotonic: float
) -> NativeRuntimeStatus:
    """Select within one existing owner, retaining its cancellation and deadline."""

    def check_continuation() -> None:
        if cancelled.is_set() or time.monotonic() >= deadline_monotonic:
            raise TimeoutError("Native control runtime selection deadline exceeded")

    def capabilities(identity: NativeRuntimeIdentity) -> NativeRuntimeCapabilities | None:
        check_continuation()
        # Same one-second capability ceiling as the ordinary selector,
        # composed with the caller's original absolute maintenance budget.
        capability_deadline = min(deadline_monotonic, time.monotonic() + 1.0)
        result = run_isolated_hook_process(
            (str(identity.path), "capabilities", "--json"),
            input_text="",
            cwd=identity.path.parent,
            environment=native_runtime._isolated_environment(),
            deadline_monotonic=capability_deadline,
            output_limit=native_runtime._MAX_RESPONSE_BYTES,
            stop_event=cancelled,
            bound_input_to_deadline=True,
        )
        check_continuation()
        if (
            result.returncode != 0
            or result.timed_out
            or result.output_limit_exceeded
            or result.containment_failed
            or time.monotonic() >= capability_deadline
        ):
            return None
        try:
            payload = json.loads(result.stdout)
        except (ValueError, RecursionError):
            return None
        return native_runtime._decode_capabilities(payload)

    return native_runtime._native_runtime_status_with_setup(
        check_continuation=check_continuation,
        capability_provider=capabilities,
    )
