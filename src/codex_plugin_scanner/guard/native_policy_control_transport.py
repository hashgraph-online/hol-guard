"""One-attempt off-hook control transport with an absolute caller deadline.

A timed-out owner never accepts a late result. Cleanup retains a bounded worker
slot until the existing process containment path finishes; no hook pool or
hook deadline semantics are changed. A request already dispatched can have an
ambiguous outcome and is never retried here.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from queue import Empty, Queue
from typing import TypeVar

from .codex_hook_launch_runtime import isolated_hook_environment, run_isolated_hook_process
from .native_resident_client import _MAX_PERSISTENT_CLIENTS

_MAX_CONTROL_BYTES = 4 * 1024
# Retain the existing bound on simultaneous native client helpers. A worker
# keeps its slot throughout startup and containment, even after its caller exits.
_CONTROL_SLOTS = threading.BoundedSemaphore(_MAX_PERSISTENT_CLIENTS)
_ControlResult = TypeVar("_ControlResult")


def native_policy_control_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    deadline_monotonic: float,
) -> bytes | None:
    """Return only an on-time, contained one-shot result, without retrying."""
    operation = _control_request_operation(
        executable=executable,
        guard_home=guard_home,
        environment=environment,
        payload=payload,
        deadline_monotonic=deadline_monotonic,
    )
    if operation is None:
        return None
    return run_native_control_worker(operation, deadline_monotonic=deadline_monotonic)


def _native_policy_control_request_owned(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    deadline_monotonic: float,
    cancelled: threading.Event,
) -> bytes | None:
    """Use the caller's existing bounded owner; never acquire a second slot."""
    if cancelled.is_set() or time.monotonic() >= deadline_monotonic:
        return None
    operation = _control_request_operation(
        executable=executable,
        guard_home=guard_home,
        environment=environment,
        payload=payload,
        deadline_monotonic=deadline_monotonic,
    )
    return None if operation is None else operation(cancelled)


def _control_request_operation(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    deadline_monotonic: float,
) -> Callable[[threading.Event], bytes | None] | None:
    if (
        type(deadline_monotonic) not in (int, float)
        or type(payload) is not bytes
        or not payload
        or len(payload) > _MAX_CONTROL_BYTES
    ):
        return None
    try:
        if not math.isfinite(deadline_monotonic):
            return None
    except OverflowError:
        return None
    try:
        input_text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    command = (str(executable), "resident-client", "--stdin", str(guard_home / "native-runtime"))
    child_environment = isolated_hook_environment(environment)

    def exchange(cancelled: threading.Event) -> bytes | None:
        result = run_isolated_hook_process(
            command,
            input_text=input_text,
            cwd=executable.parent,
            environment=child_environment,
            deadline_monotonic=deadline_monotonic,
            output_limit=_MAX_CONTROL_BYTES + 1,
            windows_kill_on_job_close=False,
            stop_event=cancelled,
            bound_input_to_deadline=True,
        )
        if (
            result.returncode == 0
            and not result.timed_out
            and not result.containment_failed
            and not result.output_limit_exceeded
            and not cancelled.is_set()
            and time.monotonic() < deadline_monotonic
        ):
            framed = result.stdout.encode("utf-8")
            # The native CLI appends exactly one LF. Canonical body checks
            # remain in the authenticated adapter; do not strip whitespace.
            if framed.endswith(b"\n") and 1 < len(framed) <= _MAX_CONTROL_BYTES + 1:
                return framed[:-1]
        return None

    return exchange


def run_native_control_worker(
    operation: Callable[[threading.Event], _ControlResult | None],
    *,
    deadline_monotonic: float,
) -> _ControlResult | None:
    """Own one off-hook operation through cleanup without accepting late output.

    An operation runs directly inside its acquired slot. It must not acquire
    another control slot for its own subprocess; cleanup keeps this slot owned.
    """
    if type(deadline_monotonic) not in (int, float):
        return None
    try:
        if not math.isfinite(deadline_monotonic):
            return None
    except OverflowError:
        return None
    cancelled = threading.Event()
    results: Queue[_ControlResult | None] = Queue(maxsize=1)
    slots = _CONTROL_SLOTS
    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0 or remaining > threading.TIMEOUT_MAX or not slots.acquire(timeout=remaining):
        return None

    def exchange() -> None:
        output: _ControlResult | None = None
        try:
            if cancelled.is_set() or time.monotonic() >= deadline_monotonic:
                return
            output = operation(cancelled)
        except Exception:
            # Neither child errors nor cleanup details cross this boundary.
            output = None
        finally:
            results.put_nowait(output)
            slots.release()

    try:
        worker = threading.Thread(target=exchange, name="hol-guard-native-control", daemon=True)
        worker.start()
    except (RuntimeError, OSError):
        cancelled.set()
        slots.release()
        return None
    remaining = deadline_monotonic - time.monotonic()
    if remaining <= 0:
        cancelled.set()
        return None
    try:
        output = results.get(timeout=remaining)
    except Empty:
        cancelled.set()
        return None
    if time.monotonic() >= deadline_monotonic:
        cancelled.set()
        return None
    return output
