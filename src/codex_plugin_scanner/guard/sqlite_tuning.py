"""Shared SQLite timing configuration for Guard local storage."""

from __future__ import annotations

import math
import os
import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar

_DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS = 30.0
_INTERNAL_HOOK_SQLITE_TIMEOUT_ENV = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
_MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS = 250
_SQLITE_CONNECT_TIMEOUT_OVERRIDE: ContextVar[float | None] = ContextVar(
    "guard_sqlite_connect_timeout_override",
    default=None,
)
_SQLITE_OPERATION_DEADLINE: ContextVar[float | None] = ContextVar("guard_sqlite_operation_deadline", default=None)


def sqlite_operation_deadline_monotonic() -> float | None:
    return _SQLITE_OPERATION_DEADLINE.get()


def sqlite_connect_timeout_seconds(environment: Mapping[str, str] | None = None) -> float:
    timeout = _sqlite_wait_limit_seconds(environment)
    deadline = _SQLITE_OPERATION_DEADLINE.get()
    return timeout if deadline is None else min(timeout, max(0.0, deadline - time.monotonic()))


def _sqlite_wait_limit_seconds(environment: Mapping[str, str] | None = None) -> float:
    override = _SQLITE_CONNECT_TIMEOUT_OVERRIDE.get()
    if override is not None:
        return override
    source = os.environ if environment is None else environment
    raw_timeout = source.get(_INTERNAL_HOOK_SQLITE_TIMEOUT_ENV)
    if not isinstance(raw_timeout, str):
        return _DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS
    try:
        timeout_ms = int(raw_timeout)
    except ValueError:
        return _DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS
    if timeout_ms <= 0:
        return _DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS
    return min(timeout_ms, _MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS) / 1000


@contextmanager
def sqlite_operation_deadline(deadline_monotonic: float) -> Generator[None]:
    """Compose all storage waits with the caller's original operation clock."""

    if not math.isfinite(deadline_monotonic):
        raise ValueError("SQLite deadline must be finite")
    parent = _SQLITE_OPERATION_DEADLINE.get()
    token = _SQLITE_OPERATION_DEADLINE.set(deadline_monotonic if parent is None else min(parent, deadline_monotonic))
    try:
        yield
    finally:
        _SQLITE_OPERATION_DEADLINE.reset(token)


@contextmanager
def sqlite_connect_timeout_override(
    timeout_seconds: float,
    *,
    operation_seconds: float | None = None,
) -> Generator[None]:
    """Bound SQLite waits for one thread-local operation.

    ``timeout_seconds`` is the lock-wait cap. ``operation_seconds`` is the wall
    clock for work that already holds the database; it defaults to the same cap.
    """

    operation_budget = timeout_seconds if operation_seconds is None else operation_seconds
    if (
        not math.isfinite(timeout_seconds)
        or timeout_seconds <= 0
        or not math.isfinite(operation_budget)
        or operation_budget <= 0
    ):
        raise ValueError("SQLite timeout override must be positive")
    token = _SQLITE_CONNECT_TIMEOUT_OVERRIDE.set(timeout_seconds)
    try:
        with sqlite_operation_deadline(time.monotonic() + operation_budget):
            yield
    finally:
        _SQLITE_CONNECT_TIMEOUT_OVERRIDE.reset(token)


SQLITE_CONNECT_TIMEOUT_SECONDS = sqlite_connect_timeout_seconds()
SQLITE_BUSY_TIMEOUT_MS = int(SQLITE_CONNECT_TIMEOUT_SECONDS * 1000)
SQLITE_WAL_BUSY_TIMEOUT_MS = 1000
# Per-connection hot-path tuning (connection-scoped, applied in _connect).
# Negative cache_size = KiB; 256 MiB page cache so multi-GB stores don't thrash.
SQLITE_CACHE_SIZE_KIB = 256 * 1024
# mmap window for read-heavy paths; SQLite falls back gracefully if unsupported.
SQLITE_MMAP_SIZE_BYTES = 1024 * 1024 * 1024
