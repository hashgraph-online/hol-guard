"""Shared SQLite timing configuration for Guard local storage."""

from __future__ import annotations

import os
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar

from .sqlite_constants import SQLITE_CACHE_SIZE_KIB as SQLITE_CACHE_SIZE_KIB
from .sqlite_constants import SQLITE_MMAP_SIZE_BYTES as SQLITE_MMAP_SIZE_BYTES
from .sqlite_deadline import sqlite_deadline_timeout

_DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS = 30.0
_INTERNAL_HOOK_SQLITE_TIMEOUT_ENV = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS"
_MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS = 250
_SQLITE_CONNECT_TIMEOUT_OVERRIDE: ContextVar[float | None] = ContextVar(
    "guard_sqlite_connect_timeout_override",
    default=None,
)


def _sqlite_base_timeout_seconds(environment: Mapping[str, str] | None = None) -> float:
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


def sqlite_connect_timeout_seconds(environment: Mapping[str, str] | None = None) -> float:
    return sqlite_deadline_timeout(_sqlite_base_timeout_seconds(environment))


@contextmanager
def sqlite_connect_timeout_override(timeout_seconds: float) -> Generator[None]:
    """Bound SQLite waits for one thread-local operation."""

    if timeout_seconds <= 0:
        raise ValueError("SQLite timeout override must be positive")
    token = _SQLITE_CONNECT_TIMEOUT_OVERRIDE.set(timeout_seconds)
    try:
        yield
    finally:
        _SQLITE_CONNECT_TIMEOUT_OVERRIDE.reset(token)


SQLITE_CONNECT_TIMEOUT_SECONDS = _sqlite_base_timeout_seconds()
SQLITE_BUSY_TIMEOUT_MS = int(SQLITE_CONNECT_TIMEOUT_SECONDS * 1000)
SQLITE_WAL_BUSY_TIMEOUT_MS = 1000
